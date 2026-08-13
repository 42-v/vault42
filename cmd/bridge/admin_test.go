package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAdminAuth(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	ah := NewAdminHandler(fs, "secret-token")

	tests := []struct {
		name   string
		auth   string
		status int
	}{
		{"no auth", "", http.StatusUnauthorized},
		{"wrong token", "Bearer wrong", http.StatusUnauthorized},
		{"correct token", "Bearer secret-token", http.StatusMethodNotAllowed}, // GET on /bridge/flag = method not allowed
		{"no bearer prefix", "secret-token", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/bridge/flag", nil)
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}
			w := httptest.NewRecorder()
			ah.ServeFlag(w, req)

			if w.Code != tt.status {
				t.Errorf("status = %d, want %d", w.Code, tt.status)
			}
		})
	}
}

func TestAdminFlagUnflag(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	ah := NewAdminHandler(fs, "token123")

	// Flag an IP
	body, _ := json.Marshal(map[string]string{"ip": "10.0.0.1", "reason": "testing"})
	req := httptest.NewRequest(http.MethodPost, "/bridge/flag", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer token123")
	w := httptest.NewRecorder()
	ah.ServeFlag(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("flag status = %d, want %d", w.Code, http.StatusCreated)
	}

	if !fs.IsFlagged("10.0.0.1") {
		t.Error("IP should be flagged")
	}

	// List flags
	req = httptest.NewRequest(http.MethodGet, "/bridge/flags", nil)
	req.Header.Set("Authorization", "Bearer token123")
	w = httptest.NewRecorder()
	ah.ServeFlags(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("list status = %d, want %d", w.Code, http.StatusOK)
	}

	var listResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &listResp)
	if count, ok := listResp["count"].(float64); !ok || count != 1 {
		t.Errorf("list count = %v, want 1", listResp["count"])
	}

	// Unflag
	body, _ = json.Marshal(map[string]string{"ip": "10.0.0.1"})
	req = httptest.NewRequest(http.MethodDelete, "/bridge/flag", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer token123")
	w = httptest.NewRecorder()
	ah.ServeFlag(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("unflag status = %d, want %d", w.Code, http.StatusOK)
	}

	if fs.IsFlagged("10.0.0.1") {
		t.Error("IP should not be flagged after unflag")
	}
}

func TestAdminEmptyToken(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	ah := NewAdminHandler(fs, "") // No token configured

	req := httptest.NewRequest(http.MethodGet, "/bridge/flags", nil)
	req.Header.Set("Authorization", "Bearer anything")
	w := httptest.NewRecorder()
	ah.ServeFlags(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("empty token: status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

// TestAdminUnconfiguredTokenFailsClosedOnEveryRoute extends the case above to
// the whole surface. BRIDGE_ADMIN_TOKEN_FILE is optional, so a bridge deployed
// without it is a normal configuration rather than a broken one, and in that
// configuration the admin API must be unreachable rather than open. Flagging is
// destructive from a user's point of view, since a flagged address is quietly
// served fabricated data, so an unauthenticated caller must never reach it.
func TestAdminUnconfiguredTokenFailsClosedOnEveryRoute(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	ah := NewAdminHandler(fs, "")

	cases := []struct {
		method  string
		path    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{http.MethodPost, "/bridge/flag", ah.ServeFlag},
		{http.MethodDelete, "/bridge/flag", ah.ServeFlag},
		{http.MethodGet, "/bridge/flags", ah.ServeFlags},
	}

	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			for _, auth := range []string{"", "Bearer ", "Bearer anything"} {
				body := bytes.NewReader([]byte(`{"ip":"10.0.0.1"}`))
				req := httptest.NewRequest(c.method, c.path, body)
				if auth != "" {
					req.Header.Set("Authorization", auth)
				}
				w := httptest.NewRecorder()
				c.handler(w, req)

				if w.Code != http.StatusUnauthorized {
					t.Errorf("Authorization %q: status = %d, want %d", auth, w.Code, http.StatusUnauthorized)
				}
			}
		})
	}

	if len(fs.List()) != 0 {
		t.Error("an unauthenticated request changed the flag store")
	}
}

// TestAdminAuthRejectsMalformedAuthorization walks the header shapes a caller
// can get wrong or can try on purpose. Nothing but an exact bearer token may
// pass, and in particular the comparison must not be prefix based: a token that
// merely starts with the right bytes has to fail like any other.
func TestAdminAuthRejectsMalformedAuthorization(t *testing.T) {
	const token = "correct-token-value"

	fs := NewFlagStore(time.Hour, "")
	ah := NewAdminHandler(fs, token)

	tests := []struct {
		name string
		auth string
		want int
	}{
		{"exact token", "Bearer " + token, http.StatusOK},
		{"absent", "", http.StatusUnauthorized},
		{"scheme only", "Bearer", http.StatusUnauthorized},
		{"scheme with no value", "Bearer ", http.StatusUnauthorized},
		{"lowercase scheme", "bearer " + token, http.StatusUnauthorized},
		{"basic scheme", "Basic " + token, http.StatusUnauthorized},
		{"no scheme", token, http.StatusUnauthorized},
		{"a prefix of the token", "Bearer correct-token", http.StatusUnauthorized},
		{"the token with a suffix", "Bearer " + token + "x", http.StatusUnauthorized},
		{"leading whitespace", " Bearer " + token, http.StatusUnauthorized},
		{"trailing whitespace", "Bearer " + token + " ", http.StatusUnauthorized},
		{"double scheme", "Bearer Bearer " + token, http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/bridge/flags", nil)
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}
			w := httptest.NewRecorder()
			ah.ServeFlags(w, req)

			if w.Code != tt.want {
				t.Errorf("status = %d, want %d", w.Code, tt.want)
			}
		})
	}
}

// TestAdminFlagsListShapeWhenEmpty pins the empty case to a JSON array rather
// than a null. A client that iterates the response without a nil check breaks on
// null, and the empty flag list is by far the most common response this endpoint
// gives.
func TestAdminFlagsListShapeWhenEmpty(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	ah := NewAdminHandler(fs, "token")

	req := httptest.NewRequest(http.MethodGet, "/bridge/flags", nil)
	req.Header.Set("Authorization", "Bearer token")
	w := httptest.NewRecorder()
	ah.ServeFlags(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	raw := w.Body.String()
	if strings.Contains(raw, "null") {
		t.Errorf("body = %s, want an empty array rather than null", raw)
	}

	var doc struct {
		Flags []FlagEntry `json:"flags"`
		Count int         `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("body %s is not the documented shape: %v", raw, err)
	}
	if doc.Flags == nil {
		t.Error("flags decoded to nil, want an empty array")
	}
	if doc.Count != 0 {
		t.Errorf("count = %d, want 0", doc.Count)
	}
}

// TestAdminFlagsListContent checks that the fields an operator makes decisions
// from actually reach them. The reason and the expiry are the whole basis for
// judging whether a flag was a false positive, and an entry past its expiry must
// not be listed since it no longer routes anything.
func TestAdminFlagsListContent(t *testing.T) {
	fs := NewFlagStore(2*time.Hour, "")
	ah := NewAdminHandler(fs, "token")

	fs.Flag("203.0.113.1", "auto:rate_exceeded", 150)
	fs.Flag("203.0.113.2", "decoy:/wp-admin", 100)

	expired := NewFlagStore(time.Nanosecond, "")
	expired.Flag("203.0.113.3", "stale", 100)
	if len(expired.List()) != 0 {
		t.Fatal("an already expired flag is still listed")
	}

	req := httptest.NewRequest(http.MethodGet, "/bridge/flags", nil)
	req.Header.Set("Authorization", "Bearer token")
	w := httptest.NewRecorder()
	ah.ServeFlags(w, req)

	var doc struct {
		Flags []FlagEntry `json:"flags"`
		Count int         `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("body %s: %v", w.Body.String(), err)
	}
	if doc.Count != 2 || len(doc.Flags) != 2 {
		t.Fatalf("count = %d with %d entries, want 2 and 2", doc.Count, len(doc.Flags))
	}

	byIP := map[string]FlagEntry{}
	for _, e := range doc.Flags {
		byIP[e.IP] = e
	}
	first, ok := byIP["203.0.113.1"]
	if !ok {
		t.Fatalf("203.0.113.1 missing from %+v", doc.Flags)
	}
	if first.Reason != "auto:rate_exceeded" || first.Score != 150 {
		t.Errorf("entry = %q/%d, want auto:rate_exceeded/150", first.Reason, first.Score)
	}
	if first.FlaggedAt.IsZero() || first.ExpiresAt.IsZero() {
		t.Errorf("entry has zero timestamps: %+v", first)
	}
	if !first.ExpiresAt.After(first.FlaggedAt) {
		t.Errorf("ExpiresAt %v is not after FlaggedAt %v", first.ExpiresAt, first.FlaggedAt)
	}
}

// TestAdminMethodRouting covers the verbs each endpoint refuses. A 405 rather
// than a 404 matters here because an operator who gets a 404 will assume the
// bridge build is too old to have the endpoint at all.
func TestAdminMethodRouting(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	ah := NewAdminHandler(fs, "token")

	tests := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		method  string
		want    int
	}{
		{"flag rejects GET", ah.ServeFlag, http.MethodGet, http.StatusMethodNotAllowed},
		{"flag rejects PUT", ah.ServeFlag, http.MethodPut, http.StatusMethodNotAllowed},
		{"flag rejects PATCH", ah.ServeFlag, http.MethodPatch, http.StatusMethodNotAllowed},
		{"flags rejects POST", ah.ServeFlags, http.MethodPost, http.StatusMethodNotAllowed},
		{"flags rejects DELETE", ah.ServeFlags, http.MethodDelete, http.StatusMethodNotAllowed},
		{"flags rejects PUT", ah.ServeFlags, http.MethodPut, http.StatusMethodNotAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/bridge/flag", bytes.NewReader([]byte(`{"ip":"10.0.0.1"}`)))
			req.Header.Set("Authorization", "Bearer token")
			w := httptest.NewRecorder()
			tt.handler(w, req)

			if w.Code != tt.want {
				t.Errorf("status = %d, want %d", w.Code, tt.want)
			}
		})
	}

	if len(fs.List()) != 0 {
		t.Error("a rejected method still changed the flag store")
	}
}

// TestAdminFlagRejectsBadRequests covers the validation the flag endpoint does
// perform. Every rejection must leave the store untouched, since a half-applied
// flag is worse than none: it routes a user to the honeypot while reporting an
// error to the operator who would have unflagged them.
func TestAdminFlagRejectsBadRequests(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int
	}{
		{"empty body", "", http.StatusBadRequest},
		{"not JSON", "this is not json", http.StatusBadRequest},
		{"truncated JSON", `{"ip":"10.0.0.1"`, http.StatusBadRequest},
		{"JSON array", `["10.0.0.1"]`, http.StatusBadRequest},
		{"wrong field type", `{"ip":12345}`, http.StatusBadRequest},
		{"no ip field", `{"reason":"because"}`, http.StatusBadRequest},
		{"empty ip", `{"ip":"","reason":"because"}`, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := NewFlagStore(time.Hour, "")
			ah := NewAdminHandler(fs, "token")

			req := httptest.NewRequest(http.MethodPost, "/bridge/flag", strings.NewReader(tt.body))
			req.Header.Set("Authorization", "Bearer token")
			w := httptest.NewRecorder()
			ah.ServeFlag(w, req)

			if w.Code != tt.want {
				t.Errorf("status = %d, want %d; body %s", w.Code, tt.want, w.Body.String())
			}
			if len(fs.List()) != 0 {
				t.Errorf("a rejected request still flagged something: %+v", fs.List())
			}
		})
	}
}

// TestAdminUnflagRejectsBadRequests is the same guard on the delete side, plus
// the not-found case. Reporting 404 rather than 200 for an address that was
// never flagged is what lets an operator notice they typed the wrong address
// instead of believing they have fixed an incident.
func TestAdminUnflagRejectsBadRequests(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		preFlag   string
		want      int
		stillHeld string
	}{
		{name: "empty body", body: "", want: http.StatusBadRequest},
		{name: "not JSON", body: "nope", want: http.StatusBadRequest},
		{name: "no ip field", body: `{"reason":"x"}`, want: http.StatusBadRequest},
		{name: "empty ip", body: `{"ip":""}`, want: http.StatusBadRequest},
		{name: "never flagged", body: `{"ip":"10.0.0.9"}`, want: http.StatusNotFound},
		{
			name:      "unflagging one address leaves the others alone",
			body:      `{"ip":"10.0.0.1"}`,
			preFlag:   "10.0.0.2",
			want:      http.StatusNotFound,
			stillHeld: "10.0.0.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := NewFlagStore(time.Hour, "")
			ah := NewAdminHandler(fs, "token")
			if tt.preFlag != "" {
				fs.Flag(tt.preFlag, "pre-existing", 100)
			}

			req := httptest.NewRequest(http.MethodDelete, "/bridge/flag", strings.NewReader(tt.body))
			req.Header.Set("Authorization", "Bearer token")
			w := httptest.NewRecorder()
			ah.ServeFlag(w, req)

			if w.Code != tt.want {
				t.Errorf("status = %d, want %d; body %s", w.Code, tt.want, w.Body.String())
			}
			if tt.stillHeld != "" && !fs.IsFlagged(tt.stillHeld) {
				t.Errorf("%s was unflagged by a request naming a different address", tt.stillHeld)
			}
		})
	}
}

// TestAdminFlagDefaultsTheReason covers the fallback that keeps every entry in
// the flag list attributable. An empty reason in the list would be
// indistinguishable from a bug in the auto-flag path.
func TestAdminFlagDefaultsTheReason(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	ah := NewAdminHandler(fs, "token")

	req := httptest.NewRequest(http.MethodPost, "/bridge/flag", strings.NewReader(`{"ip":"10.0.0.1"}`))
	req.Header.Set("Authorization", "Bearer token")
	w := httptest.NewRecorder()
	ah.ServeFlag(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusCreated)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var doc map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("body %s: %v", w.Body.String(), err)
	}
	if doc["status"] != "flagged" || doc["ip"] != "10.0.0.1" {
		t.Errorf("body = %v, want status flagged for 10.0.0.1", doc)
	}

	entries := fs.List()
	if len(entries) != 1 {
		t.Fatalf("flag list has %d entries, want 1", len(entries))
	}
	if entries[0].Reason != "manual flag" {
		t.Errorf("reason = %q, want the default %q", entries[0].Reason, "manual flag")
	}
	if entries[0].Score != 100 {
		t.Errorf("score = %d, want 100", entries[0].Score)
	}
}

// TestAdminUnflagResponseShape pins the success body of the delete path.
func TestAdminUnflagResponseShape(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	ah := NewAdminHandler(fs, "token")
	fs.Flag("10.0.0.1", "manual", 100)

	req := httptest.NewRequest(http.MethodDelete, "/bridge/flag", strings.NewReader(`{"ip":"10.0.0.1"}`))
	req.Header.Set("Authorization", "Bearer token")
	w := httptest.NewRecorder()
	ah.ServeFlag(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var doc map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("body %s: %v", w.Body.String(), err)
	}
	if doc["status"] != "unflagged" || doc["ip"] != "10.0.0.1" {
		t.Errorf("body = %v, want status unflagged for 10.0.0.1", doc)
	}
	if fs.IsFlagged("10.0.0.1") {
		t.Error("the address is still flagged after a successful unflag")
	}
}

// TestAdminFlagAcceptsAnythingAsAnIP records that the endpoint does not check
// that "ip" is an address.
//
// Any string is accepted and stored, so a typo such as an address with a stray
// character, a hostname, or a whole CIDR range is reported back as a successful
// 201 and then never matches a client, because routing compares against the
// exact string clientIP produced. The operator believes an address is contained
// when nothing is. The stored key is also what goes into Redis as
// "bridge:flag:<value>", so an arbitrary string ends up in the shared keyspace.
//
// The test asserts the current behaviour so that adding validation, which would
// mean rejecting these with a 400, shows up here as a deliberate change.
func TestAdminFlagAcceptsAnythingAsAnIP(t *testing.T) {
	notAddresses := []struct {
		name  string
		value string
	}{
		{"octet out of range", "10.0.0.256"},
		{"trailing space", "10.0.0.1 "},
		{"a CIDR range", "10.0.0.0/24"},
		{"a hostname", "vault.example.com"},
		{"an SQL fragment", "'; DROP TABLE flags; --"},
		{"512 bytes of padding", strings.Repeat("a", 512)},
	}

	for _, tt := range notAddresses {
		t.Run(tt.name, func(t *testing.T) {
			fs := NewFlagStore(time.Hour, "")
			ah := NewAdminHandler(fs, "token")

			body, err := json.Marshal(map[string]string{"ip": tt.value})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			req := httptest.NewRequest(http.MethodPost, "/bridge/flag", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer token")
			w := httptest.NewRecorder()
			ah.ServeFlag(w, req)

			if w.Code != http.StatusCreated {
				t.Fatalf("status = %d, want %d; validation was added, so this test needs updating", w.Code, http.StatusCreated)
			}
			if !fs.IsFlagged(tt.value) {
				t.Errorf("%q was accepted but not stored", tt.value)
			}
			// It matches nothing clientIP could ever produce for a real client.
			if trimmed := strings.TrimSpace(tt.value); trimmed != tt.value && fs.IsFlagged(trimmed) {
				t.Errorf("%q also matched its trimmed form", tt.value)
			}
		})
	}
}

// TestAdminHandlerConcurrentUse drives both endpoints from many goroutines
// against one store. The admin API is reachable while the proxy is serving, so
// the handlers share the flag store with the request path by construction and
// must not corrupt it.
func TestAdminHandlerConcurrentUse(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	ah := NewAdminHandler(fs, "token")

	const workers = 16
	const iterations = 40

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.1.0.%d", w)
			wantReason := fmt.Sprintf("worker-%d", w)

			for i := 0; i < iterations; i++ {
				flagBody := fmt.Sprintf(`{"ip":%q,"reason":%q}`, ip, wantReason)
				req := httptest.NewRequest(http.MethodPost, "/bridge/flag", strings.NewReader(flagBody))
				req.Header.Set("Authorization", "Bearer token")
				rec := httptest.NewRecorder()
				ah.ServeFlag(rec, req)
				if rec.Code != http.StatusCreated {
					t.Errorf("flag returned %d, want 201", rec.Code)
					return
				}

				listReq := httptest.NewRequest(http.MethodGet, "/bridge/flags", nil)
				listReq.Header.Set("Authorization", "Bearer token")
				listRec := httptest.NewRecorder()
				ah.ServeFlags(listRec, listReq)
				if listRec.Code != http.StatusOK {
					t.Errorf("list returned %d, want 200", listRec.Code)
					return
				}

				var doc struct {
					Flags []FlagEntry `json:"flags"`
					Count int         `json:"count"`
				}
				if err := json.Unmarshal(listRec.Body.Bytes(), &doc); err != nil {
					t.Errorf("list body %s: %v", listRec.Body.String(), err)
					return
				}
				// The count must always agree with the array it describes, which
				// a torn read of the store would break.
				if doc.Count != len(doc.Flags) {
					t.Errorf("count = %d but the array holds %d entries", doc.Count, len(doc.Flags))
					return
				}
				// This worker's own entry must always carry this worker's reason.
				for _, e := range doc.Flags {
					if e.IP == ip && e.Reason != wantReason {
						t.Errorf("%s carries reason %q, want %q", ip, e.Reason, wantReason)
						return
					}
				}
			}
		}(w)
	}
	wg.Wait()

	if got := len(fs.List()); got != workers {
		t.Errorf("flag list holds %d entries, want %d", got, workers)
	}
}
