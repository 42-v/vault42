package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIsDecoyPath(t *testing.T) {
	tests := []struct {
		path    string
		isDecoy bool
		tmpl    string
	}{
		{"/wp-admin", true, "wp-login.html"},
		{"/wp-admin/", true, "wp-login.html"},
		{"/wp-login.php", true, "wp-login.html"},
		{"/phpmyadmin", true, "phpmyadmin.html"},
		{"/pma", true, "phpmyadmin.html"},
		{"/cpanel", true, "cpanel.html"},
		{"/webmail", true, "cpanel.html"},
		// /admin is deliberately NOT a decoy: vault42 serves its admin SPA and
		// roughly thirty documented API routes under it, and flagging an operator
		// for opening the admin console is a self-inflicted outage.
		// tests/spec/decoy_paths_test.go enforces that against the real routes.
		{"/admin", false, ""},
		{"/admin/auth/login", false, ""},
		{"/administrator", true, "admin.html"},
		{"/auth/login", false, ""},
		{"/healthz", false, ""},
		{"/", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			tmpl, ok := IsDecoyPath(tt.path)
			if ok != tt.isDecoy {
				t.Errorf("IsDecoyPath(%q) = %v, want %v", tt.path, ok, tt.isDecoy)
			}
			if tmpl != tt.tmpl {
				t.Errorf("IsDecoyPath(%q) template = %q, want %q", tt.path, tmpl, tt.tmpl)
			}
		})
	}
}

func TestDecoyServesHTMLOnGET(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	dh := NewDecoyHandler(fs, nil)

	req := httptest.NewRequest(http.MethodGet, "/wp-admin", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()

	dh.ServeDecoy(w, req, "10.0.0.1", "wp-login.html")

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	if !fs.IsFlagged("10.0.0.1") {
		t.Error("IP should be flagged after decoy hit")
	}
}

func TestDecoyReturnsFakeCredentialsOnPOST(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	dh := NewDecoyHandler(fs, nil)

	req := httptest.NewRequest(http.MethodPost, "/wp-login.php", nil)
	w := httptest.NewRecorder()

	dh.ServeDecoy(w, req, "10.0.0.2", "wp-login.html")

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if !fs.IsFlagged("10.0.0.2") {
		t.Error("IP should be flagged after decoy POST")
	}
}

// TestNewDecoyHandlerLoadsEveryTemplate checks that all four pages parsed out of
// the embedded filesystem. A template that failed to parse is only logged, so
// the handler starts happily and then answers that decoy path with a 404, which
// tells a scanner the path is simply absent and costs the trap its purpose.
func TestNewDecoyHandlerLoadsEveryTemplate(t *testing.T) {
	dh := NewDecoyHandler(NewFlagStore(time.Hour, ""), nil)

	want := []string{"wp-login.html", "phpmyadmin.html", "cpanel.html", "admin.html"}
	if len(dh.templates) != len(want) {
		t.Errorf("loaded %d templates, want %d", len(dh.templates), len(want))
	}
	for _, name := range want {
		if dh.templates[name] == nil {
			t.Errorf("template %q was not loaded", name)
		}
	}

	// Every template decoyPaths can select has to exist, otherwise some decoy
	// path answers 404 while the rest answer with a page.
	for path, tmpl := range decoyPaths {
		if dh.templates[tmpl] == nil {
			t.Errorf("decoy path %q maps to %q, which was not loaded", path, tmpl)
		}
	}
}

// TestNewDecoyHandlerKeepsGoingWhenAPageDoesNotLoad drives the parse failure in
// the constructor loop. Swapping the embedded set for an empty one is the only
// way in: the four pages are compiled into the binary and
// TestNewDecoyHandlerLoadsEveryTemplate proves they parse, so no caller can
// supply a broken one.
//
// The branch logs and continues on purpose, and both halves of that matter. A
// constructor that gave up on the first bad page would leave the remaining
// decoys unloaded, and one that refused to start would turn a missing cosmetic
// asset into a bridge that does not come up. What must survive is the flag: the
// trap is the point, the page is the decoration.
func TestNewDecoyHandlerKeepsGoingWhenAPageDoesNotLoad(t *testing.T) {
	original := decoyFS
	decoyFS = embed.FS{}
	t.Cleanup(func() { decoyFS = original })

	fs := NewFlagStore(time.Hour, "")
	dh := NewDecoyHandler(fs, nil)

	if dh == nil {
		t.Fatal("NewDecoyHandler returned nil when no template loaded")
	}
	if len(dh.templates) != 0 {
		t.Fatalf("loaded %d templates out of an empty filesystem, want 0", len(dh.templates))
	}

	req := httptest.NewRequest(http.MethodGet, "/wp-admin", nil)
	w := httptest.NewRecorder()
	dh.ServeDecoy(w, req, "10.0.0.7", "wp-login.html")

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
	if !fs.IsFlagged("10.0.0.7") {
		t.Error("the caller escaped the flag because the decoy page had not loaded")
	}
}

// TestDecoyPagesLookLikeTheirTargets keeps the pages convincing. A decoy that no
// longer resembles the product it imitates is worse than no decoy: an attacker
// who recognizes the page as a trap learns that the host runs a deception layer,
// which is the single fact the design is trying to withhold.
func TestDecoyPagesLookLikeTheirTargets(t *testing.T) {
	tests := []struct {
		tmpl   string
		needle string
	}{
		{"wp-login.html", "WordPress"},
		{"phpmyadmin.html", "phpMyAdmin"},
		{"cpanel.html", "cPanel"},
		{"admin.html", "Sign In"},
	}

	for _, tt := range tests {
		t.Run(tt.tmpl, func(t *testing.T) {
			fs := NewFlagStore(time.Hour, "")
			dh := NewDecoyHandler(fs, nil)

			req := httptest.NewRequest(http.MethodGet, "/probe", nil)
			w := httptest.NewRecorder()
			dh.ServeDecoy(w, req, "10.0.0.1", tt.tmpl)

			body := w.Body.String()
			if !strings.Contains(body, tt.needle) {
				t.Errorf("%s does not mention %q: %.200q", tt.tmpl, tt.needle, body)
			}
			// A login form is the whole point: it is what invites the next
			// request and keeps the attacker engaged.
			if !strings.Contains(body, "<form") || !strings.Contains(body, "password") {
				t.Errorf("%s does not present a password form: %.200q", tt.tmpl, body)
			}
			// Nothing in the page may name the product it is protecting.
			for _, leak := range []string{"vault42", "Vault42", "honeypot", "bridge"} {
				if strings.Contains(body, leak) {
					t.Errorf("%s leaks %q into the decoy page", tt.tmpl, leak)
				}
			}
		})
	}
}

// TestDecoyUnknownTemplateStillFlags is the failure path of a page that did not
// load. The flag is applied before the render is attempted, so an unrenderable
// decoy still traps the caller and only loses the plausible response. That
// ordering is the important half: the trap must not be conditional on the
// cosmetics working.
func TestDecoyUnknownTemplateStillFlags(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	dh := NewDecoyHandler(fs, nil)

	req := httptest.NewRequest(http.MethodGet, "/wp-admin", nil)
	w := httptest.NewRecorder()
	dh.ServeDecoy(w, req, "10.0.0.3", "no-such-template.html")

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
	if !fs.IsFlagged("10.0.0.3") {
		t.Error("the caller was not flagged when the decoy template was missing")
	}
}

// brokenResponseWriter fails every body write, which is what a client that hung
// up mid-render looks like from inside a handler.
type brokenResponseWriter struct {
	header http.Header
	code   int
	writes int
}

func (b *brokenResponseWriter) Header() http.Header {
	if b.header == nil {
		b.header = make(http.Header)
	}
	return b.header
}

func (b *brokenResponseWriter) Write(p []byte) (int, error) {
	b.writes++
	return 0, errors.New("write: connection reset by peer")
}

func (b *brokenResponseWriter) WriteHeader(code int) { b.code = code }

// TestDecoyTolerantOfAClientThatHangsUp covers the render error. A scanner that
// fires a request and closes the socket without reading is ordinary behavior
// for automated tooling, so the write failure must be logged and swallowed
// rather than propagated, and the flag must already have been applied.
func TestDecoyTolerantOfAClientThatHangsUp(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	dh := NewDecoyHandler(fs, nil)

	req := httptest.NewRequest(http.MethodGet, "/wp-admin", nil)
	w := &brokenResponseWriter{}
	dh.ServeDecoy(w, req, "10.0.0.4", "wp-login.html")

	if w.writes == 0 {
		t.Error("the template never attempted a write")
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
	if !fs.IsFlagged("10.0.0.4") {
		t.Error("a client that hung up mid-render escaped the flag")
	}
}

// TestDecoyPostAnswersLikeAFailedLogin pins the POST branch. The response has to
// be the boring one a real login form gives on bad credentials, so the operator
// of a credential-stuffing tool sees a normal miss and keeps going.
func TestDecoyPostAnswersLikeAFailedLogin(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	dh := NewDecoyHandler(fs, nil)

	req := httptest.NewRequest(http.MethodPost, "/wp-login.php", strings.NewReader("log=admin&pwd=admin"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	dh.ServeDecoy(w, req, "10.0.0.5", "wp-login.html")

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "invalid_credentials") {
		t.Errorf("body = %q, want an invalid credentials error", body)
	}
	// The response must be the same whatever the submitted credentials were, so
	// nothing echoes back the guess.
	if strings.Contains(body, "admin") {
		t.Errorf("body = %q, want it to echo nothing from the submission", body)
	}
	if !fs.IsFlagged("10.0.0.5") {
		t.Error("the POST did not flag the caller")
	}
}

// TestDecoyRecordsTheRequestedPathAsTheReason checks what an operator sees in
// the flag list after a decoy hit, since the path is the whole evidence that the
// flag was earned rather than guessed.
func TestDecoyRecordsTheRequestedPathAsTheReason(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	dh := NewDecoyHandler(fs, nil)

	req := httptest.NewRequest(http.MethodGet, "/wp-admin/setup-config.php?step=1", nil)
	w := httptest.NewRecorder()
	dh.ServeDecoy(w, req, "10.0.0.6", "wp-login.html")

	entries := fs.List()
	if len(entries) != 1 {
		t.Fatalf("flag list has %d entries, want 1", len(entries))
	}
	// The query string is not part of the reason, only the path.
	if entries[0].Reason != "decoy:/wp-admin/setup-config.php" {
		t.Errorf("reason = %q, want decoy:/wp-admin/setup-config.php", entries[0].Reason)
	}
	if entries[0].Score != 100 {
		t.Errorf("score = %d, want 100; a decoy hit bypasses scoring", entries[0].Score)
	}
}

// TestDecoyWebhookCarriesTheEvidence covers the alert a decoy hit raises. The
// user agent and the path are what turn the alert into something an operator can
// act on rather than a bare address.
func TestDecoyWebhookCarriesTheEvidence(t *testing.T) {
	payloads := make(chan map[string]interface{}, 2)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var doc map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
			t.Errorf("webhook body: %v", err)
			return
		}
		payloads <- doc
	}))
	defer hook.Close()

	fs := NewFlagStore(time.Hour, "")
	ws := NewWebhookSender(hook.URL)
	defer ws.Close()
	dh := NewDecoyHandler(fs, ws)

	req := httptest.NewRequest(http.MethodPost, "/phpmyadmin/index.php", nil)
	req.Header.Set("User-Agent", "sqlmap/1.7.2")
	w := httptest.NewRecorder()
	dh.ServeDecoy(w, req, "203.0.113.44", "phpmyadmin.html")

	select {
	case doc := <-payloads:
		if doc["event"] != "decoy_hit" {
			t.Errorf("event = %v, want decoy_hit", doc["event"])
		}
		if doc["ip"] != "203.0.113.44" {
			t.Errorf("ip = %v, want 203.0.113.44", doc["ip"])
		}
		if doc["path"] != "/phpmyadmin/index.php" {
			t.Errorf("path = %v, want /phpmyadmin/index.php", doc["path"])
		}
		if doc["user_agent"] != "sqlmap/1.7.2" {
			t.Errorf("user_agent = %v, want sqlmap/1.7.2", doc["user_agent"])
		}
		if doc["method"] != http.MethodPost {
			t.Errorf("method = %v, want POST", doc["method"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no webhook fired for a decoy hit")
	}
}

// TestDecoyHandlerConcurrentUse hammers the handler from many goroutines. A
// scanner sprays decoy paths in parallel by design, so this is the traffic shape
// the trap actually meets, and every caller must come away flagged with a page
// in hand.
func TestDecoyHandlerConcurrentUse(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	dh := NewDecoyHandler(fs, nil)

	templates := []string{"wp-login.html", "phpmyadmin.html", "cpanel.html", "admin.html"}

	const workers = 32
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			ip := fmt.Sprintf("198.51.100.%d", w)
			tmpl := templates[w%len(templates)]

			method := http.MethodGet
			if w%3 == 0 {
				method = http.MethodPost
			}

			req := httptest.NewRequest(method, fmt.Sprintf("/trap/%d", w), nil)
			rec := httptest.NewRecorder()
			dh.ServeDecoy(rec, req, ip, tmpl)

			wantCode := http.StatusOK
			if method == http.MethodPost {
				wantCode = http.StatusUnauthorized
			}
			if rec.Code != wantCode {
				t.Errorf("%s from %s: status %d, want %d", method, ip, rec.Code, wantCode)
			}
			if rec.Body.Len() == 0 {
				t.Errorf("%s from %s produced an empty body", method, ip)
			}
		}(w)
	}
	wg.Wait()

	if got := len(fs.List()); got != workers {
		t.Errorf("flag list holds %d entries, want %d", got, workers)
	}
	for w := 0; w < workers; w++ {
		ip := fmt.Sprintf("198.51.100.%d", w)
		if !fs.IsFlagged(ip) {
			t.Errorf("%s was not flagged", ip)
		}
	}
}
