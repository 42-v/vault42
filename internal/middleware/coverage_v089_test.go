package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// addLimiter must register every localRateLimiter it is handed so the eviction
// sweep can reach it. Construct a fresh limiter, register it, and confirm it is
// now present in the package-level activeLimiters slice.
func TestAddLimiter_RegistersForEviction(t *testing.T) {
	l := &localRateLimiter{entries: make(map[string]*localRLEntry)}

	addLimiter(l)

	activeLimiters.mu.Lock()
	found := false
	for _, reg := range activeLimiters.limiters {
		if reg == l {
			found = true
			break
		}
	}
	activeLimiters.mu.Unlock()

	if !found {
		t.Fatal("addLimiter did not register the limiter in activeLimiters")
	}
}

// MaxBodyWithExemptions must skip the size cap for paths matching an exempt
// prefix: a body far larger than the limit reads through without error.
func TestMaxBodyWithExemptions_ExemptPathBypassesLimit(t *testing.T) {
	const limit = 8
	big := strings.Repeat("a", limit*4)

	handler := MaxBodyWithExemptions(limit, []string{"/user/blobs"})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n, err := io.Copy(io.Discard, r.Body)
			if err != nil {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}
			if n != int64(len(big)) {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodPost, "/user/blobs/abc", strings.NewReader(big))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("exempt path should read full body, got status %d", rec.Code)
	}
}

// A non-exempt POST whose body exceeds the cap must surface the limit: the
// wrapped MaxBytesReader errors once the downstream handler reads past it.
func TestMaxBodyWithExemptions_NonExemptOverLimit(t *testing.T) {
	const limit = 8
	big := strings.Repeat("a", limit*4)

	handler := MaxBodyWithExemptions(limit, []string{"/user/blobs"})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}
			w.WriteHeader(http.StatusOK)
		}))

	// "/user/profile" does not match the "/user/blobs" exemption.
	req := httptest.NewRequest(http.MethodPost, "/user/profile", strings.NewReader(big))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("non-exempt over-limit body should be capped (413), got %d", rec.Code)
	}
}

// GET requests carry no body cap regardless of exemptions, so a non-exempt GET
// passes straight through.
func TestMaxBodyWithExemptions_GetExemptByMethod(t *testing.T) {
	handler := MaxBodyWithExemptions(1, []string{"/user/blobs"})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET should bypass body cap, got %d", rec.Code)
	}
}

// RequestID generates a fresh ID when none is supplied, exposes it on both the
// response header and the request context with matching values, and produces a
// distinct ID per request (the handler never trusts an inbound X-Request-ID).
func TestRequestID_GeneratesDistinctIDs(t *testing.T) {
	var ctxID string
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxID = GetRequestID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	// Inbound header value must not be echoed back; a fresh ID is always minted.
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("X-Request-ID", "attacker-supplied")
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	id1 := rec1.Header().Get("X-Request-ID")
	if id1 == "" {
		t.Fatal("X-Request-ID header should be set")
	}
	if id1 == "attacker-supplied" {
		t.Fatal("inbound X-Request-ID must not be trusted/echoed")
	}
	if id1 != ctxID {
		t.Fatalf("header ID %q must match context ID %q", id1, ctxID)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	id2 := rec2.Header().Get("X-Request-ID")

	if id1 == id2 {
		t.Fatalf("each request must get a distinct ID, both were %q", id1)
	}
}
