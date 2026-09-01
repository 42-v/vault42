package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// withSubject puts a claims value carrying subject on the request, the way
// middleware.Auth would have.
func withSubject(r *http.Request, subject string) *http.Request {
	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: subject},
	}
	return r.WithContext(context.WithValue(r.Context(), ClaimsKey, claims))
}

// The four answers LiveAccount can give, and what each one is for.
//
// The reached flag is the assertion that matters. A test that only reads the
// status code passes against a middleware that writes 401 and then calls next
// anyway, which is the exact shape of a guard that does not guard: the erased
// caller sees an error and the write still lands.
func TestLiveAccountAdmitsOnlyALiveSubject(t *testing.T) {
	for _, tc := range []struct {
		name        string
		subject     string
		isLive      func(context.Context, string) (bool, error)
		wantStatus  int
		wantReached bool
	}{
		{
			name:        "a live account reaches the handler",
			subject:     "user-live",
			isLive:      func(context.Context, string) (bool, error) { return true, nil },
			wantStatus:  http.StatusOK,
			wantReached: true,
		},
		{
			name:        "an erased account is refused",
			subject:     "user-erased",
			isLive:      func(context.Context, string) (bool, error) { return false, nil },
			wantStatus:  http.StatusUnauthorized,
			wantReached: false,
		},
		{
			// Fail closed. An erasure a database blip can undo is not an erasure.
			name:        "a failed lookup is refused, not allowed",
			subject:     "user-unknown",
			isLive:      func(context.Context, string) (bool, error) { return false, errors.New("connection refused") },
			wantStatus:  http.StatusUnauthorized,
			wantReached: false,
		},
		{
			// A lookup that errors must not be admitted on the strength of the
			// bool beside the error: `return true, err` is a plausible repository
			// bug and must not open the gate.
			name:        "a lookup that errors is refused even when it reports live",
			subject:     "user-unknown",
			isLive:      func(context.Context, string) (bool, error) { return true, errors.New("connection refused") },
			wantStatus:  http.StatusUnauthorized,
			wantReached: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			h := LiveAccount(tc.isLive)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			}))

			req := withSubject(httptest.NewRequest(http.MethodPut, "/user/identity", nil), tc.subject)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if reached != tc.wantReached {
				t.Errorf("handler reached = %v, want %v -- the guard let the write through", reached, tc.wantReached)
			}
		})
	}
}

// No claims means Auth did not run, or ran and admitted nothing. Refuse rather
// than dereference, and refuse without consulting isLive: there is no subject to
// consult it about, and calling it with the empty string would ask the database
// whether "" is live.
func TestLiveAccountRefusesWithoutClaims(t *testing.T) {
	consulted := false
	reached := false
	h := LiveAccount(func(context.Context, string) (bool, error) {
		consulted = true
		return true, nil
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/user/blobs", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if reached {
		t.Error("handler ran without claims")
	}
	if consulted {
		t.Error("isLive was called with no subject to look up")
	}
}

// The subject the guard looks up must be the one on the token. Looking up a
// constant, or the empty string, would pass every test above while checking the
// wrong account -- and would admit an erased caller whose id differs from
// whatever was hardcoded.
func TestLiveAccountLooksUpTheTokenSubject(t *testing.T) {
	var got string
	h := LiveAccount(func(_ context.Context, userID string) (bool, error) {
		got = userID
		return true, nil
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := withSubject(httptest.NewRequest(http.MethodPut, "/user/identity", nil), "user-42")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if got != "user-42" {
		t.Errorf("isLive consulted %q, want the token subject %q", got, "user-42")
	}
}

// The request context must reach the lookup, so a client disconnect cancels the
// query rather than leaving it to run against the pool. Passing
// context.Background() would satisfy every other test here.
func TestLiveAccountPassesTheRequestContext(t *testing.T) {
	type ctxKeyProbe struct{}
	var saw bool
	h := LiveAccount(func(ctx context.Context, _ string) (bool, error) {
		saw = ctx.Value(ctxKeyProbe{}) == "carried"
		return true, nil
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := withSubject(httptest.NewRequest(http.MethodPut, "/user/identity", nil), "user-1")
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyProbe{}, "carried"))
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !saw {
		t.Error("isLive did not receive the request context")
	}
}
