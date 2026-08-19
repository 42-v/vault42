package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// oversizedProfileServer answers every request with a syntactically valid
// profile document padded past any sane response size, and reports how many
// bytes the client took before it stopped.
func oversizedProfileServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(body)); err != nil {
			// The client hanging up early is the outcome under test, not a failure.
			return
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// hugeProfileJSON builds a well-formed profile object whose padding field alone
// runs to sizeMB megabytes.
func hugeProfileJSON(idField, id string, sizeMB int) string {
	return fmt.Sprintf(`{%q:%q,"email":"user@example.com","padding":%q}`,
		idField, id, strings.Repeat("A", sizeMB<<20))
}

// TestAProviderProfileResponseIsReadUnderABound covers the three profile calls
// that read straight off the socket.
//
// Every token exchange in this package, and the OIDC userinfo call, already wrap
// the response in an io.LimitReader. These three did not: they handed
// resp.Body to a json.Decoder with no ceiling, so the size of the allocation was
// the provider's to pick. That is the one call in the login flow where the peer
// is not vault42 and not the browser, and it lands on an unauthenticated path,
// so a provider having a bad day (or an operator who pointed an issuer at the
// wrong host) can turn one login into an arbitrarily large heap allocation
// inside the auth service.
//
// A document past the bound is refused rather than decoded, which is the correct
// end: the callback treats a userinfo error as provider_error and issues nothing.
func TestAProviderProfileResponseIsReadUnderABound(t *testing.T) {
	const oversizeMB = 3

	t.Run("google", func(t *testing.T) {
		srv := oversizedProfileServer(t, hugeProfileJSON("id", "g-123", oversizeMB))
		p := &GoogleProvider{clientID: "gcid", userInfoURL: srv.URL}

		if _, err := p.UserInfo(context.Background(), "tok"); err == nil {
			t.Fatalf("decoded a %d MB profile document; the response size is the provider's to choose", oversizeMB)
		}
	})

	t.Run("facebook", func(t *testing.T) {
		srv := oversizedProfileServer(t, hugeProfileJSON("id", "fb-123", oversizeMB))
		p := &FacebookProvider{clientID: "fcid", userInfoURL: srv.URL}

		if _, err := p.UserInfo(context.Background(), "tok"); err == nil {
			t.Fatalf("decoded a %d MB profile document; the response size is the provider's to choose", oversizeMB)
		}
	})

	// GitHub reads twice: the profile, then the address list. Both were unbounded.
	t.Run("github profile", func(t *testing.T) {
		srv := oversizedProfileServer(t, hugeProfileJSON("login", "octocat", oversizeMB))
		p := &GitHubProvider{clientID: "ghcid", userInfoURL: srv.URL}

		if _, err := p.UserInfo(context.Background(), "tok"); err == nil {
			t.Fatalf("decoded a %d MB profile document; the response size is the provider's to choose", oversizeMB)
		}
	})

	t.Run("github address list", func(t *testing.T) {
		var emailsRead int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if strings.HasSuffix(r.URL.Path, "/emails") {
				body := fmt.Sprintf(`[{"email":"user@example.com","primary":true,"verified":true,"padding":%q}]`,
					strings.Repeat("A", oversizeMB<<20))
				n, _ := w.Write([]byte(body))
				emailsRead = int64(n)
				return
			}
			fmt.Fprint(w, `{"id":42,"login":"octocat","email":"user@example.com"}`)
		}))
		t.Cleanup(srv.Close)

		p := &GitHubProvider{clientID: "ghcid", userInfoURL: srv.URL}
		info, err := p.UserInfo(context.Background(), "tok")
		if err != nil {
			t.Fatalf("the profile call itself must still succeed: %v", err)
		}
		// The address list is best-effort: a decode failure leaves the address
		// unverified rather than failing the login. What must not happen is the
		// whole oversized document being decoded into a verified address.
		if info.EmailVerified {
			t.Fatalf("read a %d MB address list to completion (%d bytes served) and trusted it", oversizeMB, emailsRead)
		}
	})
}

// TestAnOrdinaryProviderProfileStillDecodes is the counterweight. A bound set
// too tight would refuse real logins, and every failure above would keep passing
// for the wrong reason.
func TestAnOrdinaryProviderProfileStillDecodes(t *testing.T) {
	t.Run("google", func(t *testing.T) {
		srv := oversizedProfileServer(t, `{"id":"g-1","email":"user@example.com","verified_email":true,"name":"User"}`)
		p := &GoogleProvider{clientID: "gcid", userInfoURL: srv.URL}

		info, err := p.UserInfo(context.Background(), "tok")
		if err != nil {
			t.Fatalf("UserInfo: %v", err)
		}
		if info.ID != "g-1" || !info.EmailVerified {
			t.Fatalf("profile = %+v, want the served identity", info)
		}
	})

	t.Run("facebook", func(t *testing.T) {
		srv := oversizedProfileServer(t, `{"id":"fb-1","email":"user@example.com","name":"User"}`)
		p := &FacebookProvider{clientID: "fcid", userInfoURL: srv.URL}

		info, err := p.UserInfo(context.Background(), "tok")
		if err != nil {
			t.Fatalf("UserInfo: %v", err)
		}
		if info.ID != "fb-1" {
			t.Fatalf("profile = %+v, want the served identity", info)
		}
	})

	t.Run("github", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if strings.HasSuffix(r.URL.Path, "/emails") {
				fmt.Fprint(w, `[{"email":"user@example.com","primary":true,"verified":true}]`)
				return
			}
			fmt.Fprint(w, `{"id":42,"login":"octocat","name":"Octo"}`)
		}))
		t.Cleanup(srv.Close)

		p := &GitHubProvider{clientID: "ghcid", userInfoURL: srv.URL}
		info, err := p.UserInfo(context.Background(), "tok")
		if err != nil {
			t.Fatalf("UserInfo: %v", err)
		}
		if info.ID != "42" || info.Email != "user@example.com" || !info.EmailVerified {
			t.Fatalf("profile = %+v, want the served identity with a verified address", info)
		}
	})
}
