package oauth2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The profile fetch is the step that decides who is logging in. Every provider
// here checks the status of its token exchange and refuses a non-200, then
// decodes the profile response without looking at its status at all, so an
// answer the API refused to give is unmarshalled into the struct that names the
// user and returned with a nil error.
//
// GitHub is where that turns into an identity. Its id is an int, so a body that
// carries no id decodes to 0 and the provider hands back the subject "0" rather
// than the empty string internal/handler/oauth.go refuses. That subject is
// non-empty, so it passes the guard, and every GitHub login whose profile fetch
// came back an error lands on the one row UNIQUE(provider, provider_user_id)
// allows for github/0: the first one claims it, the rest are answered with that
// account's session. GitHub user ids start at 1, so no real login can ever
// contest the row.
//
// The two calls are independent requests, which is what makes the useful shape
// reachable rather than theoretical: /user can fail while /user/emails succeeds,
// and then the subject is "0" while the address and its verified flag are real.

// githubServer answers /user with the given status and body, and /user/emails
// with a verified primary address.
func githubServer(t *testing.T, userStatus int, userBody string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/emails", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"email":"attacker@example.com","primary":true,"verified":true}]`)) // #nosec G104
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(userStatus)
		w.Write([]byte(userBody)) // #nosec G104
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestGitHubUserInfoRefusesAProfileTheAPIRefusedToServe(t *testing.T) {
	srv := githubServer(t, http.StatusUnauthorized, `{"message":"Bad credentials","documentation_url":"https://docs.github.com/rest"}`)

	p := &GitHubProvider{clientID: "cid", userInfoURL: srv.URL}
	info, err := p.UserInfo(context.Background(), "tok")
	if err == nil {
		t.Fatalf("a 401 from /user was read as a profile: subject %q, email %q, verified %v",
			info.ID, info.Email, info.EmailVerified)
	}
	if !strings.Contains(err.Error(), "github userinfo") {
		t.Errorf("error = %q, want it wrapped with 'github userinfo'", err.Error())
	}
	if info != nil {
		t.Errorf("info = %+v, want nil alongside the error", info)
	}
}

func TestGitHubUserInfoRefusesAResponseThatNamesNoUser(t *testing.T) {
	srv := githubServer(t, http.StatusOK, `{"login":"nobody"}`)

	p := &GitHubProvider{clientID: "cid", userInfoURL: srv.URL}
	info, err := p.UserInfo(context.Background(), "tok")
	if err == nil {
		t.Fatalf("a 200 carrying no id was read as a profile: subject %q", info.ID)
	}
	if info != nil {
		t.Errorf("info = %+v, want nil alongside the error", info)
	}
}

func TestGoogleUserInfoRefusesAProfileTheAPIRefusedToServe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":{"code":403,"message":"Insufficient Permission"}}`)) // #nosec G104
	}))
	defer srv.Close()

	p := &GoogleProvider{clientID: "cid", userInfoURL: srv.URL}
	info, err := p.UserInfo(context.Background(), "tok")
	if err == nil {
		t.Fatalf("a 403 from the userinfo endpoint was read as a profile: %+v", info)
	}
	if info != nil {
		t.Errorf("info = %+v, want nil alongside the error", info)
	}
}

func TestFacebookUserInfoRefusesAProfileTheAPIRefusedToServe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":{"message":"Invalid OAuth access token","code":190}}`)) // #nosec G104
	}))
	defer srv.Close()

	p := &FacebookProvider{clientID: "cid", userInfoURL: srv.URL}
	info, err := p.UserInfo(context.Background(), "tok")
	if err == nil {
		t.Fatalf("a 400 from the Graph API was read as a profile: %+v", info)
	}
	if info != nil {
		t.Errorf("info = %+v, want nil alongside the error", info)
	}
}
