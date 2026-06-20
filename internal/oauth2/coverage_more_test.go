package oauth2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ctlURL contains a control character that http.NewRequestWithContext rejects,
// forcing the request-building branch of a provider method to error.
const ctlURL = "http://example.com/\x7f"

// --- httpClient: configured-client branch (constructor-built providers) ---
//
// The public constructors install a non-nil *http.Client, so exercising a
// method on a constructor-built provider drives the "return configured client"
// branch of httpClient rather than the http.DefaultClient fallback.

func TestFacebookHTTPClientUsesConfiguredClient(t *testing.T) {
	hit := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit <- struct{}{}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"1","name":"x"}`))
	}))
	defer srv.Close()

	p := NewFacebookProvider("cid", "sec", "https://app/cb")
	p.userInfoURL = srv.URL
	if _, err := p.UserInfo(context.Background(), "tok"); err != nil {
		t.Fatalf("UserInfo via configured client: %v", err)
	}
	select {
	case <-hit:
	default:
		t.Fatal("configured client never reached the test server")
	}
}

func TestGoogleHTTPClientUsesConfiguredClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"1","name":"x"}`))
	}))
	defer srv.Close()

	p := NewGoogleProvider("cid", "sec", "https://app/cb")
	p.userInfoURL = srv.URL
	if _, err := p.UserInfo(context.Background(), "tok"); err != nil {
		t.Fatalf("UserInfo via configured client: %v", err)
	}
}

func TestGitHubHTTPClientUsesConfiguredClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":1,"login":"x","name":"x"}`))
	}))
	defer srv.Close()

	p := NewGitHubProvider("cid", "sec", "https://app/cb")
	p.userInfoURL = srv.URL
	if _, err := p.UserInfo(context.Background(), "tok"); err != nil {
		t.Fatalf("UserInfo via configured client: %v", err)
	}
}

// TestOIDCHTTPClientFallsBackToDefault drives the http.DefaultClient branch of
// the OIDC httpClient helper by zeroing the configured client. The unreachable
// issuer makes discovery error, which is the expected outcome here; what matters
// is that the helper returns a usable client rather than panicking on nil.
func TestOIDCHTTPClientFallsBackToDefault(t *testing.T) {
	p := NewOIDCProvider("okta", "http://127.0.0.1:1", "cid", "sec", "https://app/cb", "")
	p.client = nil
	if _, err := p.discover(context.Background()); err == nil {
		t.Fatal("discovery against an unreachable issuer must fail")
	}
}

// --- discover: error branches ---

func TestOIDCDiscoverBuildRequestError(t *testing.T) {
	// A control character in the issuer makes the discovery request unbuildable.
	p := NewOIDCProvider("okta", "http://example.com/\x7f", "cid", "sec", "https://app/cb", "")
	if _, err := p.discover(context.Background()); err == nil {
		t.Fatal("discover must fail to build a request for an invalid issuer URL")
	}
}

func TestOIDCDiscoverFetchError(t *testing.T) {
	// Server is created then immediately closed: the connection is refused.
	srv := httptest.NewServer(http.NewServeMux())
	srv.Close()
	p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://app/cb", "")
	if _, err := p.discover(context.Background()); err == nil {
		t.Fatal("discover must fail when the discovery fetch errors at the transport")
	}
}

func TestOIDCDiscoverDecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}))
	defer srv.Close()
	p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://app/cb", "")
	if _, err := p.discover(context.Background()); err == nil {
		t.Fatal("discover must fail when the discovery body is not valid JSON")
	}
}

func TestOIDCDiscoverMissingEndpoints(t *testing.T) {
	// Issuer matches but the document omits the authorization/token endpoints.
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"` + srv.URL + `"}`))
	})
	p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://app/cb", "")
	if _, err := p.discover(context.Background()); err == nil {
		t.Fatal("discover must fail when authorization/token endpoints are absent")
	}
}

// --- AuthURL: invalid authorization endpoint ---

func TestOIDCAuthURLInvalidAuthEndpoint(t *testing.T) {
	// Discovery succeeds but advertises an authorization_endpoint that url.Parse
	// rejects, so AuthURL returns "" (the handler's redirect guard then refuses it).
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"` + srv.URL + `","authorization_endpoint":"http://%zz","token_endpoint":"` + srv.URL + `/token"}`))
	})
	p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://app/cb", "")
	if got := p.AuthURL("s", "n", "c"); got != "" {
		t.Fatalf("AuthURL must be empty for an unparseable authorization endpoint, got %q", got)
	}
}

// --- Exchange: error branches ---

func TestOIDCExchangeBuildRequestError(t *testing.T) {
	// Discovery yields a token endpoint with a control character, so the POST
	// request cannot be built.
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"` + srv.URL + `","authorization_endpoint":"` + srv.URL + `/authorize","token_endpoint":"` + ctlURL + `"}`))
	})
	p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://app/cb", "")
	if _, err := p.Exchange(context.Background(), "code", "verifier"); err == nil {
		t.Fatal("Exchange must fail when the token request cannot be built")
	}
}

func TestOIDCExchangeFetchError(t *testing.T) {
	// Token endpoint points at a closed listener, so the POST errors.
	dead := httptest.NewServer(http.NewServeMux())
	deadURL := dead.URL
	dead.Close()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"` + srv.URL + `","authorization_endpoint":"` + srv.URL + `/authorize","token_endpoint":"` + deadURL + `/token"}`))
	})
	p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://app/cb", "")
	if _, err := p.Exchange(context.Background(), "code", "verifier"); err == nil {
		t.Fatal("Exchange must fail when the token fetch errors at the transport")
	}
}

func TestOIDCExchangeNon200(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"` + srv.URL + `","authorization_endpoint":"` + srv.URL + `/authorize","token_endpoint":"` + srv.URL + `/token"}`))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	})
	p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://app/cb", "")
	if _, err := p.Exchange(context.Background(), "code", "verifier"); err == nil {
		t.Fatal("Exchange must fail on a non-200 token status")
	}
}

func TestOIDCExchangeDecodeError(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"` + srv.URL + `","authorization_endpoint":"` + srv.URL + `/authorize","token_endpoint":"` + srv.URL + `/token"}`))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	})
	p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://app/cb", "")
	if _, err := p.Exchange(context.Background(), "code", "verifier"); err == nil {
		t.Fatal("Exchange must fail when the token body is not valid JSON")
	}
}

func TestOIDCExchangeEmptyAccessToken(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"` + srv.URL + `","authorization_endpoint":"` + srv.URL + `/authorize","token_endpoint":"` + srv.URL + `/token"}`))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"token_type":"Bearer","expires_in":3600}`))
	})
	p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://app/cb", "")
	if _, err := p.Exchange(context.Background(), "code", "verifier"); err == nil {
		t.Fatal("Exchange must reject a token response with an empty access_token")
	}
}

// --- refreshJWKS: build-request error ---

func TestRefreshJWKSBuildRequestError(t *testing.T) {
	// Discovery advertises a jwks_uri with a control character, so the JWKS GET
	// request cannot be built.
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"` + srv.URL + `","authorization_endpoint":"` + srv.URL + `/authorize","token_endpoint":"` + srv.URL + `/token","jwks_uri":"` + ctlURL + `"}`))
	})
	p := NewOIDCProvider("okta", srv.URL, "cid", "sec", "https://app/cb", "")
	if err := p.refreshJWKS(context.Background()); err == nil {
		t.Fatal("refreshJWKS must fail when the JWKS request cannot be built")
	}
}
