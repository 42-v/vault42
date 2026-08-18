package handler

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// RFC 6749 2.3.1 is explicit that the client credentials "can only be
// transmitted in the request-body and MUST NOT be included in the request URI".
// http.Request.FormValue merges the URL query into r.Form, so a handler reading
// it accepts a secret presented as a query parameter, and the reason the RFC
// makes that a MUST NOT is everything downstream of the request line: the
// TLS-terminating ingress access log, any CDN or WAF in front of it, Referer on
// a later navigation, shell history and APM traces all keep URLs and none of
// them keep bodies.
//
// The secret in question gates kms:unwrap, mint:token and the service-document
// store, so it is the highest-value credential this service issues, and it is
// long-lived. vault42's own logger records r.URL.Path without the query
// (internal/middleware/logger.go), which is precisely why accepting the
// parameter is a defect rather than a leak: the exposure lands in components
// vault42 does not control, and the only place it can be refused is here.
//
// These tests pin the reading, not the plumbing. They pass a query the handler
// must not look at and a body it must.

// clientQueryFixture wires a handler over one active client with the given
// allowed scopes.
func clientQueryFixture(t *testing.T, id, secret string, scopes []string) *ClientHandler {
	t.Helper()
	client := makeClientWithSecret(t, id, "query-fixture", secret, "frontend", scopes, true)
	return newTestClientHandler(t, &mocks.MockClientRepo{
		GetByIDFn: func(_ context.Context, got string) (*model.Client, error) {
			if got == id {
				return client, nil
			}
			return nil, nil
		},
	})
}

// formRequest builds a POST /client/token carrying query and body exactly as
// given. An empty body still declares the form content type, which is what a
// caller putting the whole grant in the URL would send.
func formRequest(query, body string) *http.Request {
	target := "/client/token"
	if query != "" {
		target += "?" + query
	}
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.0.0.9:5000"
	return req
}

// A grant whose credentials live only in the URL must be refused. Accepting it
// is what makes putting a service secret in a URL work, and a working shortcut
// is the one integrators copy.
func TestClientToken_CredentialsInTheQueryStringAreNotAccepted(t *testing.T) {
	const id, secret = "client-query", "query-secret-123456"
	h := clientQueryFixture(t, id, secret, []string{"read"})

	q := url.Values{"client_id": {id}, "client_secret": {secret}}
	rec := httptest.NewRecorder()
	h.Token(rec, formRequest(q.Encode(), ""))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — RFC 6749 2.3.1 forbids the credentials in the "+
			"request URI, and this grant authenticated from the query string alone; body: %s",
			rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "access_token") {
		t.Error("a query-string credential was issued a token")
	}
}

// The body form remains the supported way to present credentials without Basic
// auth. Refusing the query must not cost the RFC-sanctioned path.
func TestClientToken_CredentialsInTheBodyAreStillAccepted(t *testing.T) {
	const id, secret = "client-body", "body-secret-123456"
	h := clientQueryFixture(t, id, secret, []string{"read"})

	body := url.Values{"client_id": {id}, "client_secret": {secret}}
	rec := httptest.NewRecorder()
	h.Token(rec, formRequest("", body.Encode()))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — the body form of the grant stopped working; body: %s",
			rec.Code, rec.Body.String())
	}
}

// A body credential must not be overridable, or reachable, from the query. Both
// halves present in the URL and neither in the body is the case above; this one
// pins that a request carrying both reads the body, so a proxy that inspects
// bodies sees the grant it is asked to police.
func TestClientToken_BodyCredentialsWinOverAQueryString(t *testing.T) {
	const id, secret = "client-both", "both-secret-123456"
	h := clientQueryFixture(t, id, secret, []string{"read"})

	q := url.Values{"client_id": {"attacker-id"}, "client_secret": {"attacker-secret"}}
	body := url.Values{"client_id": {id}, "client_secret": {secret}}
	rec := httptest.NewRecorder()
	h.Token(rec, formRequest(q.Encode(), body.Encode()))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a query string alongside a valid body grant changed "+
			"the outcome; body: %s", rec.Code, rec.Body.String())
	}
}

// The scope moves with the credentials. Leaving one component readable from the
// URL lets a caller split the grant across two channels, so a proxy inspecting
// bodies sees a request for the client's default scopes while the token that
// comes back was cut to a different set.
func TestClientToken_ScopeInTheQueryStringIsIgnored(t *testing.T) {
	const id, secret = "client-scope", "scope-secret-123456"
	h := clientQueryFixture(t, id, secret, []string{"read"})

	creds := base64.StdEncoding.EncodeToString([]byte(id + ":" + secret))
	req := formRequest("scope=kms%3Aunwrap", "")
	req.Header.Set("Authorization", "Basic "+creds)
	rec := httptest.NewRecorder()
	h.Token(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a scope in the query string was read as a request "+
			"and narrowed the grant to nothing; body: %s", rec.Code, rec.Body.String())
	}
	var out ClientTokenResponse
	decodeResponse(t, rec, &out)
	if out.Scope != "read" {
		t.Errorf("scope = %q, want read — the query string reached the granted scopes", out.Scope)
	}
}
