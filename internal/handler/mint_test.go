package handler

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

const (
	mintHandlerIssuer   = "https://vault.example"
	mintHandlerAudience = "https://legacy.example"
	mintHandlerClient   = "44444444-4444-4444-4444-444444444444"
)

var (
	mintHandlerKeyOnce sync.Once
	mintHandlerKey     *rsa.PrivateKey
	mintHandlerKID     string
)

func mintHandlerSigner(t *testing.T) service.SigningKeyProvider {
	t.Helper()
	mintHandlerKeyOnce.Do(func() {
		key, err := vaultcrypto.GenerateRSAKeyPair()
		if err != nil {
			t.Fatalf("generate signing key: %v", err)
		}
		mintHandlerKey = key
		mintHandlerKID = vaultcrypto.KIDFromPublicKey(&key.PublicKey)
	})
	return func() (*rsa.PrivateKey, string) { return mintHandlerKey, mintHandlerKID }
}

// mintUnusableKeySigner reports a key and a kid the way a live provider does,
// but hands back a key whose factors do not multiply to its modulus: the shape
// a signing key corrupted at rest has. crypto/rsa refuses it rather than
// producing a signature that would not verify.
func mintUnusableKeySigner(t *testing.T) service.SigningKeyProvider {
	t.Helper()
	mintHandlerSigner(t)
	broken := *mintHandlerKey
	broken.Primes = []*big.Int{big.NewInt(61), big.NewInt(53)}
	broken.Precomputed = rsa.PrecomputedValues{}
	return func() (*rsa.PrivateKey, string) { return &broken, mintHandlerKID }
}

// newMintTestHandlerWith builds a handler over a caller-supplied signer, for
// the paths where the signing key itself is what is under test.
func newMintTestHandlerWith(t *testing.T, signer service.SigningKeyProvider, auditLog *audit.Logger) *MintHandler {
	t.Helper()
	svc, err := service.NewMintService(signer, service.MintConfig{
		Issuer:     mintHandlerIssuer,
		Audience:   mintHandlerAudience,
		DefaultTTL: 5 * time.Minute,
		MaxTTL:     10 * time.Minute,
	}, nil)
	if err != nil {
		t.Fatalf("NewMintService: %v", err)
	}
	return NewMintHandler(svc, auditLog)
}

func newMintTestHandler(t *testing.T, mutate func(*service.MintConfig)) *MintHandler {
	t.Helper()
	cfg := service.MintConfig{
		Issuer:        mintHandlerIssuer,
		Audience:      mintHandlerAudience,
		DefaultTTL:    5 * time.Minute,
		MaxTTL:        10 * time.Minute,
		AllowedRoles:  []string{"moderator"},
		AllowedScopes: []string{"read"},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	svc, err := service.NewMintService(mintHandlerSigner(t), cfg, nil)
	if err != nil {
		t.Fatalf("NewMintService: %v", err)
	}
	return NewMintHandler(svc, newTestAuditLogger())
}

// withServiceClaims injects client-credential claims, bypassing the Auth
// middleware for handler-direct tests.
func withServiceClaims(req *http.Request, clientID string, scopes []string) *http.Request {
	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: clientID},
		ClientID:         clientID,
		Scopes:           scopes,
		TokenType:        "Bearer",
	}
	return req.WithContext(context.WithValue(req.Context(), middleware.ClaimsKey, claims))
}

func mintRequest(t *testing.T, body MintRequestBody) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mint", jsonBody(t, body))
	req.RemoteAddr = "127.0.0.1:9999"
	return req
}

// mintedTokenPayload decodes a minted token's JWT payload as raw JSON.
//
// The claim assertions below are about the names on the wire, because that is
// what a relying party parses. Decoding into VaultClaims would assert Go field
// names instead and would keep passing if a json tag were renamed underneath it.
func mintedTokenPayload(t *testing.T, token string) map[string]interface{} {
	t.Helper()
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("minted token has %d dot-separated parts, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode minted token payload: %v", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("parse minted token payload: %v", err)
	}
	return payload
}

// A minted token asserts a subject vault42 never authenticated, so the client
// that asked for it is the only actor a relying party can hold responsible.
// Without this claim an RP can see that a token was minted, because token_type
// is "mint", but not by whom. Attribution then exists only in vault42's audit
// log, which the RP cannot read, so an RP that finds a forged subject in its own
// data has no way to narrow the incident to one mint credential.
func TestMintHandler_AMintedTokenNamesTheClientThatRequestedIt(t *testing.T) {
	const requestingClient = "7e2f9a10-2222-4000-8000-0000000000ab"

	h := newMintTestHandler(t, nil)
	req := withServiceClaims(mintRequest(t, MintRequestBody{Subject: "user-1"}), requestingClient, []string{MintScope})

	rec := httptest.NewRecorder()
	h.Mint(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("mint failed: %d %s", rec.Code, rec.Body.String())
	}
	var resp MintResponse
	decodeResponse(t, rec, &resp)

	payload := mintedTokenPayload(t, resp.AccessToken)
	if payload["minted_by"] != requestingClient {
		t.Fatalf("minted_by = %v, want the authenticated client %q; the token does not say who minted it",
			payload["minted_by"], requestingClient)
	}
}

// The attribution claim must never be spelled client_id. requireClient in
// servicedoc.go and ClientRateLimitKey both read a non-empty client_id claim as
// proof of a service caller, so a minted token carrying one would be admitted to
// the service document store as its minting client and could read and overwrite
// that client's private documents for any subject the mint holder chose to name.
func TestMintHandler_AMintedTokenCarriesNoClientIDClaim(t *testing.T) {
	h := newMintTestHandler(t, nil)
	rec := httptest.NewRecorder()
	h.Mint(rec, withServiceClaims(mintRequest(t, MintRequestBody{Subject: "user-1"}), mintHandlerClient, []string{MintScope}))
	if rec.Code != http.StatusOK {
		t.Fatalf("mint failed: %d %s", rec.Code, rec.Body.String())
	}
	var resp MintResponse
	decodeResponse(t, rec, &resp)

	payload := mintedTokenPayload(t, resp.AccessToken)
	if value, present := payload["client_id"]; present {
		t.Fatalf("minted token carries client_id = %v; every svcdoc route would read it as the calling service", value)
	}
}

// The attribution is only worth reading if it comes from the authenticated
// client rather than from the caller. If minted_by were ever accepted as a
// request field, one stolen mint credential could sign assertions attributed to
// a different tenant's client, and both the token and the audit row would name
// the wrong service for the whole incident.
func TestMintHandler_TheRequestBodyCannotChooseTheMintedByClaim(t *testing.T) {
	h := newMintTestHandler(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/mint",
		strings.NewReader(`{"subject":"user-1","minted_by":"another-tenants-client"}`))
	req.RemoteAddr = "127.0.0.1:9999"
	req = withServiceClaims(req, mintHandlerClient, []string{MintScope})

	rec := httptest.NewRecorder()
	h.Mint(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a caller-supplied minted_by was accepted with %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMintHandler_IssuesToken(t *testing.T) {
	h := newMintTestHandler(t, nil)
	req := withServiceClaims(mintRequest(t, MintRequestBody{
		Subject: "a5bd6c1e-0000-4000-8000-000000000001",
		Roles:   []string{"moderator"},
		Scopes:  []string{"read"},
	}), mintHandlerClient, []string{MintScope})

	rec := httptest.NewRecorder()
	h.Mint(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp MintResponse
	decodeResponse(t, rec, &resp)
	if resp.AccessToken == "" || resp.JTI == "" || resp.KID == "" {
		t.Fatalf("incomplete response: %+v", resp)
	}
	if resp.Audience != mintHandlerAudience {
		t.Errorf("audience = %q", resp.Audience)
	}
	if resp.Subject != "a5bd6c1e-0000-4000-8000-000000000001" {
		t.Errorf("subject = %q", resp.Subject)
	}
	// The response field is the RFC 6749 presentation scheme, not the JWT's own
	// token_type claim.
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", resp.TokenType)
	}
}

// A minted token must not open vault42's own authenticated routes. This is the
// end-to-end version of that claim: the real Auth middleware, the real key, and
// vault42's own issuer and audience.
func TestMintHandler_MintedTokenCannotAuthenticateAgainstVault(t *testing.T) {
	h := newMintTestHandler(t, nil)
	req := withServiceClaims(mintRequest(t, MintRequestBody{Subject: "user-1"}), mintHandlerClient, []string{MintScope})
	rec := httptest.NewRecorder()
	h.Mint(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("mint failed: %d %s", rec.Code, rec.Body.String())
	}
	var resp MintResponse
	decodeResponse(t, rec, &resp)

	keys := map[string]*rsa.PublicKey{mintHandlerKID: &mintHandlerKey.PublicKey}
	reached := false
	protected := middleware.Auth(keys, mintHandlerIssuer, mintHandlerIssuer)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))

	probe := httptest.NewRequest(http.MethodGet, "/user/identity", nil)
	probe.Header.Set("Authorization", "Bearer "+resp.AccessToken)
	probeRec := httptest.NewRecorder()
	protected.ServeHTTP(probeRec, probe)

	if reached {
		t.Fatal("a minted token authenticated against a vault42 user route")
	}
	if probeRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", probeRec.Code, probeRec.Body.String())
	}
}

// The scope check alone is only accidentally sufficient: user tokens cannot
// carry mint:token today only because the user issuance sites hardcode their
// scopes. The handler asserts the client claim directly.
func TestMintHandler_RejectsTokensWithoutAClientClaim(t *testing.T) {
	h := newMintTestHandler(t, nil)
	req := mintRequest(t, MintRequestBody{Subject: "user-1"})
	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: "an-end-user"},
		Scopes:           []string{MintScope},
		TokenType:        "Bearer",
	}
	req = req.WithContext(context.WithValue(req.Context(), middleware.ClaimsKey, claims))

	rec := httptest.NewRecorder()
	h.Mint(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "client_credentials_required") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestMintHandler_RejectsUnauthenticated(t *testing.T) {
	h := newMintTestHandler(t, nil)
	rec := httptest.NewRecorder()
	h.Mint(rec, mintRequest(t, MintRequestBody{Subject: "user-1"}))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestMintHandler_ErrorMapping(t *testing.T) {
	h := newMintTestHandler(t, nil)
	cases := []struct {
		name   string
		body   MintRequestBody
		status int
		code   string
	}{
		{"missing subject", MintRequestBody{}, http.StatusBadRequest, "invalid_subject"},
		{"malformed subject", MintRequestBody{Subject: "has space"}, http.StatusBadRequest, "invalid_subject"},
		{"admin role", MintRequestBody{Subject: "user-1", Roles: []string{"admin"}}, http.StatusForbidden, "role_not_permitted"},
		{"unlisted role", MintRequestBody{Subject: "user-1", Roles: []string{"creator"}}, http.StatusForbidden, "role_not_permitted"},
		{"capability scope", MintRequestBody{Subject: "user-1", Scopes: []string{"kms:unwrap"}}, http.StatusForbidden, "scope_not_permitted"},
		{"ttl over max", MintRequestBody{Subject: "user-1", TTLSeconds: 4000}, http.StatusBadRequest, "invalid_ttl"},
		{"negative ttl", MintRequestBody{Subject: "user-1", TTLSeconds: -1}, http.StatusBadRequest, "invalid_ttl"},
	}
	for _, tc := range cases {
		req := withServiceClaims(mintRequest(t, tc.body), mintHandlerClient, []string{MintScope})
		rec := httptest.NewRecorder()
		h.Mint(rec, req)
		if rec.Code != tc.status {
			t.Errorf("%s: status %d, want %d (%s)", tc.name, rec.Code, tc.status, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), tc.code) {
			t.Errorf("%s: body %s, want %s", tc.name, rec.Body.String(), tc.code)
		}
	}
}

// ttlSecondsWrapPeriod is the period of the seconds-to-nanoseconds conversion.
//
// time.Duration is int64 nanoseconds and time.Second is 1e9 = 2^9 * 1953125.
// The odd factor is invertible modulo a power of two, so two ttl_seconds values
// that differ by 2^55 multiply to the identical int64 nanosecond count once the
// product wraps. That is why an absurd request can land exactly on an ordinary
// lifetime rather than on an obviously broken one.
const ttlSecondsWrapPeriod = 1 << 55

// ttlSecondsMaxExact is the largest ttl_seconds whose conversion to nanoseconds
// does not wrap.
const ttlSecondsMaxExact = math.MaxInt64 / int64(time.Second)

// A minted token cannot be revoked, so the lifetime granted is the entire
// exposure window, and the documented contract is that an out-of-range
// ttl_seconds is refused rather than turned into some other lifetime. Without a
// bound before the multiply, a caller asking for roughly 1.1 billion years is
// answered 200 with a signed subject assertion, because the wrapped product
// lands inside the ceiling and passes the comparison the ceiling is checked
// with. In production that means the one endpoint that forges subjects accepts
// input nobody validated, the caller never learns its configuration is wrong,
// and the audit trail records a successful mint at a lifetime the caller never
// asked for.
func TestMintHandler_OutOfRangeTTLSecondsIsRefusedRatherThanWrappedIntoAnAcceptedLifetime(t *testing.T) {
	// Configured MaxTTL is 10m and DefaultTTL is 5m, so the wrap targets below
	// are chosen to land on or inside that ceiling.
	h := newMintTestHandler(t, nil)

	cases := []struct {
		name string
		ttl  int
	}{
		{"largest value that converts exactly, already above the configured maximum", int(ttlSecondsMaxExact)},
		{"first value whose conversion wraps", int(ttlSecondsMaxExact) + 1},
		{"maximum int64 seconds", math.MaxInt64},
		{"wraps to exactly the configured maximum", ttlSecondsWrapPeriod + 600},
		{"wraps to a minute", ttlSecondsWrapPeriod + 60},
		{"wraps to zero, which the service reads as no TTL requested", ttlSecondsWrapPeriod},
		{"wraps to five minutes after two periods", 2*ttlSecondsWrapPeriod + 300},
		{"negative", -1},
	}
	for _, tc := range cases {
		req := withServiceClaims(mintRequest(t, MintRequestBody{Subject: "user-1", TTLSeconds: tc.ttl}), mintHandlerClient, []string{MintScope})
		rec := httptest.NewRecorder()
		h.Mint(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: ttl_seconds=%d got status %d, want 400: %s", tc.name, tc.ttl, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "invalid_ttl") {
			t.Errorf("%s: ttl_seconds=%d body %s, want invalid_ttl", tc.name, tc.ttl, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "access_token") {
			t.Errorf("%s: ttl_seconds=%d was signed a token: %s", tc.name, tc.ttl, rec.Body.String())
		}
	}
}

// The guard above must not cost the endpoint its documented range. Every
// lifetime an operator can configure has to stay mintable, or the fix for the
// overflow becomes an outage for the callers that were using the endpoint
// correctly.
func TestMintHandler_TTLSecondsWithinTheConfiguredCeilingIsStillGrantedExactly(t *testing.T) {
	h := newMintTestHandler(t, nil)

	for _, ttl := range []int{1, 60, 300, 600} {
		req := withServiceClaims(mintRequest(t, MintRequestBody{Subject: "user-1", TTLSeconds: ttl}), mintHandlerClient, []string{MintScope})
		rec := httptest.NewRecorder()
		h.Mint(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("ttl_seconds=%d got status %d, want 200: %s", ttl, rec.Code, rec.Body.String())
		}
		var got MintResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("ttl_seconds=%d decode response: %v", ttl, err)
		}
		if got.ExpiresIn != ttl {
			t.Errorf("ttl_seconds=%d granted expires_in=%d, want %d", ttl, got.ExpiresIn, ttl)
		}
	}
}

// Unknown fields must be refused: a caller that misspells "scopes" would
// otherwise be silently issued a token without them.
func TestMintHandler_RejectsUnknownFields(t *testing.T) {
	h := newMintTestHandler(t, nil)
	req := httptest.NewRequest(http.MethodPost, "/mint", strings.NewReader(`{"subject":"user-1","scope":"read"}`))
	req.RemoteAddr = "127.0.0.1:9999"
	req = withServiceClaims(req, mintHandlerClient, []string{MintScope})

	rec := httptest.NewRecorder()
	h.Mint(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMintHandler_RejectsOversizeBody(t *testing.T) {
	h := newMintTestHandler(t, nil)
	huge := `{"subject":"user-1","roles":["` + strings.Repeat("a", mintMaxBody) + `"]}`
	req := httptest.NewRequest(http.MethodPost, "/mint", strings.NewReader(huge))
	req.RemoteAddr = "127.0.0.1:9999"
	req = withServiceClaims(req, mintHandlerClient, []string{MintScope})

	rec := httptest.NewRecorder()
	h.Mint(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an oversize body, got %d", rec.Code)
	}
}

// A refused mint exists nowhere but the audit log. An accepted one is visible on
// the wire, since the token carries token_type "mint", an audience that is not
// this service's origin, and a minted_by naming the calling client. A refusal
// signs nothing, so the record is the only trace that the attempt happened at
// all. Both paths have to leave one.
func TestMintHandler_AuditsEveryOutcome(t *testing.T) {
	var captured []*model.AuditEntry
	auditRepo := &mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, entry *model.AuditEntry) error {
			captured = append(captured, entry)
			return nil
		},
	}
	svc, err := service.NewMintService(mintHandlerSigner(t), service.MintConfig{
		Issuer: mintHandlerIssuer, Audience: mintHandlerAudience,
		DefaultTTL: time.Minute, MaxTTL: time.Minute,
	}, nil)
	if err != nil {
		t.Fatalf("NewMintService: %v", err)
	}
	h := NewMintHandler(svc, audit.NewLogger(auditRepo, 0))

	ok := withServiceClaims(mintRequest(t, MintRequestBody{Subject: "user-1"}), mintHandlerClient, []string{MintScope})
	h.Mint(httptest.NewRecorder(), ok)

	bad := withServiceClaims(mintRequest(t, MintRequestBody{Subject: "bad subject"}), mintHandlerClient, []string{MintScope})
	h.Mint(httptest.NewRecorder(), bad)

	if len(captured) != 2 {
		t.Fatalf("recorded %d audit entries, want 2", len(captured))
	}
	for _, e := range captured {
		if e.EventType != audit.TokenMinted {
			t.Errorf("event type = %q, want %q", e.EventType, audit.TokenMinted)
		}
		if e.ClientID != mintHandlerClient {
			t.Errorf("client_id = %q, want the minting client", e.ClientID)
		}
		if e.Metadata["minted"] != true {
			t.Errorf("entry does not mark itself as minted: %+v", e.Metadata)
		}
		for _, forbidden := range []string{"token", "access_token"} {
			if _, present := e.Metadata[forbidden]; present {
				t.Errorf("audit metadata carried %q", forbidden)
			}
		}
	}
	if captured[0].UserID != "user-1" {
		t.Errorf("success entry user id = %q, want the asserted subject", captured[0].UserID)
	}
	if captured[1].Metadata["success"] != false {
		t.Errorf("refusal entry marked successful: %+v", captured[1].Metadata)
	}
}

// Auditing is best effort and must never block the mint path. A deployment with
// no audit logger loses the record, which is the operator's choice, but it must
// not lose the endpoint: neither the accepted nor the refused path may fault on
// the missing logger.
func TestMintHandler_MintsWithoutAnAuditLogger(t *testing.T) {
	h := newMintTestHandlerWith(t, mintHandlerSigner(t), nil)

	rec := httptest.NewRecorder()
	h.Mint(rec, withServiceClaims(mintRequest(t, MintRequestBody{Subject: "user-1"}), mintHandlerClient, []string{MintScope}))
	if rec.Code != http.StatusOK {
		t.Fatalf("issue: %d %s", rec.Code, rec.Body.String())
	}

	// A refusal takes the other audit helper, so both need the same guard.
	refused := mintRequest(t, MintRequestBody{Subject: "user-1"})
	refused = refused.WithContext(context.WithValue(refused.Context(), middleware.ClaimsKey, &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: "an-end-user"},
		Scopes:           []string{MintScope},
		TokenType:        "Bearer",
	}))
	rec = httptest.NewRecorder()
	h.Mint(rec, refused)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("refusal: %d %s", rec.Code, rec.Body.String())
	}
}

// A rotating deployment can be between keys, and the mint service is handed the
// active key on every request rather than holding one. No key means no
// assertion: a 503 the caller can retry, never a token signed with something
// else.
func TestMintHandler_NoSigningKeyIsRetryable(t *testing.T) {
	h := newMintTestHandlerWith(t, func() (*rsa.PrivateKey, string) { return nil, "" }, newTestAuditLogger())

	rec := httptest.NewRecorder()
	h.Mint(rec, withServiceClaims(mintRequest(t, MintRequestBody{Subject: "user-1"}), mintHandlerClient, []string{MintScope}))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "server_busy") {
		t.Fatalf("body = %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "access_token") {
		t.Fatalf("a failed mint returned a token: %s", rec.Body.String())
	}
}

// A signing failure that is not one of the policy refusals is an internal
// error, and it must stay one: the signing key's condition is not something a
// mint client is told about, and no token may be returned alongside it.
func TestMintHandler_UnusableSigningKeyIsAnInternalError(t *testing.T) {
	h := newMintTestHandlerWith(t, mintUnusableKeySigner(t), newTestAuditLogger())

	rec := httptest.NewRecorder()
	h.Mint(rec, withServiceClaims(mintRequest(t, MintRequestBody{Subject: "user-1"}), mintHandlerClient, []string{MintScope}))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500 (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "internal_error") {
		t.Fatalf("body = %s", rec.Body.String())
	}
	for _, leak := range []string{"access_token", "rsa", "p * q"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Fatalf("response carried %q: %s", leak, rec.Body.String())
		}
	}
}

// The refusal is audited like every other outcome, including the ones that come
// from the signing key rather than from the request.
func TestMintHandler_AuditsASigningFailure(t *testing.T) {
	var captured []*model.AuditEntry
	auditRepo := &mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, entry *model.AuditEntry) error {
			captured = append(captured, entry)
			return nil
		},
	}
	h := newMintTestHandlerWith(t, mintUnusableKeySigner(t), audit.NewLogger(auditRepo, 0))

	rec := httptest.NewRecorder()
	h.Mint(rec, withServiceClaims(mintRequest(t, MintRequestBody{Subject: "user-1"}), mintHandlerClient, []string{MintScope}))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", rec.Code)
	}
	if len(captured) != 1 {
		t.Fatalf("recorded %d audit entries, want 1", len(captured))
	}
	if captured[0].Metadata["success"] != false {
		t.Errorf("failed mint marked successful: %+v", captured[0].Metadata)
	}
	if captured[0].Metadata["reason"] != "internal_error" {
		t.Errorf("reason = %v, want internal_error", captured[0].Metadata["reason"])
	}
	if captured[0].UserID != "user-1" {
		t.Errorf("user id = %q, want the asserted subject", captured[0].UserID)
	}
}

// The opt-in is refused at the HTTP edge with a code of its own, so a caller
// pointed at an instance that does not allow the claim learns that, rather than
// receiving a token that silently says less than it asked for and failing later
// inside the relying party.
func TestMintHandler_EmailWithoutTheOptInIsRefused(t *testing.T) {
	h := newMintTestHandler(t, nil) // AllowEmail defaults off
	rec := httptest.NewRecorder()
	h.Mint(rec, withServiceClaims(mintRequest(t, MintRequestBody{
		Subject: "user-1", Email: "alice@example.com",
	}), "client-1", []string{MintScope}))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "email_not_permitted") {
		t.Fatalf("body = %s, want email_not_permitted", rec.Body.String())
	}
}

func TestMintHandler_AnInvalidEmailIsABadRequest(t *testing.T) {
	h := newMintTestHandler(t, func(c *service.MintConfig) { c.AllowEmail = true })
	rec := httptest.NewRecorder()
	h.Mint(rec, withServiceClaims(mintRequest(t, MintRequestBody{
		Subject: "user-1", Email: "Alice <alice@example.com>",
	}), "client-1", []string{MintScope}))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_email") {
		t.Fatalf("body = %s, want invalid_email", rec.Body.String())
	}
}

// The response echoes the asserted address so a client can see what it actually
// got. It is echoed normalised, which is the value that went into the claim.
func TestMintHandler_TheResponseEchoesTheAssertedEmail(t *testing.T) {
	h := newMintTestHandler(t, func(c *service.MintConfig) { c.AllowEmail = true })
	rec := httptest.NewRecorder()
	h.Mint(rec, withServiceClaims(mintRequest(t, MintRequestBody{
		Subject: "user-1", Email: "  Alice@Example.COM ",
	}), "client-1", []string{MintScope}))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var resp MintResponse
	decodeResponse(t, rec, &resp)
	if resp.Email != "alice@example.com" {
		t.Fatalf("response email = %q", resp.Email)
	}
	payload := mintedTokenPayload(t, resp.AccessToken)
	if payload["email"] != "alice@example.com" {
		t.Fatalf("claim email = %v", payload["email"])
	}
}

// The audit row deliberately does not carry the address. Audit entries outlive
// an erasure, and this is caller-asserted personal data that vault42 never
// verified and holds no other record of -- writing it here would create one,
// in the one table designed to survive the subject asking to be forgotten.
func TestMintHandler_TheAuditRowDoesNotCarryTheEmail(t *testing.T) {
	var captured []*model.AuditEntry
	auditRepo := &mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, entry *model.AuditEntry) error {
			captured = append(captured, entry)
			return nil
		},
	}
	svc, err := service.NewMintService(mintHandlerSigner(t), service.MintConfig{
		Issuer: mintHandlerIssuer, Audience: mintHandlerAudience,
		DefaultTTL: time.Minute, MaxTTL: time.Minute, AllowEmail: true,
	}, nil)
	if err != nil {
		t.Fatalf("NewMintService: %v", err)
	}
	h := NewMintHandler(svc, audit.NewLogger(auditRepo, 0))

	rec := httptest.NewRecorder()
	h.Mint(rec, withServiceClaims(mintRequest(t, MintRequestBody{
		Subject: "user-1", Email: "alice@example.com",
	}), mintHandlerClient, []string{MintScope}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}

	if len(captured) == 0 {
		t.Fatal("no audit entry recorded")
	}
	for _, e := range captured {
		for k, v := range e.Metadata {
			if str, ok := v.(string); ok && strings.Contains(str, "alice@example.com") {
				t.Errorf("audit metadata %q carries the asserted email", k)
			}
		}
	}
}
