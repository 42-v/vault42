package compliance

import (
	"context"
	"encoding/base32"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/oauth2"
)

// =============================================================================
// IETF RFC / OpenID Connect — register-audit re-verification (ietf group)
//
// These tests replace grep-only / tautological register entries with checks
// that drive the REAL shipped code end to end:
//   - RFC 8725 s3.8  reject dangerous JWT headers on INBOUND tokens
//   - RFC 6238       TOTP is RFC-correct (Appendix B KATs) and 30s-stepped
//   - RFC 9700 s4.1.1 OAuth state integrity + browser/session binding via the
//                     real Authorize+Callback handler
//   - RFC 8725 s3.9  validity-window (exp/nbf/iat) + iss/aud fail-closed, UTF-8
// =============================================================================

// --- RFC 8725 s3.8: "Do Not Trust Received Public Keys" ---------------------
//
// The verifier (ParseAndValidate) MUST reject an INBOUND token that carries a
// key-source header (jku/x5u/x5c/jwk), so an attacker cannot point the verifier
// at a key it controls (key-confusion). The old register test asserted only
// that vault's OWN signed OUTPUT omits those headers — the signer side, the
// wrong direction. This forges validly-signed inbound tokens that each carry a
// dangerous header and asserts the verifier refuses them by name.

func TestIETF_RFC8725_s38_VerifierRejectsInboundKeySourceHeaders(t *testing.T) {
	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	kid, err := vaultcrypto.RandomUUID()
	if err != nil {
		t.Fatalf("RandomUUID: %v", err)
	}
	keyFunc := func(_ *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "u1",
			Issuer:    "vault",
			Audience:  vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}

	// Positive control: a clean, validly-signed token with NO key-source header
	// is accepted. This proves the rejections below are caused specifically by
	// the dangerous header and not by some incidental parse failure.
	clean, err := vjwt.SignRS256WithHeader(map[string]any{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	}, claims, key)
	if err != nil {
		t.Fatalf("sign clean token: %v", err)
	}
	if _, err := vaultcrypto.ParseAndValidate(clean, keyFunc, "vault", "app"); err != nil {
		t.Fatalf("s3.8: clean token (no key-source header) must be accepted, got: %v", err)
	}

	// Each dangerous header, on an otherwise-valid, correctly-signed token, must
	// be rejected — the signature over the header does not matter, the presence
	// of the header is disqualifying (attacker-supplied key material).
	dangerous := []struct {
		name  string
		value any
	}{
		{"jku", "https://attacker.example/keys.json"},
		{"x5u", "https://attacker.example/cert.pem"},
		{"x5c", []any{"MIIB...attacker-cert-chain..."}},
		{"jwk", map[string]any{"kty": "RSA", "n": "attacker-modulus", "e": "AQAB"}},
	}
	for _, d := range dangerous {
		t.Run(d.name, func(t *testing.T) {
			hdr := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid, d.name: d.value}
			tokenStr, err := vjwt.SignRS256WithHeader(hdr, claims, key)
			if err != nil {
				t.Fatalf("sign token with %q header: %v", d.name, err)
			}
			_, err = vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "vault", "app")
			if err == nil {
				t.Fatalf("s3.8: inbound token carrying %q header was ACCEPTED", d.name)
			}
			if !strings.Contains(err.Error(), d.name) {
				t.Fatalf("s3.8: rejection for %q must name the header, got: %v", d.name, err)
			}
		})
	}
}

// --- RFC 6238: TOTP algorithm conformance -----------------------------------
//
// The old register test only proved determinism (a pure function returns the
// same value twice) and the 30s constant. Neither checked a code VALUE against
// a known-answer vector, so a consistent-but-wrong truncation would pass. This
// checks vault's GenerateTOTPCode against RFC 6238 Appendix B (HMAC-SHA1 seed
// "12345678901234567890"), reduced to vault's 6 digits (the low 6 decimals of
// the published 8-digit values).

func TestIETF_RFC6238_TOTPAppendixBKnownAnswerVectors(t *testing.T) {
	// RFC 6238 Appendix B, SHA-1 test seed (20 ASCII bytes), base32-encoded the
	// way vault's TOTP layer expects the shared secret.
	seed := []byte("12345678901234567890")
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)

	// Published 8-digit vectors truncated to vault's 6 digits:
	//   94287082->287082, 07081804->081804, 14050471->050471,
	//   89005924->005924, 69279037->279037, 65353130->353130
	vectors := []struct {
		unix int64
		code string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}

	for _, v := range vectors {
		got, err := vaultcrypto.GenerateTOTPCode(secret, time.Unix(v.unix, 0).UTC())
		if err != nil {
			t.Fatalf("RFC6238: GenerateTOTPCode(T=%d): %v", v.unix, err)
		}
		if got != v.code {
			t.Fatalf("RFC6238: T=%d expected %s (Appendix B), got %s", v.unix, v.code, got)
		}
		// The RFC-correct code MUST also verify against vault's validator at the
		// same instant (end-to-end HMAC-SHA1 conformance, not just generation).
		if _, err := vaultcrypto.ValidateTOTPCode(secret, got, time.Unix(v.unix, 0).UTC()); err != nil {
			t.Fatalf("RFC6238: validator rejected its own RFC-correct code at T=%d: %v", v.unix, err)
		}
	}
}

func TestIETF_RFC6238_TOTPThirtySecondTimeStep(t *testing.T) {
	// RFC 6238: the default time step X is 30 seconds. Prove it behaviorally:
	// a code is stable across a full 30s window and rolls exactly at the
	// boundary — not 29s, not 31s. 1234567890 is an exact multiple of 30, so it
	// sits on a step boundary.
	seed := []byte("12345678901234567890")
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)

	base := time.Unix(1234567890, 0).UTC()
	at := func(off int64) string {
		c, err := vaultcrypto.GenerateTOTPCode(secret, base.Add(time.Duration(off)*time.Second))
		if err != nil {
			t.Fatalf("RFC6238: GenerateTOTPCode(off=%d): %v", off, err)
		}
		return c
	}

	start := at(0)
	if end := at(29); end != start {
		t.Fatalf("RFC6238: code changed within the 30s window (t+29 %s != t %s)", end, start)
	}
	if next := at(30); next == start {
		t.Fatalf("RFC6238: code did not roll at the 30s boundary (t+30 still %s)", next)
	}
	if prev := at(-1); prev == start {
		t.Fatalf("RFC6238: previous step shares the code (t-1 == t %s); step is not 30s", start)
	}

	// The provisioning artifact handed to authenticator apps must also advertise
	// the 30s period and HMAC-SHA1, so third-party generators agree with vault.
	otpauth := vaultcrypto.BuildOTPAuthURL(secret, "vault42", "user@example.test")
	if !strings.Contains(otpauth, "period=30") {
		t.Fatalf("RFC6238: otpauth URL must advertise period=30, got: %s", otpauth)
	}
	if !strings.Contains(otpauth, "algorithm=SHA1") {
		t.Fatalf("RFC6238: otpauth URL must advertise algorithm=SHA1, got: %s", otpauth)
	}
}

// --- RFC 9700 s4.1.1: CSRF via integrity-protected, browser-bound state ------
//
// The old register test hand-built "provider.nonce.expiry.csrfHash" inside the
// test and called the generic HMACSign/HMACVerify pair — proving only that
// HMAC-SHA256 is a MAC, never that vault's endpoint is CSRF-protected. This
// drives the REAL OAuthHandler.Authorize (state minting + cookie binding) and
// OAuthHandler.Callback (state verification + browser binding), and asserts
// every forged/tampered/cross-browser/unbound variant is refused while the
// legitimately-bound pairing is accepted.

type ietfStubProvider struct{ name string }

func (p ietfStubProvider) Name() string { return p.name }
func (p ietfStubProvider) AuthURL(state, nonce, _ string) string {
	return "https://idp.example.test/authorize?state=" + url.QueryEscape(state) +
		"&nonce=" + url.QueryEscape(nonce)
}

func (p ietfStubProvider) Exchange(_ context.Context, _, _ string) (*oauth2.TokenResponse, error) {
	return nil, errors.New("stub: exchange not reached in these tests")
}

func (p ietfStubProvider) UserInfo(_ context.Context, _ string) (*oauth2.UserInfo, error) {
	return nil, errors.New("stub: userinfo not reached in these tests")
}

const ietfOAuthStateCookie = "__Host-oauth_state"

func ietfNewOAuthHandler(secret []byte, c cache.Cache) *handler.OAuthHandler {
	providers := map[string]oauth2.Provider{"google": ietfStubProvider{name: "google"}}
	return handler.NewOAuthHandler(
		providers, secret, c, "https://app.test",
		nil, nil, nil, // users, social, tokens
		nil, nil, nil, // authSvc, tokenSvc, mfaSvc
		nil,   // auditLog
		false, // secureCookies
	)
}

// ietfMintState runs the real /authorize handler and returns the signed state
// and the browser-binding cookie it minted.
func ietfMintState(t *testing.T, h *handler.OAuthHandler) (state, cookie string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/authorize?provider=google", nil)
	rec := httptest.NewRecorder()
	h.Authorize(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize: expected 302, got %d (%s)", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("authorize: parse Location: %v", err)
	}
	state = loc.Query().Get("state")
	if state == "" {
		t.Fatal("authorize: no state in redirect URL")
	}
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == ietfOAuthStateCookie {
			cookie = ck.Value
		}
	}
	if cookie == "" {
		t.Fatalf("authorize: no %s cookie set", ietfOAuthStateCookie)
	}
	return state, cookie
}

// ietfDoCallback runs the real /callback handler and returns status + body.
func ietfDoCallback(h *handler.OAuthHandler, state, cookie, code string) (int, string) {
	q := url.Values{}
	q.Set("provider", "google")
	if state != "" {
		q.Set("state", state)
	}
	if code != "" {
		q.Set("code", code)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth2/callback?"+q.Encode(), nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: ietfOAuthStateCookie, Value: cookie})
	}
	rec := httptest.NewRecorder()
	h.Callback(rec, req)
	return rec.Code, rec.Body.String()
}

func TestIETF_RFC9700_s411_StateIntegrityAndSessionBinding(t *testing.T) {
	c := cache.NewMemoryCache()
	defer c.Close() //nolint:errcheck // test cleanup
	secret := []byte("ietf-rfc9700-state-hmac-secret-0001")
	h := ietfNewOAuthHandler(secret, c)

	// Positive: a state + cookie pair minted by the real /authorize handler is
	// accepted by /callback — it passes signature, browser binding, expiry, and
	// the nonce->PKCE-verifier lookup, stopping only at the (deliberately
	// omitted) authorization code. That end state proves the CSRF gate accepts
	// the legitimately-bound request rather than rejecting everything.
	t.Run("legit_pairing_passes_state_gate", func(t *testing.T) {
		state, cookie := ietfMintState(t, h)
		status, body := ietfDoCallback(h, state, cookie, "")
		if strings.Contains(body, "invalid_state") || strings.Contains(body, "state_expired") {
			t.Fatalf("legit pairing rejected at state gate: %d %s", status, body)
		}
		if !strings.Contains(body, "missing_code") {
			t.Fatalf("legit pairing should pass state gate and reach missing_code, got: %d %s", status, body)
		}
	})

	// No cookie: an HMAC-valid state replayed into a browser that never started
	// the flow (no binding cookie) must be refused — session-fixation defense.
	t.Run("no_binding_cookie_rejected", func(t *testing.T) {
		state, _ := ietfMintState(t, h)
		status, body := ietfDoCallback(h, state, "", "")
		if status != http.StatusBadRequest || !strings.Contains(body, "invalid_state") {
			t.Fatalf("state without binding cookie must be invalid_state, got: %d %s", status, body)
		}
	})

	// Cross-browser: browser A's state presented with browser B's cookie. Both
	// are individually valid, but the csrfHash bound into state A does not match
	// SHA-256 of cookie B — the exact login-CSRF / fixation replay.
	t.Run("cross_browser_cookie_rejected", func(t *testing.T) {
		stateA, _ := ietfMintState(t, h)
		_, cookieB := ietfMintState(t, h)
		status, body := ietfDoCallback(h, stateA, cookieB, "")
		if status != http.StatusBadRequest || !strings.Contains(body, "invalid_state") {
			t.Fatalf("cross-browser state/cookie must be invalid_state, got: %d %s", status, body)
		}
	})

	// Tampered payload, authentic cookie: mutate the expiry field of a real
	// state but keep the original signature. Only the HMAC can reject this, so
	// it isolates the integrity property of the state parameter.
	t.Run("tampered_payload_rejected", func(t *testing.T) {
		state, cookie := ietfMintState(t, h)
		lastDot := strings.LastIndex(state, ".")
		if lastDot < 0 {
			t.Fatalf("state has no signature segment: %q", state)
		}
		payload, sig := state[:lastDot], state[lastDot+1:]
		parts := strings.SplitN(payload, ".", 4)
		if len(parts) != 4 {
			t.Fatalf("state payload not 4 parts: %q", payload)
		}
		parts[2] += "9" // extend the expiry — attacker keeps a valid-looking state alive
		forged := parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3] + "." + sig
		status, body := ietfDoCallback(h, forged, cookie, "")
		if status != http.StatusBadRequest || !strings.Contains(body, "invalid_state") {
			t.Fatalf("tampered state must be invalid_state, got: %d %s", status, body)
		}
	})

	// Wrong signing key: a state minted by a DIFFERENT server (different HMAC
	// secret), replayed with its own valid cookie, must fail our verifier — the
	// state is bound to this server's key.
	t.Run("foreign_key_state_rejected", func(t *testing.T) {
		c2 := cache.NewMemoryCache()
		defer c2.Close() //nolint:errcheck // test cleanup
		h2 := ietfNewOAuthHandler([]byte("some-OTHER-servers-hmac-secret-99"), c2)
		foreignState, foreignCookie := ietfMintState(t, h2)
		status, body := ietfDoCallback(h, foreignState, foreignCookie, "")
		if status != http.StatusBadRequest || !strings.Contains(body, "invalid_state") {
			t.Fatalf("foreign-key state must be invalid_state, got: %d %s", status, body)
		}
	})
}

// --- RFC 8725 s3.9: validity-window + iss/aud verified, UTF-8 ---------------
//
// The old register entries were pure source-greps and never proved fail-closed
// behavior; the "use UTF-8" element was untested entirely. This drives the real
// verifier (ParseAndValidate, which pins WithExpirationRequired/WithIssuedAt/
// WithIssuer/WithAudience) against tokens that each violate exactly one of
// exp/nbf/iat/iss/aud and asserts the matching sentinel error, then proves a
// UTF-8 iss/sub round-trips and compares correctly.

func TestIETF_RFC8725_s39_ValidityWindowAndBindingFailClosed(t *testing.T) {
	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	kid, err := vaultcrypto.RandomUUID()
	if err != nil {
		t.Fatalf("RandomUUID: %v", err)
	}
	keyFunc := func(_ *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	const iss, aud = "vault", "app"
	now := time.Now()
	base := func() vjwt.RegisteredClaims {
		return vjwt.RegisteredClaims{
			Subject:   "u1",
			Issuer:    iss,
			Audience:  vjwt.ClaimStrings{aud},
			ExpiresAt: vjwt.NewNumericDate(now.Add(time.Hour)),
			NotBefore: vjwt.NewNumericDate(now.Add(-time.Minute)),
			IssuedAt:  vjwt.NewNumericDate(now.Add(-time.Minute)),
		}
	}
	sign := func(rc vjwt.RegisteredClaims) string {
		s, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{RegisteredClaims: rc}, key, kid)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return s
	}

	// Positive control: a fully valid token passes.
	if _, err := vaultcrypto.ParseAndValidate(sign(base()), keyFunc, iss, aud); err != nil {
		t.Fatalf("s3.9: valid token must be accepted, got: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(rc *vjwt.RegisteredClaims)
		wantErr error
	}{
		{"expired", func(rc *vjwt.RegisteredClaims) {
			rc.ExpiresAt = vjwt.NewNumericDate(now.Add(-time.Hour))
		}, vjwt.ErrTokenExpired},
		{"not_yet_valid", func(rc *vjwt.RegisteredClaims) {
			rc.NotBefore = vjwt.NewNumericDate(now.Add(time.Hour))
		}, vjwt.ErrTokenNotValidYet},
		{"used_before_issued", func(rc *vjwt.RegisteredClaims) {
			rc.IssuedAt = vjwt.NewNumericDate(now.Add(time.Hour))
		}, vjwt.ErrTokenUsedBeforeIssued},
		{"missing_exp", func(rc *vjwt.RegisteredClaims) {
			rc.ExpiresAt = nil
		}, vjwt.ErrTokenRequiredClaimMissing},
		{"wrong_issuer", func(rc *vjwt.RegisteredClaims) {
			rc.Issuer = "attacker-idp"
		}, vjwt.ErrTokenInvalidIssuer},
		{"wrong_audience", func(rc *vjwt.RegisteredClaims) {
			rc.Audience = vjwt.ClaimStrings{"some-other-app"}
		}, vjwt.ErrTokenInvalidAudience},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := base()
			tc.mutate(&rc)
			_, err := vaultcrypto.ParseAndValidate(sign(rc), keyFunc, iss, aud)
			if err == nil {
				t.Fatalf("s3.9: %s token was ACCEPTED (must fail closed)", tc.name)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("s3.9: %s expected %v, got: %v", tc.name, tc.wantErr, err)
			}
		})
	}
}

func TestIETF_RFC8725_s39_UTF8ClaimsRoundTrip(t *testing.T) {
	// RFC 8725 s3.9 ("Use UTF-8"): JWT text strings are UTF-8. Prove vault's
	// signer/verifier preserve multibyte UTF-8 in a round-tripped claim (sub)
	// AND compare a UTF-8 issuer correctly (bytewise, not mangled).
	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}
	kid, err := vaultcrypto.RandomUUID()
	if err != nil {
		t.Fatalf("RandomUUID: %v", err)
	}
	keyFunc := func(_ *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	const utf8Issuer = "issuer-café-日本語"
	const utf8Subject = "üser-café-日本語-😀"

	tokenStr, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   utf8Subject,
			Issuer:    utf8Issuer,
			Audience:  vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key, kid)
	if err != nil {
		t.Fatalf("sign UTF-8 token: %v", err)
	}

	// Validation must succeed with the UTF-8 issuer compared byte-for-byte.
	claims, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, utf8Issuer, "app")
	if err != nil {
		t.Fatalf("s3.9: UTF-8 issuer token must validate, got: %v", err)
	}
	if claims.Subject != utf8Subject {
		t.Fatalf("s3.9: UTF-8 subject not preserved: got %q want %q", claims.Subject, utf8Subject)
	}
	if claims.Issuer != utf8Issuer {
		t.Fatalf("s3.9: UTF-8 issuer not preserved: got %q want %q", claims.Issuer, utf8Issuer)
	}

	// A byte-different issuer (one codepoint changed) must fail closed, proving
	// the comparison is exact over UTF-8 rather than lenient/normalized.
	if _, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "issuer-cafe-日本語", "app"); !errors.Is(err, vjwt.ErrTokenInvalidIssuer) {
		t.Fatalf("s3.9: near-miss UTF-8 issuer must be rejected, got: %v", err)
	}
}
