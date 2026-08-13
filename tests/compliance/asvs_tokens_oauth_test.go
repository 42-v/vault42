package compliance

import (
	"regexp"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// =============================================================================
// OWASP Application Security Verification Standard (ASVS) 5.0.0
// V9:  Self-contained Tokens
// V10: OAuth and OIDC
// https://github.com/OWASP/ASVS/tree/v5.0.0_release/5.0
//
// Both chapters are new in 5.0.0 and they are the reason the re-baseline lets
// vault42 claim more rather than less. Under v4.0.3 the JWT hardening lived
// under a session-management requirement (V3.5.3) and the OAuth work had no
// ASVS home at all, so it was hived off into a bespoke "RFC family" section an
// auditor had to take on trust. These two chapters absorb that section into the
// standard's own numbering.
// =============================================================================

// --- V9.1.2: only allowlisted algorithms may verify a self-contained token ---

// "Verify that only algorithms on an allowlist can be used to create and verify
// self-contained tokens ... and must not include the 'None' algorithm."
func TestASVS_V9_1_2_TokenAlgorithmAllowlistExcludesNoneAndHMAC(t *testing.T) {
	if vaultcrypto.AllowedAlgorithm != "RS256" {
		t.Fatalf("V9.1.2: the token algorithm allowlist is %q, not RS256", vaultcrypto.AllowedAlgorithm)
	}

	// The parser is the second layer. A verifier that reaches a symmetric
	// branch at all reintroduces the key-confusion attack the allowlist exists
	// to prevent, so the parser must have no HMAC or "none" case.
	parse := readCodeOnly(t, "internal/jwt/parse.go")
	for _, forbidden := range []string{`"none"`, `"HS256"`, `"HS384"`, `"HS512"`} {
		if strings.Contains(parse, forbidden) {
			t.Errorf("V9.1.2: internal/jwt/parse.go references %s; a symmetric or unsigned branch must not exist in the verifier", forbidden)
		}
	}
	if !strings.Contains(parse, "unsupported algorithm") {
		t.Error("V9.1.2: the parser no longer rejects unrecognized algorithms by default")
	}
}

// --- V9.1.3: key material comes only from trusted pre-configured sources ---

// "For JWTs and other JWS structures, headers such as 'jku', 'x5u', and 'jwk'
// must be validated against an allowlist of trusted sources."
//
// vault42's answer is stricter than an allowlist: the headers are rejected
// outright, because there is no case in which a caller should be choosing the
// verification key.
func TestASVS_V9_1_3_KeySourceHeadersAreRejected(t *testing.T) {
	for _, site := range []string{"internal/crypto/jwt.go", "internal/oauth2/oidc_idtoken.go"} {
		src := readProductionSource(t, site)
		for _, header := range []string{"jku", "x5u", "jwk"} {
			if !strings.Contains(src, `"`+header+`"`) {
				t.Errorf("V9.1.3: %s no longer names the %q header; a caller-supplied key source would be accepted", site, header)
			}
		}
	}

	// The kid selects a key from the trusted set and is used to index it, so
	// its shape has to be constrained or it becomes a path into that lookup.
	if !strings.Contains(readProductionSource(t, "internal/crypto/jwt.go"), "isValidKID") {
		t.Error("V9.1.3: the kid format check is gone; the key lookup would accept an arbitrary caller-supplied identifier")
	}
}

// --- V9.2.1 / V9.2.3: validity window and audience are enforced ---

// "Verify that, if a validity time span is present in the token data, the token
// and its content are accepted only if the verification time is within this
// validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be
// verified."
func TestASVS_V9_2_1_ValidityWindowClaimsAreVerified(t *testing.T) {
	src := readProductionSource(t, "internal/jwt/validate.go")
	for _, claim := range []string{"exp", "nbf", "iat"} {
		if !strings.Contains(src, claim) {
			t.Errorf("V9.2.1: internal/jwt/validate.go no longer verifies the %q claim", claim)
		}
	}
	// An expiry that is merely optional is not a validity window.
	if !strings.Contains(src, "GetExpirationTime") {
		t.Error("V9.2.1: expiry is no longer read from the token")
	}
}

// "Verify that the service only accepts tokens which are intended for use with
// that service (audience)."
func TestASVS_V9_2_3_IssuerAndAudienceAreBound(t *testing.T) {
	validate := readProductionSource(t, "internal/jwt/validate.go")
	for _, needle := range []string{"expectedIssuer", "expectedAud"} {
		if !strings.Contains(validate, needle) {
			t.Errorf("V9.2.3: internal/jwt/validate.go no longer carries %s", needle)
		}
	}
	// A validator that supports the check but is never configured with it is
	// not enforcing anything, so the wiring is asserted too.
	crypto := readProductionSource(t, "internal/crypto/jwt.go")
	for _, needle := range []string{"WithIssuer(", "WithAudience("} {
		if !strings.Contains(crypto, needle) {
			t.Errorf("V9.2.3: the vault token parser no longer configures %s", needle)
		}
	}
}

// A self-contained token with no size bound is a parsing denial of service.
func TestASVS_V9_1_1_TokenSizeIsBoundedBeforeParsing(t *testing.T) {
	if vaultcrypto.MaxJWTSize <= 0 || vaultcrypto.MaxJWTSize > 64*1024 {
		t.Errorf("V9.1.1: MaxJWTSize is %d, which is not a usable bound", vaultcrypto.MaxJWTSize)
	}
	src := readProductionSource(t, "internal/crypto/jwt.go")
	if !strings.Contains(src, "len(tokenString) > MaxJWTSize") {
		t.Error("V9.1.1: the token size bound is declared but no longer enforced before parsing")
	}
}

// --- V10.4.6: PKCE is used on the authorization code flow ---

// "Verify that, if the code grant is used, the authorization server mitigates
// authorization code interception attacks by requiring proof key for code
// exchange (PKCE)."
//
// vault42 is the OAuth client here, so the obligation is to send a challenge on
// every provider rather than to enforce one. The plain method is worthless, so
// every provider must use S256.
func TestASVS_V10_4_6_EveryProviderSendsAnS256Challenge(t *testing.T) {
	providers := []string{
		"internal/oauth2/oidc.go",
		"internal/oauth2/google.go",
		"internal/oauth2/github.go",
		"internal/oauth2/facebook.go",
	}
	for _, p := range providers {
		src := readProductionSource(t, p)
		if !strings.Contains(src, "code_challenge") {
			t.Errorf("V10.4.6: %s no longer sends a PKCE challenge", p)
			continue
		}
		if !strings.Contains(src, `"S256"`) {
			t.Errorf("V10.4.6: %s does not pin code_challenge_method to S256; the plain method offers no protection", p)
		}
	}

	// The challenge must be derived from the verifier, not from a second
	// random value, or the exchange proves nothing.
	if !strings.Contains(readProductionSource(t, "internal/handler/oauth.go"), "SHA256Base64URL(verifier)") {
		t.Error("V10.4.6: the code challenge is no longer derived from the verifier by SHA-256")
	}
}

// --- V10.4.2: an authorization code is usable exactly once ---

// "Verify that ... the authorization code ... can be used only once for a token
// request."
func TestASVS_V10_4_2_AuthorizationArtifactsAreSingleUse(t *testing.T) {
	src := readProductionSource(t, "internal/handler/oauth.go")
	// GetAndDelete is the atomic single-use primitive: a second exchange finds
	// nothing rather than racing a read against a delete.
	if strings.Count(src, "GetAndDelete(") < 2 {
		t.Error("V10.4.2: the PKCE verifier and the exchange code are no longer both consumed atomically")
	}
}

// --- V10.2.1: the client is protected against request forgery on the callback ---

// "Verify that, if the code flow is used, the OAuth client has protection
// against browser-based request forgery attacks ... which trigger token
// requests."
//
// The state parameter is only a CSRF defense if its integrity is checked, and
// only a session binding if it is mirrored somewhere the attacker cannot set.
func TestASVS_V10_2_1_StateIsIntegrityProtectedAndSessionBound(t *testing.T) {
	src := readProductionSource(t, "internal/handler/oauth.go")

	if !strings.Contains(src, "HMACSign(") || !strings.Contains(src, "HMACVerify(") {
		t.Error("V10.2.1: the OAuth state parameter is no longer integrity-protected by HMAC")
	}
	if !strings.Contains(src, "__Host-oauth_state") {
		t.Error("V10.2.1: the mirrored state cookie is gone or has lost its __Host- prefix, which is what stops a subdomain from setting it")
	}
	// A callback that accepts a state minted for a different provider allows a
	// mix-up, which is V10.2.2.
	if !strings.Contains(src, "provider") {
		t.Error("V10.2.2: the state payload no longer binds the provider it was minted for")
	}
}

// --- V10.5.1: ID token replay is mitigated by nonce binding ---

// "Verify that the client (as the relying party) mitigates ID Token replay
// attacks. For example, by ensuring that the 'nonce' claim in the ID Token
// matches the 'nonce' value sent in the authentication request."
//
// The failure mode worth pinning is not a missing comparison but a comparison
// that is skipped when the expected nonce is empty, which turns the control off
// exactly when state has been lost.
func TestASVS_V10_5_1_EmptyExpectedNonceFailsClosed(t *testing.T) {
	src := readProductionSource(t, "internal/oauth2/oidc_idtoken.go")
	if !strings.Contains(src, "expectedNonce") {
		t.Fatal("V10.5.1: ID token nonce binding is gone")
	}
	if !strings.Contains(src, "no expected nonce") {
		t.Error("V10.5.1: an empty expected nonce no longer fails closed; the replay defense would silently switch off")
	}
}

// --- V10.5.3 / V10.5.4: the provider's identity and the audience are pinned ---

func TestASVS_V10_5_3_ProviderMetadataIssuerIsPinned(t *testing.T) {
	src := readProductionSource(t, "internal/oauth2/oidc.go")
	if !strings.Contains(src, "doc.Issuer") {
		t.Error("V10.5.3: the discovery document issuer is no longer compared against the configured issuer; a malicious provider could impersonate another")
	}
}

func TestASVS_V10_5_4_IDTokenAudienceIsCheckedAgainstTheClientID(t *testing.T) {
	src := readProductionSource(t, "internal/oauth2/oidc_idtoken.go")
	if !strings.Contains(src, "WithAudience(") {
		t.Error("V10.5.4: the ID token audience is no longer bound to this client")
	}
	if !strings.Contains(src, "WithIssuer(") {
		t.Error("V10.5.4: the ID token issuer is no longer validated")
	}
}

// --- V10.4.5: refresh token replay is mitigated ---

// "Verify that the authorization server mitigates refresh token replay
// attacks."
//
// vault42's mitigation is rotation with single-use enforcement and family
// revocation, not sender-constraining. The single-use update has to be a
// compare-and-set in one statement, or two concurrent refreshes both win.
func TestASVS_V10_4_5_RefreshRotationIsSingleUseByCompareAndSet(t *testing.T) {
	repo := readProductionSource(t, "internal/repository/postgres/refresh_token.go")
	if !strings.Contains(repo, "SET used = TRUE WHERE id = $1 AND used = FALSE") {
		t.Error("V10.4.5: MarkUsed is no longer a single-statement compare-and-set; concurrent refreshes could both succeed")
	}
	if !strings.Contains(repo, "RevokeFamily") {
		t.Error("V10.4.5: family revocation on replay is gone")
	}
}

// The ordering is the property that matters and it was previously carried in
// docs/COMPLIANCE.md as an unverified partial: the old token must be
// invalidated before the new one is issued. A crash between the two then loses
// the session, which fails closed; the reverse order would leave two live
// tokens, which fails open.
func TestASVS_V10_4_5_OldTokenIsInvalidatedBeforeTheNewOneIsCreated(t *testing.T) {
	src := readProductionSource(t, "internal/service/auth.go")

	body := funcBody(t, src, "func (s *AuthService) Refresh(")

	markUsed := strings.Index(body, "s.tokens.MarkUsed(")
	if markUsed < 0 {
		t.Fatal("V10.4.5: Refresh no longer marks the presented token used")
	}

	// The replacement may be created directly in Refresh or in a helper it
	// calls. It moved into issueRotatedPair when the rotation guard pushed
	// Refresh past the complexity limit, and an assertion that only looked at
	// Refresh's own body reported the mitigation gone when nothing about it had
	// changed. Following one level of local call keeps the property asserted
	// across a refactor instead of retiring on one.
	create := strings.Index(body, "s.tokens.Create(")
	where := "Refresh"
	if create < 0 {
		for _, helper := range localCallsAfter(body, markUsed) {
			hb := funcBody(t, src, "func (s *AuthService) "+helper+"(")
			if hb == "" {
				continue
			}
			if strings.Contains(hb, "s.tokens.Create(") {
				// Reached only after MarkUsed, by construction of localCallsAfter.
				create, where = markUsed+1, helper
				break
			}
		}
	}
	if create < 0 {
		t.Fatal("V10.4.5: neither Refresh nor any helper it calls creates a replacement token")
	}
	if markUsed > create {
		t.Errorf("V10.4.5: the replacement token is created in %s before the presented one is "+
			"invalidated; an interrupted rotation would leave two usable refresh tokens", where)
	}
}

// funcBody returns the source of the function whose declaration starts with
// prefix, or "" when there is none.
func funcBody(t *testing.T, src, prefix string) string {
	t.Helper()

	at := strings.Index(src, prefix)
	if at < 0 {
		return ""
	}
	body := src[at:]
	if end := strings.Index(body[1:], "\nfunc "); end > 0 {
		body = body[:end+1]
	}
	return body
}

// localCallsAfter returns the names of methods on the receiver called after
// offset, in source order, so the search follows the path the rotation actually
// takes rather than every helper in the file.
func localCallsAfter(body string, offset int) []string {
	matches := regexp.MustCompile(`s\.([a-z][A-Za-z0-9]*)\(`).FindAllStringSubmatchIndex(body[offset:], -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, body[offset+m[2]:offset+m[3]])
	}
	return out
}

// --- V10.4.8: refresh tokens have an absolute expiration ---

// "Verify that refresh tokens have an absolute expiration, including if sliding
// refresh token expiration is applied."
//
// This is the requirement the sliding-window issue lands on. Rotation currently
// stamps a fresh full TTL on every refresh and no column records when the
// family was created, so a continuously refreshing client holds a session
// indefinitely. The register carries it as an accepted risk (AR-14) until the
// family-age column lands.
//
// This test asserts the half that holds, an expiry on each individual token,
// and fails once the family-creation column appears, which is the signal to
// promote the register row to Met.
func TestASVS_V10_4_8_PerTokenExpiryExistsAndFamilyAgeIsStillUnrecorded(t *testing.T) {
	if !strings.Contains(readProductionSource(t, "internal/service/token.go"), "RefreshExpAt") {
		t.Fatal("V10.4.8: refresh tokens no longer carry an expiry at all")
	}

	schema := readProductionSource(t, "migrations/001_initial_schema.sql")
	idx := strings.Index(schema, "CREATE TABLE auth.refresh_tokens")
	if idx < 0 {
		t.Fatal("V10.4.8: auth.refresh_tokens is no longer created in 001_initial_schema.sql")
	}
	if !strings.Contains(schema[idx:idx+800], "expires_at") {
		t.Error("V10.4.8: auth.refresh_tokens has no expires_at column")
	}

	for _, column := range []string{"family_created_at", "family_expires_at", "absolute_expires_at"} {
		if strings.Contains(schema, column) {
			t.Fatalf("V10.4.8: %s now exists. AR-14 is closed: move the register row to Met and replace this test with an assertion that a family older than the cap is refused.", column)
		}
	}
}
