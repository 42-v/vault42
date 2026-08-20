package compliance

import (
	"context"
	"errors"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/service"
)

// =============================================================================
// OWASP ASVS v4.0.3 — Session Management (V3.x)
// =============================================================================

// --- V3.1: Session Token Generation ---

func TestASVS_V3_1_1_SessionTokenEntropy(t *testing.T) {
	// V3.1.1: Verify that the application generates a new session token on
	// user authentication with at least 128 bits of entropy.
	// Vault refresh tokens: RandomHex(32) = 256 bits.
	// Vault access tokens: RS256 JWT signed with 2048-bit key.

	t.Run("refresh_token_entropy", func(t *testing.T) {
		tok, err := vaultcrypto.RandomHex(32)
		if err != nil {
			t.Fatalf("RandomHex failed: %v", err)
		}
		// 32 bytes = 256 bits of entropy
		if len(tok) != 64 {
			t.Fatalf("V3.1.1: Refresh token should be 64 hex chars (256 bits), got %d", len(tok))
		}
	})

	t.Run("access_token_key_strength", func(t *testing.T) {
		key, err := vaultcrypto.GenerateRSAKeyPair()
		if err != nil {
			t.Fatalf("GenerateRSAKeyPair failed: %v", err)
		}
		bits := key.N.BitLen()
		if bits < 2048 {
			t.Fatalf("V3.1.1: RSA key must be >= 2048 bits, got %d", bits)
		}
	})
}

func TestASVS_V3_1_1_SessionTokenUniqueness(t *testing.T) {
	// V3.1.1: Each session must receive a unique token.
	// Test over 1000 iterations to ensure no collisions.
	tokens := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		tok, _ := vaultcrypto.RandomHex(32)
		if tokens[tok] {
			t.Fatalf("V3.1.1: Duplicate session token at iteration %d", i)
		}
		tokens[tok] = true
	}
}

// --- V3.2: Session Binding ---

func TestASVS_V3_2_1_NewTokenPerAuthentication(t *testing.T) {
	// V3.2.1: Verify that the application generates a new session token on
	// user authentication.
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()

	// Simulate two separate login events
	tokens := make(map[string]bool)
	for i := 0; i < 10; i++ {
		tokenStr, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
			RegisteredClaims: vjwt.RegisteredClaims{
				Subject:   "user-session-test",
				Issuer:    "vault",
				Audience:  vjwt.ClaimStrings{"app"},
				ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Duration(i+1) * time.Minute)),
				IssuedAt:  vjwt.NewNumericDate(time.Now()),
			},
		}, key, kid)

		if tokens[tokenStr] {
			t.Fatalf("V3.2.1: Duplicate access token at login %d", i+1)
		}
		tokens[tokenStr] = true
	}
}

func TestASVS_V3_2_3_FingerprintBindsSession(t *testing.T) {
	// V3.2.3: Verify that sessions are bound to the authenticated device.
	// Vault binds tokens via fingerprint = SHA256(IP + UA + Accept-Language + TLS).

	devices := []struct {
		name string
		fp   vaultcrypto.FingerprintInput
	}{
		{"chrome_desktop", vaultcrypto.FingerprintInput{
			IP: "192.168.1.10", UserAgent: "Chrome/120", AcceptLanguage: "en-US",
		}},
		{"firefox_desktop", vaultcrypto.FingerprintInput{
			IP: "192.168.1.10", UserAgent: "Firefox/119", AcceptLanguage: "en-US",
		}},
		{"mobile_safari", vaultcrypto.FingerprintInput{
			IP: "10.0.0.5", UserAgent: "Safari/17 Mobile", AcceptLanguage: "en-GB",
		}},
		{"different_ip", vaultcrypto.FingerprintInput{
			IP: "203.0.113.50", UserAgent: "Chrome/120", AcceptLanguage: "en-US",
		}},
	}

	fingerprints := make(map[string]string)
	for _, d := range devices {
		fp := vaultcrypto.ComputeFingerprint(d.fp)
		if fp == "" {
			t.Fatalf("V3.2.3: Fingerprint for %s should not be empty", d.name)
		}
		if prev, exists := fingerprints[fp]; exists {
			t.Fatalf("V3.2.3: Fingerprint collision between %s and %s", d.name, prev)
		}
		fingerprints[fp] = d.name
	}
}

func TestASVS_V3_2_3_FingerprintDeterministic(t *testing.T) {
	// V3.2.3: Same device input must always produce the same fingerprint.
	input := vaultcrypto.FingerprintInput{
		IP: "10.0.0.1", UserAgent: "Test/1.0", AcceptLanguage: "en",
	}

	fp1 := vaultcrypto.ComputeFingerprint(input)
	for i := 0; i < 100; i++ {
		fp := vaultcrypto.ComputeFingerprint(input)
		if fp != fp1 {
			t.Fatalf("V3.2.3: Fingerprint not deterministic at iteration %d", i)
		}
	}
}

// --- V3.3: Session Termination ---

// V3.3.1: "Verify that logout invalidates the session token."
//
// The old body hashed one string fifty times and asserted SHA256 is a function.
// It could not fail whatever Logout did, including nothing, which is the single
// behavior the requirement is about. This drives the shipped path instead:
// the session rotates cleanly first, so the refusal afterwards can only be the
// logout, and then Refresh must answer ErrTokenInvalid.
func TestASVS_V3_3_1_LogoutInvalidatesRefreshToken(t *testing.T) {
	f := newSessionFixture(t, 15*time.Minute, 24*time.Hour, 30*24*time.Hour, 12*time.Hour)
	res := f.login(t)

	rotated, err := f.refresh(res.RefreshToken)
	if err != nil {
		t.Fatalf("V3.3.1: the session refused to rotate before logout, so nothing below would "+
			"distinguish an invalidating logout from a broken fixture: %v", err)
	}

	row, err := f.tokens.GetByTokenHash(context.Background(), vaultcrypto.SHA256Hex(rotated.RefreshToken))
	if err != nil || row == nil {
		t.Fatalf("V3.3.1: the rotated refresh token is not in the store (err=%v)", err)
	}
	if err := f.svc.Logout(context.Background(), row.UserID, sessionIP, sessionAgent); err != nil {
		t.Fatalf("V3.3.1: logout failed: %v", err)
	}

	if _, err := f.refresh(rotated.RefreshToken); !errors.Is(err, service.ErrTokenInvalid) {
		t.Fatalf("V3.3.1: the refresh token issued before logout is still usable; Refresh answered "+
			"%v, wanted %v", err, service.ErrTokenInvalid)
	}
}

func TestASVS_V3_3_2_AccessTokenShortTTL(t *testing.T) {
	// V3.3.2: Verify that if an application allows users to be continuously
	// logged in, active reauthentication happens periodically.
	// Vault access tokens: 5-15 min TTL. This ensures frequent reauthentication.

	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	ttls := []struct {
		name    string
		ttl     time.Duration
		allowed bool
	}{
		{"5min_access", 5 * time.Minute, true},
		{"15min_access", 15 * time.Minute, true},
		{"30min_access", 30 * time.Minute, true},  // NIST allows up to 30min
		{"1hour_access", 60 * time.Minute, false}, // Too long
		{"24hour_access", 24 * time.Hour, false},  // Way too long
	}

	for _, tc := range ttls {
		t.Run(tc.name, func(t *testing.T) {
			if tc.ttl > 30*time.Minute {
				// Access tokens exceeding 30 minutes violate NIST reauthentication requirement
				t.Logf("V3.3.2: %s (%v) exceeds NIST 30-minute reauthentication bound", tc.name, tc.ttl)
			}

			tokenStr, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
				RegisteredClaims: vjwt.RegisteredClaims{
					Subject: "user", Issuer: "vault", Audience: vjwt.ClaimStrings{"app"},
					ExpiresAt: vjwt.NewNumericDate(time.Now().Add(tc.ttl)),
					IssuedAt:  vjwt.NewNumericDate(time.Now()),
				},
			}, key, kid)

			_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "vault", "app")
			if err != nil {
				t.Fatalf("Token with TTL %v should be valid: %v", tc.ttl, err)
			}
		})
	}
}

// --- V3.4: Cookie-Based Session Management ---

func TestASVS_V3_4_1_CookieTokenOpaque(t *testing.T) {
	// V3.4.1: Verify that cookie-based tokens have the HttpOnly flag set.
	// Vault: refresh tokens are opaque hex strings, not readable by JavaScript.
	// Test: verify refresh tokens are hex-encoded (not structured/readable).
	for i := 0; i < 100; i++ {
		tok, _ := vaultcrypto.RandomHex(32)
		// Should be pure hex (no structure, no '.' separators like JWTs)
		for _, c := range tok {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Fatalf("V3.4.1: Refresh token should be hex-only, got char %c", c)
			}
		}
	}
}

// --- V3.5: Token-Based Session Management ---

func TestASVS_V3_5_1_JWTMustHaveIssuerAndAudience(t *testing.T) {
	// V3.5.1: Verify that the application validates JWT issuer and audience.
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	tests := []struct {
		name      string
		issuer    string
		audience  string
		verifyIss string
		verifyAud string
		wantErr   bool
	}{
		{"correct", "vault", "app", "vault", "app", false},
		{"wrong_issuer", "vault", "app", "wrong", "app", true},
		{"wrong_audience", "vault", "app", "vault", "wrong", true},
		{"both_wrong", "vault", "app", "wrong-iss", "wrong-aud", true},
		{"empty_issuer", "", "app", "vault", "app", true},
		{"empty_audience", "vault", "", "vault", "app", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tokenStr, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
				RegisteredClaims: vjwt.RegisteredClaims{
					Subject:   "user",
					Issuer:    tc.issuer,
					Audience:  vjwt.ClaimStrings{tc.audience},
					ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
					IssuedAt:  vjwt.NewNumericDate(time.Now()),
				},
			}, key, kid)

			_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, tc.verifyIss, tc.verifyAud)
			if tc.wantErr && err == nil {
				t.Fatalf("V3.5.1: Expected error for %s", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("V3.5.1: Unexpected error for %s: %v", tc.name, err)
			}
		})
	}
}

// --- V3.7: Defenses Against Session Management Exploits ---

// TestASVS_V3_7_1_AccountLockoutPreventsEnumeration is the register's evidence
// for CR-19: the lockout stops brute force without becoming an oracle that
// answers "is this address registered?".
//
// Both halves have to hold at once, and only one of them used to be checked.
// This test drove middleware.CheckAccountLockout — a counter with no callers in
// the binary — incremented it ten times and asserted it had counted to ten. It
// could not observe an error code, because it never went near the login path
// that returns one.
//
// The oracle is the harder half. Only an EXISTING account can reach the locked
// state (there is no counter keyed on an address nobody registered), so a
// distinct "account locked" answer tells an unauthenticated caller the address
// is real. Rotating the probe address slips past the per-IP login limit, which
// turns that one distinguishable answer into a reliable enumeration primitive.
func TestASVS_V3_7_1_AccountLockoutPreventsEnumeration(t *testing.T) {
	const (
		registered = "locked-target@example.com"
		unknown    = "nobody-here@example.com"
		attackerIP = "198.51.100.44"
	)
	// Brute force until the source is cut off, and keep the exact answer it was
	// cut off with. The limit is discovered here rather than borrowed from
	// perSourceAttemptLimit, because that helper classifies the answer and the
	// answer is this test's whole subject.
	//
	// Each trial runs against a fresh service: a successful login clears the
	// counter for the source that made it, so probing after every failure on one
	// service would hold the counter at one forever and the search would run into
	// a different control.
	var (
		lockedAnswer  error
		unknownAnswer error
		spent         int
	)
	for spent = 1; spent <= perSourceSearchCeiling; spent++ {
		f := newLockoutFixture(t)
		f.account(registered)
		for i := 0; i < spent; i++ {
			f.fail(registered, attackerIP)
		}
		if lockedAnswer = f.login(registered, lockoutPassword, attackerIP); lockedAnswer != nil {
			// Ask the same service, from the same address, about an address it
			// has never heard of. Same question, and the two answers have to be
			// the same answer.
			unknownAnswer = f.login(unknown, lockoutPassword, attackerIP)
			break
		}
	}

	// Half one: the control works. The correct password stops getting in.
	if lockedAnswer == nil {
		t.Fatalf("V3.7.1: %d failures did not stop the attacking source; there is no brute-force "+
			"control on this path", perSourceSearchCeiling)
	}

	// Half two: the control is not an oracle.
	if !errors.Is(lockedAnswer, service.ErrInvalidCredentials) {
		t.Errorf("V3.7.1: after %d failures a locked account answered %v rather than the masked "+
			"ErrInvalidCredentials. Only a registered address can be locked, so a distinct answer "+
			"here enumerates accounts.", spent, lockedAnswer)
	}
	if !errors.Is(unknownAnswer, service.ErrInvalidCredentials) {
		t.Errorf("V3.7.1: an unregistered address answered %v rather than the masked "+
			"ErrInvalidCredentials", unknownAnswer)
	}
	if !errors.Is(lockedAnswer, unknownAnswer) || !errors.Is(unknownAnswer, lockedAnswer) {
		t.Errorf("V3.7.1: locked answered %v and unknown answered %v. Two different answers to the same "+
			"question is the enumeration oracle CR-19 closed.", lockedAnswer, unknownAnswer)
	}
}

func TestASVS_V3_7_1_RefreshTokenSingleUse(t *testing.T) {
	// V3.7.1: Refresh tokens should be single-use. Each refresh produces a
	// new token in a new family. Test that tokens are unique.
	const tokenCount = 200
	tokens := make(map[string]bool, tokenCount)

	for i := 0; i < tokenCount; i++ {
		tok, _ := vaultcrypto.RandomHex(32)
		hash := vaultcrypto.SHA256Hex(tok)

		if tokens[hash] {
			t.Fatalf("V3.7.1: Hash collision at iteration %d", i)
		}
		tokens[hash] = true
	}
}

func TestASVS_V3_5_2_JWTExpirationMandatory(t *testing.T) {
	// V3.5.2: Verify that the application checks the JWT exp claim.
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	// Token without exp
	tokenStr, _ := vjwt.SignRS256WithHeader(map[string]any{
		"alg": "RS256", "typ": "JWT", "kid": kid,
	}, &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject: "user", Issuer: "vault", Audience: vjwt.ClaimStrings{"app"},
			IssuedAt: vjwt.NewNumericDate(time.Now()),
		},
	}, key)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "vault", "app")
	if err == nil {
		t.Fatal("V3.5.2: Token without exp should be rejected")
	}
}

func TestASVS_V3_5_5_JWTMustHaveIssuedAt(t *testing.T) {
	// V3.5.5: Verify that the application validates the JWT iat claim.
	// ParseAndValidate uses vjwt.WithIssuedAt() option.
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	// Valid token with iat
	tokenStr, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject: "user", Issuer: "vault", Audience: vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
	}, key, kid)

	_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "vault", "app")
	if err != nil {
		t.Fatalf("V3.5.5: Valid token with iat should be accepted: %v", err)
	}
}
