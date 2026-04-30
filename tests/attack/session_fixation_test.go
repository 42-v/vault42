package attack

import (
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// TestSessionFixation_TokensUniquePerUser verifies that access tokens signed
// for different users are cryptographically distinct and cannot be reused
// across user sessions.
func TestSessionFixation_TokensUniquePerUser(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	now := time.Now()

	users := []string{"alice", "bob", "charlie", "dave", "eve"}
	tokens := make(map[string]string)

	for _, user := range users {
		tokenStr, err := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
			RegisteredClaims: vjwt.RegisteredClaims{
				Subject:   user,
				Issuer:    "vault",
				Audience:  vjwt.ClaimStrings{"app"},
				ExpiresAt: vjwt.NewNumericDate(now.Add(15 * time.Minute)),
				IssuedAt:  vjwt.NewNumericDate(now),
			},
			Fingerprint: vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
				IP: "10.0.0.1", UserAgent: user + "-agent",
			}),
		}, key, kid)
		if err != nil {
			t.Fatalf("SignToken failed for %s: %v", user, err)
		}
		tokens[user] = tokenStr
	}

	// Every token must be unique
	seen := make(map[string]string)
	for user, tok := range tokens {
		if prev, dup := seen[tok]; dup {
			t.Fatalf("Token collision: %s and %s produced identical tokens", user, prev)
		}
		seen[tok] = user
	}
}

// TestSessionFixation_TokenBindsToSubject verifies that a token signed for
// user A carries user A's subject and cannot be misattributed.
func TestSessionFixation_TokenBindsToSubject(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	tokenStr, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "victim-user",
			Issuer:    "vault",
			Audience:  vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
		Roles: []string{"user"},
	}, key, kid)

	claims, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "vault", "app")
	if err != nil {
		t.Fatalf("ParseAndValidate failed: %v", err)
	}

	// An attacker who obtains this token cannot change the subject
	if claims.Subject != "victim-user" {
		t.Fatalf("Subject should be victim-user, got %q", claims.Subject)
	}
	// Roles are bound to the token
	if len(claims.Roles) != 1 || claims.Roles[0] != "user" {
		t.Fatalf("Roles should be [user], got %v", claims.Roles)
	}
}

// TestSessionFixation_FingerprintPreventsHijack verifies that tokens bound
// to a specific device fingerprint cannot be used from a different device.
func TestSessionFixation_FingerprintPreventsHijack(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	legitimateFP := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "192.168.1.100", UserAgent: "Chrome/120", AcceptLanguage: "en-US",
	})
	attackerFP := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP: "10.0.0.99", UserAgent: "Firefox/119", AcceptLanguage: "ru-RU",
	})

	tokenStr, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "vault",
			Audience:  vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
		Fingerprint: legitimateFP,
	}, key, kid)

	claims, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, "vault", "app")
	if err != nil {
		t.Fatalf("ParseAndValidate failed: %v", err)
	}

	// The fingerprint in the token must match the legitimate device
	if !vaultcrypto.CompareFingerprints(claims.Fingerprint, legitimateFP) {
		t.Fatal("Token fingerprint should match legitimate device")
	}

	// Attacker's fingerprint must NOT match
	if vaultcrypto.CompareFingerprints(claims.Fingerprint, attackerFP) {
		t.Fatal("Token fingerprint should NOT match attacker's device")
	}
}

// TestSessionFixation_RefreshTokensUnique verifies that each session gets a
// unique refresh token, preventing fixation via pre-generated tokens.
func TestSessionFixation_RefreshTokensUnique(t *testing.T) {
	tokens := make(map[string]bool)
	for i := 0; i < 500; i++ {
		tok, err := vaultcrypto.RandomHex(32)
		if err != nil {
			t.Fatalf("RandomHex failed at iteration %d: %v", i, err)
		}
		if tokens[tok] {
			t.Fatalf("Duplicate refresh token at iteration %d", i)
		}
		tokens[tok] = true
	}
}

// TestSessionFixation_TokenNotReusableAcrossIssuers verifies that a token
// issued by one server instance cannot be accepted by a differently-configured
// instance (different issuer).
func TestSessionFixation_TokenNotReusableAcrossIssuers(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	issuers := []struct {
		signIss    string
		verifyIss  string
		shouldFail bool
	}{
		{"vault-prod", "vault-staging", true},
		{"vault-v1", "vault-v2", true},
		{"https://auth.example.com", "https://auth.evil.com", true},
		{"vault-prod", "vault-prod", false},
	}

	for _, tc := range issuers {
		t.Run(tc.signIss+"->"+tc.verifyIss, func(t *testing.T) {
			tokenStr, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
				RegisteredClaims: vjwt.RegisteredClaims{
					Subject:   "user-123",
					Issuer:    tc.signIss,
					Audience:  vjwt.ClaimStrings{"app"},
					ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
					IssuedAt:  vjwt.NewNumericDate(time.Now()),
				},
			}, key, kid)

			_, err := vaultcrypto.ParseAndValidate(tokenStr, keyFunc, tc.verifyIss, "app")
			if tc.shouldFail && err == nil {
				t.Fatalf("Token from %q should be rejected by %q", tc.signIss, tc.verifyIss)
			}
			if !tc.shouldFail && err != nil {
				t.Fatalf("Token from %q should be accepted by %q: %v", tc.signIss, tc.verifyIss, err)
			}
		})
	}
}

// TestSessionFixation_RoleEscalationViaTokenReuse verifies that a low-privilege
// token cannot be confused with a high-privilege token for the same user.
func TestSessionFixation_RoleEscalationViaTokenReuse(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	keyFunc := func(t *vjwt.Token) (any, error) { return &key.PublicKey, nil }

	// Issue a low-privilege token
	lowPrivToken, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "vault",
			Audience:  vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
		Roles:  []string{"viewer"},
		Scopes: []string{"read"},
	}, key, kid)

	// Issue a high-privilege token
	highPrivToken, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "user-123",
			Issuer:    "vault",
			Audience:  vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
		Roles:  []string{"admin"},
		Scopes: []string{"read", "write", "delete"},
	}, key, kid)

	// Tokens must be different
	if lowPrivToken == highPrivToken {
		t.Fatal("Different-role tokens for same user should be distinct")
	}

	// Parse low-priv token and verify it doesn't have admin role
	lowClaims, _ := vaultcrypto.ParseAndValidate(lowPrivToken, keyFunc, "vault", "app")
	for _, role := range lowClaims.Roles {
		if role == "admin" {
			t.Fatal("Low-privilege token should not contain admin role")
		}
	}
	for _, scope := range lowClaims.Scopes {
		if scope == "delete" {
			t.Fatal("Low-privilege token should not contain delete scope")
		}
	}
}

// TestSessionHijack_DifferentKeyCannotForge verifies that an attacker with
// their own RSA key cannot forge tokens accepted by the server.
func TestSessionHijack_DifferentKeyCannotForge(t *testing.T) {
	serverKey, _ := vaultcrypto.GenerateRSAKeyPair()
	attackerKey, _ := vaultcrypto.GenerateRSAKeyPair()
	serverKID, _ := vaultcrypto.RandomUUID()

	serverKeyFunc := func(t *vjwt.Token) (any, error) {
		return &serverKey.PublicKey, nil
	}

	// Attacker signs a token with their own key but uses server's KID
	forgedToken, _ := vaultcrypto.SignToken(vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Subject:   "admin",
			Issuer:    "vault",
			Audience:  vjwt.ClaimStrings{"app"},
			ExpiresAt: vjwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  vjwt.NewNumericDate(time.Now()),
		},
		Roles: []string{"admin", "superadmin"},
	}, attackerKey, serverKID)

	// Server rejects the forged token because signature verification fails
	_, err := vaultcrypto.ParseAndValidate(forgedToken, serverKeyFunc, "vault", "app")
	if err == nil {
		t.Fatal("Forged token signed with attacker's key should be rejected by server")
	}
}
