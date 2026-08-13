package honeypot_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/honeypot"
	"github.com/42-v/vault42/internal/service"
)

// The honeypot exists to be mistaken for the real vault. vault42 is public
// source, so an attacker knows exactly what a real access token looks like, and
// the bridge hands them a before-and-after sample anyway: it reroutes a caller
// mid-session, so the tokens they collected from the real instance are sitting
// next to the one the trap issues. Every claim the trap gets wrong is a free
// answer to "am I in a honeypot".
//
// These tests mint a real token through the production token service and
// compare it against a trap token, so they track the real claim set rather than
// a copy of it that can drift.

const (
	parityIssuer   = "https://vault.example.test"
	parityAudience = "https://vault.example.test"
	// parityKID is the shape internal/crypto.KIDFromPublicKey produces for every
	// key the keystore files.
	parityKID = "1a2b3c4d-5e6f7a8b"
	// paritySubject is a user id, which is a v4 UUID everywhere else in the vault.
	paritySubject = "6d1f0f4a-3d2e-4f7b-9c31-8b2a5f0e7d44"
	// parityFingerprint is what crypto.ComputeFingerprint returns: SHA-256 hex.
	parityFingerprint = "9f2c1e6b8a4d0f37c5b9e2a71d84f06c3ba5178e9d0c4f2b6a3e8710d5c9b4f21"
)

// realAccessToken mints an access token through the same TokenService call the
// password-login path makes, so the comparison below is against production
// output rather than against a hand-written expectation of it.
func realAccessToken(t *testing.T) string {
	t.Helper()

	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	svc := service.NewTokenService(
		key, parityKID, parityIssuer, parityAudience,
		15*time.Minute, 7*24*time.Hour, 30*24*time.Hour,
	)
	// The argument list is the one internal/service.Login uses for a successful
	// password login: default roles, read+write scopes, no client id, the
	// request fingerprint, a new family, no remember-me.
	pair, err := svc.IssueTokenPair(
		paritySubject, []string{"user"}, []string{"read", "write"},
		"", parityFingerprint, "", false,
	)
	if err != nil {
		t.Fatalf("issue real token pair: %v", err)
	}
	return pair.AccessToken
}

// claimOrder returns the payload's member names in the order they appear on the
// wire. Order is part of the comparison because a JSON object built from a map
// is emitted with its keys sorted, which no struct-built payload ever is: a
// trap token whose claims read aud, exp, iat, iss is distinguishable from a real
// one at a glance even when both carry the same names.
func claimOrder(t *testing.T, token string) []string {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not three segments: %q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	dec := json.NewDecoder(strings.NewReader(string(payload)))
	if _, err := dec.Token(); err != nil {
		t.Fatalf("read opening brace: %v", err)
	}
	var names []string
	depth := 0
	for dec.More() || depth > 0 {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("read payload token: %v", err)
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		case string:
			if depth == 0 {
				names = append(names, v)
				// Skip this member's value, however nested it is.
				val, err := dec.Token()
				if err != nil {
					t.Fatalf("read value of %q: %v", v, err)
				}
				if d, ok := val.(json.Delim); ok && (d == '{' || d == '[') {
					depth++
				}
			}
		}
	}
	return names
}

func decodeClaimMap(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not three segments: %q", token)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims
}

func decodeHeaderMap(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not three segments: %q", token)
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var h map[string]any
	if err := json.Unmarshal(header, &h); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	return h
}

// A trap token must carry the same claim names in the same order as a real one.
// If it does not, one base64 decode of the token the trap just handed over ends
// the deception: the attacker stops feeding the trap, and every observation the
// honeypot exists to collect is lost.
func TestTheFakeAccessTokenCarriesTheSameClaimsInTheSameOrderAsARealOne(t *testing.T) {
	honeypot.ConfigureFakeJWT(parityIssuer, parityAudience, 15*time.Minute)

	fake, err := honeypot.GenerateFakeJWT()
	if err != nil {
		t.Fatalf("GenerateFakeJWT: %v", err)
	}

	want := claimOrder(t, realAccessToken(t))
	got := claimOrder(t, fake)

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("trap token claims are\n  %v\nbut a real access token carries\n  %v", got, want)
	}
}

// aud is a JSON array on every token the vault signs, because ClaimStrings
// marshals as one. A trap token that spells it as a bare string is a one-request
// tell, and it is the kind an attacker's tooling reports for free: a JWT
// debugger renders the two differently.
func TestTheFakeAccessTokenEncodesAudienceAsAnArrayLikeARealOne(t *testing.T) {
	honeypot.ConfigureFakeJWT(parityIssuer, parityAudience, 15*time.Minute)

	fake, err := honeypot.GenerateFakeJWT()
	if err != nil {
		t.Fatalf("GenerateFakeJWT: %v", err)
	}

	realAud := decodeClaimMap(t, realAccessToken(t))["aud"]
	fakeAud := decodeClaimMap(t, fake)["aud"]

	realList, ok := realAud.([]any)
	if !ok {
		t.Fatalf("a real access token stopped encoding aud as an array (%T); this test compares the wrong thing now", realAud)
	}
	fakeList, ok := fakeAud.([]any)
	if !ok {
		t.Fatalf("trap token encodes aud as %T, but a real one encodes it as an array", fakeAud)
	}
	if len(fakeList) != len(realList) {
		t.Errorf("trap aud has %d members, a real one has %d", len(fakeList), len(realList))
	}
}

// Two logins a second apart must name the same signing key. A vault has one
// active key at a time and publishes it in its JWKS, so a kid that changes
// between two responses says the issuer is inventing key ids per token, which no
// real deployment does. Two requests with the same trap credential is the
// cheapest probe an attacker has.
func TestTwoFakeAccessTokensNameTheSameSigningKey(t *testing.T) {
	first, err := honeypot.GenerateFakeJWT()
	if err != nil {
		t.Fatalf("GenerateFakeJWT: %v", err)
	}
	second, err := honeypot.GenerateFakeJWT()
	if err != nil {
		t.Fatalf("GenerateFakeJWT: %v", err)
	}

	firstKID, _ := decodeHeaderMap(t, first)["kid"].(string)
	secondKID, _ := decodeHeaderMap(t, second)["kid"].(string)

	if firstKID == "" {
		t.Fatal("trap token header carries no kid; a real one always does")
	}
	if firstKID != secondKID {
		t.Errorf("two trap tokens name different signing keys: %q then %q", firstKID, secondKID)
	}
}
