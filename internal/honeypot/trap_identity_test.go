package honeypot

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// tiClaims decodes the payload of a minted trap token.
func tiClaims(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("trap token is not three segments: %q", token)
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

// tiHeader decodes the header of a minted trap token.
func tiHeader(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("trap token is not three segments: %q", token)
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

// sub is an account id: one address has one, for the life of the account, and
// it is jti that is fresh per token. Answering one trap credential with a
// different sub on each login says the issuer invented a new account between
// two consecutive requests, which no real deployment does. Two logins with the
// planted credential is the cheapest probe an attacker has, and the answer ends
// the deception: everything the honeypot exists to collect after that is an
// attacker who knows they are being watched.
func TestTwoTrapLoginsWithOneIdentityAnswerWithTheSameSubject(t *testing.T) {
	const identity = "admin@trap.example"

	first, err := GenerateFakeJWTForIdentity(TrapCaller{Identity: identity})
	if err != nil {
		t.Fatalf("first mint: %v", err)
	}
	second, err := GenerateFakeJWTForIdentity(TrapCaller{Identity: identity})
	if err != nil {
		t.Fatalf("second mint: %v", err)
	}

	firstSub, _ := tiClaims(t, first)["sub"].(string)
	secondSub, _ := tiClaims(t, second)["sub"].(string)

	if firstSub == "" {
		t.Fatal("a trap token carries no sub; a real access token always does")
	}
	if firstSub != secondSub {
		t.Errorf("two logins with %q were answered with different user ids: %q then %q", identity, firstSub, secondSub)
	}
}

// The address is matched case-insensitively before it ever reaches the mint, so
// the two spellings are one account everywhere else in the vault. A sub that
// changed with the capitalization of the address would let an attacker who
// already knows the trap address enumerate its accounts from one mailbox.
func TestTrapSubjectsIgnoreTheCaseOfTheIdentity(t *testing.T) {
	lower, err := GenerateFakeJWTForIdentity(TrapCaller{Identity: "admin@trap.example"})
	if err != nil {
		t.Fatalf("lower-case mint: %v", err)
	}
	upper, err := GenerateFakeJWTForIdentity(TrapCaller{Identity: "ADMIN@TRAP.EXAMPLE"})
	if err != nil {
		t.Fatalf("upper-case mint: %v", err)
	}

	if got, want := tiClaims(t, upper)["sub"], tiClaims(t, lower)["sub"]; got != want {
		t.Errorf("the same address in two spellings was answered with %v and %v", got, want)
	}
}

// Stability must not be bought with collision. Two planted addresses are two
// accounts, and a vault that answered both with one user id would be telling an
// attacker holding two trap credentials that neither address is real.
func TestTwoTrapIdentitiesAnswerWithDifferentSubjects(t *testing.T) {
	first, err := GenerateFakeJWTForIdentity(TrapCaller{Identity: "admin@trap.example"})
	if err != nil {
		t.Fatalf("first mint: %v", err)
	}
	second, err := GenerateFakeJWTForIdentity(TrapCaller{Identity: "root@trap.example"})
	if err != nil {
		t.Fatalf("second mint: %v", err)
	}

	firstSub, _ := tiClaims(t, first)["sub"].(string)
	secondSub, _ := tiClaims(t, second)["sub"].(string)
	if firstSub == secondSub {
		t.Errorf("two different trap addresses were answered with the same user id %q", firstSub)
	}
}

// jti is the claim that must be fresh. A trap token that reused it alongside a
// stable sub would be a token an attacker can replay-detect against itself, and
// a real vault mints a new one per issuance.
func TestTwoTrapLoginsWithOneIdentityCarryDifferentTokenIDs(t *testing.T) {
	const identity = "admin@trap.example"

	first, err := GenerateFakeJWTForIdentity(TrapCaller{Identity: identity})
	if err != nil {
		t.Fatalf("first mint: %v", err)
	}
	second, err := GenerateFakeJWTForIdentity(TrapCaller{Identity: identity})
	if err != nil {
		t.Fatalf("second mint: %v", err)
	}

	firstJTI, _ := tiClaims(t, first)["jti"].(string)
	secondJTI, _ := tiClaims(t, second)["jti"].(string)
	if firstJTI == "" {
		t.Fatal("a trap token carries no jti; a real access token always does")
	}
	if firstJTI == secondJTI {
		t.Errorf("two trap tokens share the token id %q", firstJTI)
	}
}

// A real token echoes the client_id the caller sent, and omits the claim
// entirely when they sent none. A trap token that always omits it answers a
// caller who sent one with a payload that is a member short of the real thing,
// which is a single base64 decode away from being read.
func TestATrapTokenEchoesTheClientIDTheCallerSent(t *testing.T) {
	token, err := GenerateFakeJWTForIdentity(TrapCaller{Identity: "admin@trap.example", ClientID: "acme-web"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if got := tiClaims(t, token)["client_id"]; got != "acme-web" {
		t.Errorf("trap token client_id = %v, want the client_id the caller sent", got)
	}

	anonymous, err := GenerateFakeJWTForIdentity(TrapCaller{Identity: "admin@trap.example"})
	if err != nil {
		t.Fatalf("mint without a client id: %v", err)
	}
	if _, present := tiClaims(t, anonymous)["client_id"]; present {
		t.Error("trap token carries client_id for a caller that sent none; a real token omits it")
	}
}

// The fingerprint claim is computed from the caller's IP, User-Agent and
// Accept-Language, so it moves when they do. A trap token carrying one value
// for every client the process ever answers tells an attacker who repeats a
// login from a second address that the issuer is not looking at the request at
// all.
func TestATrapTokenCarriesTheFingerprintOfTheCallerItAnswers(t *testing.T) {
	const fingerprint = "9f2c1e6b8a4d0f37c5b9e2a71d84f06c3ba5178e9d0c4f2b6a3e8710d5c9b4f21"

	token, err := GenerateFakeJWTForIdentity(TrapCaller{Identity: "admin@trap.example", Fingerprint: fingerprint})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if got := tiClaims(t, token)["fingerprint"]; got != fingerprint {
		t.Errorf("trap token fingerprint = %v, want the fingerprint computed for the request", got)
	}
}

// The trap serves GET /.well-known/jwks.json unauthenticated, so the key the
// trap token names has to be a key that document publishes and the signature
// has to verify under it. A kid that is absent from the JWKS costs one login
// plus one anonymous GET to spot; a signature that does not verify is spotted
// for free by any relying party the attacker feeds the token to.
func TestATrapTokenVerifiesUnderTheKeyTheHoneypotPublishes(t *testing.T) {
	const issuer = "https://vault.example.test"
	restore := currentFakeJWTConfig()
	storeFakeJWTConfig(fakeJWTConfig{issuer: issuer, audience: issuer, accessTTL: 15 * time.Minute})
	t.Cleanup(func() { storeFakeJWTConfig(restore) })

	publishedKID, publishedKey, err := TrapSigningKey()
	if err != nil {
		t.Fatalf("TrapSigningKey: %v", err)
	}

	token, err := GenerateFakeJWTForIdentity(TrapCaller{Identity: "admin@trap.example"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	tokenKID, _ := tiHeader(t, token)["kid"].(string)
	if tokenKID != publishedKID {
		t.Errorf("trap token names key %q, but the JWKS the trap serves publishes %q", tokenKID, publishedKID)
	}

	// The JWKS is what a relying party resolves the kid through, so verify the
	// way one does: look the header's kid up in the published set.
	published := map[string]*rsa.PublicKey{publishedKID: publishedKey}
	claims, err := vaultcrypto.ParseAndValidate(token, func(tok *vjwt.Token) (any, error) {
		kid, _ := tok.Header["kid"].(string)
		key, ok := published[kid]
		if !ok {
			return nil, errUnpublishedKID
		}
		return key, nil
	}, issuer, issuer)
	if err != nil {
		t.Fatalf("a trap token did not verify against the JWKS the trap publishes: %v", err)
	}
	if claims.Subject == "" {
		t.Error("the verified trap token carries no subject")
	}
}

// KIDFromPublicKey is what every key the keystore files is named by, and its
// output is 17 characters. A trap token naming a 36-character UUID is a tell
// that needs no comparison against anything: the shape alone is wrong, and
// vault42 is public source so the attacker knows the shape.
func TestTheTrapKeyIDHasTheShapeEveryRealKeyIDHas(t *testing.T) {
	kid, _, err := TrapSigningKey()
	if err != nil {
		t.Fatalf("TrapSigningKey: %v", err)
	}

	key, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("generate a comparison key: %v", err)
	}
	want := vaultcrypto.KIDFromPublicKey(&key.PublicKey)

	if len(kid) != len(want) {
		t.Errorf("the trap key id %q is %d characters, but every real key id is %d", kid, len(kid), len(want))
	}
	if strings.Count(kid, "-") != strings.Count(want, "-") {
		t.Errorf("the trap key id %q is not shaped like a real one (%q)", kid, want)
	}
}

// expires_in in the login body and exp inside the token are two statements of
// one lifetime. The trap read its exp from a hardcoded 15 minutes while the
// response carried the deployment's configured TTL, so the two agreed only on a
// deployment that never changed VAULT_ACCESS_TOKEN_TTL, and disagreed by a
// readable margin everywhere else.
func TestATrapTokenExpiresAfterTheConfiguredAccessTokenTTL(t *testing.T) {
	const configured = 42 * time.Minute
	restore := currentFakeJWTConfig()
	storeFakeJWTConfig(fakeJWTConfig{issuer: restore.issuer, audience: restore.audience, accessTTL: configured})
	t.Cleanup(func() { storeFakeJWTConfig(restore) })

	token, err := GenerateFakeJWTForIdentity(TrapCaller{Identity: "admin@trap.example"})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	claims := tiClaims(t, token)
	exp, expOK := claims["exp"].(float64)
	iat, iatOK := claims["iat"].(float64)
	if !expOK || !iatOK {
		t.Fatalf("trap token is missing exp or iat: %v", claims)
	}

	if got := time.Duration(exp-iat) * time.Second; got != configured {
		t.Errorf("the trap token lives %s, but the login body answers expires_in=%s", got, configured)
	}
}

// The lifetime published to a mint has to survive whatever startup hands it. A
// deployment that has not configured one yet must still mint against the
// default the response would quote, rather than a zero-length token that has
// already expired when the attacker receives it.
func TestConfiguringAZeroLifetimeKeepsTheDefaultRatherThanExpiringOnIssue(t *testing.T) {
	restore := currentFakeJWTConfig()
	configOnce = sync.Once{}
	t.Cleanup(func() {
		storeFakeJWTConfig(restore)
		configOnce = sync.Once{}
	})

	ConfigureFakeJWT("https://zero-ttl.invalid", "https://zero-ttl.invalid", 0)

	if got := currentFakeJWTConfig().accessTTL; got != defaultFakeAccessTTL {
		t.Errorf("an unset access TTL was published as %s, want the %s default", got, defaultFakeAccessTTL)
	}
}

// errUnpublishedKID marks a token naming a key the JWKS does not carry, which
// is what a relying party's key lookup answers with.
var errUnpublishedKID = Err("token names a key the JWKS does not publish")
