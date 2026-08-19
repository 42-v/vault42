package compliance

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/42-v/vault42/internal/cache"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// =============================================================================
// NIST SP 800-63B-4 WebAuthn / FIDO2 cryptographic authenticator (§3.1.6,
// §3.2.5, §3.2.8).
//
// The register previously proved all three of these rows with a single
// re-authentication test (TestNIST80053_IA_11_...), which never touches the
// WebAuthn code path. These tests drive the SHIPPED assertion verifier
// (internal/handler/webauthn.go VerifyFinish, which calls the real
// go-webauthn ValidateLogin configured exactly the way internal/server wires
// it) with a virtual authenticator that produces genuine ES256 assertions.
//
// A full attestation ceremony (registration) is not run: registration is not
// what these clauses turn on, and "none" attestation carries no signature to
// verify. Login verification is where the cryptographic, anti-phishing and
// intent properties are enforced, so login is what is exercised end to end.
// =============================================================================

const (
	webauthnRPID    = "vault42.test"
	webauthnOrigin  = "https://vault42.test"
	webauthnUserID  = "user-webauthn-0000-0000-000000000001"
	webauthnStoredN = uint32(5) // stored sign counter; a fresh assertion must exceed it
)

// authenticator flag bits (§6.1 of the WebAuthn spec).
const (
	flagUP byte = 0x01 // user present
	flagUV byte = 0x04 // user verified
)

// coseP256PublicKey encodes an ECDSA P-256 public key as the COSE_Key
// (webauthncose) structure the verifier parses out of the stored credential.
func coseP256PublicKey(t *testing.T, priv *ecdsa.PrivateKey) []byte {
	t.Helper()
	x := make([]byte, 32)
	y := make([]byte, 32)
	priv.X.FillBytes(x)
	priv.Y.FillBytes(y)
	key := struct {
		Kty int64  `cbor:"1,keyasint"`
		Alg int64  `cbor:"3,keyasint"`
		Crv int64  `cbor:"-1,keyasint"`
		X   []byte `cbor:"-2,keyasint"`
		Y   []byte `cbor:"-3,keyasint"`
	}{
		Kty: 2,  // EC2
		Alg: -7, // ES256
		Crv: 1,  // P-256
		X:   x,
		Y:   y,
	}
	b, err := webauthncbor.Marshal(key)
	if err != nil {
		t.Fatalf("marshal COSE public key: %v", err)
	}
	return b
}

// signAssertion builds a WebAuthn authentication assertion the way a real
// authenticator would: it assembles authenticatorData, hashes it together with
// the clientDataJSON, and signs the result with signKey. rpIDForHash and origin
// are separated so a test can bind the assertion to the wrong relying party or
// the wrong origin while keeping everything else valid.
func signAssertion(t *testing.T, signKey *ecdsa.PrivateKey, credID []byte, rpIDForHash, origin, challenge string, flags byte, counter uint32) []byte {
	t.Helper()

	clientData := map[string]any{
		"type":        "webauthn.get",
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	}
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		t.Fatalf("marshal clientDataJSON: %v", err)
	}

	rpIDHash := sha256.Sum256([]byte(rpIDForHash))
	authData := make([]byte, 0, 37)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flags)
	ctr := make([]byte, 4)
	binary.BigEndian.PutUint32(ctr, counter)
	authData = append(authData, ctr...)

	clientDataHash := sha256.Sum256(clientDataJSON)
	signed := make([]byte, 0, len(authData)+len(clientDataHash))
	signed = append(signed, authData...)
	signed = append(signed, clientDataHash[:]...)
	digest := sha256.Sum256(signed)

	sig, err := ecdsa.SignASN1(rand.Reader, signKey, digest[:])
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}

	enc := base64.RawURLEncoding.EncodeToString
	assertion := map[string]any{
		"id":    enc(credID),
		"rawId": enc(credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    enc(clientDataJSON),
			"authenticatorData": enc(authData),
			"signature":         enc(sig),
		},
	}
	body, err := json.Marshal(assertion)
	if err != nil {
		t.Fatalf("marshal assertion: %v", err)
	}
	return body
}

// webAuthnRP builds the relying party the vault42 way (RPID = origin host, a
// single allowed origin), matching internal/server.webAuthnConfig.
func webAuthnRP(t *testing.T) *webauthn.WebAuthn {
	t.Helper()
	ttl := handler.WebAuthnCeremonyTTL
	wan, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "vault42",
		RPID:          webauthnRPID,
		RPOrigins:     []string{webauthnOrigin},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: ttl, TimeoutUVD: ttl},
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: ttl, TimeoutUVD: ttl},
		},
	})
	if err != nil {
		t.Fatalf("build relying party: %v", err)
	}
	return wan
}

// webAuthnBeginChallenge starts a real login ceremony for a stored credential
// and returns the relying party, the serialized session data (what the handler
// reads back out of its cache), and the challenge the authenticator must sign.
func webAuthnBeginChallenge(t *testing.T, wan *webauthn.WebAuthn, storedPub []byte, storedFlag byte, credID []byte) (sessionJSON, challenge string) {
	t.Helper()
	cred := webauthn.Credential{
		ID:            credID,
		PublicKey:     storedPub,
		Flags:         webauthn.CredentialFlagsFromMsgpByte(storedFlag),
		Authenticator: webauthn.Authenticator{SignCount: webauthnStoredN},
	}
	u := &model.WebAuthnUser{
		User:        &model.User{ID: webauthnUserID, Email: "user@vault42.test"},
		Credentials: []webauthn.Credential{cred},
	}
	_, session, err := wan.BeginLogin(u)
	if err != nil {
		t.Fatalf("begin login: %v", err)
	}
	sj, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	return string(sj), session.Challenge
}

// webAuthnFinishResult carries what VerifyFinish did that a test asserts on.
type webAuthnFinishResult struct {
	rec              *httptest.ResponseRecorder
	signCountUpdated int // sign count written to the store, or -1 if never written
}

// webAuthnFinish drives the shipped VerifyFinish handler with a stored
// credential, the session begun above, and an assertion body.
func webAuthnFinish(t *testing.T, wan *webauthn.WebAuthn, sessionJSON string, storedPub []byte, storedFlag byte, credID, body []byte) webAuthnFinishResult {
	t.Helper()

	updated := -1
	storedCred := &model.WebAuthnCredential{
		ID:           "cred-row-1",
		UserID:       webauthnUserID,
		CredentialID: credID,
		PublicKey:    storedPub,
		SignCount:    int(webauthnStoredN),
		Flags:        int(storedFlag),
		CreatedAt:    time.Now(),
	}
	repo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(_ context.Context, _ string) ([]*model.WebAuthnCredential, error) {
			return []*model.WebAuthnCredential{storedCred}, nil
		},
		UpdateSignCountFn: func(_ context.Context, _ string, cnt int) error {
			updated = cnt
			return nil
		},
	}
	userRepo := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@vault42.test"}, nil
		},
	}
	mc := &mocks.MockCache{
		GetAndDeleteFn: func(_ context.Context, key string) (string, error) {
			if key == "webauthn_auth:"+webauthnUserID {
				return sessionJSON, nil
			}
			return "", cache.ErrNotFound
		},
	}

	h := handler.NewWebAuthnHandler(repo, userRepo, mc, wan, nil, false)
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/verify/finish", bytes.NewReader(body))
	claims := &vaultcrypto.VaultClaims{RegisteredClaims: vjwt.RegisteredClaims{Subject: webauthnUserID}}
	req = req.WithContext(context.WithValue(req.Context(), middleware.ClaimsKey, claims))
	rec := httptest.NewRecorder()
	h.VerifyFinish(rec, req)

	return webAuthnFinishResult{rec: rec, signCountUpdated: updated}
}

// newP256Key generates an authenticator key pair for a test.
func newP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	return priv
}

// TestNIST63B4_3_1_6_CryptographicAuthenticatorSignatureVerification proves the
// defining property of a multi-factor cryptographic authenticator (§3.1.6): the
// verifier accepts an assertion only when it carries a signature produced by the
// private key matching the credential's stored public key. A correctly signed
// assertion is accepted and advances the stored sign counter; an assertion
// signed by any other key over the same challenge is rejected.
//
// It does NOT run a registration/attestation ceremony; it exercises the login
// assertion path, which is where possession of the authenticator private key is
// proven.
func TestNIST63B4_3_1_6_CryptographicAuthenticatorSignatureVerification(t *testing.T) {
	authKey := newP256Key(t)
	pub := coseP256PublicKey(t, authKey)
	credID := []byte("credential-id-16")

	// Accepted: the genuine authenticator answers the challenge.
	t.Run("genuine_signature_accepted", func(t *testing.T) {
		wan := webAuthnRP(t)
		sessionJSON, challenge := webAuthnBeginChallenge(t, wan, pub, 0, credID)
		body := signAssertion(t, authKey, credID, webauthnRPID, webauthnOrigin, challenge, flagUP|flagUV, webauthnStoredN+1)

		res := webAuthnFinish(t, wan, sessionJSON, pub, 0, credID, body)
		if res.rec.Code != http.StatusOK {
			t.Fatalf("§3.1.6: genuine assertion rejected: status %d body %s", res.rec.Code, res.rec.Body.String())
		}
		if res.signCountUpdated != int(webauthnStoredN+1) {
			t.Fatalf("§3.1.6: sign counter not advanced to %d after a verified assertion (got %d)", webauthnStoredN+1, res.signCountUpdated)
		}
	})

	// Rejected: a different key signs the same challenge. Only the holder of the
	// enrolled private key can authenticate.
	t.Run("forged_signature_rejected", func(t *testing.T) {
		wan := webAuthnRP(t)
		sessionJSON, challenge := webAuthnBeginChallenge(t, wan, pub, 0, credID)
		attacker := newP256Key(t)
		body := signAssertion(t, attacker, credID, webauthnRPID, webauthnOrigin, challenge, flagUP|flagUV, webauthnStoredN+1)

		res := webAuthnFinish(t, wan, sessionJSON, pub, 0, credID, body)
		if res.rec.Code != http.StatusUnauthorized {
			t.Fatalf("§3.1.6: assertion signed by a non-enrolled key was not rejected: status %d body %s", res.rec.Code, res.rec.Body.String())
		}
		if res.signCountUpdated != -1 {
			t.Fatalf("§3.1.6: a rejected assertion still advanced the sign counter to %d", res.signCountUpdated)
		}
	})
}

// TestNIST63B4_3_2_5_VerifierImpersonationResistanceOriginBinding proves
// phishing resistance / verifier-impersonation resistance (§3.2.5): the
// assertion is cryptographically bound to the relying party. An otherwise valid,
// correctly signed assertion is refused when the client origin does not match
// the configured RP origin, and again when the authenticatorData is bound to a
// different RP ID. A phishing site on another origin therefore cannot relay an
// assertion, because the signed origin/RP-ID will not match this verifier.
func TestNIST63B4_3_2_5_VerifierImpersonationResistanceOriginBinding(t *testing.T) {
	authKey := newP256Key(t)
	pub := coseP256PublicKey(t, authKey)
	credID := []byte("credential-id-16")

	t.Run("mismatched_origin_rejected", func(t *testing.T) {
		wan := webAuthnRP(t)
		sessionJSON, challenge := webAuthnBeginChallenge(t, wan, pub, 0, credID)
		// Correct key, correct RP-ID hash, but the origin the user's browser saw
		// is the phishing site, not the relying party.
		body := signAssertion(t, authKey, credID, webauthnRPID, "https://phish.example", challenge, flagUP|flagUV, webauthnStoredN+1)

		res := webAuthnFinish(t, wan, sessionJSON, pub, 0, credID, body)
		if res.rec.Code != http.StatusUnauthorized {
			t.Fatalf("§3.2.5: assertion from a mismatched origin was accepted: status %d body %s", res.rec.Code, res.rec.Body.String())
		}
	})

	t.Run("mismatched_rp_id_rejected", func(t *testing.T) {
		wan := webAuthnRP(t)
		sessionJSON, challenge := webAuthnBeginChallenge(t, wan, pub, 0, credID)
		// Correct key and origin, but the authenticatorData is bound to a
		// different relying party.
		body := signAssertion(t, authKey, credID, "phish.example", webauthnOrigin, challenge, flagUP|flagUV, webauthnStoredN+1)

		res := webAuthnFinish(t, wan, sessionJSON, pub, 0, credID, body)
		if res.rec.Code != http.StatusUnauthorized {
			t.Fatalf("§3.2.5: assertion bound to a different RP ID was accepted: status %d body %s", res.rec.Code, res.rec.Body.String())
		}
	})
}

// TestNIST63B4_3_2_8_AuthenticationIntentUserPresenceAndVerification proves
// authentication intent (§3.2.8): each authentication requires an explicit user
// action at the authenticator, so malware cannot silently use the key. An
// assertion with the user-present bit clear is refused. Additionally, a
// credential enrolled with user verification cannot be downgraded to a
// presence-only assertion: the shipped userVerificationDowngraded gate refuses
// it before the sign counter is touched.
func TestNIST63B4_3_2_8_AuthenticationIntentUserPresenceAndVerification(t *testing.T) {
	authKey := newP256Key(t)
	pub := coseP256PublicKey(t, authKey)
	credID := []byte("credential-id-16")

	t.Run("absent_user_presence_rejected", func(t *testing.T) {
		wan := webAuthnRP(t)
		sessionJSON, challenge := webAuthnBeginChallenge(t, wan, pub, 0, credID)
		// Correctly signed, correct RP, but no user-present flag: no explicit
		// user action occurred at the authenticator.
		body := signAssertion(t, authKey, credID, webauthnRPID, webauthnOrigin, challenge, 0x00, webauthnStoredN+1)

		res := webAuthnFinish(t, wan, sessionJSON, pub, 0, credID, body)
		if res.rec.Code != http.StatusUnauthorized {
			t.Fatalf("§3.2.8: assertion with no user-presence flag was accepted: status %d body %s", res.rec.Code, res.rec.Body.String())
		}
		if res.signCountUpdated != -1 {
			t.Fatalf("§3.2.8: a presence-less assertion still advanced the sign counter to %d", res.signCountUpdated)
		}
	})

	t.Run("user_verification_downgrade_rejected", func(t *testing.T) {
		wan := webAuthnRP(t)
		// Credential enrolled as user-verifying (UP|UV recorded).
		storedFlag := flagUP | flagUV
		sessionJSON, challenge := webAuthnBeginChallenge(t, wan, pub, storedFlag, credID)
		// Genuine signature and user presence, but user verification is now
		// absent: an attacker who has the key but not the PIN/biometric.
		body := signAssertion(t, authKey, credID, webauthnRPID, webauthnOrigin, challenge, flagUP, webauthnStoredN+1)

		res := webAuthnFinish(t, wan, sessionJSON, pub, storedFlag, credID, body)
		if res.rec.Code != http.StatusUnauthorized {
			t.Fatalf("§3.2.8: user-verification downgrade was accepted: status %d body %s", res.rec.Code, res.rec.Body.String())
		}
		if res.signCountUpdated != -1 {
			t.Fatalf("§3.2.8: a downgraded assertion still advanced the sign counter to %d", res.signCountUpdated)
		}
	})
}
