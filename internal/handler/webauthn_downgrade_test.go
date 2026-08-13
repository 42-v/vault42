package handler

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// A FIDO2 key with a PIN reports UV=1 for every ceremony the PIN was entered
// for, and that bit is what makes theft of the key alone insufficient. The
// client picks whether to ask for the PIN, so an attacker holding the stolen
// key drives their own CTAP request with uv=false and gets a UP-only assertion
// over the challenge this server issued. If the server accepts it, the PIN
// protects nothing: password plus stolen key is the whole second factor.
func TestWebAuthnVerifyFinish_RefusesAnAssertionWithoutUserVerificationOnACredentialEnrolledWithIt(t *testing.T) {
	wan := newWanfidoWebAuthn(t)
	auth := newWanfidoAuthenticator(t, "pin-protected-key")
	sessions := newWanfidoSessionCache()

	existing := []*model.WebAuthnCredential{{
		ID: "cred-row-1", UserID: "user-1",
		CredentialID: auth.credID, PublicKey: auth.coseKey(),
		SignCount: 4, Flags: wanfidoFlagUP | wanfidoFlagUV,
	}}
	challenge := wanfidoLoginSession(t, wan, sessions, "user-1", existing)

	countWrites, flagWrites := 0, 0
	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) {
			return existing, nil
		},
		UpdateSignCountFn: func(context.Context, string, int) error { countWrites++; return nil },
		UpdateFlagsFn:     func(context.Context, string, int) error { flagWrites++; return nil },
	}

	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, nil, false)

	rec := httptest.NewRecorder()
	h.VerifyFinish(rec, setAuthContext(auth.assertionRequest(t, challenge, 9, wanfidoFlagUP, nil), "user-1"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "user_verification_required" {
		t.Errorf("error = %q, want user_verification_required", result["error"])
	}

	// The recorded UV bit is the only evidence the credential was ever
	// PIN-protected. Writing the UP-only flags back erases it, so a later
	// policy that reads the stored bit would find nothing to enforce on
	// exactly the credentials that were downgraded.
	if flagWrites != 0 {
		t.Errorf("flags written %d times; the recorded UserVerified bit was overwritten by a UP-only assertion", flagWrites)
	}
	if countWrites != 0 {
		t.Errorf("sign count written %d times; a refused assertion must not advance it", countWrites)
	}
}

// Security keys without a PIN, and every credential enrolled before the flags
// column existed, report UV=0 legitimately. Refusing those would lock their
// owners out of accounts that never had user verification to lose, so the gate
// must key off what was recorded for the credential and nothing else.
func TestWebAuthnVerifyFinish_AcceptsAnAssertionWithoutUserVerificationWhenNoneWasEnrolled(t *testing.T) {
	wan := newWanfidoWebAuthn(t)
	auth := newWanfidoAuthenticator(t, "pinless-key")
	sessions := newWanfidoSessionCache()

	existing := []*model.WebAuthnCredential{{
		ID: "cred-row-1", UserID: "user-1",
		CredentialID: auth.credID, PublicKey: auth.coseKey(),
		SignCount: 4, Flags: wanfidoFlagUP,
	}}
	challenge := wanfidoLoginSession(t, wan, sessions, "user-1", existing)

	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) {
			return existing, nil
		},
	}

	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, nil, false)

	rec := httptest.NewRecorder()
	h.VerifyFinish(rec, setAuthContext(auth.assertionRequest(t, challenge, 9, wanfidoFlagUP, nil), "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
}

// A credential ID is the lookup key for a public key. Registering one that is
// already on another account puts two rows with the same ID in the table, so
// any lookup that is not already scoped by user resolves to whichever row the
// database returns first. Nothing in the table stops it: there is no unique
// constraint, and attestation is "none", so the caller chooses the ID.
func TestWebAuthnRegisterFinish_RefusesACredentialIDAlreadyRegisteredToAnotherAccount(t *testing.T) {
	wan := newWanfidoWebAuthn(t)
	auth := newWanfidoAuthenticator(t, "victim-credential-id")
	sessions := newWanfidoSessionCache()
	challenge := wanfidoRegistrationSession(t, wan, sessions, "attacker-1")

	created := 0
	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) { return nil, nil },
		GetByCredentialIDFn: func(_ context.Context, credID []byte) (*model.WebAuthnCredential, error) {
			return &model.WebAuthnCredential{ID: "cred-row-victim", UserID: "victim-1", CredentialID: credID}, nil
		},
		CreateFn: func(context.Context, *model.WebAuthnCredential) error { created++; return nil },
	}

	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, nil, false)

	rec := httptest.NewRecorder()
	h.RegisterFinish(rec, setAuthContext(auth.attestationRequest(t, challenge, 1), "attacker-1"))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body: %s", rec.Code, rec.Body.String())
	}
	if created != 0 {
		t.Error("a credential ID already registered elsewhere was written to the table a second time")
	}
}

// The uniqueness lookup is the only thing standing between a caller-chosen
// credential ID and a duplicate row. If it cannot be answered, enrolling anyway
// is a decision to accept the duplicate, so the ceremony has to fail instead.
func TestWebAuthnRegisterFinish_RefusesToEnrollWhenTheCredentialIDLookupFails(t *testing.T) {
	wan := newWanfidoWebAuthn(t)
	auth := newWanfidoAuthenticator(t, "unverifiable-credential-id")
	sessions := newWanfidoSessionCache()
	challenge := wanfidoRegistrationSession(t, wan, sessions, "user-1")

	created := 0
	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) { return nil, nil },
		GetByCredentialIDFn: func(context.Context, []byte) (*model.WebAuthnCredential, error) {
			return nil, errors.New("db down")
		},
		CreateFn: func(context.Context, *model.WebAuthnCredential) error { created++; return nil },
	}

	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, nil, false)

	rec := httptest.NewRecorder()
	h.RegisterFinish(rec, setAuthContext(auth.attestationRequest(t, challenge, 1), "user-1"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
	if created != 0 {
		t.Error("a credential was enrolled without establishing that its ID was free")
	}
}

// excludeCredentials is what tells the authenticator it already holds a key for
// this account. Without it a second ceremony on the same authenticator silently
// replaces the resident credential, and the row naming the replaced credential
// ID stays in the table pointing at a key that no longer exists. The handler
// loads the credentials for this list, so the list has to reach the browser.
func TestWebAuthnRegisterBegin_ExcludesTheCredentialsAlreadyEnrolled(t *testing.T) {
	wan := newWanfidoWebAuthn(t)
	sessions := newWanfidoSessionCache()

	existing := []*model.WebAuthnCredential{
		{ID: "cred-row-1", UserID: "user-1", CredentialID: []byte("already-enrolled-a"), PublicKey: []byte("k1")},
		{ID: "cred-row-2", UserID: "user-1", CredentialID: []byte("already-enrolled-b"), PublicKey: []byte("k2")},
	}
	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) {
			return existing, nil
		},
	}

	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, nil, false)

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/webauthn/register/begin", nil)
	rec := httptest.NewRecorder()
	h.RegisterBegin(rec, setAuthContext(req, "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		PublicKey struct {
			ExcludeCredentials []struct {
				ID string `json:"id"`
			} `json:"excludeCredentials"`
		} `json:"publicKey"`
	}
	decodeResponse(t, rec, &body)

	got := map[string]bool{}
	for _, d := range body.PublicKey.ExcludeCredentials {
		raw, err := base64.RawURLEncoding.DecodeString(d.ID)
		if err != nil {
			t.Fatalf("excludeCredentials entry %q is not base64url: %v", d.ID, err)
		}
		got[string(raw)] = true
	}
	for _, c := range existing {
		if !got[string(c.CredentialID)] {
			t.Errorf("credential %q missing from excludeCredentials %v", c.CredentialID, got)
		}
	}
}
