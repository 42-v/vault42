package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

const (
	wanfidoFlagBE = 0x08
	wanfidoFlagBS = 0x10
)

// A synced passkey (iCloud Keychain, Google Password Manager, Windows Hello)
// asserts BackupEligible on every ceremony, and go-webauthn rejects a login
// whose BackupEligible flag disagrees with the stored credential record. If the
// flag is not persisted at registration the credential claims BE=0 forever, so
// enrolling one turns MFA on and then makes it impossible to satisfy: the user
// is locked out of their own account permanently.
func TestWebAuthnBackupEligiblePasskey_RegistersThenVerifies(t *testing.T) {
	wan := newWanfidoWebAuthn(t)
	auth := newWanfidoAuthenticator(t, "synced-passkey")
	sessions := newWanfidoSessionCache()

	var stored *model.WebAuthnCredential
	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) {
			if stored == nil {
				return nil, nil
			}
			return []*model.WebAuthnCredential{stored}, nil
		},
		CreateFn: func(_ context.Context, cred *model.WebAuthnCredential) error {
			stored = cred
			return nil
		},
		UpdateSignCountFn: func(_ context.Context, _ string, count int) error {
			stored.SignCount = count
			return nil
		},
		UpdateFlagsFn: func(_ context.Context, _ string, flags int) error {
			stored.Flags = flags
			return nil
		},
	}

	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, nil, false)

	regChallenge := wanfidoRegistrationSession(t, wan, sessions, "user-1")
	regFlags := byte(wanfidoFlagUP | wanfidoFlagUV | wanfidoFlagAT | wanfidoFlagBE | wanfidoFlagBS)

	rec := httptest.NewRecorder()
	h.RegisterFinish(rec, setAuthContext(auth.attestationRequestWithFlags(t, regChallenge, 1, regFlags), "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("register status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if stored == nil {
		t.Fatal("registration returned 200 without persisting a credential")
	}
	if stored.Flags&wanfidoFlagBE == 0 {
		t.Fatalf("stored flags = %#x, BackupEligible was not recorded", stored.Flags)
	}

	assertFlags := byte(wanfidoFlagUP | wanfidoFlagUV | wanfidoFlagBE | wanfidoFlagBS)
	loginChallenge := wanfidoLoginSession(t, wan, sessions, "user-1", []*model.WebAuthnCredential{stored})

	rec = httptest.NewRecorder()
	h.VerifyFinish(rec, setAuthContext(auth.assertionRequest(t, loginChallenge, 2, assertFlags, nil), "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if stored.Flags != int(assertFlags) {
		t.Errorf("stored flags = %#x, want the asserted %#x", stored.Flags, assertFlags)
	}
	if stored.SignCount != 2 {
		t.Errorf("stored sign count = %d, want the asserted 2", stored.SignCount)
	}
}

// Credentials enrolled before the flags column existed carry 0, which no
// genuine ceremony produces (user presence is mandatory, so bit 0 is always
// set). Treating that as "recorded as none" would lock out every passkey
// already in the database. The first assertion the signature check accepts
// supplies the real flags.
func TestWebAuthnVerifyFinish_AdoptsFlagsForCredentialWithNoneRecorded(t *testing.T) {
	wan := newWanfidoWebAuthn(t)
	auth := newWanfidoAuthenticator(t, "pre-migration-passkey")
	sessions := newWanfidoSessionCache()

	existing := []*model.WebAuthnCredential{
		{ID: "cred-row-1", UserID: "user-1", CredentialID: auth.credID, PublicKey: auth.coseKey(), SignCount: 3, Flags: 0},
	}
	challenge := wanfidoLoginSession(t, wan, sessions, "user-1", existing)

	var adoptedID string
	adopted := -1
	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) {
			return existing, nil
		},
		UpdateFlagsFn: func(_ context.Context, id string, flags int) error {
			adoptedID, adopted = id, flags
			return nil
		},
	}

	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, nil, false)

	assertFlags := byte(wanfidoFlagUP | wanfidoFlagUV | wanfidoFlagBE | wanfidoFlagBS)
	rec := httptest.NewRecorder()
	h.VerifyFinish(rec, setAuthContext(auth.assertionRequest(t, challenge, 4, assertFlags, nil), "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if adoptedID != "cred-row-1" {
		t.Errorf("adopted flags onto row %q, want cred-row-1", adoptedID)
	}
	if adopted != int(assertFlags) {
		t.Errorf("adopted flags = %#x, want the asserted %#x", adopted, assertFlags)
	}
}

// The flags write is part of the assertion result, not a best-effort extra. A
// silent failure leaves a stale BackupEligible value behind, which rejects the
// next login, so the caller has to learn that the ceremony did not complete.
func TestWebAuthnVerifyFinish_FlagsWriteFailureFailsVerification(t *testing.T) {
	wan := newWanfidoWebAuthn(t)
	auth := newWanfidoAuthenticator(t, "unwritable-flags")
	sessions := newWanfidoSessionCache()

	existing := []*model.WebAuthnCredential{
		{ID: "cred-row-1", UserID: "user-1", CredentialID: auth.credID, PublicKey: auth.coseKey(), SignCount: 1, Flags: 0},
	}
	challenge := wanfidoLoginSession(t, wan, sessions, "user-1", existing)

	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) {
			return existing, nil
		},
		UpdateFlagsFn: func(context.Context, string, int) error {
			return errors.New("db down")
		},
	}

	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, nil, false)

	rec := httptest.NewRecorder()
	h.VerifyFinish(rec, setAuthContext(auth.assertionRequest(t, challenge, 5, wanfidoFlagUP|wanfidoFlagUV, nil), "user-1"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "db down") {
		t.Error("storage error leaked to the client")
	}
}

// A user with several keys enrolled must have the state of the key that
// actually signed updated, not the first row that comes back from the database.
func TestWebAuthnVerifyFinish_UpdatesOnlyTheAssertingCredential(t *testing.T) {
	wan := newWanfidoWebAuthn(t)
	other := newWanfidoAuthenticator(t, "other-key")
	auth := newWanfidoAuthenticator(t, "asserting-key")
	sessions := newWanfidoSessionCache()

	existing := []*model.WebAuthnCredential{
		{ID: "cred-row-other", UserID: "user-1", CredentialID: other.credID, PublicKey: other.coseKey(), SignCount: 11, Flags: wanfidoFlagUP | wanfidoFlagUV},
		{ID: "cred-row-asserting", UserID: "user-1", CredentialID: auth.credID, PublicKey: auth.coseKey(), SignCount: 6, Flags: wanfidoFlagUP | wanfidoFlagUV | wanfidoFlagBE},
	}
	challenge := wanfidoLoginSession(t, wan, sessions, "user-1", existing)

	var countRows, flagRows []string
	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) {
			return existing, nil
		},
		UpdateSignCountFn: func(_ context.Context, id string, _ int) error {
			countRows = append(countRows, id)
			return nil
		},
		UpdateFlagsFn: func(_ context.Context, id string, _ int) error {
			flagRows = append(flagRows, id)
			return nil
		},
	}

	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, nil, false)

	assertFlags := byte(wanfidoFlagUP | wanfidoFlagUV | wanfidoFlagBE | wanfidoFlagBS)
	rec := httptest.NewRecorder()
	h.VerifyFinish(rec, setAuthContext(auth.assertionRequest(t, challenge, 7, assertFlags, nil), "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if len(countRows) != 1 || countRows[0] != "cred-row-asserting" {
		t.Errorf("sign count written to %v, want [cred-row-asserting]", countRows)
	}
	if len(flagRows) != 1 || flagRows[0] != "cred-row-asserting" {
		t.Errorf("flags written to %v, want [cred-row-asserting]", flagRows)
	}
}
