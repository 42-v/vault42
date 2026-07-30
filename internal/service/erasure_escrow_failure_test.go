package service

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
)

// apUUIDStarvedReader serves real entropy for everything except the 16-byte read
// a UUID is made of. The escrow needs entropy twice, once to wrap the payload and
// once for the recovery record's ID, and only the second failure exercises the
// branch under test, so the discriminator is the request size rather than a call
// count that would drift with crypto internals.
type apUUIDStarvedReader struct{ real io.Reader }

func (r apUUIDStarvedReader) Read(p []byte) (int, error) {
	if len(p) == 16 {
		return 0, errors.New("entropy exhausted")
	}
	return r.real.Read(p)
}

// The escrow is what makes erasure recoverable, and it fails closed: no record,
// no deletion. That has to hold for every way the record can fail to be built,
// not just a rejected write. A recovery record with no ID is not a record, since
// the recovery tool addresses escrow rows by it, so a failure to mint one must stop
// the erasure before the user row is tombstoned, leaving a live, intact account
// that a retry can erase properly.
func TestDeleteAccount_RecoveryIDFailureFailsClosed(t *testing.T) {
	priv, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}

	m := newErasureMocks()
	appended := false
	m.recovery.AppendFn = func(context.Context, *model.AccountRecovery) error {
		appended = true
		return nil
	}
	scrubbed := false
	m.users.SoftDeleteScrubFn = func(context.Context, string, string) error {
		scrubbed = true
		return nil
	}
	mfaDestroyed := false
	m.totp.DeleteByUserIDFn = func(context.Context, string) error {
		mfaDestroyed = true
		return nil
	}

	svc := newErasureService(t, &priv.PublicKey, m)

	orig := rand.Reader
	rand.Reader = apUUIDStarvedReader{real: orig}
	t.Cleanup(func() { rand.Reader = orig })

	err = svc.DeleteAccount(context.Background(), "user-1", "self", "user_request")
	if err == nil {
		t.Fatal("DeleteAccount reported the account erased while the recovery record could not be identified")
	}
	if !strings.Contains(err.Error(), "recovery record id") {
		t.Errorf("err = %v, want it to name the recovery record ID step", err)
	}
	if appended {
		t.Error("a recovery record with no ID was written; the recovery tool addresses rows by it")
	}
	if scrubbed {
		t.Error("the user row was tombstoned despite the escrow failing, so the address is gone and nothing escrowed it")
	}
	if mfaDestroyed {
		t.Error("the PII cascade ran past a failed escrow")
	}
}

// The escrow payload carries the account's creation time. If it cannot be
// encoded there is nothing to encrypt, and the erasure must stop before the
// address is scrubbed: a tombstoned row with no recovery record is the one
// outcome the escrow exists to prevent.
func TestDeleteAccount_UnserializableEscrowPayloadFailsClosed(t *testing.T) {
	priv, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair: %v", err)
	}

	m := newErasureMocks()
	m.users.GetByIDFn = func(context.Context, string) (*model.User, error) {
		u := testErasureUser()
		// time.Time refuses to marshal a year outside [0,9999].
		u.CreatedAt = time.Date(-1, time.January, 1, 0, 0, 0, 0, time.UTC)
		return u, nil
	}
	appended := false
	m.recovery.AppendFn = func(context.Context, *model.AccountRecovery) error {
		appended = true
		return nil
	}
	scrubbed := false
	m.users.SoftDeleteScrubFn = func(context.Context, string, string) error {
		scrubbed = true
		return nil
	}

	svc := newErasureService(t, &priv.PublicKey, m)

	err = svc.DeleteAccount(context.Background(), "user-1", "self", "user_request")
	if err == nil {
		t.Fatal("DeleteAccount reported the account erased with no recoverable record")
	}
	if !strings.Contains(err.Error(), "marshal recovery payload") {
		t.Errorf("err = %v, want it to name the payload marshal", err)
	}
	if appended {
		t.Error("an escrow record was written from a payload that never serialized")
	}
	if scrubbed {
		t.Error("the address was scrubbed with nothing escrowed to recover it")
	}
}
