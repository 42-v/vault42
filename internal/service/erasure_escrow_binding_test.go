package service

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
)

// The escrow write path is where the binding is chosen, and it is the half of
// the fix nothing downstream can compensate for: if the service seals a blob to
// the wrong context, or seals a payload that does not name its subject, then
// cmd/recover either cannot open the record at all or opens it and still cannot
// say who it is about.
//
// These tests drive DeleteAccount and then attack the record it produced the way
// an attacker with write access to auth.account_recovery would.

// escrowOne runs one erasure with escrow enabled and returns the record the
// service appended together with the private key that can open it. The service
// itself is constructed with the public half only, which is the point of the
// scheme, so the test has to carry the other half.
func escrowOne(t *testing.T, userID string) (*model.AccountRecovery, *rsa.PrivateKey) {
	t.Helper()

	priv, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	m := newErasureMocks()
	m.users.GetByIDFn = func(context.Context, string) (*model.User, error) {
		u := testErasureUser()
		u.ID = userID
		u.Email = userID + "@example.invalid"
		return u, nil
	}
	var appended *model.AccountRecovery
	m.recovery.AppendFn = func(_ context.Context, rec *model.AccountRecovery) error {
		appended = rec
		return nil
	}

	svc := newErasureService(t, &priv.PublicKey, m)
	if err := svc.DeleteAccount(context.Background(), userID, "self", "user_request"); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}
	if appended == nil {
		t.Fatal("no recovery record was appended")
	}
	return appended, priv
}

// The attack the escrow was vulnerable to, run against the real write path: two
// erasures, then the payload columns swapped. Both records must become
// unreadable, because a payload that still opened would be reported by
// cmd/recover next to the other row's deleted_at, deleted_by and reason.
func TestDeleteAccount_EscrowPayloadDoesNotOpenUnderAnotherRow(t *testing.T) {
	priv, err := vaultcrypto.GenerateRSAKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	seal := func(userID string) *model.AccountRecovery {
		t.Helper()
		m := newErasureMocks()
		m.users.GetByIDFn = func(context.Context, string) (*model.User, error) {
			u := testErasureUser()
			u.ID = userID
			u.Email = userID + "@example.invalid"
			return u, nil
		}
		var appended *model.AccountRecovery
		m.recovery.AppendFn = func(_ context.Context, rec *model.AccountRecovery) error {
			appended = rec
			return nil
		}
		svc := newErasureService(t, &priv.PublicKey, m)
		if err := svc.DeleteAccount(context.Background(), userID, "self", "user_request"); err != nil {
			t.Fatalf("DeleteAccount(%s): %v", userID, err)
		}
		if appended == nil {
			t.Fatalf("no recovery record appended for %s", userID)
		}
		return appended
	}

	alice, bob := seal("user-alice"), seal("user-bob")

	// Sanity: each record opens under its own row, or the swap below proves
	// nothing.
	for _, rec := range []*model.AccountRecovery{alice, bob} {
		if _, err := vaultcrypto.DecryptRecovery(priv, rec.Payload,
			vaultcrypto.RecoveryBinding(rec.ID, rec.Pseudonym)); err != nil {
			t.Fatalf("a record does not open under its own row: %v", err)
		}
	}

	// The attack: the payload columns are exchanged and every other column stays
	// where it was. auth.account_recovery is append-only, but an attacker with
	// direct database access, or a bad restore that merged two backups, is
	// exactly the case the escrow is supposed to survive.
	swaps := map[string]struct {
		row     *model.AccountRecovery
		payload []byte
	}{
		"alice's row holding bob's payload": {alice, bob.Payload},
		"bob's row holding alice's payload": {bob, alice.Payload},
	}
	for name, swap := range swaps {
		plain, err := vaultcrypto.DecryptRecovery(priv, swap.payload,
			vaultcrypto.RecoveryBinding(swap.row.ID, swap.row.Pseudonym))
		if err == nil {
			t.Errorf("%s: the swapped payload decrypted, so the escrow can still be "+
				"misattributed: %q", name, plain)
		}
		if len(plain) != 0 {
			t.Errorf("%s: a refused swap still returned %d bytes", name, len(plain))
		}
	}

	// Two erasures of the same user produce two records, and those are not
	// interchangeable either: each is bound to its own row id, so a duplicate
	// from the interrupted-erasure retry path cannot be shuffled into the other
	// row and change what deleted_at says about it.
	if alice.Pseudonym == bob.Pseudonym {
		t.Fatal("the fixture used one subject for both records")
	}
	if alice.ID == bob.ID {
		t.Fatal("two escrow records share a primary key")
	}
}

// The recovered profile has to name its own subject. The escrow row identifies
// the subject only by HMAC pseudonym, which the offline tool cannot invert, so
// without this field a decrypted record is an email with no account to restore
// it to and no way to cross-check the row it came from.
func TestDeleteAccount_EscrowPayloadNamesItsSubject(t *testing.T) {
	rec, priv := escrowOne(t, "user-subject")

	plain, err := vaultcrypto.DecryptRecovery(priv, rec.Payload,
		vaultcrypto.RecoveryBinding(rec.ID, rec.Pseudonym))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	var got struct {
		Version int    `json:"v"`
		UserID  string `json:"user_id"`
		Email   string `json:"email"`
	}
	if err := json.Unmarshal(plain, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.UserID != "user-subject" {
		t.Errorf("payload user_id = %q, want the erased subject", got.UserID)
	}
	if got.Version != recoveryPayloadVersion {
		t.Errorf("payload version = %d, want %d", got.Version, recoveryPayloadVersion)
	}
	if got.Email != "user-subject@example.invalid" {
		t.Errorf("payload email = %q, want the real address", got.Email)
	}

	// The pseudonym in the row must be the HMAC of that same subject, or the
	// binding would tie the blob to a row that is about somebody else.
	if want := vaultcrypto.HMACSign([]byte("user-subject:recovery"), testHMAC); rec.Pseudonym != want {
		t.Errorf("row pseudonym = %q, want HMAC(user-subject:recovery)", rec.Pseudonym)
	}
}

// The plaintext user id must not reach the table. It is bound INTO the payload,
// which is encrypted to the offline key; putting it in a column would hand a
// compromised database the direct link between an erasure and the account it
// erased, which is the whole reason the row carries a pseudonym instead.
func TestDeleteAccount_EscrowRowLeaksNoPlaintextIdentity(t *testing.T) {
	rec, _ := escrowOne(t, "user-leak-canary")

	for _, field := range []struct{ name, value string }{
		{"pseudonym", rec.Pseudonym},
		{"deleted_by", rec.DeletedBy},
		{"reason", rec.Reason},
		{"id", rec.ID},
	} {
		if field.value == "user-leak-canary" {
			t.Errorf("the %s column carries the plaintext user id", field.name)
		}
	}
	for _, needle := range []string{"user-leak-canary", "@example.invalid"} {
		if bytes.Contains(rec.Payload, []byte(needle)) {
			t.Errorf("the encrypted payload contains %q in the clear", needle)
		}
	}
}
