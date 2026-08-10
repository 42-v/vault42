package service

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

// The wipe runs on the way out of every rotation, so it meets whatever the
// keystore hands the signer, not only fully formed keys.
//
// Two of those shapes carry nothing to wipe. The first key a freshly built
// signer receives replaces a nil, and KeyStore.applyKeys deliberately hands the
// subscriber a nil key when the sole active key was revoked without a
// replacement, so issuance fails closed instead of minting tokens nobody can
// verify. A key restored field by field before Precompute ran has nil CRT
// values. A wipe that dereferenced any of them would turn a fail-closed key
// change into a process-wide panic on the next rotation, which is a far worse
// outcome than the one the nil key was chosen to produce.
func TestUpdateSigningKey_ToleratesKeysWithNothingToWipe(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	newSvc := func(k *rsa.PrivateKey, kid string) *TokenService {
		return NewTokenService(k, kid, "test-issuer", "test-audience",
			15*time.Minute, 7*24*time.Hour, 30*24*time.Hour)
	}

	t.Run("no key was held before", func(t *testing.T) {
		svc := newSvc(nil, "")

		svc.UpdateSigningKey(key, testKID1)

		if _, err := svc.IssueChallengeToken("user-1", "fp"); err != nil {
			t.Errorf("the first key handed to a signer did not take effect: %v", err)
		}
	})

	t.Run("the active key is dropped without a replacement", func(t *testing.T) {
		svc, active := newTestTokenService(t)

		svc.UpdateSigningKey(nil, "")

		if active.D.Sign() != 0 {
			t.Error("dropping the active key left its private exponent in memory")
		}
		if _, err := svc.IssueChallengeToken("user-1", "fp"); err == nil {
			t.Error("a signer with no key issued a token; it must fail closed")
		}
	})

	t.Run("the retired key was never fully built", func(t *testing.T) {
		partial := &rsa.PrivateKey{PublicKey: key.PublicKey}
		svc := newSvc(partial, testKID1)

		svc.UpdateSigningKey(key, testKID2)

		if _, err := svc.IssueChallengeToken("user-1", "fp"); err != nil {
			t.Errorf("issuance broke after retiring a partially built key: %v", err)
		}
	})
}
