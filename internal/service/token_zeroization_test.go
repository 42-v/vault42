package service

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
	"time"
)

// TestZeroPrivateKeyLeavesTheKeyUsable records what the rotation wipe does and,
// more importantly, what it does not do.
//
// zeroPrivateKey clears the exported secret fields of an *rsa.PrivateKey: D,
// the primes, and the three CRT values. Reading that code it is natural to
// conclude the retired key is gone. It is not. Since Go 1.24 crypto/rsa builds
// an unexported representation of the key on first use and signs from that, so
// clearing the exported fields clears copies the signing path no longer
// consults. The retired key stays usable, and its secret components stay
// resident in memory somewhere userspace cannot reach.
//
// That is not a defect this package can fix, and the assertion below is
// deliberately the uncomfortable one: it asserts the key still signs. Written
// the other way round, as "D is zero, therefore the key is gone", the test
// passes for a reason that has nothing to do with the guarantee anyone cares
// about, and it would keep passing while advertising a control that does not
// exist. If a future toolchain does make the wipe effective, this test fails
// and someone gets to delete it along with the accepted risk it documents.
func TestZeroPrivateKeyLeavesTheKeyUsable(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("the payload does not matter, only that it is fixed"))

	before, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("signing before the wipe: %v", err)
	}

	zeroPrivateKey(key)

	// The exported fields really are cleared. This half of the behavior is what
	// makes the other half surprising.
	if key.D.Sign() != 0 {
		t.Error("zeroPrivateKey left the exported private exponent set")
	}
	for i, p := range key.Primes {
		if p.Sign() != 0 {
			t.Errorf("zeroPrivateKey left prime %d set", i)
		}
	}

	after, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("the wiped key stopped signing; the wipe has become effective "+
			"and docs/security.md AR-25 plus the comment on zeroPrivateKey now "+
			"understate the control: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the wiped key produced a different signature; signing has started " +
			"reading the cleared fields and the surrounding reasoning needs revisiting")
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], after); err != nil {
		t.Fatalf("signature from the wiped key did not verify: %v", err)
	}
}

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

		if _, err := svc.IssueChallengeToken(context.Background(), "user-1", "fp"); err != nil {
			t.Errorf("the first key handed to a signer did not take effect: %v", err)
		}
	})

	t.Run("the active key is dropped without a replacement", func(t *testing.T) {
		svc, active := newTestTokenService(t)

		svc.UpdateSigningKey(nil, "")

		if active.D.Sign() != 0 {
			t.Error("dropping the active key left its private exponent in memory")
		}
		if _, err := svc.IssueChallengeToken(context.Background(), "user-1", "fp"); err == nil {
			t.Error("a signer with no key issued a token; it must fail closed")
		}
	})

	t.Run("the retired key was never fully built", func(t *testing.T) {
		partial := &rsa.PrivateKey{PublicKey: key.PublicKey}
		svc := newSvc(partial, testKID1)

		svc.UpdateSigningKey(key, testKID2)

		if _, err := svc.IssueChallengeToken(context.Background(), "user-1", "fp"); err != nil {
			t.Errorf("issuance broke after retiring a partially built key: %v", err)
		}
	})
}
