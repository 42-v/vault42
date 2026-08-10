package keystore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"strings"
	"testing"
	"time"
)

// cryptoKeysBrokenRSAKey returns a key whose modulus and primes are intact --
// so the kid still derives and the public half still marshals -- but whose
// private exponent no longer matches. x509.MarshalPKCS8PrivateKey validates the
// key and refuses it. This is the shape of signing key material corrupted in
// memory: a bit flip, a partially zeroed buffer, a mismatched restore.
func cryptoKeysBrokenRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &rsa.PrivateKey{
		PublicKey: key.PublicKey,
		D:         new(big.Int).Add(key.D, big.NewInt(1)),
		Primes:    key.Primes,
	}
}

// Import must reject a key it cannot serialize before it touches the database.
// Persisting a half-marshaled or unusable key would put a row in
// auth.signing_keys that every pod then fails to load on refresh -- and if the
// row were written as the active key while the retire UPDATE had already run,
// the deployment would be left with no usable signing key at all.
func TestKeyStore_ImportRejectsUnmarshalableKey(t *testing.T) {
	// The pool is nil on purpose: reaching the database panics instead of
	// passing.
	ks, err := New(nil, make([]byte, 32), time.Hour)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	kid, err := ks.Import(context.Background(), cryptoKeysBrokenRSAKey(t))
	if err == nil {
		t.Fatal("Import reported success for a key that cannot be marshaled")
	}
	if !strings.Contains(err.Error(), "marshal private key") {
		t.Errorf("error = %q, want it to surface the private key marshal failure", err)
	}
	if kid != "" {
		t.Errorf("kid = %q, want empty: a caller would record a key that was never stored", kid)
	}
	if active, activeKID := ks.ActiveKey(); active != nil || activeKID != "" {
		t.Error("Import published an active key despite the marshal failure")
	}
}
