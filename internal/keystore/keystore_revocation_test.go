package keystore

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"strings"
	"testing"
)

// Revoking the sole active key leaves the store with nothing to sign with.
// middleware.AuthDynamic drops that kid from the verification set the moment it
// is revoked, so a signer still holding it mints tokens that fail on arrival —
// a total token outage reported as success. The loss has to reach the
// subscriber as a nil key so issuance fails closed instead.
func TestApplyKeys_LosingTheActiveKeyPropagates(t *testing.T) {
	var logBuf keystoreLogBuffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(prev)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	ks := &KeyStore{
		activeKey:  key,
		activeKID:  "kid-doomed",
		publicKeys: map[string]*rsa.PublicKey{"kid-doomed": &key.PublicKey},
		stopCh:     make(chan struct{}),
	}

	calls := 0
	var gotKey *rsa.PrivateKey
	var gotKID string
	ks.SetOnKeyChange(func(k *rsa.PrivateKey, kid string, _ map[string]*rsa.PublicKey) {
		calls++
		gotKey, gotKID = k, kid
	})

	ks.applyKeys(nil, "", map[string]*rsa.PublicKey{})

	if calls != 1 {
		t.Fatalf("OnKeyChange fired %d times, want 1 — the signer keeps the revoked key otherwise", calls)
	}
	if gotKey != nil || gotKID != "" {
		t.Errorf("OnKeyChange got key=%v kid=%q, want a nil key and an empty kid", gotKey, gotKID)
	}
	if k, kid := ks.ActiveKey(); k != nil || kid != "" {
		t.Errorf("ActiveKey = (%v, %q), want no active key", k, kid)
	}
	if !strings.Contains(logBuf.String(), ErrNoActiveKey.Error()) {
		t.Errorf("log = %q, want it to report the missing active key", logBuf.String())
	}

	// Every subsequent refresh still finds nothing. The kid is unchanged, so it
	// must stay quiet rather than re-notify once a minute forever.
	ks.applyKeys(nil, "", map[string]*rsa.PublicKey{})
	if calls != 1 {
		t.Errorf("OnKeyChange fired %d times, want 1 — an unchanged kid must not re-notify", calls)
	}
}
