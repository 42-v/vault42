package keystore

import (
	"crypto/rsa"
	"sync"
	"testing"
)

// TestKeyStore_ConcurrentReadActiveKey verifies that concurrent reads of the
// active key are safe (no data race under -race detector).
func TestKeyStore_ConcurrentReadActiveKey(t *testing.T) {
	ks := &KeyStore{
		publicKeys: make(map[string]*rsa.PublicKey),
		stopCh:     make(chan struct{}),
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key, kid := ks.ActiveKey()
			_ = key
			_ = kid
		}()
	}
	wg.Wait()
}

// TestKeyStore_ConcurrentAllPublicKeys verifies that concurrent reads of all
// public keys return independent copies (no shared mutable state).
func TestKeyStore_ConcurrentAllPublicKeys(t *testing.T) {
	ks := &KeyStore{
		publicKeys: make(map[string]*rsa.PublicKey),
		stopCh:     make(chan struct{}),
	}

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keys := ks.AllPublicKeys()
			// Mutate the returned copy — should not affect internal state
			keys["injected-kid"] = nil
		}()
	}
	wg.Wait()

	// Internal state should not be modified
	ks.mu.RLock()
	if _, exists := ks.publicKeys["injected-kid"]; exists {
		t.Fatal("AllPublicKeys must return a copy, not the internal map")
	}
	ks.mu.RUnlock()
}

// TestKeyStore_StopZerosMasterKey verifies that Stop() zeros the master key.
func TestKeyStore_StopZerosMasterKey(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = 0xAB
	}

	ks := &KeyStore{
		masterKey:  masterKey,
		publicKeys: make(map[string]*rsa.PublicKey),
		stopCh:     make(chan struct{}),
	}

	ks.Stop()

	for i, b := range masterKey {
		if b != 0 {
			t.Fatalf("master key byte %d not zeroed: %02x", i, b)
		}
	}
}
