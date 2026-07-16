package keystore

import (
	"context"
	"crypto/rsa"
	"sync"
	"testing"
	"time"
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

// TestKeyStore_StopWaitsForRefreshLoop verifies Stop() does not zero the master
// key until the refresh loop has exited. The loop's Refresh reads masterKey
// outside ks.mu, so zeroing it early is a data race on live key material.
// A long tick interval keeps Refresh (which needs a pool) from ever running;
// the loop exits via stopCh.
func TestKeyStore_StopWaitsForRefreshLoop(t *testing.T) {
	ks := &KeyStore{
		masterKey:  make([]byte, 32),
		publicKeys: make(map[string]*rsa.PublicKey),
		stopCh:     make(chan struct{}),
	}
	ks.StartRefreshLoop(context.Background(), time.Hour)

	done := make(chan struct{})
	go func() {
		ks.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not return: it never joined the refresh loop")
	}
}

// TestKeyStore_RefreshLoopExitsOnContextCancel verifies the refresh loop honors
// context cancellation, not just Stop(). stopCh is never closed here and the
// hour-long tick never fires, so the only way the WaitGroup can settle is the
// ctx.Done exit path.
func TestKeyStore_RefreshLoopExitsOnContextCancel(t *testing.T) {
	ks := &KeyStore{
		masterKey:  make([]byte, 32),
		publicKeys: make(map[string]*rsa.PublicKey),
		stopCh:     make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	ks.StartRefreshLoop(ctx, time.Hour)
	cancel()

	done := make(chan struct{})
	go func() {
		ks.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh loop did not exit on context cancellation")
	}
	ks.Stop()
}

// TestKeyStore_StopIsIdempotent verifies a second Stop() does not panic by
// re-closing stopCh. Shutdown paths call Stop from both a defer and an error
// branch, so a double call must be harmless.
func TestKeyStore_StopIsIdempotent(t *testing.T) {
	ks := &KeyStore{
		masterKey:  make([]byte, 32),
		publicKeys: make(map[string]*rsa.PublicKey),
		stopCh:     make(chan struct{}),
	}
	ks.Stop()
	ks.Stop()
}
