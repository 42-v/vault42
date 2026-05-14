package keystore

import (
	"crypto/rsa"
	"testing"
	"time"
)

func TestNew_RejectsBadMasterKeyLen(t *testing.T) {
	if _, err := New(nil, []byte("too-short"), time.Hour); err == nil {
		t.Fatal("expected error for short master key")
	}
}

func TestNew_AcceptsValidMasterKey(t *testing.T) {
	ks, err := New(nil, make([]byte, 32), time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ks == nil {
		t.Fatal("got nil KeyStore")
	}
}

func TestSetOnKeyChange_StoresCallback(t *testing.T) {
	ks, _ := New(nil, make([]byte, 32), time.Hour)
	called := false
	ks.SetOnKeyChange(func(_ *rsa.PrivateKey, _ string, _ map[string]*rsa.PublicKey) {
		called = true
	})
	if ks.onKeyChange == nil {
		t.Fatal("onKeyChange was not stored")
	}
	ks.onKeyChange(nil, "", nil)
	if !called {
		t.Fatal("callback did not run")
	}
}

func TestKeyProvider_ReturnsAllPublicKeysFunc(t *testing.T) {
	ks, _ := New(nil, make([]byte, 32), time.Hour)
	fn := ks.KeyProvider()
	if fn == nil {
		t.Fatal("KeyProvider returned nil")
	}
	if got := fn(); len(got) != 0 {
		t.Fatalf("expected empty map from fresh keystore, got %d entries", len(got))
	}
}
