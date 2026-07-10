package kms

import (
	"bytes"
	"errors"
	"testing"
)

// testRoot returns a distinct 32-byte root seeded from b.
func testRoot(b byte) []byte {
	r := make([]byte, minRootBytes)
	for i := range r {
		r[i] = b + byte(i)
	}
	return r
}

func newService(t *testing.T, b byte) *Service {
	t.Helper()
	s, err := New(testRoot(b))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestNew_RejectsShortRoot(t *testing.T) {
	if _, err := New(make([]byte, minRootBytes-1)); err == nil {
		t.Fatal("expected error for short root, got nil")
	}
}

func TestWrapUnwrap_RoundTrip(t *testing.T) {
	s := newService(t, 0x11)
	root := []byte("this-is-a-32-byte-life42-datroot") // exactly 32 bytes
	env, err := s.Wrap("life42-root-kek", root)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	got, err := s.Unwrap("life42-root-kek", env)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, root) {
		t.Fatalf("round-trip mismatch: got %x want %x", got, root)
	}
	// The envelope must not contain the plaintext in the clear.
	if bytes.Contains(env, root) {
		t.Fatal("envelope leaks plaintext")
	}
}

// TestUnwrap_UniformFailure asserts that malformed, tampered, and wrong-KEK
// envelopes all fail with the SAME opaque ErrUnwrap — the oracle-resistance
// invariant. If any path returned a distinct error the endpoint could leak
// which check failed.
func TestUnwrap_UniformFailure(t *testing.T) {
	s := newService(t, 0x22)
	other := newService(t, 0x99) // different root => different KEKs

	root := []byte("another-32-byte-root-for-testing")
	env, err := s.Wrap("life42-root-kek", root)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	tampered := append([]byte(nil), env...)
	tampered[len(tampered)-1] ^= 0x01 // flip a ciphertext/tag bit

	cases := map[string]struct {
		svc *Service
		kid string
		env []byte
	}{
		"malformed_short": {s, "life42-root-kek", []byte{0x00, 0x01, 0x02}},
		"malformed_empty": {s, "life42-root-kek", nil},
		"empty_kid":       {s, "", env},
		"tampered":        {s, "life42-root-kek", tampered},
		"wrong_kid":       {s, "different-kid", env},
		"wrong_kek_root":  {other, "life42-root-kek", env},
	}

	for name, tc := range cases {
		_, err := tc.svc.Unwrap(tc.kid, tc.env)
		if !errors.Is(err, ErrUnwrap) {
			t.Errorf("%s: expected ErrUnwrap, got %v", name, err)
		}
	}
}
