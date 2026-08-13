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

// TestWrap_EmptyKid asserts Wrap rejects an empty kid before any key
// derivation: the kid is both the HKDF info suffix and the GCM AAD, so an
// empty kid would collapse domain separation between wrapped artifacts.
func TestWrap_EmptyKid(t *testing.T) {
	s := newService(t, 0x33)
	env, err := s.Wrap("", []byte("payload"))
	if env != nil {
		t.Fatalf("Wrap with empty kid returned an envelope: %x", env)
	}
	if err == nil || err.Error() != "kms: empty kid" {
		t.Fatalf("Wrap with empty kid: err = %v, want %q", err, "kms: empty kid")
	}
}

func TestClose_WipesRoot(t *testing.T) {
	root := make([]byte, 32)
	for i := range root {
		root[i] = 0x5a
	}
	svc, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	live, err := svc.Wrap("kid", []byte("x"))
	if err != nil {
		t.Fatalf("Wrap before Close: %v", err)
	}

	// Close must zero the service's internal copy of the root secret.
	svc.Close()

	// A wrap after Close must FAIL, and the reason is not tidiness. A wiped root
	// is 32 zero bytes, which HKDF accepts, so the old behavior was to keep
	// producing envelopes that looked correct and were sealed under a key anyone
	// can reconstruct by building a Service over 32 zeros. Returning an envelope
	// here is worse than returning nothing.
	if _, err := svc.Wrap("kid", []byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Wrap after Close returned err=%v; a closed service must not seal anything", err)
	}
	// Unwrap collapses it into ErrUnwrap so the oracle property is preserved.
	if _, err := svc.Unwrap("kid", live); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("Unwrap after Close returned err=%v, want ErrUnwrap", err)
	}
	// Close is called from more than one shutdown defer, so it must be idempotent.
	svc.Close()
}
