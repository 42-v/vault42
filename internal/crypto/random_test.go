package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestRandomBytes(t *testing.T) {
	b, err := RandomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 32 {
		t.Fatalf("got %d bytes, want 32", len(b))
	}

	// Two calls should produce different output
	b2, _ := RandomBytes(32)
	if bytes.Equal(b, b2) {
		t.Error("two random calls produced identical output")
	}
}

func TestRandomHex(t *testing.T) {
	h, err := RandomHex(16)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 32 { // 16 bytes = 32 hex chars
		t.Fatalf("got %d chars, want 32", len(h))
	}
}

func TestRandomUUID(t *testing.T) {
	u, err := RandomUUID()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(u, "-")
	if len(parts) != 5 {
		t.Fatalf("UUID should have 5 parts: %s", u)
	}
	// Version 4: third group starts with 4
	if parts[2][0] != '4' {
		t.Errorf("UUID version should be 4, got %c in %s", parts[2][0], u)
	}
}

func TestRandomToken(t *testing.T) {
	tok, err := RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 64 {
		t.Fatalf("token should be 64 hex chars, got %d", len(tok))
	}
}
