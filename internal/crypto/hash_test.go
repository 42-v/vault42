package crypto

import "testing"

func TestSHA256Hex(t *testing.T) {
	// NIST test vector: SHA-256("abc")
	got := SHA256Hex("abc")
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Errorf("SHA256Hex(\"abc\") = %s, want %s", got, want)
	}
}

func TestSHA256Empty(t *testing.T) {
	// NIST: SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	got := SHA256Hex("")
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("SHA256Hex(\"\") = %s, want %s", got, want)
	}
}
