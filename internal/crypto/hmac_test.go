package crypto

import "testing"

func TestHMACRoundTrip(t *testing.T) {
	key := []byte("secret-key")
	message := []byte("important message")

	sig := HMACSign(message, key)
	if sig == "" {
		t.Fatal("signature should not be empty")
	}

	if !HMACVerify(message, key, sig) {
		t.Error("valid signature should verify")
	}
}

func TestHMACWrongKey(t *testing.T) {
	key1 := []byte("key-one")
	key2 := []byte("key-two")
	message := []byte("message")

	sig := HMACSign(message, key1)
	if HMACVerify(message, key2, sig) {
		t.Error("wrong key should not verify")
	}
}

func TestHMACTamperedMessage(t *testing.T) {
	key := []byte("secret")
	sig := HMACSign([]byte("original"), key)
	if HMACVerify([]byte("tampered"), key, sig) {
		t.Error("tampered message should not verify")
	}
}

func TestHMACTamperedSignature(t *testing.T) {
	key := []byte("secret")
	message := []byte("message")
	HMACSign(message, key)
	if HMACVerify(message, key, "deadbeef") {
		t.Error("tampered signature should not verify")
	}
}
