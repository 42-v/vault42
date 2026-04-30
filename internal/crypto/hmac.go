package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// HMACSign computes HMAC-SHA256 of message with key, returns hex-encoded.
func HMACSign(message, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return hex.EncodeToString(mac.Sum(nil))
}

// HMACVerify checks that the hex-encoded signature matches the HMAC-SHA256
// of message with key. Uses constant-time comparison.
func HMACVerify(message, key []byte, signature string) bool {
	expected := HMACSign(message, key)
	return SecureCompare(expected, signature)
}
