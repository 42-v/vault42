package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// SHA256Hex returns the hex-encoded SHA-256 hash of the input string.
func SHA256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// SHA256Base64URL returns the base64url-encoded (no padding) SHA-256 hash of the input string.
// Used for DPoP access token hash (ath) per RFC 9449 §4.2.
func SHA256Base64URL(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// SHA256Bytes returns the raw SHA-256 hash of the input bytes.
func SHA256Bytes(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
