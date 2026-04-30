package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// FingerprintInput contains the components used to compute a device fingerprint.
type FingerprintInput struct {
	IP             string
	UserAgent      string
	AcceptLanguage string
	TLSFingerprint string
}

// ComputeFingerprint computes SHA256 over length-prefixed fields to prevent
// separator collision attacks (where a field containing the separator character
// could produce the same hash as a different combination of fields).
func ComputeFingerprint(input FingerprintInput) string {
	h := sha256.New()
	writeLengthPrefixed(h, input.IP)
	writeLengthPrefixed(h, input.UserAgent)
	writeLengthPrefixed(h, input.AcceptLanguage)
	writeLengthPrefixed(h, input.TLSFingerprint)
	return hex.EncodeToString(h.Sum(nil))
}

// writeLengthPrefixed writes a 4-byte big-endian length followed by the string data.
func writeLengthPrefixed(h interface{ Write([]byte) (int, error) }, s string) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s))) // #nosec G115 -- string length cannot exceed uint32 max
	// hash.Hash.Write is documented to never return an error.
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write([]byte(s))
}

// CompareFingerprints compares two fingerprints using constant-time comparison.
// Fingerprints are already lowercase hex from ComputeFingerprint, so no
// normalization is needed — SecureCompare handles the constant-time check.
func CompareFingerprints(a, b string) bool {
	return SecureCompare(a, b)
}
