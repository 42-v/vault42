package crypto

import "crypto/subtle"

// SecureCompare performs constant-time comparison of two strings.
// Returns true if they are equal. When lengths differ, burns constant time
// to avoid leaking length information, then returns false.
//
// Timing note: the early-return on length mismatch is not a practical timing
// concern for current callers, which always compare same-length values (hex-
// encoded hashes, HMAC signatures, UUIDs). The burn loop is a defense-in-depth
// measure in case a future caller compares variable-length inputs.
func SecureCompare(a, b string) bool {
	ab, bb := []byte(a), []byte(b)
	if len(ab) != len(bb) {
		// Burn constant time so the caller cannot distinguish length mismatch
		// from value mismatch via timing.
		subtle.ConstantTimeCompare(bb, bb)
		return false
	}
	return subtle.ConstantTimeCompare(ab, bb) == 1
}

// SecureCompareBytes performs constant-time comparison of two byte slices.
// When lengths differ, burns constant time to avoid leaking length information.
func SecureCompareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		subtle.ConstantTimeCompare(b, b)
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
