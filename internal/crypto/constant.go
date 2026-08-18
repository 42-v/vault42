package crypto

import "crypto/subtle"

// SecureCompare performs constant-time comparison of two strings.
// Returns true if they are equal. When lengths differ, burns constant time
// to avoid leaking length information, then returns false.
//
// This is the only comparison helper this package exports. A byte-slice sibling,
// SecureCompareBytes, sat beside it with no caller outside tests while the three
// production sites that do compare byte slices constant-time -- the Argon2id
// verify in argon2.go, the HIBP suffix match, and the bridge admin token --
// each call subtle.ConstantTimeCompare directly.
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
