package middleware

import (
	"strings"
	"testing"
)

// TestTheDPoPReplayKeyIsAFixedWidthWhateverTheJTI is the bound on the only cache
// key suffix in this service that an attacker picks.
//
// The jti comes out of a self-signed DPoP proof, so its content and its length
// are both chosen by whoever sends the request, up to the 4 KB proof cap.
// Concatenated raw, a multi-kilobyte jti becomes a multi-kilobyte cache key. On
// the Postgres backend that key is a TEXT PRIMARY KEY, and a btree index entry
// past roughly 2704 bytes is rejected, so SetIfNotExists returns an error rather
// than an answer. The DPoP middleware treats a cache error on a token that is
// not DPoP-bound as "log and allow", which turns the replay check into a
// formality for exactly the caller who oversized the jti on purpose.
func TestTheDPoPReplayKeyIsAFixedWidthWhateverTheJTI(t *testing.T) {
	const prefix = "dpop_jti:"

	// 64 hex characters of SHA-256, plus the prefix.
	const want = len(prefix) + 64

	for _, tc := range []struct {
		name string
		jti  string
	}{
		{"empty", ""},
		{"a normal uuid", "3f2504e0-4f89-11d3-9a0c-0305e82c3301"},
		{"one byte", "x"},
		{"four kilobytes, the proof cap", strings.Repeat("A", 4096)},
		{"past the postgres btree index limit", strings.Repeat("B", 3000)},
		{"newlines and colons that could shape a key", "a\nb:c\r\nd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := dpopReplayKey(tc.jti)

			if len(got) != want {
				t.Errorf("key is %d bytes for a %d-byte jti, want %d.\n"+
					"An attacker-sized key reaches the Postgres backend's TEXT PRIMARY KEY and "+
					"errors the replay check past the btree index limit, which the middleware "+
					"logs and allows for a token that is not DPoP-bound.",
					len(got), len(tc.jti), want)
			}
			if !strings.HasPrefix(got, prefix) {
				t.Errorf("key %q lost its namespace prefix", got)
			}
			if strings.ContainsAny(strings.TrimPrefix(got, prefix), ":\r\n") {
				t.Errorf("key %q carries a separator in its suffix, so a jti could shape the "+
					"keyspace rather than just occupy a slot in it", got)
			}
		})
	}
}

// TestTwoDifferentJTIsDoNotShareAReplayKey is the counterweight. A bound that
// collapsed distinct jtis into one key would pass the width test above and turn
// every second proof into a false replay rejection.
func TestTwoDifferentJTIsDoNotShareAReplayKey(t *testing.T) {
	a := dpopReplayKey("3f2504e0-4f89-11d3-9a0c-0305e82c3301")
	b := dpopReplayKey("3f2504e0-4f89-11d3-9a0c-0305e82c3302")

	if a == b {
		t.Fatalf("two jtis differing in the last character produced the same key %q; every "+
			"second proof would be refused as a replay", a)
	}
}
