package keystore

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// errRotateEntropyExhausted is what the installed reader returns, so the
// assertion can follow the failure from the reader all the way to Rotate's
// caller. Matching on the message alone would also accept the unreachable
// database underneath, which is a different failure with the same shape.
var errRotateEntropyExhausted = errors.New("keystore test: entropy exhausted")

type rotateExhaustedReader struct{}

func (rotateExhaustedReader) Read([]byte) (int, error) { return 0, errRotateEntropyExhausted }

// Rotate is the operator's answer to a suspected key compromise, and the answer
// only works if a rotation that did not produce a key is reported as a failure.
// A Rotate that swallowed the generation error would carry a nil or half-built
// key into Import, and the operator would read "rotated" while the compromised
// key is still the one signing.
//
// crypto/rsa draws from the module's own DRBG and ignores the io.Reader it is
// handed unless GODEBUG=cryptocustomrand=1 is set; the standard library flips
// the same switch in its own tests (crypto/tls/handshake_test.go,
// crypto/internal/fips140only/fips140only_test.go). Without it
// GenerateRSAKeyPair would succeed whatever crypto/rand.Reader holds and this
// test would pass without ever reaching the branch it names.
func TestKeyStore_RotateFailsWhenTheKeyCannotBeGenerated(t *testing.T) {
	ks := deadKeyStore(t)

	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",cryptocustomrand=1")
	keystoreRandUse(t, rotateExhaustedReader{})

	kid, err := ks.Rotate(context.Background())
	if err == nil {
		t.Fatalf("Rotate reported success (kid %q) with no entropy to build a key from", kid)
	}
	if !errors.Is(err, errRotateEntropyExhausted) {
		t.Fatalf("err = %v, want the reader's own failure wrapped; the rotation either "+
			"generated a key from somewhere else or reported a different failure as the cause", err)
	}
	if !strings.Contains(err.Error(), "generate key") {
		t.Errorf("err = %v, want it to name the key generation step so an operator "+
			"can tell it apart from a failed write", err)
	}
	if kid != "" {
		t.Errorf("kid = %q, want empty: a kid names a key that was never built", kid)
	}
}
