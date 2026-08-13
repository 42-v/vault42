package honeypot

import "errors"

// The trap login path lives in internal/service, which imports this package, so
// a test that drives a real Login cannot be written in package honeypot. It can
// be written in package honeypot_test, which sits in this directory and may
// import internal/service, but that package cannot reach the entropy source the
// failure branches hang off. These three seams bridge that gap.
//
// They are declared in a _test.go file, so they exist only in the test binary
// and add nothing to the built package: no production seam, no consumer in
// shipped code.

// StarveEntropyAfter replaces the package's CSPRNG with one that serves n real
// reads and then fails, and restores it when the returned function runs.
func StarveEntropyAfter(n int) func() {
	orig := randRead
	left := n
	randRead = func(b []byte) (int, error) {
		if left <= 0 {
			return 0, errors.New("entropy exhausted")
		}
		left--
		return orig(b)
	}
	return func() { randRead = orig }
}

// ResetTrapIdentitySalt clears the per-process salt so the next derivation has
// to draw one, which is what makes a starved read observable.
func ResetTrapIdentitySalt() {
	trapSaltMu.Lock()
	trapSalt = nil
	trapSaltMu.Unlock()
}

// PrimeTrapIdentity draws the signing key and the salt with real entropy, so a
// case that starves the CSPRNG afterwards is starving the read it names rather
// than one of these.
func PrimeTrapIdentity() error {
	if _, _, err := trapSigningKey(); err != nil {
		return err
	}
	_, err := trapIdentitySalt()
	return err
}
