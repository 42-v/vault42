package handler

import (
	"crypto/rand"
	"io"
	"os"
	"sync/atomic"
	"testing"
)

// Tests in this package drive entropy failures by replacing crypto/rand.Reader,
// which is a package-level global.
//
// Assigning to it from a test is a data race and -race fails the package for it:
// handlers hand work to goroutines on their way out (the login paths run through
// AuthService, whose Register finishes the verification email in a goroutine
// that reaches crypto/rand through RandomHex), so a test restoring the global in
// t.Cleanup writes it while a still-running goroutine reads it.
//
// The global is written exactly once here, before m.Run starts any test, and
// tests swap the reader behind it with an atomic store instead. Reads and writes
// of the source are then both atomic. It is never restored: the process is
// exiting, and a leaked goroutine reading it during shutdown would be the race
// this removes.

type handlerRandSource struct{ reader io.Reader }

var handlerRandCurrent atomic.Pointer[handlerRandSource]

// handlerRandSwitch is what crypto/rand.Reader points at for the lifetime of the
// test binary. Every read goes through the atomically-swappable source.
type handlerRandSwitch struct{}

func (handlerRandSwitch) Read(p []byte) (int, error) {
	return handlerRandCurrent.Load().reader.Read(p)
}

var _ io.Reader = handlerRandSwitch{}

// handlerRandReal is the genuine entropy source, captured before it is replaced.
var handlerRandReal io.Reader

// TestMain asserts nothing of its own by design: it is the package harness, and
// the result it reports is whatever m.Run made of the tests.
func TestMain(m *testing.M) {
	handlerRandReal = rand.Reader
	handlerRandCurrent.Store(&handlerRandSource{reader: handlerRandReal})
	rand.Reader = handlerRandSwitch{}
	os.Exit(m.Run())
}

// handlerRandUse installs r as the entropy source for the duration of the test
// and restores the real one afterwards. Both directions are atomic, so a
// goroutine still reading entropy when the test ends observes one source or the
// other and never a torn write.
func handlerRandUse(t *testing.T, r io.Reader) {
	t.Helper()
	handlerRandCurrent.Store(&handlerRandSource{reader: r})
	t.Cleanup(func() {
		handlerRandCurrent.Store(&handlerRandSource{reader: handlerRandReal})
	})
}
