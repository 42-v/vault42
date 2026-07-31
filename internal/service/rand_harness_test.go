package service

import (
	"crypto/rand"
	"io"
	"os"
	"sync/atomic"
	"testing"
)

// Several tests in this package drive an entropy failure by replacing
// crypto/rand.Reader, which is a package-level global.
//
// Doing that per test is a data race, and -race fails the package because of
// it. AuthService.Register returns as soon as the row is written and finishes
// the verification email in a goroutine (auth.go:325), and that goroutine
// reaches crypto/rand through RandomHex. A test that restored the global in
// t.Cleanup therefore wrote it while the still-running email goroutine was
// reading it. The same shape applies to any flow that hands work to a goroutine
// on its way out, so pinning it to one test would not have held for long.
//
// The global is written exactly once here, before m.Run starts any test, and
// tests swap the reader behind it with an atomic store instead. Reads and
// writes of the source are then both atomic and the race is gone, while every
// test keeps the entropy control it needs. It is never restored: the process is
// exiting, and a leaked goroutine reading it during shutdown would be the very
// race this removes.

type serviceRandSource struct{ reader io.Reader }

var serviceRandCurrent atomic.Pointer[serviceRandSource]

// serviceRandSwitch is what crypto/rand.Reader points at for the lifetime of
// the test binary. Every read goes through the atomically-swappable source.
type serviceRandSwitch struct{}

func (serviceRandSwitch) Read(p []byte) (int, error) {
	return serviceRandCurrent.Load().reader.Read(p)
}

var _ io.Reader = serviceRandSwitch{}

// serviceRandReal is the genuine entropy source, captured before it is replaced.
var serviceRandReal io.Reader

func TestMain(m *testing.M) {
	serviceRandReal = rand.Reader
	serviceRandCurrent.Store(&serviceRandSource{reader: serviceRandReal})
	rand.Reader = serviceRandSwitch{}
	os.Exit(m.Run())
}

// serviceRandUse installs r as the entropy source for the duration of the test
// and restores the real one afterwards. Both directions are atomic, so a
// goroutine still reading entropy when the test ends observes one source or the
// other and never a torn write.
func serviceRandUse(t *testing.T, r io.Reader) {
	t.Helper()
	serviceRandCurrent.Store(&serviceRandSource{reader: r})
	t.Cleanup(func() {
		serviceRandCurrent.Store(&serviceRandSource{reader: serviceRandReal})
	})
}
