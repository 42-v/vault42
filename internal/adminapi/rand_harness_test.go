package adminapi

import (
	crand "crypto/rand"
	"io"
	"os"
	"sync/atomic"
	"testing"
)

// Several tests in this package drive entropy behaviour by replacing
// crypto/rand.Reader, which is a package-level global.
//
// Doing that per test is a data race and -race fails the package because of it.
// Gateway flows hand work to goroutines that outlive the response, and those
// goroutines reach crypto/rand, so a test that restored the global in
// t.Cleanup wrote it while a still-running goroutine was reading it.
//
// The global is written exactly once here, before m.Run starts any test, and
// tests swap the reader behind it with an atomic store instead. Reads and
// writes of the source are then both atomic and the race is gone, while every
// test keeps the entropy control it needs. It is never restored: the process is
// exiting, and a leaked goroutine reading it during shutdown would be the very
// race this removes.

type adminapiRandSource struct{ reader io.Reader }

var adminapiRandCurrent atomic.Pointer[adminapiRandSource]

// adminapiRandSwitch is what crypto/rand.Reader points at for the lifetime of
// the test binary. Every read goes through the atomically-swappable source.
type adminapiRandSwitch struct{}

func (adminapiRandSwitch) Read(p []byte) (int, error) {
	return adminapiRandCurrent.Load().reader.Read(p)
}

var _ io.Reader = adminapiRandSwitch{}

// adminapiRandReal is the genuine entropy source, captured before it is replaced.
var adminapiRandReal io.Reader

func TestMain(m *testing.M) {
	adminapiRandReal = crand.Reader
	adminapiRandCurrent.Store(&adminapiRandSource{reader: adminapiRandReal})
	crand.Reader = adminapiRandSwitch{}
	os.Exit(m.Run())
}

// adminapiRandUse installs r as the entropy source for the duration of the test
// and restores the real one afterwards. Both directions are atomic, so a
// goroutine still reading entropy when the test ends observes one source or the
// other and never a torn write.
func adminapiRandUse(t *testing.T, r io.Reader) {
	t.Helper()
	adminapiRandCurrent.Store(&adminapiRandSource{reader: r})
	t.Cleanup(func() {
		adminapiRandCurrent.Store(&adminapiRandSource{reader: adminapiRandReal})
	})
}
