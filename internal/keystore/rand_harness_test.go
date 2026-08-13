package keystore

import (
	"crypto/rand"
	"io"
	"os"
	"sync/atomic"
	"testing"
)

// Rotate's only failure ahead of the database is the key generation itself, and
// the single way to drive it is to hand crypto/rsa a reader that errors. That
// reader is crypto/rand.Reader, a process-wide global.
//
// Swapping a global inside one test and restoring it in t.Cleanup writes it
// while anything the package still has in flight can be reading it, and this
// package does keep work in flight past the end of the test that started it:
// KeyStore.StartRefreshLoop runs until Stop, and pgxpool holds a background
// health-check goroutine that dials on its own schedule, a dial that reaches
// crypto/rand for the SCRAM client nonce. A swap pinned to one test would hold
// only until one of those overlapped it, and -race would then fail the package
// on a test that has nothing to do with entropy.
//
// The global is written exactly once here, before m.Run starts any test, and
// tests swap the reader behind it with an atomic store instead. Reads and
// writes of the source are then both atomic and there is no race to have, while
// every test keeps the entropy control it needs. It is never restored: the
// process is exiting, and a leaked goroutine reading it during shutdown would
// be the very race this removes. internal/service/rand_harness_test.go carries
// the same construction for the same reason.

type keystoreRandSource struct{ reader io.Reader }

var keystoreRandCurrent atomic.Pointer[keystoreRandSource]

// keystoreRandSwitch is what crypto/rand.Reader points at for the lifetime of
// the test binary. Every read goes through the atomically swappable source.
type keystoreRandSwitch struct{}

func (keystoreRandSwitch) Read(p []byte) (int, error) {
	return keystoreRandCurrent.Load().reader.Read(p)
}

var _ io.Reader = keystoreRandSwitch{}

// keystoreRandReal is the genuine entropy source, captured before it is replaced.
var keystoreRandReal io.Reader

func TestMain(m *testing.M) {
	keystoreRandReal = rand.Reader
	keystoreRandCurrent.Store(&keystoreRandSource{reader: keystoreRandReal})
	rand.Reader = keystoreRandSwitch{}
	os.Exit(m.Run())
}

// keystoreRandUse installs r as the entropy source for the duration of the test
// and restores the real one afterwards. Both directions are atomic, so a
// goroutine still reading entropy when the test ends observes one source or the
// other and never a torn write.
func keystoreRandUse(t *testing.T, r io.Reader) {
	t.Helper()
	keystoreRandCurrent.Store(&keystoreRandSource{reader: r})
	t.Cleanup(func() {
		keystoreRandCurrent.Store(&keystoreRandSource{reader: keystoreRandReal})
	})
}
