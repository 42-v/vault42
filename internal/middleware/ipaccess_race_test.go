package middleware

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
)

// The IP blocklist is the one access-control list in this package that changes
// while the server is serving. Everything else is written once by startup
// wiring and then only read; AddToIPBlocklist and RemoveFromIPBlocklist are
// reached from the admin surface during an incident, which is precisely the
// moment the request path is busiest.
//
// The list is published as an atomic pointer to a slice and mutated
// copy-on-write under ipBlockMu, and the whole safety argument rests on the
// copy never being visible before it is complete. That argument is easy to
// break by accident: appending into the live slice instead of into a copy, or
// storing the pointer before finishing the build, would both leave a reader
// holding a slice whose backing array is still being written. Such a reader
// misses a blocked CIDR, and missing a blocked CIDR means serving the address
// an operator just banned mid-attack.
//
// So the assertion here is not only "no race". It is that an address in the
// part of the list nobody is touching is refused on every single request while
// an unrelated CIDR is added and removed underneath. A torn publication shows
// up as one 200 among thousands of 403s, which a single-shot test would never
// catch.

const (
	// raceStableCIDR is never touched by the churn goroutines. Its whole job is
	// to stay blocked for the duration.
	raceStableCIDR = "203.0.113.0/24"
	raceStableIP   = "203.0.113.42"
	// raceChurnCIDR is added and removed continuously. It shares no address
	// space with the stable entry, so no interleaving of the churn can
	// legitimately change the verdict for raceStableIP.
	raceChurnCIDR = "192.0.2.0/24"
	// racePassIP is outside every configured list and must always be served.
	// Without it, a middleware that had regressed into denying everything would
	// satisfy the 403 assertion and pass.
	racePassIP = "10.11.12.13"
)

func TestIPBlocklist_MutationDoesNotDisturbConcurrentServing(t *testing.T) {
	// ClientIP only honors proxy headers when the peer is a trusted proxy, so
	// clearing the proxy list pins the client address to RemoteAddr.
	SetTrustedProxies(nil)
	resetIPAccess()
	SetIPAccessLists(nil, []string{raceStableCIDR}, nil, nil, "")
	t.Cleanup(func() {
		RemoveFromIPBlocklist(raceChurnCIDR)
		resetIPAccess()
	})

	// Every denial and every list mutation logs a line. At this request volume
	// that is tens of thousands of lines on stderr, which buries any real
	// failure output.
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	var served atomic.Int64
	handler := IPAccess()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served.Add(1)
		w.WriteHeader(http.StatusOK)
	}))

	const requestGoroutines = 16
	const roundsPerGoroutine = 400

	var readers, churners sync.WaitGroup
	start := make(chan struct{})
	stopChurn := make(chan struct{})

	for i := 0; i < requestGoroutines; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			<-start
			for n := 0; n < roundsPerGoroutine; n++ {
				if code := ipRaceRequest(handler, raceStableIP); code != http.StatusForbidden {
					t.Errorf("a stable blocklist entry let a request through: got %d, want 403 (round %d)", code, n)
					return
				}
				if code := ipRaceRequest(handler, racePassIP); code != http.StatusOK {
					t.Errorf("an address on no list was refused: got %d, want 200 (round %d)", code, n)
					return
				}
			}
		}()
	}

	// Two mutators, so the copy-on-write path is raced against itself as well as
	// against the readers.
	for i := 0; i < 2; i++ {
		churners.Add(1)
		go func() {
			defer churners.Done()
			<-start
			for {
				select {
				case <-stopChurn:
					return
				default:
				}
				AddToIPBlocklist(raceChurnCIDR)
				RemoveFromIPBlocklist(raceChurnCIDR)
			}
		}()
	}

	close(start)
	// The churn runs until the readers are finished, so the list is never
	// quiescent while a request is in flight.
	readers.Wait()
	close(stopChurn)
	churners.Wait()

	// The pass-through address is the control: if it were being denied too, the
	// 403 assertion above would be vacuous.
	if got := served.Load(); got == 0 {
		t.Error("no request ever reached the wrapped handler, so the 403 assertions prove nothing")
	}
}

// ipRaceRequest drives one request through the middleware from the given
// address and returns the status code.
func ipRaceRequest(h http.Handler, ip string) int {
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	req.RemoteAddr = ip + ":51000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}
