package service

import (
	"crypto/sha1" // #nosec G505 -- HIBP API requires SHA-1 prefix (k-anonymity protocol)
	"crypto/subtle"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// hibpMaxConcurrent caps in-flight calls to the HIBP API.
//
// Register is 3/hour/IP, so one address is harmless; a thousand addresses
// registering at once opened a thousand five-second sockets, because the check
// runs before the email-taken test and nothing counted the calls. The check is
// already fail-open by design (hibp downtime must not block registration), so
// shedding at the cap costs exactly what an HIBP outage costs — and says so in
// the counter rather than in a goroutine profile.
const hibpMaxConcurrent = 4

// hibpAcquireTimeout is how long a caller waits for a slot before giving up and
// failing open. Short: the caller is holding a registration request, and the
// point of the semaphore is to stop the sockets piling up, not to queue them
// somewhere else.
const hibpAcquireTimeout = 500 * time.Millisecond

// HIBPClient checks passwords against the Have I Been Pwned database
// using k-anonymity (only the first 5 chars of the SHA-1 hash are sent).
type HIBPClient struct {
	client *http.Client
	sem    chan struct{}
	// shed counts checks that failed open because every slot was busy. Each one
	// is a breached password that was accepted, so it is a number an operator
	// has to be able to read, not a log line.
	shed atomic.Uint64
}

// NewHIBPClient creates a new HIBP client.
func NewHIBPClient() *HIBPClient {
	return &HIBPClient{
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
				MaxConnsPerHost:       hibpMaxConcurrent,
				MaxIdleConns:          hibpMaxConcurrent,
				MaxIdleConnsPerHost:   hibpMaxConcurrent,
				IdleConnTimeout:       90 * time.Second,
				ResponseHeaderTimeout: 5 * time.Second,
				TLSHandshakeTimeout:   3 * time.Second,
				ExpectContinueTimeout: time.Second,
				ForceAttemptHTTP2:     true,
			},
		},
		sem: make(chan struct{}, hibpMaxConcurrent),
	}
}

// ShedCount reports checks that failed open because the concurrency cap was
// full.
func (h *HIBPClient) ShedCount() uint64 { return h.shed.Load() }

// acquire takes a slot, reporting false when the wait expired. A false is the
// same answer an HIBP outage gives: fail open.
func (h *HIBPClient) acquire() bool {
	t := time.NewTimer(hibpAcquireTimeout)
	defer t.Stop()
	select {
	case h.sem <- struct{}{}:
		return true
	case <-t.C:
		n := h.shed.Add(1)
		log.Printf("hibp: concurrency cap reached, check skipped (fail-open); total skipped: %d", n)
		return false
	}
}

func (h *HIBPClient) release() { <-h.sem }

// IsBreached checks if a password appears in the HIBP database.
// Returns true if breached, false if clean or if HIBP is unreachable (fail open).
// SECURITY NOTE: Fail-open is a deliberate design choice — HIBP downtime should not
// block user registration. The risk (allowing a breached password during outage) is
// accepted as lower than the risk of blocking legitimate registrations.
func (h *HIBPClient) IsBreached(password string) bool {
	if h.sem != nil {
		if !h.acquire() {
			return false // fail open — same answer an HIBP outage gives
		}
		defer h.release()
	}

	hash := fmt.Sprintf("%X", sha1.Sum([]byte(password))) // #nosec G401 -- HIBP API mandates SHA-1 (k-anonymity protocol)
	prefix := hash[:5]
	suffix := hash[5:]

	resp, err := h.client.Get("https://api.pwnedpasswords.com/range/" + prefix) // #nosec G107 -- URL is constructed from a constant base + computed SHA-1 prefix (5 hex chars only)
	if err != nil {
		log.Printf("hibp: API request failed (fail-open): %v", err)
		return false // fail open — HIBP down doesn't block registration
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("hibp: API returned status %d (fail-open)", resp.StatusCode)
		return false // fail open
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return false
	}

	suffixUpper := strings.ToUpper(suffix)
	for _, line := range strings.Split(string(body), "\r\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 && subtle.ConstantTimeCompare([]byte(strings.ToUpper(parts[0])), []byte(suffixUpper)) == 1 {
			return true
		}
	}
	return false
}
