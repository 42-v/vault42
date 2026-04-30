package service

import (
	"crypto/sha1" // #nosec G505 -- HIBP API requires SHA-1 prefix (k-anonymity protocol)
	"crypto/subtle"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// HIBPClient checks passwords against the Have I Been Pwned database
// using k-anonymity (only the first 5 chars of the SHA-1 hash are sent).
type HIBPClient struct {
	client *http.Client
}

// NewHIBPClient creates a new HIBP client.
func NewHIBPClient() *HIBPClient {
	return &HIBPClient{
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

// IsBreached checks if a password appears in the HIBP database.
// Returns true if breached, false if clean or if HIBP is unreachable (fail open).
// SECURITY NOTE: Fail-open is a deliberate design choice — HIBP downtime should not
// block user registration. The risk (allowing a breached password during outage) is
// accepted as lower than the risk of blocking legitimate registrations.
func (h *HIBPClient) IsBreached(password string) bool {
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
