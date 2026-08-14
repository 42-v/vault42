// Package ipintel is vault42's IP-intelligence layer. It answers a small,
// notify-only question about a client address: which country registered it,
// and does it look like anonymising or hosting infrastructure.
//
// The data is a compact, sorted range table built offline by
// scripts/gen-ipintel.py from public sources (the five RIR extended delegation
// files for country, published cloud/hosting prefix lists for the hosting flag,
// and the Tor bulk exit list for the tor flag) and embedded via go:embed so the
// package is self-contained in the CGO_ENABLED=0 static binary.
//
// # Fail-open contract
//
// Lookup never returns an error and never blocks a request on its own. An
// address that is unparseable, private, loopback, link-local, multicast, or
// simply absent from the table yields the zero Info{} — empty CountryCode and
// every flag false. This is a signal for notification and risk scoring, not an
// access-control oracle; callers decide policy.
//
// # Accuracy caveats
//
//   - Country is the RIR *registration* country, which is coarser than
//     commercial geo-IP (it reflects who the block is registered to, not where
//     the host physically is). Acceptable for a notify-only signal.
//   - IsVPN is always false for now. Precise consumer-VPN detection needs a
//     commercial data feed; it is deferred rather than guessed. IsAnonymous is
//     therefore currently IsTor || IsHosting.
package ipintel

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// EnvDataPath names an environment variable holding a filesystem path to an
// ipintel blob. When set and readable and structurally valid, it replaces the
// embedded default, allowing a fresher table to be shipped without a rebuild.
const EnvDataPath = "VAULT_IPINTEL_DATA"

// Info is the intelligence known about a single address. The zero value is the
// fail-open result: no country, nothing flagged.
type Info struct {
	// CountryCode is the ISO 3166-1 alpha-2 registration country, uppercase,
	// or "" when unknown.
	CountryCode string
	// IsVPN reports a known consumer-VPN exit. Always false for now (deferred:
	// precise VPN detection needs a paid data feed).
	IsVPN bool
	// IsHosting reports a datacenter / cloud / hosting-provider address.
	IsHosting bool
	// IsTor reports a published Tor exit node.
	IsTor bool
	// IsAnonymous is a convenience OR of the anonymising signals:
	// IsTor || IsHosting || IsVPN.
	IsAnonymous bool
}

// snapshot is an immutable decoded range table. It is swapped as a unit behind
// DB's atomic pointer so readers are lock-free and always see a consistent set.
type snapshot struct {
	v4 []v4Range // sorted by start ascending, non-overlapping
	v6 []v6Range // sorted by (startHi, startLo) ascending, non-overlapping
}

// DB is a hot-swappable IP-intelligence table. Lookups are lock-free; a fresh
// snapshot can be installed with Reload while lookups run concurrently.
type DB struct {
	snap atomic.Pointer[snapshot]
}

func newDB(s *snapshot) *DB {
	d := &DB{}
	d.snap.Store(s)
	return d
}

// NewEmpty returns a DB whose every lookup yields the zero Info. It is always
// safe and never nil — a usable fallback when no data is available.
func NewEmpty() *DB { return newDB(&snapshot{}) }

// Load decodes a blob produced by the generator into a DB. It returns an error
// only when the blob is structurally corrupt (bad magic, unsupported version,
// or a truncated body). A well-formed but empty blob loads to an empty DB.
func Load(blob []byte) (*DB, error) {
	s, err := decode(blob)
	if err != nil {
		return nil, err
	}
	return newDB(s), nil
}

// Reload atomically replaces the DB's table from a new blob. On decode error
// the existing table is left untouched and the error is returned, so a bad
// refresh never degrades a running process.
func (d *DB) Reload(blob []byte) error {
	s, err := decode(blob)
	if err != nil {
		return err
	}
	d.snap.Store(s)
	return nil
}

// Default returns the process default DB. It prefers the file named by
// VAULT_IPINTEL_DATA when that is set, readable, and valid; otherwise it uses
// the embedded blob. It only returns an error when the embedded blob itself is
// corrupt, which would be a build-time defect. If the embedded blob is absent
// or empty it degrades to an empty DB rather than failing.
func Default() (*DB, error) {
	if p := strings.TrimSpace(os.Getenv(EnvDataPath)); p != "" {
		if data, err := os.ReadFile(filepath.Clean(p)); err == nil { // #nosec G304 -- operator-controlled path, read-only, fail-open to embedded on any error
			if d, err := Load(data); err == nil {
				return d, nil
			}
			// Structurally invalid override: ignore and fall back to embedded.
		}
		// Unreadable override: ignore and fall back to embedded.
	}
	if len(embeddedBlob) == 0 {
		return NewEmpty(), nil
	}
	return Load(embeddedBlob)
}
