package middleware

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/httputil"
	vjwt "github.com/42-v/vault42/internal/jwt"
)

// captureLog runs fn with the standard logger redirected and returns what it
// wrote. The log package is process-global, so flags are restored too.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()

	var buf bytes.Buffer
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})

	fn()
	return buf.String()
}

// TestDeniedRequestsDoNotLogTheFullClientAddress is the regression for eight log
// lines that put a whole client IP into the operational log.
//
// The package had already settled this question. httputil.ObfuscatedIP exists,
// its doc comment names CWE-359 and GDPR pseudonymisation, internal/service
// routes every lockout log line through it, and tests/compliance asserts under
// ASVS V16.4.1 that "source addresses are pseudonymised before they reach a log
// line". What that assertion never checked was the call sites: it pinned the
// helper's behavior, not that anybody used it.
//
// These sites used httputil.SafeLogValue instead, which is a different control
// for a different attack. SafeLogValue neutralizes the control characters that
// would let a caller forge a second log record; it does nothing about logging a
// personal identifier in the first place, and the #nosec G706 comments that
// cited it read as if it did.
//
// docs/PRIVACY.md holds the full address in exactly two places, both inventoried
// with a retention period: the audit store (P4) and the device record (P3). The
// operational log is not one of the stores in §3, so a full address written
// there is processing the document does not describe. The masked form keeps the
// /24 that makes a deny line worth reading, and the request id already carries
// the link to the audit record that holds the rest.
func TestDeniedRequestsDoNotLogTheFullClientAddress(t *testing.T) {
	const (
		clientIP = "203.0.113.201"
		masked   = "203.0.113.0"
	)

	cases := []struct {
		name          string
		configure     func()
		remoteAddr    string
		countryHeader string
		wantReason    string
	}{
		{
			name:       "ip_not_in_allowlist",
			configure:  func() { SetIPAccessLists([]string{"10.0.0.0/8"}, nil, nil, nil, "") },
			remoteAddr: clientIP + ":5555",
			wantReason: "reason=ip_not_in_allowlist",
		},
		{
			name:       "ip_in_blocklist",
			configure:  func() { SetIPAccessLists(nil, []string{"203.0.113.0/24"}, nil, nil, "") },
			remoteAddr: clientIP + ":5555",
			wantReason: "reason=ip_in_blocklist",
		},
		{
			name:       "geo_country_unknown",
			configure:  func() { SetIPAccessLists(nil, nil, []string{"US"}, nil, "CF-IPCountry") },
			remoteAddr: clientIP + ":5555",
			wantReason: "reason=geo_country_unknown",
		},
		{
			name: "geo_not_in_allowlist",
			configure: func() {
				SetIPAccessLists(nil, nil, []string{"US"}, nil, "CF-IPCountry")
				SetTrustedProxies([]string{"203.0.113.0/24"})
			},
			remoteAddr:    clientIP + ":5555",
			countryHeader: "RU",
			wantReason:    "reason=geo_not_in_allowlist",
		},
		{
			name: "geo_in_blocklist",
			configure: func() {
				SetIPAccessLists(nil, nil, nil, []string{"RU"}, "CF-IPCountry")
				SetTrustedProxies([]string{"203.0.113.0/24"})
			},
			remoteAddr:    clientIP + ":5555",
			countryHeader: "RU",
			wantReason:    "reason=geo_in_blocklist",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetIPAccess()
			SetTrustedProxies(nil)
			t.Cleanup(func() {
				resetIPAccess()
				SetTrustedProxies(nil)
			})
			tc.configure()

			out := captureLog(t, func() {
				req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
				req.RemoteAddr = tc.remoteAddr
				if tc.countryHeader != "" {
					req.Header.Set("CF-IPCountry", tc.countryHeader)
				}
				rec := httptest.NewRecorder()
				IPAccess()(ok200).ServeHTTP(rec, req)

				if rec.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want 403; the deny path did not run so there is no log line to check", rec.Code)
				}
			})

			if !strings.Contains(out, tc.wantReason) {
				t.Fatalf("log = %q, want it to contain %q; the wrong branch logged", out, tc.wantReason)
			}
			if strings.Contains(out, clientIP) {
				t.Errorf("log = %q, which carries the full client address %s. "+
					"docs/PRIVACY.md inventories the full address in the audit store and the device "+
					"record only; the operational log is not one of its stores.", out, clientIP)
			}
			if !strings.Contains(out, masked) {
				t.Errorf("log = %q, want the masked network %s. Dropping the address entirely "+
					"leaves an operator unable to tell which network a deny came from.", out, masked)
			}
		})
	}
}

// TestUnparseableAddressIsNotEchoedIntoTheLog covers the one deny reason whose
// input is not an address at all.
//
// It fires when a hop the operator has declared trusted forwards something that
// does not parse, so the value is attacker-influenced and worth nothing to a
// reader beyond the fact that it was junk. ObfuscatedIP renders it as the
// constant "invalid_ip", which is the whole diagnostic, and echoing the bytes
// back is a log-injection surface with no upside.
func TestUnparseableAddressIsNotEchoedIntoTheLog(t *testing.T) {
	resetIPAccess()
	t.Cleanup(resetIPAccess)
	SetIPAccessLists([]string{"10.0.0.0/8"}, nil, nil, nil, "")

	const junk = "not-an-address-ZZZ"

	out := captureLog(t, func() {
		req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
		req.RemoteAddr = junk
		rec := httptest.NewRecorder()
		IPAccess()(ok200).ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; an address the lists cannot represent must be refused", rec.Code)
		}
	})

	if !strings.Contains(out, "reason=unparseable_ip") {
		t.Fatalf("log = %q, want the unparseable_ip line; the branch under test did not run", out)
	}
	if strings.Contains(out, junk) {
		t.Errorf("log = %q, which echoes the unparseable peer value %q back into the log", out, junk)
	}
}

// TestFingerprintMismatchDoesNotLogTheFullClientAddress covers the soft-mode
// warning, the one line in this package that pairs an address with a user id.
//
// Soft mode exists to be left on during a rollout, so this line is the one that
// runs in volume, and it is the only one here that writes both halves of a
// linkable pair. The subject is already a pseudonymous id that the audit store
// carries; the address is the half docs/PRIVACY.md keeps out of the log.
func TestFingerprintMismatchDoesNotLogTheFullClientAddress(t *testing.T) {
	const (
		clientIP = "198.51.100.77"
		masked   = "198.51.100.0"
	)

	claims := &vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{Subject: "11111111-2222-3333-4444-555555555555"},
		Fingerprint:      vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{IP: "192.0.2.1"}),
	}

	out := captureLog(t, func() {
		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		req.RemoteAddr = clientIP + ":4444"
		req = req.WithContext(context.WithValue(req.Context(), ClaimsKey, claims))

		rec := httptest.NewRecorder()
		Fingerprint(true)(ok200).ServeHTTP(rec, req)
	})

	if !strings.Contains(out, "fingerprint check: mismatch") {
		t.Fatalf("log = %q, want the soft-mode mismatch line; the branch under test did not run", out)
	}
	if strings.Contains(out, clientIP) {
		t.Errorf("log = %q, which pairs a user id with the full client address %s", out, clientIP)
	}
	if !strings.Contains(out, masked) {
		t.Errorf("log = %q, want the masked network %s", out, masked)
	}
	if got := httputil.ObfuscatedIP(clientIP); got != masked {
		t.Fatalf("ObfuscatedIP(%q) = %q, want %q", clientIP, got, masked)
	}
}
