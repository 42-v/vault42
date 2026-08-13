package middleware

import (
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/42-v/vault42/internal/httputil"
)

// ipBlockMu serializes copy-on-write mutations to the IP blocklist.
// Reads are lock-free via atomic.Pointer; only AddToIPBlocklist/RemoveFromIPBlocklist acquire this.
var ipBlockMu sync.Mutex

// IP access control state — atomic pointers for concurrent-safe reads.
var (
	ipAllowCIDRs atomic.Pointer[[]*net.IPNet]
	ipBlockCIDRs atomic.Pointer[[]*net.IPNet]
	geoAllowSet  atomic.Pointer[map[string]bool]
	geoBlockSet  atomic.Pointer[map[string]bool]
	geoIPHeader  atomic.Value // string: header name for country code
)

// SetIPAccessLists parses and stores the IP/geo access control lists.
// Called once at startup. Invalid CIDR entries are logged and skipped.
func SetIPAccessLists(ipAllow, ipBlock, geoAllow, geoBlock []string, geoHeader string) {
	ipAllowCIDRs.Store(parseCIDRList(ipAllow))
	ipBlockCIDRs.Store(parseCIDRList(ipBlock))

	allow := make(map[string]bool, len(geoAllow))
	for _, c := range geoAllow {
		allow[strings.ToUpper(strings.TrimSpace(c))] = true
	}
	geoAllowSet.Store(&allow)

	block := make(map[string]bool, len(geoBlock))
	for _, c := range geoBlock {
		block[strings.ToUpper(strings.TrimSpace(c))] = true
	}
	geoBlockSet.Store(&block)

	geoIPHeader.Store(strings.TrimSpace(geoHeader))
}

// AddToIPBlocklist adds one or more CIDRs/IPs to the blocklist at runtime.
// Safe for concurrent use — uses copy-on-write with a serializing mutex.
// Returns the number of entries successfully added.
func AddToIPBlocklist(entries ...string) int {
	parsed := parseCIDRList(entries)
	if parsed == nil || len(*parsed) == 0 {
		return 0
	}

	ipBlockMu.Lock()
	defer ipBlockMu.Unlock()

	current := loadIPBlockCIDRs()
	updated := make([]*net.IPNet, len(current), len(current)+len(*parsed))
	copy(updated, current)
	added := 0
	for _, newCIDR := range *parsed {
		if !containsCIDR(current, newCIDR) {
			updated = append(updated, newCIDR)
			added++
		}
	}
	if added > 0 {
		ipBlockCIDRs.Store(&updated)
		log.Printf("ip_access: added %d entries to blocklist (total: %d)", added, len(updated))
	}
	return added
}

// RemoveFromIPBlocklist removes one or more CIDRs/IPs from the blocklist at runtime.
// Matches by CIDR string equality. Returns the number of entries removed.
func RemoveFromIPBlocklist(entries ...string) int {
	parsed := parseCIDRList(entries)
	if parsed == nil || len(*parsed) == 0 {
		return 0
	}

	ipBlockMu.Lock()
	defer ipBlockMu.Unlock()

	current := loadIPBlockCIDRs()
	if len(current) == 0 {
		return 0
	}

	// Build set of CIDRs to remove (by string representation)
	removeSet := make(map[string]bool, len(*parsed))
	for _, c := range *parsed {
		removeSet[c.String()] = true
	}

	var updated []*net.IPNet
	removed := 0
	for _, c := range current {
		if removeSet[c.String()] {
			removed++
		} else {
			updated = append(updated, c)
		}
	}
	if removed > 0 {
		ipBlockCIDRs.Store(&updated)
		log.Printf("ip_access: removed %d entries from blocklist (total: %d)", removed, len(updated))
	}
	return removed
}

// containsCIDR checks if a CIDR is already in the list (by string equality).
func containsCIDR(list []*net.IPNet, target *net.IPNet) bool {
	s := target.String()
	for _, c := range list {
		if c.String() == s {
			return true
		}
	}
	return false
}

// parseCIDRList converts a list of CIDR/IP strings to *[]*net.IPNet.
// Bare IPs are normalized to /32 (IPv4) or /128 (IPv6). Invalid entries are logged and skipped.
func parseCIDRList(entries []string) *[]*net.IPNet {
	cidrs := make([]*net.IPNet, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			if strings.Contains(entry, ":") {
				entry += "/128"
			} else {
				entry += "/32"
			}
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			log.Printf("WARNING: invalid IP access entry %q: %v", entry, err)
			continue
		}
		cidrs = append(cidrs, cidr)
	}
	return &cidrs
}

// loadIPAllowCIDRs returns the current IP allowlist (nil-safe).
func loadIPAllowCIDRs() []*net.IPNet {
	p := ipAllowCIDRs.Load()
	if p == nil {
		return nil
	}
	return *p
}

// loadIPBlockCIDRs returns the current IP blocklist (nil-safe).
func loadIPBlockCIDRs() []*net.IPNet {
	p := ipBlockCIDRs.Load()
	if p == nil {
		return nil
	}
	return *p
}

// loadGeoAllowSet returns the current geo allowlist (nil-safe).
func loadGeoAllowSet() map[string]bool {
	p := geoAllowSet.Load()
	if p == nil {
		return nil
	}
	return *p
}

// loadGeoBlockSet returns the current geo blocklist (nil-safe).
func loadGeoBlockSet() map[string]bool {
	p := geoBlockSet.Load()
	if p == nil {
		return nil
	}
	return *p
}

// loadGeoIPHeader returns the configured geo IP header name (empty = disabled).
func loadGeoIPHeader() string {
	v, _ := geoIPHeader.Load().(string)
	return v
}

// IPAccess returns a middleware that enforces IP allowlist/blocklist and
// geographic restrictions. Health endpoints (/healthz, /readyz) bypass all checks.
// When no lists are configured, the middleware is a zero-cost passthrough.
//
//nolint:gocognit // exhaustive ladder: bypass paths, allowlist, blocklist, dynamic ban, geo-allow, geo-block — all in one place by design
func IPAccess() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Bypass health probes
			if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
				next.ServeHTTP(w, r)
				return
			}

			allowCIDRs := loadIPAllowCIDRs()
			blockCIDRs := loadIPBlockCIDRs()
			geoAllow := loadGeoAllowSet()
			geoBlock := loadGeoBlockSet()

			// Short-circuit: no lists configured
			if len(allowCIDRs) == 0 && len(blockCIDRs) == 0 && len(geoAllow) == 0 && len(geoBlock) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			clientIP := ClientIP(r)
			reqID := GetRequestID(r.Context())

			// IP checks
			if len(allowCIDRs) > 0 || len(blockCIDRs) > 0 {
				ip := net.ParseIP(clientIP)
				if ip == nil {
					log.Printf("ip_access: deny req=%s ip=%q reason=unparseable_ip", reqID, httputil.SafeLogValue(clientIP)) // #nosec G706 -- sanitized via SafeLogValue
					httputil.WriteError(w, http.StatusForbidden, "access_denied")
					return
				}

				// Allowlist: if configured, IP must match
				if len(allowCIDRs) > 0 {
					allowed := false
					for _, cidr := range allowCIDRs {
						if cidr.Contains(ip) {
							allowed = true
							break
						}
					}
					if !allowed {
						log.Printf("ip_access: deny req=%s ip=%s reason=ip_not_in_allowlist", reqID, httputil.SafeLogValue(clientIP)) // #nosec G706 -- sanitized via SafeLogValue
						httputil.WriteError(w, http.StatusForbidden, "access_denied")
						return
					}
				}

				// Blocklist: reject if IP matches
				if len(blockCIDRs) > 0 {
					for _, cidr := range blockCIDRs {
						if cidr.Contains(ip) {
							log.Printf("ip_access: deny req=%s ip=%s reason=ip_in_blocklist", reqID, httputil.SafeLogValue(clientIP)) // #nosec G706 -- sanitized via SafeLogValue
							httputil.WriteError(w, http.StatusForbidden, "access_denied")
							return
						}
					}
				}
			}

			// Geo checks — only when a geo header is configured
			geoHeader := loadGeoIPHeader()
			if geoHeader != "" && (len(geoAllow) > 0 || len(geoBlock) > 0) {
				// The country is believed only from a hop the operator trusts,
				// the same contract ClientIP applies to X-Forwarded-For and to
				// the app header. It used to be read straight off the request, so
				// anyone reaching the origin directly, through a leaked ClusterIP,
				// a NodePort, a mis-published Service, or any hop that forwards
				// client headers, simply sent the country the list wanted.
				// IPAccess is mounted globally and ahead of authentication, so
				// that was the entire fence for login, register, reset and the
				// client-credentials grant.
				var country string
				if isTrustedProxy(stripPort(r.RemoteAddr)) {
					country = strings.ToUpper(strings.TrimSpace(r.Header.Get(geoHeader)))
				}

				// An allowlist says only these countries may reach this service,
				// so a caller whose country cannot be established is not one of
				// them. Skipping the ladder on an absent header made omitting it
				// the simplest bypass available, requiring no knowledge of which
				// countries were listed.
				//
				// A blocklist is the other shape. It names what is refused, so an
				// unknown country matches nothing on it, and denying there would
				// quietly turn a blocklist into an allowlist of one.
				if country == "" && len(geoAllow) > 0 {
					log.Printf("ip_access: deny req=%s ip=%s reason=geo_country_unknown", reqID, httputil.SafeLogValue(clientIP)) // #nosec G706 -- sanitized via SafeLogValue
					httputil.WriteError(w, http.StatusForbidden, "access_denied")
					return
				}

				if country != "" {
					if len(geoAllow) > 0 && !geoAllow[country] {
						log.Printf("ip_access: deny req=%s ip=%s country=%s reason=geo_not_in_allowlist", reqID, httputil.SafeLogValue(clientIP), httputil.SafeLogValue(country)) // #nosec G706 -- sanitized via SafeLogValue
						httputil.WriteError(w, http.StatusForbidden, "access_denied")
						return
					}
					if len(geoBlock) > 0 && geoBlock[country] {
						log.Printf("ip_access: deny req=%s ip=%s country=%s reason=geo_in_blocklist", reqID, httputil.SafeLogValue(clientIP), httputil.SafeLogValue(country)) // #nosec G706 -- sanitized via SafeLogValue
						httputil.WriteError(w, http.StatusForbidden, "access_denied")
						return
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
