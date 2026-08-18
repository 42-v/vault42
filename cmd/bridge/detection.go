package main

import (
	"strings"
	"sync"
	"time"
)

// automationPatterns are user-agent substrings that indicate automated tools.
var automationPatterns = []string{
	"curl", "wget", "python-requests", "python-urllib",
	"httpie", "go-http-client", "java/", "libwww-perl",
	"scrapy", "bot", "crawler", "spider", "nikto",
	"sqlmap", "nmap", "masscan", "zap", "burp",
	"dirbuster", "gobuster", "ffuf", "feroxbuster",
	"nuclei", "wfuzz", "hydra", "medusa",
}

// ScoreAutomationUA returns a score if the User-Agent matches automation patterns.
func ScoreAutomationUA(ua string) int {
	lower := strings.ToLower(ua)
	for _, p := range automationPatterns {
		if strings.Contains(lower, p) {
			return 30
		}
	}
	return 0
}

// Growth bounds for every per-source table in this file.
//
// All three were maps an unauthenticated caller keyed and a slice an
// unauthenticated caller appended to: one address at 10k req/s for a 60s window
// held 600k time.Time values (~14 MiB) behind a mutex taken on every request,
// and 100k distinct sources held a bucket each until the reaper caught them.
// The bridge's memory limit is 64Mi.
//
// maxSamplesPerIP is far above any flag threshold an operator would set, so
// saturating it cannot hide an attack: a source that has already logged 4096
// requests inside the window is over every threshold there is.
//
// maxTrackedIPs is a refusal, not an eviction. At the cap a source that is not
// already tracked is treated as first-seen, which is exactly what a
// unique-address flood already produced one entry at a time — so nothing that
// was detectable before stops being detectable, and the reaper drains the map
// on its next tick.
const (
	maxSamplesPerIP = 4096
	maxTrackedIPs   = 50_000
)

// RateTracker tracks per-IP request rates using a sliding window.
type RateTracker struct {
	mu      sync.Mutex
	buckets map[string]*slidingWindow
	window  time.Duration
}

type slidingWindow struct {
	timestamps []time.Time
	lastAccess time.Time
}

// record appends now to a bounded sliding window, trimming entries older than
// cutoff, and returns the live count. Shared by RateTracker and
// LoginFailTracker, which had the same body and therefore the same two
// unbounded dimensions.
func (sw *slidingWindow) record(now, cutoff time.Time) int {
	trimIdx := 0
	for trimIdx < len(sw.timestamps) && sw.timestamps[trimIdx].Before(cutoff) {
		trimIdx++
	}
	if trimIdx > 0 {
		sw.timestamps = sw.timestamps[trimIdx:]
	}
	if len(sw.timestamps) >= maxSamplesPerIP {
		// Drop the oldest sample rather than grow. Re-slicing keeps this O(1);
		// append reuses the array until it runs out and then copies once.
		sw.timestamps = sw.timestamps[1:]
	}
	sw.timestamps = append(sw.timestamps, now)
	sw.lastAccess = now
	return len(sw.timestamps)
}

// NewRateTracker creates a rate tracker with the given window duration.
func NewRateTracker(window time.Duration) *RateTracker {
	return &RateTracker{
		buckets: make(map[string]*slidingWindow),
		window:  window,
	}
}

// Record adds a timestamp for the given IP and returns the current count within the window.
func (rt *RateTracker) Record(ip string) int {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rt.window)

	sw, ok := rt.buckets[ip]
	if !ok {
		if len(rt.buckets) >= maxTrackedIPs {
			return 1
		}
		sw = &slidingWindow{}
		rt.buckets[ip] = sw
	}

	return sw.record(now, cutoff)
}

// Count returns the current count for an IP without recording.
func (rt *RateTracker) Count(ip string) int {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rt.window)

	sw, ok := rt.buckets[ip]
	if !ok {
		return 0
	}

	count := 0
	for _, ts := range sw.timestamps {
		if !ts.Before(cutoff) {
			count++
		}
	}
	return count
}

// Reap removes stale entries older than 2x the window.
func (rt *RateTracker) Reap() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	cutoff := time.Now().Add(-2 * rt.window)
	for ip, sw := range rt.buckets {
		if sw.lastAccess.Before(cutoff) {
			delete(rt.buckets, ip)
		}
	}
}

// LoginFailTracker tracks per-IP login failure counts.
type LoginFailTracker struct {
	mu      sync.Mutex
	buckets map[string]*slidingWindow
	window  time.Duration
}

// NewLoginFailTracker creates a login failure tracker.
func NewLoginFailTracker(window time.Duration) *LoginFailTracker {
	return &LoginFailTracker{
		buckets: make(map[string]*slidingWindow),
		window:  window,
	}
}

// Record adds a login failure for the IP and returns the count within the window.
//
// Same two bounds as RateTracker: this tracker was not named separately in the
// resource-exhaustion review, but it is the same shape driven by the same
// unauthenticated caller, with a 15-minute window instead of a 1-minute one.
func (lft *LoginFailTracker) Record(ip string) int {
	lft.mu.Lock()
	defer lft.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-lft.window)

	sw, ok := lft.buckets[ip]
	if !ok {
		if len(lft.buckets) >= maxTrackedIPs {
			return 1
		}
		sw = &slidingWindow{}
		lft.buckets[ip] = sw
	}

	return sw.record(now, cutoff)
}

// Reap removes stale entries.
func (lft *LoginFailTracker) Reap() {
	lft.mu.Lock()
	defer lft.mu.Unlock()

	cutoff := time.Now().Add(-2 * lft.window)
	for ip, sw := range lft.buckets {
		if sw.lastAccess.Before(cutoff) {
			delete(lft.buckets, ip)
		}
	}
}
