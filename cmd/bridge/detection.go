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
		sw = &slidingWindow{}
		rt.buckets[ip] = sw
	}

	// Trim expired entries
	trimIdx := 0
	for trimIdx < len(sw.timestamps) && sw.timestamps[trimIdx].Before(cutoff) {
		trimIdx++
	}
	if trimIdx > 0 {
		sw.timestamps = sw.timestamps[trimIdx:]
	}

	sw.timestamps = append(sw.timestamps, now)
	sw.lastAccess = now
	return len(sw.timestamps)
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
func (lft *LoginFailTracker) Record(ip string) int {
	lft.mu.Lock()
	defer lft.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-lft.window)

	sw, ok := lft.buckets[ip]
	if !ok {
		sw = &slidingWindow{}
		lft.buckets[ip] = sw
	}

	trimIdx := 0
	for trimIdx < len(sw.timestamps) && sw.timestamps[trimIdx].Before(cutoff) {
		trimIdx++
	}
	if trimIdx > 0 {
		sw.timestamps = sw.timestamps[trimIdx:]
	}

	sw.timestamps = append(sw.timestamps, now)
	sw.lastAccess = now
	return len(sw.timestamps)
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
