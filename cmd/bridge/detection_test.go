package main

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestScoreAutomationUA(t *testing.T) {
	tests := []struct {
		ua    string
		score int
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", 0},
		{"curl/7.68.0", 30},
		{"sqlmap/1.5", 30},
		{"python-requests/2.28.0", 30},
		{"Nikto/2.1.6", 30},
		{"Mozilla/5.0 (compatible; Googlebot/2.1)", 30},
		{"", 0},
		{"Go-http-client/1.1", 30},
		{"Nuclei - Open-source scanner", 30},
	}

	for _, tt := range tests {
		t.Run(tt.ua, func(t *testing.T) {
			got := ScoreAutomationUA(tt.ua)
			if got != tt.score {
				t.Errorf("ScoreAutomationUA(%q) = %d, want %d", tt.ua, got, tt.score)
			}
		})
	}
}

func TestRateTracker(t *testing.T) {
	rt := NewRateTracker(100 * time.Millisecond)

	// Record several requests
	for i := 0; i < 5; i++ {
		rt.Record("1.2.3.4")
	}

	if got := rt.Count("1.2.3.4"); got != 5 {
		t.Errorf("Count = %d, want 5", got)
	}

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	if got := rt.Count("1.2.3.4"); got != 0 {
		t.Errorf("Count after expiry = %d, want 0", got)
	}
}

func TestRateTrackerReap(t *testing.T) {
	rt := NewRateTracker(50 * time.Millisecond)
	rt.Record("1.1.1.1")
	rt.Record("2.2.2.2")

	time.Sleep(120 * time.Millisecond)
	rt.Reap()

	rt.mu.Lock()
	count := len(rt.buckets)
	rt.mu.Unlock()

	if count != 0 {
		t.Errorf("Reap: %d buckets remain, want 0", count)
	}
}

func TestLoginFailTracker(t *testing.T) {
	lft := NewLoginFailTracker(100 * time.Millisecond)

	for i := 1; i <= 3; i++ {
		got := lft.Record("10.0.0.1")
		if got != i {
			t.Errorf("Record() = %d, want %d", got, i)
		}
	}

	time.Sleep(150 * time.Millisecond)

	// After window expiry, next record should be 1
	if got := lft.Record("10.0.0.1"); got != 1 {
		t.Errorf("Record after expiry = %d, want 1", got)
	}
}

// TestScoreAutomationUACoversEveryPattern makes the pattern list itself the
// fixture, so a pattern added to automationPatterns without a matching sample is
// caught here rather than silently going untested. Each entry is a tool that
// announces itself, and the whole cheap half of the detection story rests on
// them being matched.
func TestScoreAutomationUACoversEveryPattern(t *testing.T) {
	for _, pattern := range automationPatterns {
		t.Run(pattern, func(t *testing.T) {
			// Wrapped in surrounding text, because a real user agent is never
			// just the tool name.
			ua := "Something/1.0 (" + pattern + "9.9) Extra"
			if got := ScoreAutomationUA(ua); got != 30 {
				t.Errorf("ScoreAutomationUA(%q) = %d, want 30", ua, got)
			}
			// And matched regardless of case, since the header is client
			// controlled and shifting a letter must not be a bypass.
			upper := strings.ToUpper(ua)
			if got := ScoreAutomationUA(upper); got != 30 {
				t.Errorf("ScoreAutomationUA(%q) = %d, want 30", upper, got)
			}
		})
	}
}

// TestScoreAutomationUALeavesRealBrowsersAlone is the false-positive guard. A
// browser scored here starts accumulating toward a flag on ordinary use, and the
// user would be moved to the honeypot without any sign that anything changed.
func TestScoreAutomationUALeavesRealBrowsersAlone(t *testing.T) {
	browsers := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		"",
	}

	for _, ua := range browsers {
		if got := ScoreAutomationUA(ua); got != 0 {
			t.Errorf("ScoreAutomationUA(%q) = %d, want 0", ua, got)
		}
	}
}

// TestScoreAutomationUAMatchesOnBareSubstrings records that matching is
// substring based with no word boundary, which is what makes some of the shorter
// patterns broad. Anything containing "bot", "zap" or "nmap" anywhere in its
// user agent scores thirty, so a product name that happens to contain one of
// them is scored as a scanner. At thirty points against a default threshold of a
// hundred that takes four requests to become a flag, which ordinary browsing
// reaches easily.
//
// The behavior is deliberate for the long patterns and simply a consequence for
// the short ones. The test pins it so that tightening the match, for instance by
// requiring a delimiter, shows up here.
func TestScoreAutomationUAMatchesOnBareSubstrings(t *testing.T) {
	tests := []struct {
		ua    string
		score int
	}{
		{"Elabot/2.1 (a product name)", 30},
		{"ZapReader/4.0", 30},
		{"Mozilla/5.0 SpiderMonkeyShell/1.0", 30},
		// The patterns carrying a delimiter are not this broad.
		{"JavaScript-Runtime/1.0", 0},
		{"Mozilla/5.0 (Java Edition)", 0},
	}

	for _, tt := range tests {
		t.Run(tt.ua, func(t *testing.T) {
			if got := ScoreAutomationUA(tt.ua); got != tt.score {
				t.Errorf("ScoreAutomationUA(%q) = %d, want %d", tt.ua, got, tt.score)
			}
		})
	}
}

// TestRateTrackerRecordTrimsExpiredTimestamps covers the trim inside Record
// rather than the one Count performs. Without it a bucket would grow without
// bound for as long as an address keeps sending, so a sustained scan would leak
// memory in proportion to the traffic it sends rather than to the window.
func TestRateTrackerRecordTrimsExpiredTimestamps(t *testing.T) {
	rt := NewRateTracker(60 * time.Millisecond)

	for i := 1; i <= 4; i++ {
		if got := rt.Record("1.2.3.4"); got != i {
			t.Fatalf("Record %d returned %d, want %d", i, got, i)
		}
	}

	time.Sleep(90 * time.Millisecond)

	// Everything recorded before the sleep is outside the window now, so the
	// next Record starts the count over.
	if got := rt.Record("1.2.3.4"); got != 1 {
		t.Errorf("Record after the window lapsed = %d, want 1", got)
	}

	// The trim must also have released the storage, not merely stopped counting.
	rt.mu.Lock()
	held := len(rt.buckets["1.2.3.4"].timestamps)
	rt.mu.Unlock()
	if held != 1 {
		t.Errorf("the bucket holds %d timestamps, want 1", held)
	}
}

// TestRateTrackerCountIsIndependentOfRecord separates the read from the write.
// ServeHTTP records on every request, so an accidental increment inside Count
// would double every address's rate and halve the effective threshold.
func TestRateTrackerCountIsIndependentOfRecord(t *testing.T) {
	rt := NewRateTracker(time.Minute)

	if got := rt.Count("never.seen"); got != 0 {
		t.Errorf("Count on an unknown address = %d, want 0", got)
	}

	rt.Record("1.2.3.4")
	rt.Record("1.2.3.4")

	for i := 0; i < 5; i++ {
		if got := rt.Count("1.2.3.4"); got != 2 {
			t.Fatalf("Count call %d = %d, want 2", i+1, got)
		}
	}

	// Counting one address must not create or disturb another.
	if got := rt.Count("5.6.7.8"); got != 0 {
		t.Errorf("Count on a second address = %d, want 0", got)
	}
	if got := rt.Count("1.2.3.4"); got != 2 {
		t.Errorf("Count = %d after touching another address, want 2", got)
	}
}

// TestRateTrackerKeepsAddressesApart is the isolation the whole per-IP model
// depends on. One address crossing the rate threshold must not push another one
// over it, since that would let a single scanner flag every client that happens
// to share the bridge.
func TestRateTrackerKeepsAddressesApart(t *testing.T) {
	rt := NewRateTracker(time.Minute)

	for i := 0; i < 10; i++ {
		rt.Record("1.1.1.1")
	}
	rt.Record("2.2.2.2")

	if got := rt.Count("1.1.1.1"); got != 10 {
		t.Errorf("1.1.1.1 count = %d, want 10", got)
	}
	if got := rt.Count("2.2.2.2"); got != 1 {
		t.Errorf("2.2.2.2 count = %d, want 1", got)
	}
}

// TestRateTrackerReapSparesLiveEntries bounds what the reaper is allowed to
// remove. It runs on a timer with no knowledge of which addresses are active, so
// dropping a bucket that is still inside its window would reset a scanner's
// count and let it stay under the threshold indefinitely.
func TestRateTrackerReapSparesLiveEntries(t *testing.T) {
	rt := NewRateTracker(80 * time.Millisecond)

	rt.Record("stale.address")
	time.Sleep(200 * time.Millisecond)
	rt.Record("live.address")

	rt.Reap()

	rt.mu.Lock()
	_, staleHeld := rt.buckets["stale.address"]
	_, liveHeld := rt.buckets["live.address"]
	rt.mu.Unlock()

	if staleHeld {
		t.Error("the reaper kept a bucket older than twice the window")
	}
	if !liveHeld {
		t.Error("the reaper dropped a bucket that was still inside its window")
	}
	if got := rt.Count("live.address"); got != 1 {
		t.Errorf("the live count after reaping = %d, want 1", got)
	}
}

// TestLoginFailTrackerReap is the same sweep on the other tracker. It is
// separate code with its own bucket map, so a fix applied to one does not
// automatically hold for the other.
func TestLoginFailTrackerReap(t *testing.T) {
	lft := NewLoginFailTracker(50 * time.Millisecond)

	lft.Record("1.1.1.1")
	lft.Record("2.2.2.2")

	lft.mu.Lock()
	before := len(lft.buckets)
	lft.mu.Unlock()
	if before != 2 {
		t.Fatalf("tracker holds %d buckets before reaping, want 2", before)
	}

	// Not yet twice the window, so nothing is stale.
	lft.Reap()
	lft.mu.Lock()
	after := len(lft.buckets)
	lft.mu.Unlock()
	if after != 2 {
		t.Errorf("the reaper dropped %d live buckets", 2-after)
	}

	time.Sleep(150 * time.Millisecond)
	lft.Reap()

	lft.mu.Lock()
	drained := len(lft.buckets)
	lft.mu.Unlock()
	if drained != 0 {
		t.Errorf("%d buckets remain after reaping, want 0", drained)
	}
}

// TestLoginFailTrackerKeepsAddressesApart mirrors the rate tracker's isolation
// check. Failed logins are counted from ModifyResponse against the resolved
// client IP, so cross-contamination here would flag every user of a shared
// address as soon as one of them mistyped a password enough times.
func TestLoginFailTrackerKeepsAddressesApart(t *testing.T) {
	lft := NewLoginFailTracker(time.Minute)

	for i := 1; i <= 4; i++ {
		if got := lft.Record("1.1.1.1"); got != i {
			t.Errorf("Record %d for 1.1.1.1 = %d, want %d", i, got, i)
		}
	}
	if got := lft.Record("2.2.2.2"); got != 1 {
		t.Errorf("first Record for 2.2.2.2 = %d, want 1", got)
	}
	if got := lft.Record("1.1.1.1"); got != 5 {
		t.Errorf("Record for 1.1.1.1 after touching another address = %d, want 5", got)
	}
}

// TestRateTrackerConcurrentRecord is the tracker under the traffic pattern it
// exists for. Record is called from every request goroutine on the proxy's hot
// path, so a lost increment is a scanner that never reaches the threshold, and a
// torn map write is a crash in production.
func TestRateTrackerConcurrentRecord(t *testing.T) {
	rt := NewRateTracker(time.Minute)

	const workers = 32
	const iterations = 100

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			own := fmt.Sprintf("10.0.0.%d", w)
			for i := 0; i < iterations; i++ {
				rt.Record("shared")
				rt.Record(own)
				rt.Count("shared")
				rt.Reap()
			}
		}(w)
	}
	wg.Wait()

	if got := rt.Count("shared"); got != workers*iterations {
		t.Errorf("shared count = %d, want %d", got, workers*iterations)
	}
	for w := 0; w < workers; w++ {
		ip := fmt.Sprintf("10.0.0.%d", w)
		if got := rt.Count(ip); got != iterations {
			t.Errorf("%s count = %d, want %d", ip, got, iterations)
		}
	}
}

// TestLoginFailTrackerConcurrentRecord is the same check on the tracker driven
// from ModifyResponse, which runs on the proxy's response goroutines and is
// therefore just as concurrent as the request path.
func TestLoginFailTrackerConcurrentRecord(t *testing.T) {
	lft := NewLoginFailTracker(time.Minute)

	const workers = 24
	const iterations = 80

	var wg sync.WaitGroup
	counts := make(chan int, workers*iterations)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				counts <- lft.Record("shared")
				lft.Reap()
			}
		}(w)
	}
	wg.Wait()
	close(counts)

	// Every Record must have returned a distinct count from 1 to workers times
	// iterations. A lost update would show up as a repeat.
	seen := make(map[int]bool, workers*iterations)
	for c := range counts {
		if seen[c] {
			t.Fatalf("Record returned %d more than once, so an increment was lost", c)
		}
		seen[c] = true
	}
	for i := 1; i <= workers*iterations; i++ {
		if !seen[i] {
			t.Fatalf("Record never returned %d", i)
		}
	}
}
