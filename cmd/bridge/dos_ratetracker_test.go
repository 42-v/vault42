package main

import (
	"strconv"
	"testing"
	"time"
)

// The bridge's per-source tables were the request path's memory lever: Record
// appended one time.Time per request and trimmed only by age, and every map was
// keyed by an address the caller chooses. One source at 10k req/s for a
// one-minute window held 600k timestamps (~14 MiB) behind the mutex every
// request takes, and 100k distinct addresses held a bucket each until the
// reaper caught them — against a 64Mi memory limit.

func slash96(i int) string {
	return "2001:db8:0:" + strconv.Itoa(i) + "::1"
}

// TestDoS_RateTrackerCapsSamplesPerIP pins the per-source ring. Well past the
// cap the count saturates instead of growing, and it saturates far above any
// threshold an operator would configure, so nothing that was detectable stops
// being detectable.
func TestDoS_RateTrackerCapsSamplesPerIP(t *testing.T) {
	rt := NewRateTracker(time.Minute)
	const n = maxSamplesPerIP + 2000

	for i := 0; i < n; i++ {
		got := rt.Record("203.0.113.10")
		if got > maxSamplesPerIP {
			t.Fatalf("Record #%d returned %d, over the %d cap", i+1, got, maxSamplesPerIP)
		}
	}
	if got := rt.Count("203.0.113.10"); got != maxSamplesPerIP {
		t.Fatalf("Count = %d, want it pinned at the %d cap", got, maxSamplesPerIP)
	}
	if got := len(rt.buckets["203.0.113.10"].timestamps); got != maxSamplesPerIP {
		t.Fatalf("stored timestamps = %d, want %d", got, maxSamplesPerIP)
	}
	// The cap must still be far above a realistic flag threshold, or saturating
	// it would be a way to hide.
	if maxSamplesPerIP <= 60 {
		t.Fatalf("maxSamplesPerIP = %d is at or below the default rate threshold", maxSamplesPerIP)
	}
}

// TestDoS_RateTrackerCapsDistinctIPs pins the map bound. At the cap a
// previously unseen address is scored as first-seen and not stored, which is
// exactly what an address-varying flood already got one entry at a time.
func TestDoS_RateTrackerCapsDistinctIPs(t *testing.T) {
	rt := NewRateTracker(time.Minute)
	for i := 0; i < maxTrackedIPs; i++ {
		if got := rt.Record(slash96(i)); got != 1 {
			t.Fatalf("first Record(%d) = %d, want 1", i, got)
		}
	}
	if got := len(rt.buckets); got != maxTrackedIPs {
		t.Fatalf("buckets = %d, want %d", got, maxTrackedIPs)
	}

	if got := rt.Record("2001:db8:ffff::1"); got != 1 {
		t.Fatalf("Record past the cap = %d, want 1", got)
	}
	if got := len(rt.buckets); got != maxTrackedIPs {
		t.Fatalf("buckets grew past the cap to %d", got)
	}
	// An address already tracked keeps counting: the cap must not hand an
	// established attacker a fresh budget.
	if got := rt.Record(slash96(0)); got != 2 {
		t.Fatalf("Record of a tracked address at the cap = %d, want 2", got)
	}
}

// TestDoS_LoginFailTrackerIsCappedToo covers the tracker the review did not
// name separately. Same shape, same caller, a fifteen-minute window instead of
// a one-minute one.
func TestDoS_LoginFailTrackerIsCappedToo(t *testing.T) {
	lft := NewLoginFailTracker(15 * time.Minute)
	for i := 0; i < maxTrackedIPs; i++ {
		lft.Record(slash96(i))
	}
	if got := lft.Record("2001:db8:ffff::2"); got != 1 {
		t.Fatalf("Record past the cap = %d, want 1", got)
	}
	if got := len(lft.buckets); got != maxTrackedIPs {
		t.Fatalf("buckets = %d, want the cap %d", got, maxTrackedIPs)
	}

	for i := 0; i < maxSamplesPerIP+50; i++ {
		lft.Record(slash96(0))
	}
	if got := len(lft.buckets[slash96(0)].timestamps); got != maxSamplesPerIP {
		t.Fatalf("stored failures = %d, want the %d cap", got, maxSamplesPerIP)
	}
}

// TestDoS_ScoreMapCapsDistinctIPs pins the score table. Live totals never
// decay, so an entry survives for FlagTTL — 24 hours by default — and an
// address-varying flood chose the map size.
func TestDoS_ScoreMapCapsDistinctIPs(t *testing.T) {
	sm := NewScoreMap()
	for i := 0; i < maxTrackedIPs; i++ {
		if got := sm.Add(slash96(i), 1); got != 1 {
			t.Fatalf("Add(%d) = %d, want 1", i, got)
		}
	}
	if got := sm.Add("2001:db8:ffff::3", 30); got != 30 {
		t.Fatalf("Add past the cap = %d, want the delta 30", got)
	}
	if got := len(sm.scores); got != maxTrackedIPs {
		t.Fatalf("scores = %d, want the cap %d", got, maxTrackedIPs)
	}
	if got := sm.Get("2001:db8:ffff::3"); got != 0 {
		t.Fatalf("a refused address was stored anyway: score %d", got)
	}
	// A tracked address still accumulates, so a scanner already being watched
	// cannot escape by filling the map.
	if got := sm.Add(slash96(0), 50); got != 51 {
		t.Fatalf("Add to a tracked address at the cap = %d, want 51", got)
	}
}

// TestDoS_TrimmingReclaimsSampleSlots shows the cap does not wedge: samples
// that fall out of the window free space for new ones.
func TestDoS_TrimmingReclaimsSampleSlots(t *testing.T) {
	rt := NewRateTracker(20 * time.Millisecond)
	for i := 0; i < 50; i++ {
		rt.Record("198.51.100.5")
	}
	time.Sleep(40 * time.Millisecond)
	if got := rt.Record("198.51.100.5"); got != 1 {
		t.Fatalf("Record after the window lapsed = %d, want 1", got)
	}
}
