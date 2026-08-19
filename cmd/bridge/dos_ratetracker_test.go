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

// minTrackedIPs is the floor maxTrackedIPs may not fall below.
//
// The four cap tests above all drive their loops with maxTrackedIPs and then
// assert against maxTrackedIPs, so each is true for any value of it. Set the
// constant to 10 and every one of them still passes: the bridge would stop
// tracking the eleventh distinct source it ever sees, the detector would go
// blind to everything after it, and the only thing that noticed was an
// unrelated concurrency test that happens to use four addresses.
//
// maxSamplesPerIP already had this guard — `if maxSamplesPerIP <= 60` — and
// maxTrackedIPs did not, which is what makes the omission worth a name rather
// than a line: the same file knew the shape and applied it once.
//
// The number: the cap is a refusal rather than an eviction, so a cap below the
// legitimate source population converts a memory bound into a functional one —
// every source past it is permanently first-seen and can never accumulate a
// score. A bridge in front of a public vault sees far more than ten thousand
// distinct sources inside a flag TTL. 10k is an order of magnitude below the
// shipped 50k, so ordinary tuning does not trip this and gutting it does.
const minTrackedIPs = 10_000

// TestTheDistinctSourceCapIsADoSBoundNotAFunctionalOne is the anti-vacuity floor
// under all four cap tests.
//
// It drives its loops from the floor rather than from the constant, so it is a
// statement about the constant instead of a statement about itself.
func TestTheDistinctSourceCapIsADoSBoundNotAFunctionalOne(t *testing.T) {
	if maxTrackedIPs < minTrackedIPs {
		t.Fatalf("maxTrackedIPs = %d, below the floor of %d. Every cap test in this file drives "+
			"its loop with this constant and asserts against it, so all of them pass at any value. "+
			"Below the floor the cap stops being a memory bound and becomes a functional one: a "+
			"source past it is treated as first-seen forever and can never accumulate a score.",
			maxTrackedIPs, minTrackedIPs)
	}

	// The floor asserted behaviourally, not only as arithmetic: minTrackedIPs
	// distinct sources are each tracked, and the first one keeps counting.
	rt := NewRateTracker(time.Minute)
	for i := 0; i < minTrackedIPs; i++ {
		if got := rt.Record(slash96(i)); got != 1 {
			t.Fatalf("first Record of source %d of %d = %d, want 1; the tracker stopped taking "+
				"new sources below the floor", i, minTrackedIPs, got)
		}
	}
	if got := len(rt.buckets); got != minTrackedIPs {
		t.Fatalf("buckets = %d after %d distinct sources; the tracker is refusing sources it has "+
			"to be able to hold", got, minTrackedIPs)
	}
	if got := rt.Record(slash96(0)); got != 2 {
		t.Fatalf("the first source stopped counting at %d once %d were tracked", got, minTrackedIPs)
	}

	// The score map shares the constant, so it shares the floor, and scoring is
	// the half that matters: a source the map will not hold can never reach
	// FlagThreshold whatever it does.
	sm := NewScoreMap()
	for i := 0; i < minTrackedIPs; i++ {
		if got := sm.Add(slash96(i), 1); got != 1 {
			t.Fatalf("Add for source %d of %d = %d, want 1; the score map refused a source below "+
				"the floor, so it can never reach FlagThreshold", i, minTrackedIPs, got)
		}
	}
	if got := sm.Get(slash96(minTrackedIPs - 1)); got != 1 {
		t.Fatalf("the last source below the floor scores %d, want 1", got)
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
