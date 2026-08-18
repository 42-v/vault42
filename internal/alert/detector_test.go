package alert

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// recordingSink captures what a detector delivered.
type recordingSink struct {
	mu     sync.Mutex
	alerts []Alert
}

func (s *recordingSink) Deliver(_ context.Context, a Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alerts = append(s.alerts, a)
}

func (s *recordingSink) all() []Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Alert, len(s.alerts))
	copy(out, s.alerts)
	return out
}

func testRule() Rule {
	return Rule{
		Name:      "credential-stuffing",
		Threshold: 5,
		Window:    5 * time.Minute,
		Cooldown:  15 * time.Minute,
	}
}

// A single event is not an alert, and neither are four of them. The whole point
// of a windowed count is that it says something no single event says, and a
// notification per failed login is a mail bomb aimed at whoever receives it.
func TestDetector_BelowThresholdRaisesNothing(t *testing.T) {
	sink := &recordingSink{}
	d := NewDetector(sink, 64)
	r := testRule()
	base := time.Unix(1_700_000_000, 0)

	for i := 0; i < r.Threshold-1; i++ {
		d.Observe(context.Background(), base.Add(time.Duration(i)*time.Second), r, "login_failure", "user-1", "")
	}

	if got := sink.all(); len(got) != 0 {
		t.Fatalf("%d events below a threshold of %d raised %d alerts, want 0: %+v",
			r.Threshold-1, r.Threshold, len(got), got)
	}
}

// The threshold event raises exactly one alert, and every event after it inside
// the cooldown raises none. A credential-stuffing run is thousands of events; an
// alert per event is functionally the same as no alert at all.
func TestDetector_ThresholdRaisesExactlyOneAlert(t *testing.T) {
	sink := &recordingSink{}
	d := NewDetector(sink, 64)
	r := testRule()
	base := time.Unix(1_700_000_000, 0)

	for i := 0; i < 500; i++ {
		d.Observe(context.Background(), base.Add(time.Duration(i)*time.Second), r, "login_failure", "user-1", "")
	}

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("500 events raised %d alerts, want exactly 1: %+v", len(got), got)
	}
	if got[0].Rule != r.Name {
		t.Errorf("alert rule = %q, want %q", got[0].Rule, r.Name)
	}
	if got[0].Count != r.Threshold {
		t.Errorf("alert count = %d, want the threshold %d", got[0].Count, r.Threshold)
	}
	if got[0].Scope != ScopeSubject {
		t.Errorf("alert scope = %q, want %q", got[0].Scope, ScopeSubject)
	}
	if got[0].Key != "user-1" {
		t.Errorf("alert key = %q, want the subject", got[0].Key)
	}
}

// The cooldown expires. A campaign that outlives it has to be reported again,
// or a single alert at the start of a week-long run is the only thing an
// operator ever sees.
func TestDetector_AlertsAgainAfterTheCooldown(t *testing.T) {
	sink := &recordingSink{}
	d := NewDetector(sink, 64)
	r := testRule()
	base := time.Unix(1_700_000_000, 0)

	for i := 0; i < r.Threshold; i++ {
		d.Observe(context.Background(), base, r, "login_failure", "user-1", "")
	}
	later := base.Add(r.Cooldown + time.Second)
	for i := 0; i < r.Threshold; i++ {
		d.Observe(context.Background(), later, r, "login_failure", "user-1", "")
	}

	if got := sink.all(); len(got) != 2 {
		t.Fatalf("a run either side of the cooldown raised %d alerts, want 2: %+v", len(got), got)
	}
}

// Events spread thinner than the window never accumulate. A threshold with no
// window is a lifetime counter that eventually fires for every account that has
// ever mistyped a password.
func TestDetector_CountsDecayWithTheWindow(t *testing.T) {
	sink := &recordingSink{}
	d := NewDetector(sink, 64)
	r := testRule()
	base := time.Unix(1_700_000_000, 0)

	for i := 0; i < 50; i++ {
		d.Observe(context.Background(), base.Add(time.Duration(i)*(r.Window+time.Second)), r, "login_failure", "user-1", "")
	}

	if got := sink.all(); len(got) != 0 {
		t.Fatalf("events one window apart raised %d alerts, want 0: %+v", len(got), got)
	}
}

// A run against many accounts from one address is the shape credential stuffing
// actually takes, and no per-subject counter would ever see it.
func TestDetector_CorrelatesBySourceWhenTheSubjectVaries(t *testing.T) {
	sink := &recordingSink{}
	d := NewDetector(sink, 64)
	r := testRule()
	base := time.Unix(1_700_000_000, 0)

	for i := 0; i < r.Threshold; i++ {
		subject := string(rune('a'+i)) + "-victim"
		d.Observe(context.Background(), base, r, "login_failure", subject, "203.0.113.0")
	}

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("%d failures against %d subjects from one address raised %d alerts, want 1: %+v",
			r.Threshold, r.Threshold, len(got), got)
	}
	if got[0].Scope != ScopeSource {
		t.Errorf("alert scope = %q, want %q", got[0].Scope, ScopeSource)
	}
	if got[0].Key != "203.0.113.0" {
		t.Errorf("alert key = %q, want the source network", got[0].Key)
	}
}

// The key space is chosen by whoever is attacking: a stuffing run supplies a
// fresh subject and a fresh address per attempt. An unbounded map keyed on
// either is a memory exhaustion primitive handed out with the detection.
func TestDetector_KeySpaceIsBoundedAndSaturationIsReported(t *testing.T) {
	sink := &recordingSink{}
	const maxKeys = 8
	d := NewDetector(sink, maxKeys)
	r := testRule()
	base := time.Unix(1_700_000_000, 0)

	for i := 0; i < 10_000; i++ {
		d.Observe(context.Background(), base, r, "login_failure", "", "198.51.100."+itoa(i))
	}

	if n := d.TrackedKeys(); n > maxKeys {
		t.Errorf("detector tracks %d keys with a cap of %d; the map is unbounded", n, maxKeys)
	}
	var saturated int
	for _, a := range sink.all() {
		if a.Rule == RuleSaturated {
			saturated++
		}
	}
	if saturated != 1 {
		t.Fatalf("10000 distinct sources raised %d saturation alerts, want exactly 1; "+
			"a detector that silently stops detecting is worse than one that never started", saturated)
	}
}

// A key nobody has used since before the window is dead weight. Reclaiming it is
// what lets a bounded map survive ordinary traffic without saturating.
func TestDetector_ExpiredKeysAreReclaimed(t *testing.T) {
	sink := &recordingSink{}
	d := NewDetector(sink, 4)
	r := testRule()
	base := time.Unix(1_700_000_000, 0)

	for i := 0; i < 4; i++ {
		d.Observe(context.Background(), base, r, "login_failure", "", "198.51.100."+itoa(i))
	}
	if d.TrackedKeys() != 4 {
		t.Fatalf("tracked %d keys after 4 distinct sources, want 4", d.TrackedKeys())
	}

	// One window plus one cooldown later every one of them is expired, so a
	// fifth source has somewhere to go without evicting a live counter.
	d.Observe(context.Background(), base.Add(r.Window+r.Cooldown+time.Second), r, "login_failure", "", "198.51.100.99")
	if d.TrackedKeys() != 1 {
		t.Errorf("tracked %d keys after every earlier one expired, want 1", d.TrackedKeys())
	}
	for _, a := range sink.all() {
		if a.Rule == RuleSaturated {
			t.Error("a detector with room after expiry reported saturation")
		}
	}
}

// The subject reaches the audit log from POST /mint, where it is asserted by the
// caller and never authenticated. An operator reads the alert in a terminal, and
// a terminal acts on what it is sent.
func TestDetector_AttackerControlledKeysCannotForgeALogRecord(t *testing.T) {
	sink := &recordingSink{}
	d := NewDetector(sink, 64)
	r := testRule()
	r.Threshold = 1
	base := time.Unix(1_700_000_000, 0)

	subject := "victim\n2026-08-18 SECURITY ALERT: all clear\x1b[2Jrule=nothing"
	d.Observe(context.Background(), base, r, "login_failure", subject, "")

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("got %d alerts, want 1", len(got))
	}
	for _, bad := range []string{"\n", "\r", "\x1b", " "} {
		if strings.Contains(got[0].Key, bad) {
			t.Errorf("alert key %q still carries %q; a subject the caller chose can forge a record "+
				"in the operator's own log", got[0].Key, bad)
		}
	}
}

// Nothing bounds the length of a mint subject either, and an alert is a log
// line, so an unbounded key is an unbounded line per alert.
func TestDetector_KeysAreLengthBounded(t *testing.T) {
	sink := &recordingSink{}
	d := NewDetector(sink, 64)
	r := testRule()
	r.Threshold = 1

	d.Observe(context.Background(), time.Unix(1_700_000_000, 0), r,
		strings.Repeat("e", 4096), strings.Repeat("s", 65536), "")

	got := sink.all()
	if len(got) != 1 {
		t.Fatalf("got %d alerts, want 1", len(got))
	}
	if len(got[0].Key) > maxKeyLen {
		t.Errorf("alert key is %d bytes, above the %d-byte bound", len(got[0].Key), maxKeyLen)
	}
	if len(got[0].EventType) > maxKeyLen {
		t.Errorf("alert event type is %d bytes, above the %d-byte bound", len(got[0].EventType), maxKeyLen)
	}
}

// panickingSink stands in for any sink a future release plugs in.
type panickingSink struct{ calls int }

func (s *panickingSink) Deliver(context.Context, Alert) {
	s.calls++
	panic("the alert destination is having a bad day")
}

// vault42's convention is that observability never costs availability: the
// metrics listener's bind failure is deliberately non-fatal. A sink that panics
// must not take the caller down with it, because the caller is the login path.
func TestDetector_ASinkThatPanicsDoesNotTakeTheCallerDown(t *testing.T) {
	sink := &panickingSink{}
	d := NewDetector(sink, 64)
	r := testRule()
	r.Threshold = 1

	d.Observe(context.Background(), time.Unix(1_700_000_000, 0), r, "login_failure", "user-1", "")

	if sink.calls != 1 {
		t.Fatalf("sink was called %d times, want 1", sink.calls)
	}
}

// A detector with no sink is the state every unit test in the tree is in, and it
// must cost nothing rather than panic on a nil interface.
func TestDetector_NoSinkIsInert(t *testing.T) {
	d := NewDetector(nil, 64)
	r := testRule()
	r.Threshold = 1
	d.Observe(context.Background(), time.Unix(1_700_000_000, 0), r, "login_failure", "user-1", "")
	if d.TrackedKeys() != 0 {
		t.Errorf("a sinkless detector tracked %d keys; it should do no work at all", d.TrackedKeys())
	}
}

// A rule with no threshold would fire on every event, which is the amplifier
// this package exists to avoid, and a rule with no window would never decay.
func TestDetector_MalformedRulesAreIgnored(t *testing.T) {
	sink := &recordingSink{}
	d := NewDetector(sink, 64)
	base := time.Unix(1_700_000_000, 0)

	for _, r := range []Rule{
		{Name: "no-threshold", Threshold: 0, Window: time.Minute},
		{Name: "negative", Threshold: -1, Window: time.Minute},
		{Name: "no-window", Threshold: 1, Window: 0},
		{Name: "", Threshold: 1, Window: time.Minute},
	} {
		d.Observe(context.Background(), base, r, "login_failure", "user-1", "203.0.113.0")
	}

	if got := sink.all(); len(got) != 0 {
		t.Fatalf("a malformed rule raised %d alerts: %+v", len(got), got)
	}
}

// An event with neither a subject nor a source has nothing to correlate on.
func TestDetector_AnEventWithNoKeyIsNotCounted(t *testing.T) {
	sink := &recordingSink{}
	d := NewDetector(sink, 64)
	r := testRule()
	r.Threshold = 1

	d.Observe(context.Background(), time.Unix(1_700_000_000, 0), r, "login_failure", "", "")

	if got := sink.all(); len(got) != 0 {
		t.Fatalf("an event with no subject and no source raised %d alerts: %+v", len(got), got)
	}
	if d.TrackedKeys() != 0 {
		t.Errorf("tracked %d keys for an event with nothing to key on", d.TrackedKeys())
	}
}

// The detector is reached from every request path in the process.
func TestDetector_IsSafeUnderConcurrentObservation(t *testing.T) {
	sink := &recordingSink{}
	d := NewDetector(sink, 256)
	r := testRule()
	base := time.Unix(1_700_000_000, 0)

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				d.Observe(context.Background(), base.Add(time.Duration(i)*time.Millisecond), r,
					"login_failure", "user-"+itoa(g), "203.0.113."+itoa(g))
			}
		}(g)
	}
	wg.Wait()

	if len(sink.all()) == 0 {
		t.Error("16 goroutines past the threshold raised nothing")
	}
}

// itoa keeps the tests free of a strconv import that only formats loop indices.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// A caller that asks for no bound gets the package's, not an unbounded map.
func TestNewDetector_ARequestForNoBoundGetsTheDefault(t *testing.T) {
	for _, n := range []int{0, -1} {
		if got := NewDetector(&recordingSink{}, n).maxKeys; got != DefaultMaxKeys {
			t.Errorf("NewDetector(sink, %d) capped at %d, want the default %d", n, got, DefaultMaxKeys)
		}
	}
}
