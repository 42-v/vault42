package alert

import (
	"context"
	"log"
	"sync"
	"time"
)

// DefaultMaxKeys is how many distinct (rule, scope, key) counters one detector
// holds.
//
// The number is a memory bound rather than a tuning knob. Each counter is a
// bounded key string and three timestamps, so the whole map is well under a
// megabyte at this size, and the reason it needs a bound at all is that the
// attacker picks the keys: a stuffing run supplies a fresh subject and a fresh
// address per attempt, and an unbounded map keyed on either would be a memory
// exhaustion primitive handed out with the detection.
const DefaultMaxKeys = 4096

// saturationCooldown is how long the detector stays quiet after reporting that
// its key space is full. Saturation is a sustained condition, so reporting it
// per observation would reproduce the flood it is reporting.
const saturationCooldown = 15 * time.Minute

// counter is one windowed count.
type counter struct {
	// count is how many events have arrived since the window opened.
	count int
	// opened is when the current window started. A count decays by the window
	// being reopened on the next event, not by any sweeper: nothing in this
	// package runs on a timer.
	opened time.Time
	// silentUntil suppresses further alerts for this key. Events keep being
	// counted through it, so the count carried by the next alert says how much
	// was suppressed.
	silentUntil time.Time
	// deadAfter is when this counter stops being worth keeping: its window has
	// closed and any cooldown it set has lapsed. It is stored rather than
	// derived because the rule is not on the counter, and reclaiming a key whose
	// cooldown is still running would re-arm the flood the cooldown suppresses.
	deadAfter time.Time
}

// Detector keeps windowed counts over security events and raises an alert when
// one crosses its rule's threshold.
//
// It is entirely in process and deliberately so. A shared counter would need a
// store on the request path, which is a new dependency whose outage would have
// to either fail the login or fail the detection. A per-replica counter means N
// replicas each need N times fewer events to notice, which makes a fleet slower
// to alert but never blind, and costs nothing when it is down because there is
// nothing to be down.
type Detector struct {
	sink    Sink
	maxKeys int

	mu             sync.Mutex
	counters       map[string]*counter
	saturatedUntil time.Time
}

// NewDetector returns a detector delivering to sink. A nil sink makes it inert,
// which is the state every unit test in the tree that builds an audit logger is
// in. maxKeys below one falls back to DefaultMaxKeys.
func NewDetector(sink Sink, maxKeys int) *Detector {
	if maxKeys < 1 {
		maxKeys = DefaultMaxKeys
	}
	return &Detector{
		sink:     sink,
		maxKeys:  maxKeys,
		counters: make(map[string]*counter),
	}
}

// TrackedKeys reports how many counters the detector currently holds. It is the
// number the key-space bound is asserted against.
func (d *Detector) TrackedKeys() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.counters)
}

// Observe records one event against rule r and delivers any alert it raises.
//
// now is passed in rather than read here so the caller can use the timestamp the
// audit entry already carries: the alert then describes the same instant the
// record does, and the windows are testable without a clock seam whose only
// consumer would be the test. It is the same shape as the honeypot's own
// alertBudget.take(now).
//
// Both identities are counted. Delivery happens after the lock is released, so a
// slow sink delays its own caller and nothing else.
func (d *Detector) Observe(ctx context.Context, now time.Time, r Rule, eventType, subject, source string) {
	if d.sink == nil || !r.valid() {
		return
	}

	eventType = safeField(eventType)
	var raised []Alert
	for _, id := range []struct{ scope, key string }{
		{ScopeSubject, safeField(subject)},
		{ScopeSource, safeField(source)},
	} {
		if id.key == "" {
			continue
		}
		if a, ok := d.count(now, r, eventType, id.scope, id.key); ok {
			raised = append(raised, a)
		}
	}

	for _, a := range raised {
		raiseSecurityAlert()
		d.deliver(ctx, a)
	}
}

// count advances one counter under the lock and reports the alert it raises.
func (d *Detector) count(now time.Time, r Rule, eventType, scope, key string) (Alert, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// The rule name is part of the key so two rules watching the same subject
	// keep independent counts, and \x00 separates the parts because it is the
	// one byte safeField cannot leave in either of them.
	k := r.Name + "\x00" + scope + "\x00" + key

	c, known := d.counters[k]
	if !known {
		if !d.makeRoom(now) {
			return d.reportSaturation(now, r, eventType, scope)
		}
		c = &counter{opened: now}
		d.counters[k] = c
	}

	if now.Sub(c.opened) >= r.Window {
		c.count = 0
		c.opened = now
	}
	c.count++
	c.deadAfter = now.Add(r.Window)

	if now.Before(c.silentUntil) || c.count < r.Threshold {
		return Alert{}, false
	}

	observed := c.count
	c.silentUntil = now.Add(r.Cooldown)
	c.count = 0
	c.opened = now
	if c.silentUntil.After(c.deadAfter) {
		c.deadAfter = c.silentUntil
	}

	return Alert{
		Rule:      r.Name,
		EventType: eventType,
		Scope:     scope,
		Key:       key,
		Count:     observed,
		Window:    r.Window,
		Severity:  r.Severity,
		Breach:    r.Breach,
		At:        now,
	}, true
}

// makeRoom reports whether a new counter can be admitted, reclaiming dead ones
// first. Called with the lock held.
//
// Reclamation is what makes the bound survivable: ordinary traffic produces a
// steady churn of one-off subjects and addresses, and every one of them is dead
// a window later. The sweep is only run when the map is full, so its cost falls
// on the traffic that filled it.
func (d *Detector) makeRoom(now time.Time) bool {
	if len(d.counters) < d.maxKeys {
		return true
	}
	for k, c := range d.counters {
		if !now.Before(c.deadAfter) {
			delete(d.counters, k)
		}
	}
	return len(d.counters) < d.maxKeys
}

// reportSaturation raises the detector's own alert, at most once per cooldown.
// Called with the lock held; the returned alert is delivered by the caller once
// the lock is released.
func (d *Detector) reportSaturation(now time.Time, r Rule, eventType, scope string) (Alert, bool) {
	if now.Before(d.saturatedUntil) {
		return Alert{}, false
	}
	d.saturatedUntil = now.Add(saturationCooldown)
	return Alert{
		Rule:      RuleSaturated,
		EventType: eventType,
		Scope:     scope,
		Key:       "n/a",
		Count:     d.maxKeys,
		Window:    r.Window,
		Severity:  r.Severity,
		At:        now,
	}, true
}

// deliver hands one alert to the sink, containing a panic.
//
// A sink is the one part of this package a deployment replaces, and the caller
// underneath it is the login path. Letting a third-party implementation's panic
// unwind through audit.Logger.Log would turn a broken alert destination into a
// failed authentication, which is the exact inversion vault42's convention on
// observability forbids.
func (d *Detector) deliver(ctx context.Context, a Alert) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("alert: sink panicked delivering rule=%s; the alert is lost and the caller "+
				"is not: %v", a.Rule, r)
		}
	}()
	d.sink.Deliver(ctx, a)
}
