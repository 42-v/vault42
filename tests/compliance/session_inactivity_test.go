package compliance

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/config"
	"github.com/42-v/vault42/internal/service"
)

// =============================================================================
// Inactivity timeout and reauthentication.
//
// ASVS V7.1.1, V7.3.1, NIST SP 800-63B-4 §2.2.3 and §5.2 and NIST SP 800-53
// Rev 5 AC-12 all rest on one mechanism, and the register's rule is that a Met
// row names a test which proves THAT row. So they do not share one: each of the
// four tests below asserts the clause its own requirement is written in, and
// the supporting properties — fail-closed, the clamp, and which check does the
// refusing — are asserted separately again, because a control that refuses for
// the wrong reason is a control that will stop refusing when the wrong reason
// changes.
//
// Durations here are hours because the bound is measured from the family's last
// rotation and the access token TTL sets the rotation cadence. A fixture using
// minutes on both sides would be asserting a misconfiguration.
// =============================================================================

const (
	// fixtureAccessTTL and fixtureIdleTimeout keep the same relationship the
	// shipped defaults do: the idle window is several access-token lifetimes
	// wide, so a client in normal use rotates well inside it.
	fixtureAccessTTL   = 15 * time.Minute
	fixtureIdleTimeout = 1 * time.Hour
	// fixtureRefreshTTL is deliberately far longer than the idle window. Every
	// refusal below therefore has to come from the inactivity check: the
	// ordinary expiry check cannot fire inside a week.
	fixtureRefreshTTL = 168 * time.Hour
	// fixtureMaxLifetime is the shipped absolute default, present so the outer
	// bound is live in every test rather than switched off around the one under
	// assertion.
	fixtureMaxLifetime = 720 * time.Hour
)

// newIdleFixture is the standard wiring: shipped-shaped bounds, nothing
// disabled.
func newIdleFixture(t *testing.T) *sessionFixture {
	t.Helper()
	return newSessionFixture(t, fixtureAccessTTL, fixtureRefreshTTL, fixtureMaxLifetime, fixtureIdleTimeout)
}

// --- ASVS V7.3.1 — "there is an inactivity timeout such that re-authentication
// is enforced" ---

// The operative words are "there is" and "enforced". A configured duration that
// nothing consults satisfies neither, so this drives the real refresh path and
// asserts the rotation is refused — and asserts the negative half in the same
// test, because "always refuses" would also pass the positive half alone.
func TestASVS_V7_3_1_AnIdleSessionCannotRotateAndAnActiveOneCan(t *testing.T) {
	f := newIdleFixture(t)
	live := f.login(t)

	// Just inside the window: the session is idle but not idle enough.
	f.tokens.age(fixtureIdleTimeout - time.Minute)
	if _, err := f.refresh(live.RefreshToken); err != nil {
		t.Fatalf("V7.3.1: a session idle for less than the timeout was refused (%v). An inactivity "+
			"bound that refuses inside its own window is not an inactivity bound, it is an outage.", err)
	}

	// Past the window on a fresh session.
	idle := newIdleFixture(t)
	dead := idle.login(t)
	idle.tokens.age(fixtureIdleTimeout + time.Minute)
	if _, err := idle.refresh(dead.RefreshToken); err == nil {
		t.Fatalf("V7.3.1: a session that went unused for longer than the %s inactivity timeout was "+
			"rotated anyway. There is no inactivity timeout.", fixtureIdleTimeout)
	} else if !errors.Is(err, service.ErrSessionIdle) {
		t.Errorf("V7.3.1: an idle session was refused with %v rather than ErrSessionIdle; the refusal "+
			"is coming from some other control and would survive the inactivity bound being removed", err)
	}
}

// --- NIST SP 800-63B-4 §5.2 — Reauthentication ---

// §2.2.3 says that when the inactivity timeout has passed but the overall one
// has not, a verifier MAY accept a password or biometric together with the
// session secret. MAY, not SHALL. vault42 does not take that option: it ends
// the family, so the way back is a full login through the same path a new
// session uses, at the same authentication strength.
//
// That decision is what this asserts, and it is asserted as a property of the
// system rather than as a comment: after the idle refusal no credential the
// idle session still holds gets anything, and a real login does.
func TestNIST63B4_5_2_ReauthenticationMeansANewLoginNotAnotherRotation(t *testing.T) {
	f := newIdleFixture(t)
	first := f.login(t)
	family := f.familyOf(t, first.RefreshToken)

	f.tokens.age(fixtureIdleTimeout + time.Minute)
	if _, err := f.refresh(first.RefreshToken); !errors.Is(err, service.ErrSessionIdle) {
		t.Fatalf("5.2: the idle rotation was not refused with ErrSessionIdle (%v); the rest of this "+
			"test would be asserting against a session that never timed out", err)
	}

	// The session secret is now worth nothing on its own. Presenting it again
	// must not get a token, and must not get one on the second attempt either —
	// a bound that only refuses once is a retry away from not existing.
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := f.refresh(first.RefreshToken); err == nil {
			t.Fatalf("5.2: attempt %d with the timed-out session secret was accepted", attempt)
		}
	}
	if !f.tokens.familyRevoked(family) {
		t.Error("5.2: the timed-out family was left live, so reauthentication is not required — any " +
			"other generation of it would still rotate")
	}

	// And a genuine reauthentication does work, at full strength, through Login.
	fresh := f.login(t)
	if _, err := f.refresh(fresh.RefreshToken); err != nil {
		t.Errorf("5.2: reauthenticating produced a session that could not be used (%v); the timeout "+
			"would be terminating the account rather than the session", err)
	}
}

// --- NIST SP 800-53 Rev 5 AC-12 — Session Termination ---

// AC-12 asks for automatic TERMINATION on a defined trigger, not for one
// request to be refused. The distinction is the whole control: refusing the
// call and leaving the family live would let any other generation of it rotate,
// and would leave the session counted against the user's concurrent-session cap
// for the rest of its refresh TTL.
//
// Explicit termination is asserted by
// TestNIST80053_AC_12_ExplicitTerminationRevokesEveryFamily; this is the
// inactivity trigger, which is the half that did not exist.
func TestNIST80053_AC_12_InactivityTerminatesTheWholeFamily(t *testing.T) {
	f := newIdleFixture(t)
	session := f.login(t)
	family := f.familyOf(t, session.RefreshToken)

	// One rotation first, so the family has more than one generation and
	// "terminated" is a claim about the family rather than about one row.
	rotated, err := f.refresh(session.RefreshToken)
	if err != nil {
		t.Fatalf("AC-12: the first rotation failed (%v)", err)
	}

	f.tokens.age(fixtureIdleTimeout + time.Minute)
	if _, err := f.refresh(rotated.RefreshToken); !errors.Is(err, service.ErrSessionIdle) {
		t.Fatalf("AC-12: the idle rotation was not refused with ErrSessionIdle (%v)", err)
	}

	if !f.tokens.familyRevoked(family) {
		t.Error("AC-12: the inactivity trigger refused a request but did not terminate the session; " +
			"every other generation of the family is still live")
	}
	if n, err := f.tokens.CountActiveFamilies(t.Context(), "00000000-0000-0000-0000-0000000000aa"); err != nil || n != 0 {
		t.Errorf("AC-12: after termination the user still holds %d active session families (err=%v); "+
			"a terminated session must stop occupying the concurrent-session cap", n, err)
	}
	// The operator has to be able to see it happened, and see why.
	if reasons := f.auditReasons(); !contains(reasons, "session_inactivity_exceeded") {
		t.Errorf("AC-12: no audit record names the inactivity trigger; reasons recorded were %v", reasons)
	}
}

// --- ASVS V7.1.1 — documented timeouts, and the deviation justification ---

// Three clauses: both timeouts documented, appropriate in combination, and the
// deviation from NIST SP 800-63B justified. The register cites docs/config.md
// for all three, so this executes that file against the code rather than
// reading it: the documented default is parsed out of the published table and
// compared with what config.Load actually produces.
//
// The figures matter twice. docs/config.md was citing 12 hours as the AAL2
// reauthentication interval, which is the WITHDRAWN Rev 3 number — so the
// justification a reader was pointed at contradicted the standard it claimed to
// justify a deviation from. §2.2.3 of the current revision says 24 hours
// overall and 1 hour of inactivity. This fails if the withdrawn number comes
// back.
func TestASVS_V7_1_1_TheDocumentedTimeoutsAreTheEnforcedOnes(t *testing.T) {
	doc := readProductionSource(t, "docs/config.md")

	for _, tc := range []struct {
		envKey string
		got    func(config.Config) time.Duration
	}{
		{"VAULT_MAX_SESSION_LIFETIME", func(c config.Config) time.Duration { return c.MaxSessionLifetime }},
		{"VAULT_INACTIVITY_TIMEOUT", func(c config.Config) time.Duration { return c.InactivityTimeout }},
	} {
		t.Run(tc.envKey, func(t *testing.T) {
			documented := documentedDefault(t, doc, tc.envKey)
			t.Setenv(tc.envKey, "")
			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("V7.1.1: config.Load: %v", err)
			}
			if got := tc.got(*cfg); got != documented {
				t.Errorf("V7.1.1: docs/config.md documents %s as %s and the code enforces %s. The "+
					"requirement is that the timeouts are documented, so the document has to be the "+
					"one that is true.", tc.envKey, documented, got)
			}
		})
	}

	// The justification clause. It has to name the standard's current figures,
	// and it has to not name the withdrawn one.
	for _, phrase := range []string{"24 hours", "1 hour", "§2.2.3"} {
		if !strings.Contains(doc, phrase) {
			t.Errorf("V7.1.1: docs/config.md no longer states %q, so the deviation from NIST SP "+
				"800-63B-4 is no longer justified where this row says it is", phrase)
		}
	}
	if regexp.MustCompile(`(?i)(AAL2|2\.2\.3)[^.|]*\b12\s*(h|hours)\b`).MatchString(doc) {
		t.Error("V7.1.1: docs/config.md is citing 12 hours as the AAL2 reauthentication figure again. " +
			"That is the withdrawn Rev 3 number; the current revision says 24 hours overall and 1 hour " +
			"of inactivity, and this row's whole claim is that the justification quotes the standard " +
			"it deviates from correctly.")
	}
}

// documentedDefaultCell pulls the Default column out of a row of the published
// environment-variable table: | `KEY` | type | `default` | ...
var documentedDefaultCell = regexp.MustCompile("^\\|\\s*`([A-Z0-9_]+)`\\s*\\|[^|]*\\|\\s*`([^`]+)`\\s*\\|")

// documentedDefault returns the default docs/config.md publishes for one
// variable, parsed as a duration.
func documentedDefault(t *testing.T, doc, envKey string) time.Duration {
	t.Helper()
	lines := strings.Split(doc, "\n")
	if len(lines) < 100 {
		t.Fatalf("V7.1.1: docs/config.md came back as %d lines; the scan is broken and every "+
			"assertion over it would be vacuous", len(lines))
	}
	for _, line := range lines {
		m := documentedDefaultCell.FindStringSubmatch(line)
		if m == nil || m[1] != envKey {
			continue
		}
		d, err := time.ParseDuration(m[2])
		if err != nil {
			t.Fatalf("V7.1.1: docs/config.md documents %s's default as %q, which is not a duration: %v",
				envKey, m[2], err)
		}
		return d
	}
	t.Fatalf("V7.1.1: docs/config.md has no table row documenting %s. The requirement is that the "+
		"timeout is documented; an undocumented one cannot satisfy it.", envKey)
	return 0
}

// --- NIST SP 800-63B-4 §2.2.3 — the two SHOULDs, and the supporting properties ---

// §2.2.3's inactivity SHOULD is one hour, and that is now the shipped default.
// Its overall SHOULD is 24 hours and the shipped default is 720, which is why
// this row is still an accepted risk under CR-14 rather than Met.
//
// Both halves are asserted here so the row cannot drift in either direction: if
// the overall default drops to 24 the deviation is gone and CR-14 closes, and
// if the inactivity default rises above an hour the SHOULD this change
// satisfied stops being satisfied.
func TestNIST63B4_2_2_3_TheInactivityDefaultIsTheAAL2FigureAndTheOverallOneIsNot(t *testing.T) {
	t.Setenv("VAULT_INACTIVITY_TIMEOUT", "")
	t.Setenv("VAULT_MAX_SESSION_LIFETIME", "")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("2.2.3: config.Load: %v", err)
	}

	if cfg.InactivityTimeout <= 0 {
		t.Fatalf("2.2.3: the inactivity timeout defaults to %v, so no inactivity timeout is "+
			"established out of the box. This reopens the half of CR-14 that closed.", cfg.InactivityTimeout)
	}
	if cfg.InactivityTimeout > time.Hour {
		t.Errorf("2.2.3: the inactivity timeout defaults to %v, above the 1-hour AAL2 SHOULD. "+
			"CR-14 widens again: update the register and this assertion.", cfg.InactivityTimeout)
	}
	if cfg.MaxSessionLifetime <= 24*time.Hour {
		t.Errorf("2.2.3: the overall timeout now defaults to %v, inside the 24-hour SHOULD. CR-14 "+
			"closes: move the row to Met, retire the risk, and replace this assertion.",
			cfg.MaxSessionLifetime)
	}
	t.Logf("2.2.3: inactivity %v (AAL2 SHOULD is 1h, met); overall %v (AAL2 SHOULD is 24h, CR-14)",
		cfg.InactivityTimeout, cfg.MaxSessionLifetime)
}

// A refusal is only evidence for the inactivity bound if the inactivity bound is
// what produced it. The fixture ages created_at without touching expires_at
// precisely so the ordinary expiry check cannot be the one refusing; this pins
// that, by asserting the same session is accepted with the bound switched off
// and refused with it on, changing nothing else.
func TestNIST63B4_2_2_3_AnIdleSessionIsRefusedByTheInactivityCheckItself(t *testing.T) {
	unbounded := newSessionFixture(t, fixtureAccessTTL, fixtureRefreshTTL, fixtureMaxLifetime, 0)
	session := unbounded.login(t)
	unbounded.tokens.age(fixtureIdleTimeout + time.Minute)
	if _, err := unbounded.refresh(session.RefreshToken); err != nil {
		t.Fatalf("2.2.3: with VAULT_INACTIVITY_TIMEOUT=0 an idle session was still refused (%v). "+
			"Something other than the inactivity bound is refusing, so every other assertion in this "+
			"file could be passing for the wrong reason.", err)
	}

	bounded := newIdleFixture(t)
	same := bounded.login(t)
	bounded.tokens.age(fixtureIdleTimeout + time.Minute)
	if _, err := bounded.refresh(same.RefreshToken); !errors.Is(err, service.ErrSessionIdle) {
		t.Fatalf("2.2.3: with the bound configured, the identically-aged session was not refused with "+
			"ErrSessionIdle (%v)", err)
	}
}

// Fail closed. enforceSessionLifetime refuses when a family's age cannot be
// established, and the inactivity check has to do the same: a store that stops
// reporting when a token was issued must not turn an idle session into an
// unbounded one.
//
// created_at is NOT NULL in the schema, so this is not a row Postgres can
// produce. It is the store-level failure — a query that stopped selecting the
// column, a repository substituted at wiring time — and it is the one that
// would otherwise be silent.
//
// THE ABSOLUTE BOUND IS SWITCHED OFF HERE, and that is not a convenience. The
// family's origin is read from the same column, so with the absolute bound on,
// enforceSessionLifetime fails closed on this input first and the request is
// refused before the inactivity check runs at all. The first version of this
// test left it on, passed, and went on passing after the inactivity refusal was
// mutated into a discarded error — it was evidence for the wrong control. The
// third case below is what keeps that honest: with both bounds off the same row
// rotates, so the refusal in the second case can only have come from the
// inactivity check.
func TestNIST63B4_2_2_3_AnUnreadableIssuanceInstantFailsClosed(t *testing.T) {
	f := newSessionFixture(t, fixtureAccessTTL, fixtureRefreshTTL, 0, fixtureIdleTimeout)
	session := f.login(t)

	f.tokens.clearIssuanceInstants()
	_, err := f.refresh(session.RefreshToken)
	if err == nil {
		t.Fatal("2.2.3: a refresh token carrying no issuance instant was rotated anyway. An " +
			"unreadable timestamp silently becomes an unbounded idle session.")
	}
	if !errors.Is(err, service.ErrSessionAgeUnknown) {
		t.Errorf("2.2.3: the fail-closed refusal was %v, not ErrSessionAgeUnknown", err)
	}
	if reasons := f.auditReasons(); !contains(reasons, "session_age_unavailable") {
		t.Errorf("2.2.3: nothing was audited when the bound became unenforceable; reasons were %v", reasons)
	}

	// Both bounds off: the same unreadable row must rotate, or the refusal above
	// was some other control and this test proves nothing.
	unbounded := newSessionFixture(t, fixtureAccessTTL, fixtureRefreshTTL, 0, 0)
	other := unbounded.login(t)
	unbounded.tokens.clearIssuanceInstants()
	if _, err := unbounded.refresh(other.RefreshToken); err != nil {
		t.Fatalf("2.2.3: with no session bound configured at all, an unreadable issuance instant "+
			"still refused the rotation (%v). The refusal above is not the inactivity check failing "+
			"closed.", err)
	}
}

// Rotation is the activity signal, so a session that keeps rotating keeps
// living — for longer than the idle window, indefinitely, which is exactly what
// the ABSOLUTE bound exists to stop and what this bound deliberately does not.
//
// Without this, an implementation that measured idleness from the family's
// birth date rather than from its last rotation would pass every other test
// here and log every user out an hour after they signed in.
func TestNIST63B4_2_2_3_RotationIsWhatKeepsASessionAlive(t *testing.T) {
	f := newIdleFixture(t)
	token := f.login(t).RefreshToken

	const rotations = 4
	step := fixtureIdleTimeout - 10*time.Minute
	for i := 1; i <= rotations; i++ {
		f.tokens.age(step)
		res, err := f.refresh(token)
		if err != nil {
			t.Fatalf("2.2.3: rotation %d of %d, at %s since login, was refused (%v). Idleness is "+
				"being measured from something other than the last rotation.",
				i, rotations, time.Duration(i)*step, err)
		}
		token = res.RefreshToken
	}
	if total := time.Duration(rotations) * step; total <= fixtureIdleTimeout {
		t.Fatalf("2.2.3: the fixture only advanced %s, inside the %s window, so it never demonstrated "+
			"that rotation extends the session", total, fixtureIdleTimeout)
	}
}

// The absolute bound is the outer limit and the inactivity clamp must not be
// able to move it outward. Both are applied to the same expiry, and the order
// they are applied in is not allowed to matter.
func TestNIST63B4_2_2_3_TheIdleClampNeverExtendsTheAbsoluteBound(t *testing.T) {
	// An absolute bound far tighter than the idle window: every expiry the
	// service issues has to land on the absolute deadline, never an idle window
	// past it.
	const maxLifetime = 30 * time.Minute
	f := newSessionFixture(t, fixtureAccessTTL, fixtureRefreshTTL, maxLifetime, fixtureIdleTimeout)

	login := f.login(t)
	if maxAge := time.Duration(login.CookieMaxAge) * time.Second; maxAge > maxLifetime {
		t.Errorf("2.2.3: a new session's refresh cookie lives %s, past the %s absolute bound",
			maxAge, maxLifetime)
	}

	f.tokens.age(10 * time.Minute)
	rotated, err := f.refresh(login.RefreshToken)
	if err != nil {
		t.Fatalf("2.2.3: the rotation inside both bounds was refused (%v)", err)
	}
	// 10 minutes into a 30-minute family, the rotated token may live 20 more
	// minutes at most. An unclamped rotation would take the full idle window.
	if maxAge := time.Duration(rotated.CookieMaxAge) * time.Second; maxAge > maxLifetime-10*time.Minute {
		t.Errorf("2.2.3: a rotation 10 minutes into a %s family issued a refresh token good for %s. "+
			"The last rotation before the deadline walked out past it.", maxLifetime, maxAge)
	}
}

// The clamp's other job: a session that has timed out has to stop being counted
// as active, or the user's concurrent-session cap fills with sessions that can
// never be rotated again.
//
// Nothing sweeps the table on a timer, so this can only come from the stored
// expires_at. Without the clamp the row would claim the full refresh TTL — a
// week — and go on holding a slot for all of it.
func TestNIST63B4_2_2_3_AnIdleSessionStopsHoldingItsSlot(t *testing.T) {
	f := newIdleFixture(t)
	f.login(t)

	const userID = "00000000-0000-0000-0000-0000000000aa"
	if n, err := f.tokens.CountActiveFamilies(t.Context(), userID); err != nil || n != 1 {
		t.Fatalf("2.2.3: a session that was just created counts as %d active families (err=%v)", n, err)
	}

	f.tokens.ageEverything(fixtureIdleTimeout + time.Minute)
	n, err := f.tokens.CountActiveFamilies(t.Context(), userID)
	if err != nil {
		t.Fatalf("2.2.3: counting active families: %v", err)
	}
	if n != 0 {
		t.Errorf("2.2.3: %s after its last rotation the session still counts as active. Its stored "+
			"expires_at was not clamped to the inactivity window, so it holds a slot in the "+
			"concurrent-session cap for the whole %s refresh TTL.",
			fixtureIdleTimeout+time.Minute, fixtureRefreshTTL)
	}
}
