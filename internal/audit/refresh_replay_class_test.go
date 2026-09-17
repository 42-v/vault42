package audit

import "testing"

// Refresh-token reuse detection was filed as the same event class as a logout.
//
// AuthService.Refresh writes a row every time a refresh token turns up after it
// was already spent, which is the single event single-use rotation exists to
// produce. It wrote that row as token_revoke with reason: "replay_detected",
// and the reason was the only thing separating it from the row Logout writes
// and from the one a session-lifetime expiry writes. Everything that reads this
// log reads the class, not the reason: the score comes off the class, and so
// does the alert rule. So the row scored routine, sorted below a mistyped
// password, and no rule could watch it without paging on every logout -- while
// fingerprint_anomaly and dpop_binding_mismatch, which only suspect on the same
// code path what this row proves, both scored serious and both paged.
//
// Three properties close that, and they are asserted here together because each
// one alone leaves the class half-wired: a score nothing alerts on is a review
// aid, an alert on a class the buffer may drop is a rule with a hole in it, and
// a durable row nothing scores is back where this started.
func TestRefreshTokenReplayIsItsOwnCriticalClass(t *testing.T) {
	if RefreshTokenReplayed == TokenRevoke {
		t.Fatal("refresh-token reuse shares the token_revoke class with logout again; the reason " +
			"key is metadata and nothing that reads this log reads metadata")
	}

	if got := Severity(RefreshTokenReplayed); got != SeverityCritical {
		t.Errorf("%s scores %d, want critical %d. A token presented twice has no benign version, "+
			"and it must not sort below the %d a failed login carries.",
			RefreshTokenReplayed, got, SeverityCritical, SeverityNotable)
	}

	if !isCriticalEvent(RefreshTokenReplayed) {
		t.Errorf("%s is droppable, so under a non-zero flush interval a full buffer erases the only "+
			"durable record that a stolen refresh cookie was used. It inherits the synchronous "+
			"write from token_revoke, which is what the containment path used to file it as.",
			RefreshTokenReplayed)
	}

	rule, watched := AlertRule(RefreshTokenReplayed)
	switch {
	case !watched:
		t.Errorf("%s raises no alert. Confirmed reuse would stay the one signal on the refresh path "+
			"an operator is never told about, while the two heuristics beside it page.",
			RefreshTokenReplayed)
	case rule.Threshold != 1:
		t.Errorf("the rule for %s waits for %d events. The family is burned by the time the row is "+
			"written, so a second one costs the attacker a second stolen session rather than a "+
			"second request; there is nothing to wait for.", RefreshTokenReplayed, rule.Threshold)
	case !rule.Breach:
		t.Errorf("the rule for %s is not marked breach-relevant, though a replayed refresh token is "+
			"a session credential demonstrably in someone else's hands (Art. 33). The two weaker "+
			"signals for the same conclusion both carry the flag.", RefreshTokenReplayed)
	}
}
