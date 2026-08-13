package integration_test

import (
	"context"
	"testing"
)

// TestAuditCleanupRejectsEveryIntervalWhoseCutoffIsNotAWholeDayBack is the
// behavioural half of the retention guard regression. The cheap structural half
// lives in tests/spec and needs no container.
//
// audit.cleanup_old_entries is the only path that can delete an audit row: the
// audit_log_no_delete trigger blocks every other one, and this function is
// SECURITY DEFINER so it can disable that trigger for the length of one DELETE.
// vault_app holds EXECUTE. So the minimum-horizon check is the only limit on how
// much of the audit log one call can destroy, and a compromised app process
// calling it directly is the threat it exists for.
//
// Migration 012 checked the caller's INTERVAL against a minimum and then built
// the DELETE predicate by subtracting that INTERVAL from NOW(). Those disagree
// whenever the interval carries a month: comparison canonicalises a month to 30
// days so intervals can be ordered without a reference date, subtraction uses
// the real calendar month. INTERVAL '1 mon -29 days' compares as 1 day and
// passes; evaluated in February it subtracts to a cutoff one day in the FUTURE
// and the DELETE takes the entire table, intrusion record included, while
// reporting that the horizon was respected.
//
// The test uses Postgres as its own oracle rather than hardcoding which
// intervals are dangerous. Whether '1 mon -29 days' is catastrophic depends on
// the month the test runs in, so a table of expected verdicts would pass all
// year and fail every February, which is the worst possible schedule for a test
// of a February bug. Instead it asks the database for the cutoff each interval
// actually produces today, derives the verdict from that, and asserts the
// function agrees. That holds on every date.
func TestAuditCleanupRejectsEveryIntervalWhoseCutoffIsNotAWholeDayBack(t *testing.T) {
	skipIfNoDocker(t)

	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	ctx := context.Background()

	// Mixed-unit intervals are the attack: each carries a month component, so
	// each is compared one way and subtracted another. The plain ones are the
	// control, and they must keep working, since a guard that rejects everything
	// would also pass a one-directional test.
	intervals := []string{
		"1 mon -29 days",
		"1 mon -28 days",
		"1 mon -30 days",
		"2 mons -59 days",
		"12 mons -364 days",
		"1 mon",
		"30 days",
		"90 days",
		"1 day",
		"12 hours",
		"0 days",
		"-5 days",
	}

	for _, iv := range intervals {
		t.Run(iv, func(t *testing.T) {
			// The oracle: does this interval, evaluated right now on this server,
			// produce a cutoff that would reach rows less than a day old? That is
			// the only question the guard is there to answer.
			var wipesRecent bool
			if err := pool.QueryRow(ctx,
				"SELECT NOW() - $1::interval > NOW() - INTERVAL '1 day'", iv,
			).Scan(&wipesRecent); err != nil {
				t.Fatalf("oracle query failed for %q: %v", iv, err)
			}

			var deleted int64
			err := pool.QueryRow(ctx,
				"SELECT audit.cleanup_old_entries($1::interval)", iv,
			).Scan(&deleted)

			if wipesRecent && err == nil {
				var cutoff string
				_ = pool.QueryRow(ctx, "SELECT (NOW() - $1::interval)::text", iv).Scan(&cutoff)
				t.Fatalf("audit.cleanup_old_entries(%q) was ACCEPTED, but its cutoff is %s, "+
					"less than a day ago. The guard compared a canonicalised interval instead "+
					"of the cutoff it deletes on, so this call would take audit rows written "+
					"minutes before it, including whatever recorded the caller.", iv, cutoff)
			}
			if !wipesRecent && err != nil {
				t.Fatalf("audit.cleanup_old_entries(%q) was REJECTED (%v), but its cutoff is at "+
					"least a full day back, so it is a legitimate retention horizon. The sweeper "+
					"cannot run and audit rows accumulate forever.", iv, err)
			}
		})
	}
}

// TestAuditCleanupRejectsANullHorizon pins the case that the cutoff comparison
// cannot catch on its own.
//
// NOW() - NULL is NULL, and NULL > x evaluates to NULL rather than true, so
// folding the NULL check into the cutoff comparison would let a NULL argument
// fall through to a DELETE with a NULL predicate. Migration 018 keeps the NULL
// check separate and first for exactly that reason, and this is what stops a
// later simplification from merging them.
func TestAuditCleanupRejectsANullHorizon(t *testing.T) {
	skipIfNoDocker(t)

	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	var deleted int64
	err := pool.QueryRow(context.Background(),
		"SELECT audit.cleanup_old_entries(NULL::interval)").Scan(&deleted)
	if err == nil {
		t.Fatal("a NULL retention horizon was accepted. NULL > x is NULL rather than true, so " +
			"a cutoff-only guard passes it through to a DELETE whose predicate is NULL.")
	}
}
