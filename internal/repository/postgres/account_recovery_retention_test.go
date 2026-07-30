package postgres

import (
	"context"
	"strings"
	"testing"
	"time"
)

func apBeginRule() apPGRule {
	return apPGRule{match: "begin", reply: func(string) []byte {
		return append(apMsg('C', apCStr("BEGIN")), apReadyInTx()...)
	}}
}

func apLockRule(granted string) apPGRule {
	return apPGRule{match: "pg_try_advisory_xact_lock", reply: func(string) []byte {
		out := apRowDesc(apCol{name: "pg_try_advisory_xact_lock", oid: apOIDBool, size: 1})
		out = append(out, apDataRow(apText(granted))...)
		out = append(out, apMsg('C', apCStr("SELECT 1"))...)
		return append(out, apReadyInTx()...)
	}}
}

func apPruneRule(deleted string) apPGRule {
	return apPGRule{match: "cleanup_old_recovery", reply: func(string) []byte {
		out := apRowDesc(apCol{name: "cleanup_old_recovery", oid: apOIDInt8, size: 8})
		out = append(out, apDataRow(apText(deleted))...)
		out = append(out, apMsg('C', apCStr("SELECT 1"))...)
		return append(out, apReadyInTx()...)
	}}
}

// The escrow prune is the only thing bounding how long an erased user's address
// lives (Art. 5(1)(e)), and it is the only operation in the tree that may delete
// from an append-only table. Every failure point below must leave acquired=false
// or deleted=0: a caller told "acquired, 0 rows" would log a successful sweep
// that never ran, and the horizon would look enforced while nothing was removed.
func TestAccountRecoveryRepo_FailedPruneNeverClaimsItPurged(t *testing.T) {
	tests := []struct {
		name  string
		rules []apPGRule
		want  string
	}{
		{
			name: "the lock cannot be taken",
			want: "lock",
			rules: []apPGRule{{match: "pg_try_advisory_xact_lock", reply: func(string) []byte {
				return append(apErrorResponse("53300", "too many connections"), apReadyTxFailed()...)
			}}},
		},
		{
			name: "the prune itself fails",
			want: "prune account recovery",
			rules: []apPGRule{apLockRule("t"), {match: "cleanup_old_recovery", reply: func(string) []byte {
				return append(apErrorResponse("42883", "function does not exist"), apReadyTxFailed()...)
			}}},
		},
		{
			name: "the commit is refused after the delete",
			want: "commit",
			rules: []apPGRule{apLockRule("t"), apPruneRule("128"), {match: "commit", reply: func(string) []byte {
				return append(apErrorResponse("40001", "could not serialize access"), apReadyIdle()...)
			}}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rules := append([]apPGRule{}, tc.rules...)
			rules = append(rules, apBeginRule())

			deleted, acquired, err := NewAccountRecoveryRepo(apStartPG(t, rules...)).
				PruneLocked(context.Background(), time.Now().Add(-24*time.Hour))
			if err == nil {
				t.Fatal("PruneLocked reported a successful sweep")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to name the %s step", err, tc.want)
			}
			if deleted != 0 {
				t.Errorf("a failed prune reported %d escrow records purged", deleted)
			}
			if tc.want == "lock" && acquired {
				t.Error("PruneLocked claimed the advisory lock it never got an answer about")
			}
		})
	}
}

// A replica that did not win the advisory lock deleted nothing, and must say so
// without erroring: the work is idempotent and the winner is already doing it.
func TestAccountRecoveryRepo_PruneSkipsWhenAnotherReplicaHoldsTheLock(t *testing.T) {
	deleted, acquired, err := NewAccountRecoveryRepo(apStartPG(t, apLockRule("f"), apBeginRule())).
		PruneLocked(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("losing the lock is not an error: %v", err)
	}
	if acquired {
		t.Error("PruneLocked claimed a lock the database refused it")
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0 from a replica that never held the lock", deleted)
	}
}

// The success path has to report the row count back, because that count is what
// an operator reads as evidence the retention horizon was applied.
func TestAccountRecoveryRepo_PruneReportsRowsRemoved(t *testing.T) {
	db := apStartPG(t, apLockRule("t"), apPruneRule("42"), apBeginRule(),
		apPGRule{match: "commit", reply: func(string) []byte {
			return append(apMsg('C', apCStr("COMMIT")), apReadyIdle()...)
		}},
	)

	deleted, acquired, err := NewAccountRecoveryRepo(db).PruneLocked(context.Background(), time.Now().Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("PruneLocked: %v", err)
	}
	if !acquired {
		t.Error("PruneLocked did not report the lock it was granted")
	}
	if deleted != 42 {
		t.Errorf("deleted = %d, want 42", deleted)
	}
}

// The one-shot operator purge behind `vault cleanup-recovery` reports its own
// count, and must surface a database failure rather than answering zero.
func TestAccountRecoveryRepo_PruneUnlocked(t *testing.T) {
	t.Run("reports rows removed", func(t *testing.T) {
		db := apStartPG(t, apPGRule{match: "cleanup_old_recovery", reply: func(string) []byte {
			out := apRowDesc(apCol{name: "cleanup_old_recovery", oid: apOIDInt8, size: 8})
			out = append(out, apDataRow(apText("9"))...)
			out = append(out, apMsg('C', apCStr("SELECT 1"))...)
			return append(out, apReadyIdle()...)
		}})

		deleted, err := NewAccountRecoveryRepo(db).Prune(context.Background(), time.Now().Add(-24*time.Hour))
		if err != nil {
			t.Fatalf("Prune: %v", err)
		}
		if deleted != 9 {
			t.Errorf("deleted = %d, want 9", deleted)
		}
	})

	t.Run("surfaces a database failure", func(t *testing.T) {
		deleted, err := NewAccountRecoveryRepo(deadPool(t)).Prune(context.Background(), time.Now().Add(-24*time.Hour))
		if err == nil {
			t.Error("Prune reported success against an unreachable database")
		}
		if deleted != 0 {
			t.Errorf("a failed prune reported %d records purged", deleted)
		}
	})
}

// PruneLocked cannot even open its transaction against an unreachable database,
// and must not report a lock it never asked for.
func TestAccountRecoveryRepo_PruneLockedSurfacesDeadPool(t *testing.T) {
	deleted, acquired, err := NewAccountRecoveryRepo(deadPool(t)).PruneLocked(context.Background(), time.Now().Add(-24*time.Hour))
	if err == nil {
		t.Error("PruneLocked reported success against an unreachable database")
	}
	if acquired {
		t.Error("PruneLocked claimed the advisory lock while the database was unreachable")
	}
	if deleted != 0 {
		t.Errorf("a failed prune reported %d records purged", deleted)
	}
}
