package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type mockRecoveryPruner struct {
	PruneFn func(ctx context.Context, olderThan time.Time) (int64, error)
	called  bool
}

func (m *mockRecoveryPruner) Prune(ctx context.Context, olderThan time.Time) (int64, error) {
	m.called = true
	if m.PruneFn != nil {
		return m.PruneFn(ctx, olderThan)
	}
	return 0, nil
}

func (m *mockRecoveryPruner) PruneLocked(ctx context.Context, olderThan time.Time) (int64, bool, error) {
	deleted, err := m.Prune(ctx, olderThan)
	return deleted, true, err
}

func recoveryCLI(pruner *mockRecoveryPruner) *CLI {
	c := New(&mockClientRepo{}, &mockUserRepo{}, &mockRefreshTokenRepo{}, &mockAdminConfigRepo{}, &mockAuditRepo{}, "")
	if pruner == nil {
		return c
	}
	return c.WithRecoveryPruner(pruner)
}

// `vault cleanup-recovery` is the manual half of the escrow retention control, and
// the only sanctioned way to delete from an append-only table both application
// roles have DELETE revoked on. Its argument validation is therefore a safety gate:
// a mis-parsed window destroys the only recoverable copy of erased accounts, and
// there is no undo.
func TestCleanupRecovery_RejectsBadRetentionWindows(t *testing.T) {
	pruner := &mockRecoveryPruner{}
	c := recoveryCLI(pruner)

	for _, args := range [][]string{
		{"cleanup-recovery"},
		{"cleanup-recovery", "--retention-days", "0"},
		{"cleanup-recovery", "--retention-days", "-30"},
		{"cleanup-recovery", "--retention-days", "thirty"},
	} {
		pruner.called = false
		out := captureStderr(t, func() {
			if !c.cleanupRecovery(context.Background(), args) {
				t.Errorf("%v: command should have been handled", args)
			}
		})
		if pruner.called {
			t.Errorf("%v: deleted escrow records on an invalid retention window", args)
		}
		if out == "" {
			t.Errorf("%v: rejected the window silently", args)
		}
	}
}

// The cutoff is what bounds how long the escrowed email lives, so it has to be
// "now minus N days".
func TestCleanupRecovery_PurgesPastTheHorizon(t *testing.T) {
	var cutoff time.Time
	pruner := &mockRecoveryPruner{
		PruneFn: func(_ context.Context, olderThan time.Time) (int64, error) {
			cutoff = olderThan
			return 5, nil
		},
	}

	out := captureStdout(t, func() {
		if !recoveryCLI(pruner).cleanupRecovery(context.Background(), []string{"cleanup-recovery", "--retention-days", "30"}) {
			t.Fatal("command not handled")
		}
	})

	want := time.Now().AddDate(0, 0, -30)
	if cutoff.Before(want.Add(-time.Minute)) || cutoff.After(want.Add(time.Minute)) {
		t.Errorf("cutoff %v is not ~now-30d", cutoff)
	}
	if !strings.Contains(out, "Deleted 5 recovery escrow records") {
		t.Errorf("output = %q, want the purged count", out)
	}
}

// Without a pruner attached the command must say so rather than report a purge of
// zero records, which an operator would read as "the escrow is already empty".
func TestCleanupRecovery_WithoutPrunerRefuses(t *testing.T) {
	out := captureStderr(t, func() {
		if !recoveryCLI(nil).cleanupRecovery(context.Background(), []string{"cleanup-recovery", "--retention-days", "30"}) {
			t.Fatal("command not handled")
		}
	})
	if !strings.Contains(out, "not available") {
		t.Errorf("stderr = %q, want an unavailable-repository error", out)
	}
}

// A failed purge must be reported. Silence here reads as a successful retention
// run and the horizon would appear enforced when it was not.
func TestCleanupRecovery_ReportsFailure(t *testing.T) {
	pruner := &mockRecoveryPruner{
		PruneFn: func(context.Context, time.Time) (int64, error) {
			return 0, errors.New("db down")
		},
	}
	out := captureStderr(t, func() {
		if !recoveryCLI(pruner).cleanupRecovery(context.Background(), []string{"cleanup-recovery", "--retention-days", "30"}) {
			t.Fatal("command not handled")
		}
	})
	if !strings.Contains(out, "db down") {
		t.Errorf("stderr = %q, want the underlying failure", out)
	}
}

// The subcommand must be reachable through Run, behind the same admin-token gate
// as every other destructive command.
func TestCLI_RoutesToCleanupRecovery(t *testing.T) {
	c, _, _, _, _, token := setupAuthenticatedCLI(t)
	pruner := &mockRecoveryPruner{}
	c.WithRecoveryPruner(pruner)

	captureStdout(t, func() {
		if !c.Run(context.Background(), []string{"vault", "cleanup-recovery", "--admin-token", token, "--retention-days", "30"}) {
			t.Error("expected cleanup-recovery to be routed")
		}
	})

	if !pruner.called {
		t.Error("cleanup-recovery was not routed to the pruner")
	}
}
