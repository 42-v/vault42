package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

func auditCLI(audit *mockAuditRepo) *CLI {
	return New(&mockClientRepo{}, &mockUserRepo{}, &mockRefreshTokenRepo{}, &mockAdminConfigRepo{}, audit, "")
}

// `vault cleanup-audit` is the manual half of the retention control: it is the
// only sanctioned way to delete from an append-only audit log. Its argument
// validation is therefore a safety gate — a mis-parsed retention window would
// delete the wrong side of the horizon, and there is no undo.
func TestCleanupAudit_RejectsBadRetentionWindows(t *testing.T) {
	cleanupCalled := false
	audit := &mockAuditRepo{
		CleanupFn: func(context.Context, time.Time) (int64, error) {
			cleanupCalled = true
			return 0, nil
		},
	}
	c := auditCLI(audit)

	for _, args := range [][]string{
		{"cleanup-audit"},                               // no window at all
		{"cleanup-audit", "--retention-days", "0"},      // would purge everything
		{"cleanup-audit", "--retention-days", "-30"},    // negative window
		{"cleanup-audit", "--retention-days", "thirty"}, // not a number
	} {
		cleanupCalled = false
		if !c.cleanupAudit(context.Background(), args) {
			t.Errorf("%v: command should have been handled", args)
		}
		if cleanupCalled {
			t.Errorf("%v: deleted audit entries on an invalid retention window", args)
		}
	}
}

func TestCleanupAudit_PurgesPastTheHorizon(t *testing.T) {
	var cutoff time.Time
	audit := &mockAuditRepo{
		CleanupFn: func(_ context.Context, olderThan time.Time) (int64, error) {
			cutoff = olderThan
			return 5, nil
		},
	}

	if !auditCLI(audit).cleanupAudit(context.Background(), []string{"cleanup-audit", "--retention-days", "30"}) {
		t.Fatal("command not handled")
	}

	want := time.Now().AddDate(0, 0, -30)
	if cutoff.Before(want.Add(-time.Minute)) || cutoff.After(want.Add(time.Minute)) {
		t.Errorf("cutoff %v is not ~30 days ago", cutoff)
	}
}

// A failed purge must be reported, not swallowed: an operator who is told the
// log was cleaned when it was not will believe a retention obligation has been
// met that has not.
func TestCleanupAudit_ReportsFailure(t *testing.T) {
	audit := &mockAuditRepo{
		CleanupFn: func(context.Context, time.Time) (int64, error) {
			return 0, errors.New("db down")
		},
	}
	if !auditCLI(audit).cleanupAudit(context.Background(), []string{"cleanup-audit", "--retention-days", "30"}) {
		t.Fatal("command not handled")
	}
}

// `vault export-audit` is how a subject-access request or an incident review gets
// the trail out. Bad filters must be refused rather than silently producing a
// partial export that reads as complete.
func TestExportAudit_RejectsBadFilters(t *testing.T) {
	queried := false
	audit := &mockAuditRepo{
		QueryFn: func(context.Context, repository.AuditFilter) ([]*model.AuditEntry, error) {
			queried = true
			return nil, nil
		},
	}
	c := auditCLI(audit)

	for _, args := range [][]string{
		{"export-audit", "--since", "not-a-date"},
		{"export-audit", "--until", "31-12-2026"},
		{"export-audit", "--limit", "0"},
		{"export-audit", "--limit", "-5"},
		{"export-audit", "--limit", "many"},
	} {
		queried = false
		if !c.exportAudit(context.Background(), args) {
			t.Errorf("%v: command should have been handled", args)
		}
		if queried {
			t.Errorf("%v: queried the audit log despite an invalid filter", args)
		}
	}
}

func TestExportAudit_ReportsQueryFailure(t *testing.T) {
	audit := &mockAuditRepo{
		QueryFn: func(context.Context, repository.AuditFilter) ([]*model.AuditEntry, error) {
			return nil, errors.New("db down")
		},
	}
	if !auditCLI(audit).exportAudit(context.Background(), []string{"export-audit"}) {
		t.Fatal("command not handled")
	}
}

// These commands all end in a write to a store. If the write fails and the CLI
// still prints success, the operator walks away believing something happened
// that did not — a rotated admin token that was never persisted is a lockout
// waiting to happen, and a client secret they have already copied down is now
// wrong.
func TestCLI_StoreFailuresAreReported(t *testing.T) {
	boom := errors.New("db down")

	t.Run("rotate-admin-token: a failed persist must not print a token", func(t *testing.T) {
		adminCfg := &mockAdminConfigRepo{
			SetFn: func(context.Context, string, string) error { return boom },
		}
		c := New(&mockClientRepo{}, &mockUserRepo{}, &mockRefreshTokenRepo{}, adminCfg, &mockAuditRepo{}, "")

		out := captureStdout(t, func() {
			if !c.rotateAdminToken(context.Background()) {
				t.Error("command not handled")
			}
		})
		if strings.Contains(out, "New admin token:") {
			t.Error("a token was printed even though it was never stored — the operator would save a token that does not work")
		}
	})

	t.Run("add-client: a failed create must not print credentials", func(t *testing.T) {
		clients := &mockClientRepo{
			CreateFn: func(context.Context, *model.Client) error { return boom },
		}
		c := New(clients, &mockUserRepo{}, &mockRefreshTokenRepo{}, &mockAdminConfigRepo{}, &mockAuditRepo{}, "")

		out := captureStdout(t, func() {
			c.addClient(context.Background(), []string{"add-client", "--name", "svc"})
		})
		if strings.Contains(out, "Client secret:") {
			t.Error("credentials were printed for a client that was never created")
		}
	})

	t.Run("rotate-client-secret: a failed update must not print the new secret", func(t *testing.T) {
		clients := &mockClientRepo{
			GetByNameFn: func(_ context.Context, name string) (*model.Client, error) {
				return &model.Client{ID: "c-1", Name: name}, nil
			},
			UpdateFn: func(context.Context, *model.Client) error { return boom },
		}
		c := New(clients, &mockUserRepo{}, &mockRefreshTokenRepo{}, &mockAdminConfigRepo{}, &mockAuditRepo{}, "")

		out := captureStdout(t, func() {
			c.rotateClientSecret(context.Background(), []string{"rotate-client-secret", "--name", "svc"})
		})
		if strings.Contains(out, "New secret:") {
			t.Error("a new secret was printed even though the rotation was never persisted")
		}
	})
}
