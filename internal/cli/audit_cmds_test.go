package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

func auditCLI(audit *mockAuditRepo) *CLI {
	return New(&mockClientRepo{}, &mockUserRepo{}, &mockRefreshTokenRepo{}, &mockAdminConfigRepo{}, audit, "")
}

// `vault cleanup-audit` is retired (F-17): it reached an audit-delete the RBAC
// model grants no admin, through a gate the calling role could rewrite. What
// used to be asserted about its retention window is now asserted about its
// refusal, in cli_cleanup_audit_retired_test.go; the surviving retention path is
// VAULT_AUDIT_RETENTION_DAYS, tested in internal/audit.

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

func TestExportAudit_AppliesValidLimit(t *testing.T) {
	var got repository.AuditFilter
	audit := &mockAuditRepo{
		QueryFn: func(_ context.Context, filter repository.AuditFilter) ([]*model.AuditEntry, error) {
			got = filter
			return nil, nil
		},
	}
	if !auditCLI(audit).exportAudit(context.Background(), []string{"export-audit", "--limit", "5"}) {
		t.Fatal("command not handled")
	}
	if got.Limit != 5 {
		t.Errorf("filter.Limit = %d, want 5 (the 1000 default must be overridden)", got.Limit)
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
