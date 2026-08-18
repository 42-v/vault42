package cli

import (
	"context"
	"strings"
	"testing"
	"time"
)

// F-17. `vault cleanup-audit` reached a capability the RBAC model grants no
// admin, behind a gate the role running it can rewrite.
//
// internal/rbac/rbac.go states that audit access "is read-only by design: there
// is no corresponding write or delete permission, because an admin who can edit
// the audit trail can erase their own actions", and no admin tier holds an
// audit-delete permission. Migration 018 grants EXECUTE on
// audit.cleanup_old_entries to vault_app and deliberately not to vault_admin.
// The CLI runs as vault_app and called it, gated only by admin_token_hash in
// auth.admin_config — a table migration 001 grants vault_app SELECT, INSERT and
// UPDATE on, so the caller could overwrite its own gate.
//
// So this was an on-demand, arbitrary-horizon delete against an append-only
// audit log, available to the semi-hostile role, described nowhere as a
// capability the admin plane refuses everyone. It is retired here, on the model
// of lock-user, unlock-user, revoke-client and rotate-client-secret. Retention
// stays where it belongs: VAULT_AUDIT_RETENTION_DAYS, a deployment-level horizon
// swept in-process by internal/audit.Retention, which is declarative, applies the
// same SECURITY DEFINER function, and cannot be aimed at an arbitrary cutoff by
// whoever holds the CLI token.
func TestCleanupAudit_RetiredIssuesNoDeleteAndNamesTheReplacement(t *testing.T) {
	cleanupCalled := false
	audit := &mockAuditRepo{
		CleanupFn: func(context.Context, time.Time) (int64, error) {
			cleanupCalled = true
			return 0, nil
		},
	}
	c := auditCLI(audit)

	for _, args := range [][]string{
		{"cleanup-audit"},
		{"cleanup-audit", "--retention-days", "30"},
		{"cleanup-audit", "--retention-days", "1"},
	} {
		stderr := captureStderr(t, func() {
			if !c.cleanupAudit(context.Background(), args) {
				t.Errorf("%v: command should still be recognized so cmd/vault does not boot the server", args)
			}
		})
		if cleanupCalled {
			t.Fatalf("%v: retired cleanup-audit still deleted audit entries", args)
		}
		if !strings.Contains(stderr, "retired") {
			t.Errorf("%v: stderr does not say the command is retired: %q", args, stderr)
		}
		if !strings.Contains(stderr, "VAULT_AUDIT_RETENTION_DAYS") {
			t.Errorf("%v: stderr does not name the supported replacement: %q", args, stderr)
		}
	}
}

// Dispatch must keep recognizing the subcommand. Returning false would make
// cmd/vault treat `vault cleanup-audit` as an unknown argument and fall through
// to booting the server, which is how the other four retirements are written.
func TestRun_RoutesRetiredCleanupAudit(t *testing.T) {
	cleanupCalled := false
	c, _, _, _, admin, token := setupAuthenticatedCLI(t)
	c.audit = &mockAuditRepo{CleanupFn: func(context.Context, time.Time) (int64, error) {
		cleanupCalled = true
		return 0, nil
	}}
	_ = admin

	args := []string{"vault", "cleanup-audit", "--admin-token", token, "--retention-days", "30"}
	captureStderr(t, func() {
		if !c.Run(context.Background(), args) {
			t.Error("cleanup-audit was not routed")
		}
	})
	if cleanupCalled {
		t.Error("retired cleanup-audit issued a vault_app audit delete through Run")
	}
}
