package compliance

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/config"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// =============================================================================
// EU GDPR 2016/679 -- Storage Limitation & Data Minimisation (Art. 5(1))
// https://eur-lex.europa.eu/eli/reg/2016/679/oj
// =============================================================================

// --- Art. 5(1)(e): personal data kept no longer than is necessary ---

func TestGDPR_Art5_1_e_RetentionDisabledByDefault(t *testing.T) {
	// Audit entries hold user IDs, IPs, user agents and fingerprint hashes, so
	// Art. 5(1)(e) caps how long they may live -- but silently deleting security
	// logs is not a safe default either. Out of the box the horizon is 0
	// (disabled) and the sweeper refuses to run until the operator explicitly
	// picks one consistent with docs/PRIVACY.md paragraph 4.
	t.Setenv("VAULT_AUDIT_RETENTION_DAYS", "")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}
	if cfg.AuditRetentionPeriod != 0 {
		t.Fatalf("default AuditRetentionPeriod = %v, want 0 (disabled)", cfg.AuditRetentionPeriod)
	}

	swept := false
	repo := &mocks.MockAuditRepo{
		CleanupLockedFn: func(context.Context, time.Time) (int64, bool, error) {
			swept = true
			return 0, true, nil
		},
	}
	r := audit.NewRetention(repo, cfg.AuditRetentionPeriod)
	if r.Enabled() {
		t.Error("a zero horizon must leave the sweeper disabled")
	}
	deleted, err := r.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0 from a disabled sweeper", deleted)
	}
	if swept {
		t.Error("a disabled sweeper must never touch the audit store")
	}
}

// The account-recovery escrow is the audit log's twin: append-only at the
// database layer, exempt from the erasure cascade by design (it exists to
// survive one), and holding personal data -- an encrypted copy of the erased
// user's email, creation date, roles and display name. It shipped bounded by
// nothing at all: no expiry column, DELETE revoked from both application roles,
// and no code path that removed a row. It is now bounded the same way the audit
// log is, and with the same disabled-by-default posture, because the escrow is
// the only recoverable copy of an erased account.
func TestGDPR_Art5_1_e_RecoveryEscrowRetentionDisabledByDefault(t *testing.T) {
	t.Setenv("VAULT_RECOVERY_RETENTION_DAYS", "")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}
	if cfg.RecoveryRetentionPeriod != 0 {
		t.Fatalf("default RecoveryRetentionPeriod = %v, want 0 (disabled)", cfg.RecoveryRetentionPeriod)
	}

	pruner := &countingPruner{}
	r := service.NewRecoveryRetention(pruner, cfg.RecoveryRetentionPeriod)
	if r.Enabled() {
		t.Error("a zero horizon must leave the escrow sweeper disabled")
	}
	deleted, err := r.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if deleted != 0 {
		t.Errorf("deleted = %d, want 0 from a disabled sweeper", deleted)
	}
	if pruner.calls != 0 {
		t.Error("a disabled sweeper must never touch the escrow store")
	}
}

type countingPruner struct{ calls int }

func (p *countingPruner) Prune(context.Context, time.Time) (int64, error) {
	p.calls++
	return 0, nil
}

func (p *countingPruner) PruneLocked(context.Context, time.Time) (int64, bool, error) {
	p.calls++
	return 0, true, nil
}

// --- Art. 5(1)(c): adequate, relevant and limited to what is necessary ---

func TestGDPR_Art5_1_c_AuditMetadataScrubbed(t *testing.T) {
	// Audit entries outlive sessions and are exempt from erasure, so secrets
	// and credentials must never enter them. The logger strips sensitive keys
	// case-insensitively, and through nested maps, before storage.
	var got *model.AuditEntry
	repo := &mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, entry *model.AuditEntry) error {
			got = entry
			return nil
		},
	}
	logger := audit.NewLogger(repo, 0)

	err := logger.Log(context.Background(), audit.LoginFailure, "user-1", "", "203.0.113.7", "ua", "", "", map[string]interface{}{
		"password": "hunter2-hunter2",
		"Token":    "eyJhbGciOiJSUzI1NiJ9",
		"purpose":  "marketing_email",
		"oauth": map[string]interface{}{
			"secret":   "client-secret-value",
			"provider": "github",
		},
	})
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if got == nil {
		t.Fatal("entry never reached the repository")
	}
	if _, ok := got.Metadata["password"]; ok {
		t.Error("Art. 5(1)(c): password stored in audit metadata")
	}
	if _, ok := got.Metadata["Token"]; ok {
		t.Error("Art. 5(1)(c): token stored in audit metadata (scrub must be case-insensitive)")
	}
	if got.Metadata["purpose"] != "marketing_email" {
		t.Errorf("benign metadata lost: %v", got.Metadata)
	}
	nested, ok := got.Metadata["oauth"].(map[string]interface{})
	if !ok {
		t.Fatalf("nested metadata lost: %v", got.Metadata)
	}
	if _, ok := nested["secret"]; ok {
		t.Error("Art. 5(1)(c): secret survived inside a nested map")
	}
	if nested["provider"] != "github" {
		t.Errorf("benign nested metadata lost: %v", nested)
	}
}
