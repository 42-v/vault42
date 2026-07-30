package config

import (
	"testing"
	"time"
)

// The account-recovery escrow holds an encrypted copy of every erased user's
// email, creation date, roles and display name, and it is exempt from the erasure
// cascade by design — so Art. 5(1)(e) is the only thing capping its lifetime, and
// VAULT_RECOVERY_RETENTION_DAYS is that cap.
//
// Disabled-by-default is the deliberate half: the escrow is the only recoverable
// copy of an erased account, so a deployment that never picked a horizon must not
// have one inferred for it and start destroying records on upgrade. That is the
// same posture as VAULT_AUDIT_RETENTION_DAYS.
func TestRecoveryRetentionDays(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want time.Duration
	}{
		{"unset is disabled", "", 0},
		{"explicit zero is disabled", "0", 0},
		{"days become a horizon", "30", 30 * 24 * time.Hour},
		{"non-numeric falls back to disabled", "thirty", 0},
		{"negative cannot enable a sweep", "-30", -30 * 24 * time.Hour},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("VAULT_RECOVERY_RETENTION_DAYS", tc.env)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() = %v", err)
			}
			if cfg.RecoveryRetentionPeriod != tc.want {
				t.Errorf("RecoveryRetentionPeriod = %v, want %v", cfg.RecoveryRetentionPeriod, tc.want)
			}
		})
	}
}
