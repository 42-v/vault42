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

// A horizon the operator wrote and this service cannot honor must refuse to
// start. Both of these used to load as zero, which is the disabled state: the
// config recorded a retention policy, the sweeper never ran, and the escrow
// kept every erased account's personal data indefinitely.
func TestRecoveryRetentionDaysRefusesAHorizonItCannotHonor(t *testing.T) {
	for _, value := range []string{"thirty", "30d", "-30"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("VAULT_RECOVERY_RETENTION_DAYS", value)

			if _, err := Load(); err == nil {
				t.Fatalf("Load accepted VAULT_RECOVERY_RETENTION_DAYS=%q and silently disabled the sweeper", value)
			}
		})
	}
}
