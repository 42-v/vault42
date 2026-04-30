package service

import (
	"context"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// ---------------------------------------------------------------------------
// Additional MFA tests (~10)
// ---------------------------------------------------------------------------

func TestGetStatusWebAuthnOnly(t *testing.T) {
	svc := NewMFAService(
		&mocks.MockTOTPRepo{},
		&mocks.MockWebAuthnRepo{
			ListByUserFn: func(_ context.Context, _ string) ([]*model.WebAuthnCredential, error) {
				return []*model.WebAuthnCredential{{ID: "cred-1"}, {ID: "cred-2"}}, nil
			},
		},
		&mocks.MockBackupCodeRepo{},
		false,
	)

	status, err := svc.GetStatus(context.Background(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if !status.WebAuthnEnabled {
		t.Error("WebAuthnEnabled should be true")
	}
	if status.TOTPEnabled {
		t.Error("TOTPEnabled should be false")
	}
	if len(status.Methods) != 1 || status.Methods[0] != "webauthn" {
		t.Errorf("methods should be [webauthn], got %v", status.Methods)
	}
}

func TestGetStatusBackupCodesOnly(t *testing.T) {
	svc := NewMFAService(
		&mocks.MockTOTPRepo{},
		&mocks.MockWebAuthnRepo{},
		&mocks.MockBackupCodeRepo{
			ListUnusedByUserFn: func(_ context.Context, _ string) ([]*model.BackupCode, error) {
				return []*model.BackupCode{
					{ID: "bc-1"}, {ID: "bc-2"}, {ID: "bc-3"},
				}, nil
			},
		},
		false,
	)

	status, err := svc.GetStatus(context.Background(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if status.BackupCodes != 3 {
		t.Errorf("BackupCodes should be 3, got %d", status.BackupCodes)
	}
	if len(status.Methods) != 1 || status.Methods[0] != "backup_code" {
		t.Errorf("methods should be [backup_code], got %v", status.Methods)
	}
}

func TestGetStatusTOTPAndBackupCodes(t *testing.T) {
	svc := NewMFAService(
		&mocks.MockTOTPRepo{
			GetByUserIDFn: func(_ context.Context, _ string) (*model.TOTPSecret, error) {
				return &model.TOTPSecret{Verified: true}, nil
			},
		},
		&mocks.MockWebAuthnRepo{},
		&mocks.MockBackupCodeRepo{
			ListUnusedByUserFn: func(_ context.Context, _ string) ([]*model.BackupCode, error) {
				return []*model.BackupCode{{ID: "bc-1"}, {ID: "bc-2"}}, nil
			},
		},
		true,
	)

	status, err := svc.GetStatus(context.Background(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if !status.TOTPEnabled {
		t.Error("TOTPEnabled should be true")
	}
	if status.WebAuthnEnabled {
		t.Error("WebAuthnEnabled should be false")
	}
	if status.BackupCodes != 2 {
		t.Errorf("BackupCodes should be 2, got %d", status.BackupCodes)
	}
	if !status.Required {
		t.Error("Required should be true")
	}
	// Methods: totp + backup_code
	if len(status.Methods) != 2 {
		t.Fatalf("expected 2 methods, got %v", status.Methods)
	}
	methodSet := map[string]bool{}
	for _, m := range status.Methods {
		methodSet[m] = true
	}
	if !methodSet["totp"] || !methodSet["backup_code"] {
		t.Errorf("methods should include totp and backup_code, got %v", status.Methods)
	}
}

func TestGetStatusZeroBackupCodes(t *testing.T) {
	svc := NewMFAService(
		&mocks.MockTOTPRepo{
			GetByUserIDFn: func(_ context.Context, _ string) (*model.TOTPSecret, error) {
				return &model.TOTPSecret{Verified: true}, nil
			},
		},
		&mocks.MockWebAuthnRepo{},
		&mocks.MockBackupCodeRepo{
			ListUnusedByUserFn: func(_ context.Context, _ string) ([]*model.BackupCode, error) {
				return []*model.BackupCode{}, nil // zero remaining
			},
		},
		false,
	)

	status, err := svc.GetStatus(context.Background(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if status.BackupCodes != 0 {
		t.Errorf("BackupCodes should be 0, got %d", status.BackupCodes)
	}
	// Only totp should be in methods (not backup_code since 0 remaining)
	if len(status.Methods) != 1 || status.Methods[0] != "totp" {
		t.Errorf("methods should be [totp] when 0 backup codes, got %v", status.Methods)
	}
}

func TestGetStatusWebAuthnAndBackupCodes(t *testing.T) {
	svc := NewMFAService(
		&mocks.MockTOTPRepo{},
		&mocks.MockWebAuthnRepo{
			ListByUserFn: func(_ context.Context, _ string) ([]*model.WebAuthnCredential, error) {
				return []*model.WebAuthnCredential{{ID: "cred-1"}}, nil
			},
		},
		&mocks.MockBackupCodeRepo{
			ListUnusedByUserFn: func(_ context.Context, _ string) ([]*model.BackupCode, error) {
				return []*model.BackupCode{{ID: "bc-1"}, {ID: "bc-2"}, {ID: "bc-3"}, {ID: "bc-4"}, {ID: "bc-5"}}, nil
			},
		},
		false,
	)

	status, err := svc.GetStatus(context.Background(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if !status.WebAuthnEnabled {
		t.Error("WebAuthnEnabled should be true")
	}
	if status.BackupCodes != 5 {
		t.Errorf("BackupCodes should be 5, got %d", status.BackupCodes)
	}
	if len(status.Methods) != 2 {
		t.Fatalf("expected 2 methods, got %v", status.Methods)
	}
}

func TestGetStatusRequiredFlag(t *testing.T) {
	tests := []struct {
		name     string
		required bool
	}{
		{"required_true", true},
		{"required_false", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewMFAService(
				&mocks.MockTOTPRepo{},
				&mocks.MockWebAuthnRepo{},
				&mocks.MockBackupCodeRepo{},
				tt.required,
			)

			status, err := svc.GetStatus(context.Background(), "user-1")
			if err != nil {
				t.Fatal(err)
			}
			if status.Required != tt.required {
				t.Errorf("Required = %v, want %v", status.Required, tt.required)
			}
		})
	}
}

func TestRequiresMFAWithWebAuthnUntrusted(t *testing.T) {
	svc := NewMFAService(
		&mocks.MockTOTPRepo{},
		&mocks.MockWebAuthnRepo{
			ListByUserFn: func(_ context.Context, _ string) ([]*model.WebAuthnCredential, error) {
				return []*model.WebAuthnCredential{{ID: "cred-1"}}, nil
			},
		},
		&mocks.MockBackupCodeRepo{},
		false,
	)

	required, err := svc.RequiresMFA(context.Background(), "user-1", false)
	if err != nil {
		t.Fatal(err)
	}
	if !required {
		t.Error("should require MFA for untrusted device with WebAuthn credential")
	}
}

func TestRequiresMFAWithWebAuthnTrusted(t *testing.T) {
	svc := NewMFAService(
		&mocks.MockTOTPRepo{},
		&mocks.MockWebAuthnRepo{
			ListByUserFn: func(_ context.Context, _ string) ([]*model.WebAuthnCredential, error) {
				return []*model.WebAuthnCredential{{ID: "cred-1"}}, nil
			},
		},
		&mocks.MockBackupCodeRepo{},
		false,
	)

	required, err := svc.RequiresMFA(context.Background(), "user-1", true)
	if err != nil {
		t.Fatal(err)
	}
	if required {
		t.Error("trusted device should skip MFA even with WebAuthn")
	}
}

func TestRequiresMFABackupCodesOnlyUntrusted(t *testing.T) {
	svc := NewMFAService(
		&mocks.MockTOTPRepo{},
		&mocks.MockWebAuthnRepo{},
		&mocks.MockBackupCodeRepo{
			ListUnusedByUserFn: func(_ context.Context, _ string) ([]*model.BackupCode, error) {
				return []*model.BackupCode{{ID: "bc-1"}}, nil
			},
		},
		false,
	)

	required, err := svc.RequiresMFA(context.Background(), "user-1", false)
	if err != nil {
		t.Fatal(err)
	}
	if !required {
		t.Error("should require MFA with backup codes available on untrusted device")
	}
}

func TestIsRequired(t *testing.T) {
	svcTrue := NewMFAService(&mocks.MockTOTPRepo{}, &mocks.MockWebAuthnRepo{}, &mocks.MockBackupCodeRepo{}, true)
	if !svcTrue.IsRequired() {
		t.Error("IsRequired should return true when mfaRequired=true")
	}

	svcFalse := NewMFAService(&mocks.MockTOTPRepo{}, &mocks.MockWebAuthnRepo{}, &mocks.MockBackupCodeRepo{}, false)
	if svcFalse.IsRequired() {
		t.Error("IsRequired should return false when mfaRequired=false")
	}
}
