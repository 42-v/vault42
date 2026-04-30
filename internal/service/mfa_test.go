package service

import (
	"context"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

func TestGetStatusNoMFA(t *testing.T) {
	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			return nil, nil
		},
	}
	mockWebAuthn := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error) {
			return nil, nil
		},
	}
	mockBackup := &mocks.MockBackupCodeRepo{
		ListUnusedByUserFn: func(ctx context.Context, userID string) ([]*model.BackupCode, error) {
			return nil, nil
		},
	}

	svc := NewMFAService(mockTOTP, mockWebAuthn, mockBackup, false)
	status, err := svc.GetStatus(context.Background(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Methods) != 0 {
		t.Errorf("expected no methods, got %v", status.Methods)
	}
	if status.TOTPEnabled {
		t.Error("TOTPEnabled should be false")
	}
	if status.WebAuthnEnabled {
		t.Error("WebAuthnEnabled should be false")
	}
	if status.BackupCodes != 0 {
		t.Errorf("BackupCodes should be 0, got %d", status.BackupCodes)
	}
}

func TestGetStatusTOTPOnly(t *testing.T) {
	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{Verified: true}, nil
		},
	}
	mockWebAuthn := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error) {
			return nil, nil
		},
	}
	mockBackup := &mocks.MockBackupCodeRepo{
		ListUnusedByUserFn: func(ctx context.Context, userID string) ([]*model.BackupCode, error) {
			return nil, nil
		},
	}

	svc := NewMFAService(mockTOTP, mockWebAuthn, mockBackup, false)
	status, err := svc.GetStatus(context.Background(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Methods) != 1 {
		t.Fatalf("expected 1 method, got %v", status.Methods)
	}
	if status.Methods[0] != "totp" {
		t.Errorf("expected method 'totp', got %q", status.Methods[0])
	}
	if !status.TOTPEnabled {
		t.Error("TOTPEnabled should be true")
	}
}

func TestGetStatusAllMethods(t *testing.T) {
	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{Verified: true}, nil
		},
	}
	mockWebAuthn := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error) {
			return []*model.WebAuthnCredential{{ID: "cred-1"}}, nil
		},
	}
	mockBackup := &mocks.MockBackupCodeRepo{
		ListUnusedByUserFn: func(ctx context.Context, userID string) ([]*model.BackupCode, error) {
			return []*model.BackupCode{{ID: "bc-1"}, {ID: "bc-2"}}, nil
		},
	}

	svc := NewMFAService(mockTOTP, mockWebAuthn, mockBackup, true)
	status, err := svc.GetStatus(context.Background(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Methods) != 3 {
		t.Fatalf("expected 3 methods, got %v", status.Methods)
	}

	want := map[string]bool{"totp": true, "webauthn": true, "backup_code": true}
	for _, m := range status.Methods {
		if !want[m] {
			t.Errorf("unexpected method %q", m)
		}
		delete(want, m)
	}
	if len(want) > 0 {
		t.Errorf("missing methods: %v", want)
	}

	if !status.TOTPEnabled {
		t.Error("TOTPEnabled should be true")
	}
	if !status.WebAuthnEnabled {
		t.Error("WebAuthnEnabled should be true")
	}
	if status.BackupCodes != 2 {
		t.Errorf("BackupCodes should be 2, got %d", status.BackupCodes)
	}
	if !status.Required {
		t.Error("Required should be true")
	}
}

func TestGetStatusUnverifiedTOTP(t *testing.T) {
	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{Verified: false}, nil
		},
	}
	mockWebAuthn := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(ctx context.Context, userID string) ([]*model.WebAuthnCredential, error) {
			return nil, nil
		},
	}
	mockBackup := &mocks.MockBackupCodeRepo{
		ListUnusedByUserFn: func(ctx context.Context, userID string) ([]*model.BackupCode, error) {
			return nil, nil
		},
	}

	svc := NewMFAService(mockTOTP, mockWebAuthn, mockBackup, false)
	status, err := svc.GetStatus(context.Background(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if status.TOTPEnabled {
		t.Error("unverified TOTP should not be enabled")
	}
	for _, m := range status.Methods {
		if m == "totp" {
			t.Error("unverified TOTP should not appear in methods")
		}
	}
}

func TestRequiresMFANoMethodsNotRequired(t *testing.T) {
	mockTOTP := &mocks.MockTOTPRepo{}
	mockWebAuthn := &mocks.MockWebAuthnRepo{}
	mockBackup := &mocks.MockBackupCodeRepo{}

	svc := NewMFAService(mockTOTP, mockWebAuthn, mockBackup, false)
	required, err := svc.RequiresMFA(context.Background(), "user-1", false)
	if err != nil {
		t.Fatal(err)
	}
	if required {
		t.Error("should not require MFA when no methods and mfaRequired=false")
	}
}

func TestRequiresMFANoMethodsRequired(t *testing.T) {
	mockTOTP := &mocks.MockTOTPRepo{}
	mockWebAuthn := &mocks.MockWebAuthnRepo{}
	mockBackup := &mocks.MockBackupCodeRepo{}

	svc := NewMFAService(mockTOTP, mockWebAuthn, mockBackup, true)
	required, err := svc.RequiresMFA(context.Background(), "user-1", false)
	if err != nil {
		t.Fatal(err)
	}
	if !required {
		t.Error("should require MFA when mfaRequired=true even with no methods")
	}
}

func TestRequiresMFAWithMethodsTrusted(t *testing.T) {
	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{Verified: true}, nil
		},
	}
	mockWebAuthn := &mocks.MockWebAuthnRepo{}
	mockBackup := &mocks.MockBackupCodeRepo{}

	svc := NewMFAService(mockTOTP, mockWebAuthn, mockBackup, true)
	required, err := svc.RequiresMFA(context.Background(), "user-1", true)
	if err != nil {
		t.Fatal(err)
	}
	if required {
		t.Error("trusted device should skip MFA")
	}
}

func TestRequiresMFAWithMethodsUntrusted(t *testing.T) {
	mockTOTP := &mocks.MockTOTPRepo{
		GetByUserIDFn: func(ctx context.Context, userID string) (*model.TOTPSecret, error) {
			return &model.TOTPSecret{Verified: true}, nil
		},
	}
	mockWebAuthn := &mocks.MockWebAuthnRepo{}
	mockBackup := &mocks.MockBackupCodeRepo{}

	svc := NewMFAService(mockTOTP, mockWebAuthn, mockBackup, true)
	required, err := svc.RequiresMFA(context.Background(), "user-1", false)
	if err != nil {
		t.Fatal(err)
	}
	if !required {
		t.Error("untrusted device with MFA methods should require MFA")
	}
}
