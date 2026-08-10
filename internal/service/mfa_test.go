package service

import (
	"context"
	"encoding/json"
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

// GET /auth/2fa/status serialises MFAStatus directly, so this struct is a
// public wire contract. Two things must hold for every value of it: the method
// list is an array and never null, and the list is published under both
// mfa_methods (canonical) and available_methods (the deprecated pre-1.0.0
// name), carrying identical contents.
func TestMFAStatusJSON_MethodListIsAnArrayUnderBothNames(t *testing.T) {
	cases := map[string]MFAStatus{
		"no factor enrolled": {Required: true},
		"an empty list":      {Methods: []string{}},
		"enrolled factors":   {TOTPEnabled: true, Methods: []string{MethodTOTP, MethodWebAuthn}},
	}

	for name, status := range cases {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(status)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			var decoded map[string]json.RawMessage
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatalf("decode: %v", err)
			}

			canonical, ok := decoded["mfa_methods"]
			if !ok {
				t.Fatalf("mfa_methods is missing: %s", raw)
			}
			alias, ok := decoded["available_methods"]
			if !ok {
				t.Fatalf("the deprecated available_methods alias is missing: %s", raw)
			}
			if string(canonical) != string(alias) {
				t.Errorf("the two names disagree: mfa_methods=%s available_methods=%s", canonical, alias)
			}
			if string(canonical) == "null" {
				t.Errorf("the method list serialised as null rather than []: %s", raw)
			}
		})
	}
}

// GetStatus is the only production constructor, and its result reaches the wire
// unchanged. A user with nothing enrolled must come back with an empty list.
func TestGetStatus_EmptyMethodsIsNotNil(t *testing.T) {
	svc := NewMFAService(&mocks.MockTOTPRepo{}, &mocks.MockWebAuthnRepo{}, &mocks.MockBackupCodeRepo{}, false)

	status, err := svc.GetStatus(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if status.Methods == nil {
		t.Fatal("Methods is nil, so the status serialises as null")
	}
}
