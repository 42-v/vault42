package service

import (
	"context"
	"fmt"

	"github.com/42-v/vault42/internal/repository"
)

// MFAService handles MFA policy decisions.
type MFAService struct {
	totpRepo     repository.TOTPRepository
	webauthnRepo repository.WebAuthnRepository
	backupRepo   repository.BackupCodeRepository
	mfaRequired  bool
}

// NewMFAService creates a new MFA service.
func NewMFAService(totp repository.TOTPRepository, webauthn repository.WebAuthnRepository, backup repository.BackupCodeRepository, required bool) *MFAService {
	return &MFAService{
		totpRepo: totp, webauthnRepo: webauthn, backupRepo: backup, mfaRequired: required,
	}
}

// IsRequired returns whether MFA is required by server configuration.
func (s *MFAService) IsRequired() bool {
	return s.mfaRequired
}

// MFAStatus describes the MFA state for a user.
type MFAStatus struct {
	TOTPEnabled     bool     `json:"totp_enabled"`
	WebAuthnEnabled bool     `json:"webauthn_enabled"`
	BackupCodes     int      `json:"backup_codes_remaining"`
	Methods         []string `json:"available_methods"`
	Required        bool     `json:"mfa_required"`
}

// GetStatus returns the MFA status for a user.
// Returns an error if the primary MFA methods (TOTP, WebAuthn) cannot be determined,
// to ensure callers fail closed rather than silently skipping MFA.
func (s *MFAService) GetStatus(ctx context.Context, userID string) (*MFAStatus, error) {
	status := &MFAStatus{Required: s.mfaRequired}

	totp, totpErr := s.totpRepo.GetByUserID(ctx, userID)
	if totp != nil && totp.Verified {
		status.TOTPEnabled = true
		status.Methods = append(status.Methods, "totp")
	}

	creds, credsErr := s.webauthnRepo.ListByUser(ctx, userID)
	if len(creds) > 0 {
		status.WebAuthnEnabled = true
		status.Methods = append(status.Methods, "webauthn")
	}

	// If both primary MFA lookups failed, return error to fail closed
	if totpErr != nil && credsErr != nil {
		return nil, fmt.Errorf("mfa: unable to determine MFA status: totp: %w, webauthn: %w", totpErr, credsErr)
	}

	codes, _ := s.backupRepo.ListUnusedByUser(ctx, userID)
	status.BackupCodes = len(codes)
	if len(codes) > 0 {
		status.Methods = append(status.Methods, "backup_code")
	}

	return status, nil
}

// RequiresMFA determines if a user needs to complete 2FA.
func (s *MFAService) RequiresMFA(ctx context.Context, userID string, trustedDevice bool) (bool, error) {
	status, err := s.GetStatus(ctx, userID)
	if err != nil {
		return false, err
	}

	// No MFA methods configured
	if len(status.Methods) == 0 {
		return s.mfaRequired, nil
	}

	// Trusted device can skip MFA (within trust window)
	if trustedDevice {
		return false, nil
	}

	return true, nil
}
