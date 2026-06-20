package service

import (
	"context"
	"fmt"

	"github.com/42-v/vault42/internal/repository"
)

// AuthenticatorAssuranceLevel models the NIST SP 800-63B authenticator
// assurance levels (AAL, §4) reached by a completed authentication. The level
// is a function of which authenticator combination the user presented; these
// constants give callers a stable vocabulary for reasoning about that mapping
// (see AALForMethods). They are descriptive only and impose no policy on their
// own.
type AuthenticatorAssuranceLevel int

const (
	// AAL1 — single-factor authentication (e.g. password alone). Provides some
	// assurance that the claimant controls an authenticator bound to the
	// account. NIST SP 800-63B §4.1.
	AAL1 AuthenticatorAssuranceLevel = 1

	// AAL2 — multi-factor authentication: a memorized secret (password) plus a
	// second factor such as a TOTP authenticator or an email one-time code.
	// Proves possession and control of two distinct factors. NIST SP 800-63B
	// §4.2 / §5.2.4.
	AAL2 AuthenticatorAssuranceLevel = 2

	// AAL3 — multi-factor authentication using a hardware-based, phishing-
	// resistant authenticator (WebAuthn / FIDO2 security key or platform
	// authenticator). Requires proof of possession of a key via a cryptographic
	// protocol and verifier impersonation resistance. NIST SP 800-63B §4.3.
	AAL3 AuthenticatorAssuranceLevel = 3
)

// Authenticator method identifiers as surfaced in MFAStatus.Methods. These are
// the canonical strings used to describe a completed factor.
const (
	MethodPassword   = "password"    // memorized secret (something you know)
	MethodTOTP       = "totp"        // time-based one-time password authenticator
	MethodEmailOTP   = "email_otp"   // one-time code delivered out-of-band by email
	MethodBackupCode = "backup_code" // pre-shared single-use recovery code
	MethodWebAuthn   = "webauthn"    // WebAuthn / FIDO2 phishing-resistant authenticator
)

// AALForMethods maps a set of completed authenticator methods to the NIST SP
// 800-63B assurance level they satisfy. It applies the §5.2.4 combination rules:
//
//   - WebAuthn / FIDO2 present                  → AAL3 (phishing-resistant MFA)
//   - password + TOTP or password + email-OTP   → AAL2 (multi-factor)
//   - password (or any single factor) only      → AAL1 (single-factor)
//   - no recognized factor                       → AAL1 (lowest)
//
// This is a documentation-grade helper: it derives the assurance level from the
// factors already verified elsewhere and changes no authentication behavior.
func AALForMethods(methods []string) AuthenticatorAssuranceLevel {
	var hasPassword, hasTOTP, hasEmailOTP, hasWebAuthn bool
	for _, m := range methods {
		switch m {
		case MethodPassword:
			hasPassword = true
		case MethodTOTP:
			hasTOTP = true
		case MethodEmailOTP:
			hasEmailOTP = true
		case MethodWebAuthn:
			hasWebAuthn = true
		}
	}
	switch {
	case hasWebAuthn:
		return AAL3
	case hasPassword && (hasTOTP || hasEmailOTP):
		return AAL2
	default:
		return AAL1
	}
}

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
