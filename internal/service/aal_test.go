package service

import (
	"slices"
	"testing"
	"time"

	vaultemail "github.com/42-v/vault42/internal/email"
)

// A WebAuthn assertion alone used to return AAL3 regardless of the UV flag. A
// discoverable-credential assertion without user verification proves possession
// of a key and nothing else — it is single-factor — so the old mapping asserted
// the highest assurance level NIST defines over one factor.
func TestAALForMethods(t *testing.T) {
	tests := []struct {
		name         string
		methods      []string
		userVerified bool
		want         AuthenticatorAssuranceLevel
	}{
		{"none is AAL1", nil, false, AAL1},
		{"password only is AAL1", []string{MethodPassword}, false, AAL1},
		{"password + totp is AAL2", []string{MethodPassword, MethodTOTP}, false, AAL2},
		{"password + email otp is AAL2", []string{MethodPassword, MethodEmailOTP}, false, AAL2},
		{"password + backup code is AAL2", []string{MethodPassword, MethodBackupCode}, false, AAL2},
		{"federated + totp is AAL2", []string{MethodFederated, MethodTOTP}, false, AAL2},
		{"totp without a first factor stays AAL1", []string{MethodTOTP}, false, AAL1},
		{"unverified webauthn alone is AAL1", []string{MethodWebAuthn}, false, AAL1},
		{"unverified webauthn plus password is AAL2", []string{MethodPassword, MethodWebAuthn}, false, AAL2},
		{"user-verified webauthn is AAL3", []string{MethodWebAuthn}, true, AAL3},
		{"user-verified webauthn wins over password+totp", []string{MethodPassword, MethodTOTP, MethodWebAuthn}, true, AAL3},
		{"user verification without webauthn is ignored", []string{MethodPassword}, true, AAL1},
		{"unknown methods ignored", []string{"carrier-pigeon"}, false, AAL1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AALForMethods(tt.methods, tt.userVerified); got != tt.want {
				t.Errorf("AALForMethods(%v, uv=%v) = %d, want %d", tt.methods, tt.userVerified, got, tt.want)
			}
		})
	}
}

// RFC 8176 amr values and the acr the assurance level maps to (OIDC Core §2).
func TestAuthContextClaims(t *testing.T) {
	tests := []struct {
		name         string
		methods      []string
		userVerified bool
		wantACR      string
		wantAMR      []string
	}{
		{"password only", []string{MethodPassword}, false, "urn:vault42:aal:1", []string{"pwd"}},
		{"password + totp", []string{MethodPassword, MethodTOTP}, false, "urn:vault42:aal:2", []string{"pwd", "otp", "mfa"}},
		{"password + email otp", []string{MethodPassword, MethodEmailOTP}, false, "urn:vault42:aal:2", []string{"pwd", "otp", "mfa"}},
		{"verified webauthn", []string{MethodWebAuthn}, true, "urn:vault42:aal:3", []string{"hwk", "user", "mfa"}},
		{"unverified webauthn", []string{MethodWebAuthn}, false, "urn:vault42:aal:1", []string{"hwk"}},
		{"federated + totp", []string{MethodFederated, MethodTOTP}, false, "urn:vault42:aal:2", []string{"otp", "mfa"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			at := time.Unix(1_700_000_000, 0)
			got := NewAuthContext(at, tt.methods, tt.userVerified)
			if got.ACR != tt.wantACR {
				t.Errorf("acr = %q, want %q", got.ACR, tt.wantACR)
			}
			if !slices.Equal(got.AMR, tt.wantAMR) {
				t.Errorf("amr = %v, want %v", got.AMR, tt.wantAMR)
			}
			if !got.AuthTime.Equal(at) {
				t.Errorf("auth_time = %v, want %v", got.AuthTime, at)
			}
		})
	}
}

func TestAuthService_SetMailer(t *testing.T) {
	s := &AuthService{}
	s.SetMailer(nil)
	if s.mailer != nil {
		t.Error("nil mailer should be ignored by SetMailer")
	}
	m := vaultemail.NewMailer(nil, nil, nil, vaultemail.Branding{}, nil)
	s.SetMailer(m)
	if s.mailer != m {
		t.Error("non-nil mailer should be stored")
	}
}
