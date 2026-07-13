package service

import (
	"testing"

	vaultemail "github.com/42-v/vault42/internal/email"
)

func TestAALForMethods(t *testing.T) {
	tests := []struct {
		name    string
		methods []string
		want    AuthenticatorAssuranceLevel
	}{
		{"none is AAL1", nil, AAL1},
		{"password only is AAL1", []string{MethodPassword}, AAL1},
		{"password + totp is AAL2", []string{MethodPassword, MethodTOTP}, AAL2},
		{"password + email otp is AAL2", []string{MethodPassword, MethodEmailOTP}, AAL2},
		{"totp without password stays AAL1", []string{MethodTOTP}, AAL1},
		{"webauthn is AAL3", []string{MethodWebAuthn}, AAL3},
		{"webauthn wins over password+totp", []string{MethodPassword, MethodTOTP, MethodWebAuthn}, AAL3},
		{"unknown methods ignored", []string{"carrier-pigeon"}, AAL1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AALForMethods(tt.methods); got != tt.want {
				t.Errorf("AALForMethods(%v) = %d, want %d", tt.methods, got, tt.want)
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
