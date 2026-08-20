package jwt

import (
	"errors"
	"testing"
	"time"
)

func TestValidate_ExpiredToken(t *testing.T) {
	claims := RegisteredClaims{
		ExpiresAt: NewNumericDate(time.Now().Add(-time.Hour)),
	}
	err := validateClaims(claims, &validationConfig{})
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("got %v, want ErrTokenExpired", err)
	}
}

func TestValidate_ValidExpiration(t *testing.T) {
	claims := RegisteredClaims{
		ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
	}
	err := validateClaims(claims, &validationConfig{})
	if err != nil {
		t.Errorf("got %v, want nil", err)
	}
}

func TestValidate_MissingExp_Required(t *testing.T) {
	claims := RegisteredClaims{}
	err := validateClaims(claims, &validationConfig{requireExp: true})
	if !errors.Is(err, ErrTokenRequiredClaimMissing) {
		t.Errorf("got %v, want ErrTokenRequiredClaimMissing", err)
	}
}

func TestValidate_MissingExp_NotRequired(t *testing.T) {
	claims := RegisteredClaims{}
	err := validateClaims(claims, &validationConfig{})
	if err != nil {
		t.Errorf("got %v, want nil", err)
	}
}

func TestValidate_NotValidYet(t *testing.T) {
	claims := RegisteredClaims{
		ExpiresAt: NewNumericDate(time.Now().Add(2 * time.Hour)),
		NotBefore: NewNumericDate(time.Now().Add(time.Hour)),
	}
	err := validateClaims(claims, &validationConfig{})
	if !errors.Is(err, ErrTokenNotValidYet) {
		t.Errorf("got %v, want ErrTokenNotValidYet", err)
	}
}

func TestValidate_ValidNBF(t *testing.T) {
	claims := RegisteredClaims{
		ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
		NotBefore: NewNumericDate(time.Now().Add(-time.Hour)),
	}
	err := validateClaims(claims, &validationConfig{})
	if err != nil {
		t.Errorf("got %v, want nil", err)
	}
}

func TestValidate_FutureIAT(t *testing.T) {
	claims := RegisteredClaims{
		ExpiresAt: NewNumericDate(time.Now().Add(2 * time.Hour)),
		IssuedAt:  NewNumericDate(time.Now().Add(time.Hour)),
	}
	err := validateClaims(claims, &validationConfig{verifyIat: true})
	if !errors.Is(err, ErrTokenUsedBeforeIssued) {
		t.Errorf("got %v, want ErrTokenUsedBeforeIssued", err)
	}
}

func TestValidate_PastIAT(t *testing.T) {
	claims := RegisteredClaims{
		ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  NewNumericDate(time.Now().Add(-time.Minute)),
	}
	err := validateClaims(claims, &validationConfig{verifyIat: true})
	if err != nil {
		t.Errorf("got %v, want nil", err)
	}
}

func TestValidate_IATNotChecked(t *testing.T) {
	claims := RegisteredClaims{
		ExpiresAt: NewNumericDate(time.Now().Add(2 * time.Hour)),
		IssuedAt:  NewNumericDate(time.Now().Add(time.Hour)), // future
	}
	// verifyIat = false, so future iat should not error
	err := validateClaims(claims, &validationConfig{verifyIat: false})
	if err != nil {
		t.Errorf("got %v, want nil (iat not checked)", err)
	}
}

func TestValidate_WrongIssuer(t *testing.T) {
	claims := RegisteredClaims{
		Issuer:    "wrong",
		ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
	}
	err := validateClaims(claims, &validationConfig{expectedIssuer: "vault"})
	if !errors.Is(err, ErrTokenInvalidIssuer) {
		t.Errorf("got %v, want ErrTokenInvalidIssuer", err)
	}
}

func TestValidate_CorrectIssuer(t *testing.T) {
	claims := RegisteredClaims{
		Issuer:    "vault",
		ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
	}
	err := validateClaims(claims, &validationConfig{expectedIssuer: "vault"})
	if err != nil {
		t.Errorf("got %v, want nil", err)
	}
}

func TestValidate_WrongAudience(t *testing.T) {
	claims := RegisteredClaims{
		Audience:  ClaimStrings{"other"},
		ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
	}
	err := validateClaims(claims, &validationConfig{expectedAud: "api"})
	if !errors.Is(err, ErrTokenInvalidAudience) {
		t.Errorf("got %v, want ErrTokenInvalidAudience", err)
	}
}

func TestValidate_CorrectAudience(t *testing.T) {
	claims := RegisteredClaims{
		Audience:  ClaimStrings{"api"},
		ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
	}
	err := validateClaims(claims, &validationConfig{expectedAud: "api"})
	if err != nil {
		t.Errorf("got %v, want nil", err)
	}
}

func TestValidate_MultipleAudiences(t *testing.T) {
	claims := RegisteredClaims{
		Audience:  ClaimStrings{"web", "api", "mobile"},
		ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
	}
	err := validateClaims(claims, &validationConfig{expectedAud: "api"})
	if err != nil {
		t.Errorf("got %v, want nil (api in audience list)", err)
	}
}

func TestValidate_EmptyAudience_Expected(t *testing.T) {
	claims := RegisteredClaims{
		ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
	}
	err := validateClaims(claims, &validationConfig{expectedAud: "api"})
	if !errors.Is(err, ErrTokenInvalidAudience) {
		t.Errorf("got %v, want ErrTokenInvalidAudience", err)
	}
}

// An empty expectedAud means the caller is not checking audience, so a token
// that carries one has to pass unexamined. The claims used to carry no aud at
// all, which made this a second copy of TestValidate_ValidExpiration: same
// branch, same outcome, and it would have kept passing if the check had started
// refusing every audience it was not asked about.
func TestValidate_NoAudienceRequired(t *testing.T) {
	claims := RegisteredClaims{
		Audience:  ClaimStrings{"some-other-api"},
		ExpiresAt: NewNumericDate(time.Now().Add(time.Hour)),
	}
	err := validateClaims(claims, &validationConfig{})
	if err != nil {
		t.Errorf("got %v, want nil (no audience required)", err)
	}
}

func TestValidate_AllErrorsCollected(t *testing.T) {
	claims := RegisteredClaims{
		Issuer:    "wrong-issuer",
		Audience:  ClaimStrings{"wrong-audience"},
		ExpiresAt: NewNumericDate(time.Now().Add(-time.Hour)),
	}
	cfg := &validationConfig{
		expectedIssuer: "vault",
		expectedAud:    "api",
	}
	err := validateClaims(claims, cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// All three errors should be present
	if !errors.Is(err, ErrTokenExpired) {
		t.Error("missing ErrTokenExpired")
	}
	if !errors.Is(err, ErrTokenInvalidIssuer) {
		t.Error("missing ErrTokenInvalidIssuer")
	}
	if !errors.Is(err, ErrTokenInvalidAudience) {
		t.Error("missing ErrTokenInvalidAudience")
	}
}

func TestValidate_SkipValidation(t *testing.T) {
	claims := RegisteredClaims{
		ExpiresAt: NewNumericDate(time.Now().Add(-time.Hour)), // expired
	}
	// skipValidation doesn't affect validateClaims directly — it's used by ParseWithClaims
	// This tests that the caller can choose to skip
	err := validateClaims(claims, &validationConfig{})
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("got %v, want ErrTokenExpired (validation not skipped at this level)", err)
	}
}
