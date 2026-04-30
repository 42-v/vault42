package jwt

import (
	"encoding/json"
	"testing"
	"time"
)

// Compile-time check that RegisteredClaims implements Claims.
var (
	_ Claims = RegisteredClaims{}
	_ Claims = &RegisteredClaims{}
)

func TestRegisteredClaims_Getters(t *testing.T) {
	now := time.Unix(1700000000, 0)
	claims := RegisteredClaims{
		Issuer:    "vault",
		Subject:   "user-123",
		Audience:  ClaimStrings{"api"},
		ExpiresAt: NewNumericDate(now.Add(time.Hour)),
		NotBefore: NewNumericDate(now),
		IssuedAt:  NewNumericDate(now),
		ID:        "jti-abc",
	}

	if got := claims.GetIssuer(); got != "vault" {
		t.Errorf("GetIssuer() = %q, want %q", got, "vault")
	}
	if got := claims.GetSubject(); got != "user-123" {
		t.Errorf("GetSubject() = %q, want %q", got, "user-123")
	}
	aud := claims.GetAudience()
	if len(aud) != 1 || aud[0] != "api" {
		t.Errorf("GetAudience() = %v, want [api]", aud)
	}
	if claims.GetExpirationTime() == nil {
		t.Error("GetExpirationTime() = nil")
	}
	if claims.GetNotBefore() == nil {
		t.Error("GetNotBefore() = nil")
	}
	if claims.GetIssuedAt() == nil {
		t.Error("GetIssuedAt() = nil")
	}
}

func TestRegisteredClaims_NilGetters(t *testing.T) {
	claims := RegisteredClaims{}
	if claims.GetExpirationTime() != nil {
		t.Error("GetExpirationTime() should be nil for empty claims")
	}
	if claims.GetIssuedAt() != nil {
		t.Error("GetIssuedAt() should be nil for empty claims")
	}
	if claims.GetNotBefore() != nil {
		t.Error("GetNotBefore() should be nil for empty claims")
	}
	if claims.GetIssuer() != "" {
		t.Error("GetIssuer() should be empty for empty claims")
	}
	if claims.GetSubject() != "" {
		t.Error("GetSubject() should be empty for empty claims")
	}
	if claims.GetAudience() != nil {
		t.Error("GetAudience() should be nil for empty claims")
	}
}

func TestRegisteredClaims_MarshalJSON(t *testing.T) {
	now := time.Unix(1700000000, 0)
	claims := RegisteredClaims{
		Issuer:    "vault",
		Subject:   "user-1",
		Audience:  ClaimStrings{"api"},
		ExpiresAt: NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  NewNumericDate(now),
		ID:        "jti-1",
	}

	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal into map: %v", err)
	}

	if m["iss"] != "vault" {
		t.Errorf("iss = %v, want vault", m["iss"])
	}
	if m["sub"] != "user-1" {
		t.Errorf("sub = %v, want user-1", m["sub"])
	}
	if m["jti"] != "jti-1" {
		t.Errorf("jti = %v, want jti-1", m["jti"])
	}
}

func TestRegisteredClaims_OmitEmpty(t *testing.T) {
	claims := RegisteredClaims{Issuer: "vault"}
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Only iss should be present
	if _, ok := m["sub"]; ok {
		t.Error("sub should be omitted")
	}
	if _, ok := m["aud"]; ok {
		t.Error("aud should be omitted")
	}
	if _, ok := m["exp"]; ok {
		t.Error("exp should be omitted")
	}
	if _, ok := m["nbf"]; ok {
		t.Error("nbf should be omitted")
	}
	if _, ok := m["iat"]; ok {
		t.Error("iat should be omitted")
	}
	if _, ok := m["jti"]; ok {
		t.Error("jti should be omitted")
	}
}

func TestRegisteredClaims_UnmarshalJSON(t *testing.T) {
	raw := `{"iss":"vault","sub":"u","aud":["a","b"],"exp":1700003600,"iat":1700000000,"jti":"j1"}`
	var claims RegisteredClaims
	if err := json.Unmarshal([]byte(raw), &claims); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if claims.Issuer != "vault" {
		t.Errorf("Issuer = %q, want vault", claims.Issuer)
	}
	if claims.Subject != "u" {
		t.Errorf("Subject = %q, want u", claims.Subject)
	}
	if len(claims.Audience) != 2 {
		t.Errorf("Audience len = %d, want 2", len(claims.Audience))
	}
	if claims.ExpiresAt == nil || claims.ExpiresAt.Unix() != 1700003600 {
		t.Error("ExpiresAt mismatch")
	}
	if claims.IssuedAt == nil || claims.IssuedAt.Unix() != 1700000000 {
		t.Error("IssuedAt mismatch")
	}
	if claims.ID != "j1" {
		t.Errorf("ID = %q, want j1", claims.ID)
	}
}
