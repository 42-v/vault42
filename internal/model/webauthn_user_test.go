package model

import (
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

// *WebAuthnUser satisfies webauthn.User at compile time. This was a test
// function whose body was this line, so it ran, asserted nothing, and reported
// the same result whether or not the package still compiled -- the compiler had
// already decided by then.
var _ webauthn.User = (*WebAuthnUser)(nil)

func TestWebAuthnID(t *testing.T) {
	tests := []struct {
		name   string
		userID string
		want   []byte
	}{
		{"uuid", "550e8400-e29b-41d4-a716-446655440000", []byte("550e8400-e29b-41d4-a716-446655440000")},
		{"short id", "abc", []byte("abc")},
		{"empty id", "", []byte("")},
		{"numeric id", "12345", []byte("12345")},
		{"unicode id", "user-\u00e9\u00e0\u00fc", []byte("user-\u00e9\u00e0\u00fc")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &WebAuthnUser{User: &User{ID: tt.userID}}
			got := u.WebAuthnID()
			if string(got) != string(tt.want) {
				t.Errorf("WebAuthnID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWebAuthnName(t *testing.T) {
	tests := []struct {
		name  string
		email string
	}{
		{"standard email", "user@example.com"},
		{"empty email", ""},
		{"plus address", "user+tag@example.com"},
		{"subdomain", "admin@auth.example.co.uk"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &WebAuthnUser{User: &User{Email: tt.email}}
			got := u.WebAuthnName()
			if got != tt.email {
				t.Errorf("WebAuthnName() = %q, want %q", got, tt.email)
			}
		})
	}
}

func TestWebAuthnDisplayName(t *testing.T) {
	tests := []struct {
		name        string
		displayName string
		email       string
		want        string
	}{
		{"display name set", "Alice Vault", "alice@example.com", "Alice Vault"},
		{"display name empty falls back to email", "", "alice@example.com", "alice@example.com"},
		{"both empty", "", "", ""},
		{"whitespace display name used as-is", "  ", "alice@example.com", "  "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &WebAuthnUser{User: &User{
				Email:       tt.email,
				DisplayName: tt.displayName,
			}}
			got := u.WebAuthnDisplayName()
			if got != tt.want {
				t.Errorf("WebAuthnDisplayName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWebAuthnCredentials(t *testing.T) {
	t.Run("nil credentials", func(t *testing.T) {
		u := &WebAuthnUser{User: &User{ID: "u1"}, Credentials: nil}
		got := u.WebAuthnCredentials()
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("empty credentials", func(t *testing.T) {
		u := &WebAuthnUser{User: &User{ID: "u1"}, Credentials: []webauthn.Credential{}}
		got := u.WebAuthnCredentials()
		if got == nil {
			t.Error("expected non-nil empty slice, got nil")
		}
		if len(got) != 0 {
			t.Errorf("expected 0 credentials, got %d", len(got))
		}
	})

	t.Run("single credential", func(t *testing.T) {
		creds := []webauthn.Credential{
			{ID: []byte("cred-1")},
		}
		u := &WebAuthnUser{User: &User{ID: "u1"}, Credentials: creds}
		got := u.WebAuthnCredentials()
		if len(got) != 1 {
			t.Fatalf("expected 1 credential, got %d", len(got))
		}
		if string(got[0].ID) != "cred-1" {
			t.Errorf("credential ID = %q, want %q", got[0].ID, "cred-1")
		}
	})

	t.Run("multiple credentials", func(t *testing.T) {
		creds := []webauthn.Credential{
			{ID: []byte("cred-1")},
			{ID: []byte("cred-2")},
			{ID: []byte("cred-3")},
		}
		u := &WebAuthnUser{User: &User{ID: "u1"}, Credentials: creds}
		got := u.WebAuthnCredentials()
		if len(got) != 3 {
			t.Fatalf("expected 3 credentials, got %d", len(got))
		}
		for i, c := range got {
			if string(c.ID) != string(creds[i].ID) {
				t.Errorf("credential[%d].ID = %q, want %q", i, c.ID, creds[i].ID)
			}
		}
	})

	t.Run("returns same slice reference", func(t *testing.T) {
		creds := []webauthn.Credential{{ID: []byte("c1")}}
		u := &WebAuthnUser{User: &User{ID: "u1"}, Credentials: creds}

		got := u.WebAuthnCredentials()
		// Mutating the returned slice should affect the original
		got[0].ID = []byte("mutated")
		if string(u.Credentials[0].ID) != "mutated" {
			t.Error("WebAuthnCredentials should return the same slice, not a copy")
		}
	})
}
