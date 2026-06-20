package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOIDCProviders(t *testing.T) {
	// Client secret follows the _FILE convention (like the other OAuth secrets).
	secretFile := filepath.Join(t.TempDir(), "okta-secret")
	if err := os.WriteFile(secretFile, []byte("okta-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULT_OIDC_PROVIDERS", " okta , my-idp ,, ")
	t.Setenv("VAULT_OIDC_OKTA_ISSUER", "https://acme.okta.com")
	t.Setenv("VAULT_OIDC_OKTA_CLIENT_ID", "okta-client")
	t.Setenv("VAULT_OIDC_OKTA_CLIENT_SECRET_FILE", secretFile)
	t.Setenv("VAULT_OIDC_OKTA_SCOPES", "openid email")
	// hyphen in name maps to underscore in env key
	t.Setenv("VAULT_OIDC_MY_IDP_ISSUER", "https://idp.test")
	t.Setenv("VAULT_OIDC_MY_IDP_CLIENT_ID", "idp-client")

	c := &Config{}
	c.loadOIDCProviders()

	if len(c.OIDCProviders) != 2 {
		t.Fatalf("expected 2 providers, got %d: %+v", len(c.OIDCProviders), c.OIDCProviders)
	}
	okta := c.OIDCProviders[0]
	if okta.Name != "okta" || okta.Issuer != "https://acme.okta.com" || okta.ClientID != "okta-client" {
		t.Fatalf("okta provider parsed wrong: %+v", okta)
	}
	if okta.ClientSecret != "okta-secret" || okta.Scopes != "openid email" {
		t.Fatalf("okta secret/scopes wrong: %+v", okta)
	}
	if c.OIDCProviders[1].Name != "my-idp" || c.OIDCProviders[1].Issuer != "https://idp.test" {
		t.Fatalf("my-idp provider parsed wrong: %+v", c.OIDCProviders[1])
	}
}

func TestLoadOIDCProviders_SkipsIncomplete(t *testing.T) {
	t.Setenv("VAULT_OIDC_PROVIDERS", "noissuer,noid")
	// noissuer: has client id but no issuer
	t.Setenv("VAULT_OIDC_NOISSUER_CLIENT_ID", "x")
	// noid: has issuer but no client id
	t.Setenv("VAULT_OIDC_NOID_ISSUER", "https://x.test")

	c := &Config{}
	c.loadOIDCProviders()
	if len(c.OIDCProviders) != 0 {
		t.Fatalf("incomplete providers must be skipped, got %+v", c.OIDCProviders)
	}
}

func TestLoadOIDCProviders_NoneConfigured(t *testing.T) {
	t.Setenv("VAULT_OIDC_PROVIDERS", "")
	c := &Config{}
	c.loadOIDCProviders()
	if c.OIDCProviders != nil {
		t.Fatalf("expected no providers, got %+v", c.OIDCProviders)
	}
}
