package config

import (
	"net/url"
	"strings"
	"testing"
)

func TestDatabaseURLPasswordEncoding(t *testing.T) {
	cfg := &Config{
		Profile:       ProfileDev,
		DBHost:        "localhost",
		DBPort:        "5432",
		DBName:        "vault",
		DBSSLMode:     "disable",
		DBAppPassword: "p@ss w0rd!#$%&",
	}

	dbURL := cfg.DatabaseURL("app")

	// Parse the URL to verify it's valid
	parsed, err := url.Parse(dbURL)
	if err != nil {
		t.Fatalf("DatabaseURL should produce a valid URL, got error: %v", err)
	}

	// Extract password from the parsed URL
	password, ok := parsed.User.Password()
	if !ok {
		t.Fatal("URL should contain a password")
	}

	// The password should be decoded back to the original
	if password != "p@ss w0rd!#$%&" {
		t.Errorf("decoded password = %q, want %q", password, "p@ss w0rd!#$%&")
	}
}

func TestDatabaseURLSpecialCharsInPassword(t *testing.T) {
	specialPasswords := []string{
		"p@ssword",
		"pass word",
		"p/a/s/s",
		"p?a=s&s",
		"p#ass",
		"p%20ass",
		"日本語パスワード",
	}

	for _, pw := range specialPasswords {
		t.Run(pw, func(t *testing.T) {
			cfg := &Config{
				Profile:       ProfileDev,
				DBHost:        "localhost",
				DBPort:        "5432",
				DBName:        "vault",
				DBSSLMode:     "disable",
				DBAppPassword: pw,
			}

			dbURL := cfg.DatabaseURL("app")
			parsed, err := url.Parse(dbURL)
			if err != nil {
				t.Fatalf("DatabaseURL should produce a valid URL for password %q: %v", pw, err)
			}

			gotPw, _ := parsed.User.Password()
			if gotPw != pw {
				t.Errorf("round-trip password = %q, want %q", gotPw, pw)
			}
		})
	}
}

func TestDatabaseURLUserEncoding(t *testing.T) {
	cfg := &Config{
		Profile:       ProfileProduction,
		DBHost:        "db.example.com",
		DBPort:        "5432",
		DBName:        "vault",
		DBSSLMode:     "require",
		DBAppPassword: "simple",
	}

	dbURL := cfg.DatabaseURL("app")
	if !strings.Contains(dbURL, "vault_app") {
		t.Error("app URL should contain vault_app user")
	}
	if !strings.Contains(dbURL, "sslmode=require") {
		t.Error("production should preserve sslmode")
	}

	migURL := cfg.DatabaseURL("migration")
	if !strings.Contains(migURL, "vault_mig") {
		t.Error("migration URL should contain vault_mig user")
	}
}
