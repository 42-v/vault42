package config

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestDatabaseURLPinsTheSessionTimezoneToUTC covers a promise the API makes and
// the connection string did not keep.
//
// docs/spec.md states that every timestamp the API emits is RFC 3339 in UTC.
// Nothing enforced it. Postgres returns a timestamptz rendered in the session's
// TimeZone, pgx builds a time.Time carrying that offset, and the handlers
// marshal it straight through, so the offset in the response body is whatever
// the database server's timezone happens to be. A server running Europe/Berlin
// emits 2026-08-13T07:41:00+02:00 where the specification promises
// 2026-08-13T05:41:00Z.
//
// Both are the same instant and both are valid RFC 3339, which is why no test
// and no client crash would ever have surfaced it. What breaks is anything
// comparing timestamps as strings: a cursor, an ETag, a signature over a
// serialized body, a log correlation, or a client that slices the first ten
// characters to get a date and silently gets the wrong day for two hours every
// night.
//
// The fix belongs on the connection rather than at each marshal site because
// there are dozens of the latter and one of the former, and a new handler
// returning a new timestamp inherits it for free.
func TestDatabaseURLPinsTheSessionTimezoneToUTC(t *testing.T) {
	for _, role := range []string{"app", "migration"} {
		t.Run(role, func(t *testing.T) {
			cfg := &Config{
				Profile:       ProfileProduction,
				DBHost:        "db.internal",
				DBPort:        "5432",
				DBName:        "vault",
				DBSSLMode:     "verify-full",
				DBAppPassword: "app-secret",
				DBMigPassword: "mig-secret",
			}

			// Parsed with the same parser the pool uses, so this asserts what
			// pgx will actually send in the startup packet rather than what the
			// query string looks like.
			parsed, err := pgxpool.ParseConfig(cfg.DatabaseURL(role))
			if err != nil {
				t.Fatalf("pgxpool.ParseConfig rejected the DSN: %v", err)
			}

			if got := parsed.ConnConfig.RuntimeParams["timezone"]; got != "UTC" {
				t.Errorf("session timezone = %q, want %q. Without it Postgres renders every "+
					"timestamptz in the server's own zone and the API emits offsets where "+
					"docs/spec.md promises UTC.", got, "UTC")
			}
		})
	}
}

// TestDatabaseURLSurvivesAPasswordWithURLMetacharacters is the neighbouring
// property, pinned here because the timezone parameter is appended to the same
// query string that the password's encoding depends on.
//
// The password is placed with url.UserPassword, so it is percent-encoded, and
// this asserts that a password containing the characters that break a
// hand-built DSN still round-trips through the real parser. cmd/admin-gateway
// shipped the hand-built form and a '%' in the password was decoded silently,
// authenticating the process as a different string than the one on disk.
func TestDatabaseURLSurvivesAPasswordWithURLMetacharacters(t *testing.T) {
	const nasty = "a%b/c?d#e f:g@h&i=j"

	cfg := &Config{
		Profile:       ProfileProduction,
		DBHost:        "db.internal",
		DBPort:        "5432",
		DBName:        "vault",
		DBSSLMode:     "verify-full",
		DBAppPassword: nasty,
	}

	parsed, err := pgxpool.ParseConfig(cfg.DatabaseURL("app"))
	if err != nil {
		t.Fatalf("pgxpool.ParseConfig rejected a DSN with a metacharacter password: %v", err)
	}
	if parsed.ConnConfig.Password != nasty {
		t.Errorf("password round-tripped as %q, want %q; the process would authenticate as a "+
			"different string than the one on disk", parsed.ConnConfig.Password, nasty)
	}
	if parsed.ConnConfig.User != "vault_app" {
		t.Errorf("user = %q, want vault_app", parsed.ConnConfig.User)
	}
	if got := parsed.ConnConfig.RuntimeParams["timezone"]; got != "UTC" {
		t.Errorf("session timezone = %q, want UTC; the password encoding must not displace it", got)
	}
}
