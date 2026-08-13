package main

import (
	"errors"
	"strings"
	"testing"
)

// TestSanitizeDBErrorRedactsEveryDSNShape is the regression for a credential
// that reached the log through the function written to keep it out.
//
// The pattern was `postgres://[^\s]+@`, which missed two things. pgx accepts
// postgresql:// as well as postgres://, and the DSN can come from an
// operator-supplied DATABASE_URL, so the longer spelling passed through
// untouched. And [^\s]+ stops at whitespace, so a DSN carrying a space anywhere
// before the @ did not match at all and the whole string, password included,
// went to the log.
//
// Connection errors are exactly where this fires: they carry the DSN, they
// happen at boot, and they are the first thing an operator pastes into a ticket.
func TestSanitizeDBErrorRedactsEveryDSNShape(t *testing.T) {
	for _, tc := range []struct {
		name   string
		secret string
		dsn    string
	}{
		{"postgres scheme", "hunter2", "postgres://vault_app:hunter2@db.internal:5432/vault?sslmode=require"},
		{"postgresql scheme", "hunter2", "postgresql://vault_app:hunter2@db.internal:5432/vault"},
		{"password with a space", "pass word", "postgres://vault_app:pass word@db.internal:5432/vault"},
		{"percent-encoded password", "p%20w", "postgres://vault_app:p%20w@db.internal:5432/vault"},
		{"password with an at sign", "a@b", "postgres://vault_app:a@b@db.internal:5432/vault"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeDBError(errors.New("failed to connect to `" + tc.dsn + "`: timeout")).Error()

			if strings.Contains(got, tc.secret) {
				t.Errorf("the password survived redaction in %q: %s", tc.name, got)
			}
			// The host and database have to survive, or an operator cannot tell
			// which target failed and the redaction has cost them the diagnosis.
			if !strings.Contains(got, "db.internal") {
				t.Errorf("the host was redacted away, leaving nothing to diagnose: %s", got)
			}
		})
	}
}

// TestSanitizeDBErrorLeavesUnrelatedErrorsAlone keeps the redaction from
// rewriting messages that carry no DSN at all.
func TestSanitizeDBErrorLeavesUnrelatedErrorsAlone(t *testing.T) {
	const msg = "relation \"auth.users\" does not exist"
	if got := sanitizeDBError(errors.New(msg)).Error(); got != msg {
		t.Errorf("an error with no DSN was rewritten: %q", got)
	}
	if sanitizeDBError(nil) != nil {
		t.Error("a nil error did not stay nil")
	}
}
