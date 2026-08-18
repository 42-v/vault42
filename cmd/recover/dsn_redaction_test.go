package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// This is the one tool that always holds the production DSN — it is the whole
// point of the offline host it runs on — and it was the only one that logged a
// connect failure without redacting it. pgx puts the DSN it dialled into that
// error, so a wrong host or a firewall between the two printed the database
// password onto the operator's terminal and into whatever captured its stderr.
// cmd/vault and cmd/admin-gateway both strip the userinfo before logging; this
// asserts recover does too.
func TestRun_ConnectErrorDoesNotPrintTheDSNPassword(t *testing.T) {
	const password = "sup3r-s3cret-db-passw0rd"
	const dsn = "postgres://vault_recover:" + password + "@db.internal:5432/vault?sslmode=require"

	for name, scheme := range map[string]string{
		"postgres":   "postgres://vault_recover:" + password + "@db.internal:5432/vault",
		"postgresql": "postgresql://vault_recover:" + password + "@db.internal:5432/vault",
	} {
		t.Run(name, func(t *testing.T) {
			o := &opened{err: errors.New(`failed to connect to ` + "`" + scheme + "`" + `: dial error`)}
			var stdout, stderr bytes.Buffer

			code := run([]string{"--key", writeKey(t, escrowKey), "--dsn", dsn}, &stdout, &stderr, o.open)
			if code != 1 {
				t.Fatalf("exit code = %d, want 1", code)
			}
			if strings.Contains(stderr.String(), password) {
				t.Errorf("the database password reached stderr:\n%s", stderr.String())
			}
			if !strings.Contains(stderr.String(), "db.internal:5432") {
				t.Errorf("redaction also removed the host, which the operator needs:\n%s", stderr.String())
			}
		})
	}
}
