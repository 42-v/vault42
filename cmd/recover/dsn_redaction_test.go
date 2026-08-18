package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// This is the one tool that always holds the production DSN — it is the whole
// point of the offline host it runs on — and it was the only one that logged a
// connect failure without redacting it. pgx puts the DSN it dialed into that
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

// The connect failure above was the only leak channel with a test. Three more
// log lines print an error the tool did not build while the DSN is in scope -
// the row scan, the iteration error raised after the last row, and the encode of
// a record to the output - and none of them carried one.
//
// Both halves matter. The driver's own error text embeds the DSN it dialed, so
// these lines have to be redacted; and nothing may append the DSN itself, which
// is what a leak test with no needle cannot notice. Adding `(dsn=%s)` to any of
// the three used to leave the whole suite green.
//
// TestRun_ScanFailureIsFatal, TestRun_IterationErrorIsFatal and
// TestRun_OutputWriteFailureIsFatal all drive these same statements. They assert
// on the exit code and the summary, which is why the leak sat under 159 passing
// assertions; the exercise here is the same, with a password in the DSN and an
// error that carries it.
func TestRun_RowFailuresDoNotPrintTheDSNPassword(t *testing.T) {
	const password = "sup3r-s3cret-db-passw0rd"
	const dsn = "postgres://vault_recover:" + password + "@db.internal:5432/vault?sslmode=require"

	// The shape pgx raises: it puts the DSN it dialed into its errors, so this is
	// what these three lines are handed on a real recovery run, not a contrivance.
	driverErr := errors.New("failed to connect to `" + dsn + "`: read tcp 10.0.0.2:5432: connection reset by peer")

	tests := map[string]struct {
		rows   *fakeRows
		stdout io.Writer
		want   string
	}{
		"scan": {
			rows: &fakeRows{rows: []escrowRow{{scanErr: driverErr}}},
			want: "recover: scan:",
		},
		"iterate": {
			rows: &fakeRows{rows: []escrowRow{goodRow(t, sampleEmail)}, iterErr: driverErr},
			want: "recover: iterate:",
		},
		"encode": {
			rows:   &fakeRows{rows: []escrowRow{goodRow(t, sampleEmail)}},
			stdout: &failingWriter{err: driverErr},
			want:   "recover: encode:",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Setenv("DATABASE_URL", "")
			o := &opened{rows: tc.rows}
			stdout := tc.stdout
			if stdout == nil {
				stdout = &bytes.Buffer{}
			}
			var stderr bytes.Buffer

			code := run([]string{"--key", writeKey(t, escrowKey), "--dsn", dsn}, stdout, &stderr, o.open)

			if code != 1 {
				t.Fatalf("exit code = %d, want 1: this test is only meaningful on the failure path", code)
			}
			// Without this the leak check could pass because the diagnostic never
			// ran, rather than because it ran and said nothing.
			if !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("stderr does not carry %q, so the line under test never ran:\n%s", tc.want, stderr.String())
			}
			mustNotLeak(t, name+" diagnostic", stderr.String(), password)
			// Redaction must stop at the userinfo. An operator reading this on an
			// incident bridge needs to know which database the run was talking to.
			if !strings.Contains(stderr.String(), "db.internal:5432") {
				t.Errorf("redaction also removed the host, which the operator needs:\n%s", stderr.String())
			}
		})
	}
}
