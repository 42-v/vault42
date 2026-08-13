// Tests for the offline erasure-recovery tool.
//
// cmd/recover is the only code in the tree that can turn an escrow record back
// into a real person's email address. It runs on an operator's offline host,
// against input (the escrow log) that a compromised server or database can
// influence, holding the one private key the product deliberately keeps away
// from production. Two properties therefore matter more than the feature set:
//
//   - It fails closed. A wrong key, a truncated blob, a bit-flip, a
//     length-extended record or a payload that decrypts but is not the expected
//     JSON must all produce nothing on stdout. A restore driven off partial
//     output would write half-recovered identities back into the user table.
//   - It leaks nothing on the way. Recovered plaintext goes to the stdout the
//     caller asked for and nowhere else, and the diagnostics an operator reads
//     (and pastes into tickets) must not carry key material.
//
// These tests drive run() directly with an in-memory escrow log so every reject
// path is reachable without a database. postgres_test.go covers the same tool
// through the real pgx driver.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
)

// escrowKey is the recovery key pair the fixtures encrypt to, and wrongKey is a
// second, unrelated pair standing in for "the operator grabbed the wrong PEM".
// Both are generated once because RSA-2048 keygen dominates the runtime of this
// package otherwise.
var (
	escrowKey *rsa.PrivateKey
	wrongKey  *rsa.PrivateKey
)

// subprocessArgsEnv, when set, turns the test binary into the recover binary so
// TestMainWiring can observe the real process exit code and the real
// os.Stdout/os.Stderr. Arguments are unit-separated because a recovery DSN can
// legitimately contain spaces.
const subprocessArgsEnv = "RECOVER_TEST_ARGS"

const argSep = "\x1f"

func TestMain(m *testing.M) {
	if raw, ok := os.LookupEnv(subprocessArgsEnv); ok {
		os.Args = append([]string{"recover"}, splitArgs(raw)...)
		main()
		return
	}

	var err error
	if escrowKey, err = vaultcrypto.GenerateRSAKeyPair(); err != nil {
		fmt.Fprintf(os.Stderr, "generate escrow key: %v\n", err)
		os.Exit(1)
	}
	if wrongKey, err = vaultcrypto.GenerateRSAKeyPair(); err != nil {
		fmt.Fprintf(os.Stderr, "generate wrong key: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func splitArgs(raw string) []string {
	if raw == "" {
		return nil
	}
	return strings.Split(raw, argSep)
}

// ---------------------------------------------------------------------------
// In-memory escrow log
// ---------------------------------------------------------------------------

// escrowRow is one row of auth.account_recovery. deletedBy and reason are
// pointers because both columns are nullable in the schema.
//
// id and pseudonym are not output; they are the context a bound payload was
// sealed to, which is why they have to travel with the row rather than being
// invented at decrypt time. A test that leaves them empty is describing a row
// whose binding does not match its payload, and the tool must refuse it.
type escrowRow struct {
	id        string
	pseudonym string
	payload   []byte
	deletedAt time.Time
	deletedBy *string
	reason    *string

	// scanErr models a driver-level decode failure on this row (a NULL in a NOT
	// NULL column, a type the driver cannot map). The tool must treat it as
	// fatal, not as one more skippable record.
	scanErr error
}

// fakeRows is an in-memory rowSource. It records how many times it was closed so
// tests can prove the tool releases the connection it opened.
type fakeRows struct {
	rows    []escrowRow
	next    int
	iterErr error
	closed  int
}

func (f *fakeRows) Next() bool {
	if f.next >= len(f.rows) {
		return false
	}
	f.next++
	return true
}

func (f *fakeRows) Scan(dest ...any) error {
	row := f.rows[f.next-1]
	if row.scanErr != nil {
		return row.scanErr
	}
	if len(dest) != 6 {
		return fmt.Errorf("escrow query selects 6 columns, tool scanned %d", len(dest))
	}
	id, ok := dest[0].(*string)
	if !ok {
		return fmt.Errorf("column 1 (id::text) scanned into %T", dest[0])
	}
	pseudonym, ok := dest[1].(*string)
	if !ok {
		return fmt.Errorf("column 2 (pseudonym, TEXT) scanned into %T", dest[1])
	}
	payload, ok := dest[2].(*[]byte)
	if !ok {
		return fmt.Errorf("column 3 (payload, BYTEA) scanned into %T", dest[2])
	}
	deletedAt, ok := dest[3].(*time.Time)
	if !ok {
		return fmt.Errorf("column 4 (deleted_at, TIMESTAMPTZ) scanned into %T", dest[3])
	}
	deletedBy, ok := dest[4].(**string)
	if !ok {
		return fmt.Errorf("column 5 (deleted_by, nullable TEXT) scanned into %T", dest[4])
	}
	reason, ok := dest[5].(**string)
	if !ok {
		return fmt.Errorf("column 6 (reason, nullable TEXT) scanned into %T", dest[5])
	}
	*id, *pseudonym = row.id, row.pseudonym
	*payload, *deletedAt, *deletedBy, *reason = row.payload, row.deletedAt, row.deletedBy, row.reason
	return nil
}

func (f *fakeRows) Err() error { return f.iterErr }

func (f *fakeRows) Close() { f.closed++ }

// opened records what run() asked the opener for, so tests can assert on the DSN
// and LIMIT that would have reached the database.
type opened struct {
	calls int
	dsn   string
	limit int
	rows  *fakeRows
	err   error
}

func (o *opened) open(_ context.Context, dsn string, limit int) (rowSource, func(), error) {
	o.calls++
	o.dsn, o.limit = dsn, limit
	if o.err != nil {
		return nil, nil, o.err
	}
	return o.rows, o.rows.Close, nil
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// sampleAccount is the profile the erasure service escrows
// (internal/service/erasure.go recoveryPayload). The values are distinctive so a
// leak test can search for them.
const (
	sampleEmail       = "erased.subject@example.invalid"
	sampleDisplayName = "Erased Subject"
)

var sampleCreatedAt = time.Date(2023, 4, 5, 6, 7, 8, 0, time.UTC)

// escrowJSON is the plaintext the erasure service writes before encrypting. The
// object is spelled out rather than marshaled from escrowedPayload so the
// fixture pins the wire format independently of the struct the tool parses it
// with: renaming a json tag on one side has to break these tests.
func escrowJSON(t *testing.T, email, displayName string, roles []string) []byte {
	t.Helper()
	return escrowJSONFor(t, userIDFor(email), email, displayName, roles)
}

// escrowJSONFor is escrowJSON with the subject named explicitly, for the cases
// that need a payload whose user_id disagrees with the row, or is missing.
func escrowJSONFor(t *testing.T, userID, email, displayName string, roles []string) []byte {
	t.Helper()
	return fmt.Appendf(nil,
		`{"v":2,"user_id":%s,"email":%s,"created_at":%s,"roles":%s,"display_name":%s}`,
		jsonValue(t, userID), jsonValue(t, email), jsonValue(t, sampleCreatedAt),
		jsonValue(t, roles), jsonValue(t, displayName))
}

// The fixture rows are derived from the account they describe so that a test can
// rebuild the same binding without threading a row through every helper. Real
// ids come from crypto.RandomUUID and real pseudonyms from HMAC-SHA256; these
// only have to be stable, distinct per account, and shaped like the columns.
func userIDFor(email string) string { return "user-" + hexOf(email)[:12] }

func rowIDFor(email string) string {
	h := hexOf(email)
	return h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-8" + h[17:20] + "-" + h[20:32]
}

func pseudonymFor(email string) string { return hexOf("pseudonym:" + email) }

func hexOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// bindingFor rebuilds the context the row's payload is sealed to, the same way
// cmd/recover rebuilds it from the columns it read.
func bindingFor(email string) []byte {
	return vaultcrypto.RecoveryBinding(rowIDFor(email), pseudonymFor(email))
}

func jsonValue(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal fixture value %v: %v", v, err)
	}
	return out
}

// sealTo produces a real escrow blob: the exact bytes internal/service/erasure.go
// would have appended to auth.account_recovery, bound to binding.
func sealTo(t *testing.T, pub *rsa.PublicKey, plaintext, binding []byte) []byte {
	t.Helper()
	blob, err := vaultcrypto.EncryptRecovery(pub, plaintext, binding)
	if err != nil {
		t.Fatalf("EncryptRecovery: %v", err)
	}
	return blob
}

// sealLegacy produces an escrow blob in the pre-binding format: a bare
// wrapped-key length prefix, RSA-OAEP under a nil label, AES-GCM with no AAD.
//
// It is built by hand because the product can no longer write one. Every record
// already sitting in auth.account_recovery looks like this, and they are the
// only recoverable copy of the accounts they describe, so the format has to stay
// readable and therefore has to stay testable. internal/crypto and tests/attack
// carry their own copy for the same reason.
func sealLegacy(t *testing.T, pub *rsa.PublicKey, plaintext []byte) []byte {
	t.Helper()

	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatalf("aes key: %v", err)
	}
	aesBlob, err := vaultcrypto.Encrypt(plaintext, aesKey)
	if err != nil {
		t.Fatalf("legacy aes encrypt: %v", err)
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		t.Fatalf("legacy wrap: %v", err)
	}

	out := make([]byte, 4+len(wrapped)+len(aesBlob))
	binary.BigEndian.PutUint32(out[:4], uint32(len(wrapped)))
	copy(out[4:], wrapped)
	copy(out[4+len(wrapped):], aesBlob)
	return out
}

// bareRow is one row of auth.account_recovery with no payload yet: the columns a
// bound blob would be sealed to, plus the audit columns.
func bareRow(email string) escrowRow {
	by, reason := "admin:00000000-0000-0000-0000-000000000001", "user_request"
	return escrowRow{
		id:        rowIDFor(email),
		pseudonym: pseudonymFor(email),
		deletedAt: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		deletedBy: &by,
		reason:    &reason,
	}
}

// goodRow is one recoverable record sealed to the escrow key and bound to its
// own row.
func goodRow(t *testing.T, email string) escrowRow {
	t.Helper()
	row := bareRow(email)
	row.payload = sealTo(t, &escrowKey.PublicKey, escrowJSON(t, email, sampleDisplayName, []string{"user"}), bindingFor(email))
	return row
}

// pemFor encodes priv the way an operator's offline key file holds it.
func pemFor(t *testing.T, priv *rsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// writeKey drops a PKCS#8 PEM of priv into a fresh directory and returns its path.
func writeKey(t *testing.T, priv *rsa.PrivateKey) string {
	t.Helper()
	return writeFile(t, "recovery_private.pem", pemFor(t, priv))
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// result is one captured run: the exit code plus everything the tool wrote.
type result struct {
	code   int
	stdout string
	stderr string
}

// exercise runs the tool against an in-memory escrow log. DATABASE_URL is
// cleared so a developer's shell environment cannot make a test pass.
func exercise(t *testing.T, args []string, o *opened) result {
	t.Helper()
	t.Setenv("DATABASE_URL", "")
	var stdout, stderr strings.Builder
	code := run(args, &stdout, &stderr, o.open)
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// withRows is the common case: a valid key file and a DSN that is never dialed.
func withRows(t *testing.T, rows ...escrowRow) (*opened, []string) {
	t.Helper()
	o := &opened{rows: &fakeRows{rows: rows}}
	return o, []string{"--key", writeKey(t, escrowKey), "--dsn", "postgres://offline/vault"}
}

// records decodes the JSON-lines output. It insists on one complete object per
// line, which is what makes the output safe to pipe into jq or split with head.
func records(t *testing.T, stdout string) []recoveredRecord {
	t.Helper()
	if stdout == "" {
		return nil
	}
	if !strings.HasSuffix(stdout, "\n") {
		t.Fatalf("output is not newline-terminated, a truncated last line would be parsed as a record: %q", stdout)
	}
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	out := make([]recoveredRecord, 0, len(lines))
	for i, line := range lines {
		var rec recoveredRecord
		if err := decodeStrict(line, &rec); err != nil {
			t.Fatalf("line %d is not one JSON record (%v): %q", i+1, err, line)
		}
		out = append(out, rec)
	}
	return out
}

func decodeStrict(line string, rec *recoveredRecord) error {
	dec := json.NewDecoder(strings.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(rec); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("more than one JSON value on the line")
	}
	return nil
}

// mustNotLeak fails if any secret appears in the captured output. Diagnostics are
// pasted into tickets and shipped to log collectors, so an email or a fragment of
// the private key showing up there defeats the point of holding the key offline.
func mustNotLeak(t *testing.T, where, out string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if secret == "" {
			t.Fatal("mustNotLeak called with an empty needle, which would always match")
		}
		if strings.Contains(out, secret) {
			t.Errorf("%s leaked %q:\n%s", where, secret, out)
		}
	}
}

// keyMaterial is the set of strings that must never surface in tool output: the
// PEM itself, its base64 body, and the raw modulus bytes.
func keyMaterial(t *testing.T, priv *rsa.PrivateKey) []string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	body := strings.ReplaceAll(strings.TrimPrefix(strings.TrimSuffix(pemText, "-----END PRIVATE KEY-----\n"), "-----BEGIN PRIVATE KEY-----\n"), "\n", "")
	return []string{
		pemText,
		body[:64],
		priv.N.String(),
		priv.D.String(),
		priv.Primes[0].String(),
	}
}

// ---------------------------------------------------------------------------
// Flag handling
// ---------------------------------------------------------------------------

// An unparseable command line must stop before the key file is read and before
// anything dials the database. Exit 2 is the stdlib flag convention and is what
// the tool produced when it used flag.ExitOnError; a wrapper script that treats
// "not 0" as a retryable outage should still be able to tell a typo apart from a
// failed restore.
func TestRun_UnknownFlagIsRejectedBeforeAnyWork(t *testing.T) {
	o := &opened{rows: &fakeRows{}}
	got := exercise(t, []string{"--dump-key", "--key", writeKey(t, escrowKey)}, o)

	if got.code != 2 {
		t.Errorf("exit code = %d, want 2 for a flag error", got.code)
	}
	if o.calls != 0 {
		t.Errorf("opener called %d times, want 0: an unparseable command line must not reach the database", o.calls)
	}
	if got.stdout != "" {
		t.Errorf("stdout = %q, want empty", got.stdout)
	}
	if !strings.Contains(got.stderr, "not defined") {
		t.Errorf("stderr does not name the offending flag:\n%s", got.stderr)
	}
}

// -h is a request, not a failure. Exiting non-zero here would make `recover -h`
// look like a broken tool to any script that checks the status.
func TestRun_HelpExitsZeroAndTouchesNothing(t *testing.T) {
	o := &opened{rows: &fakeRows{}}
	got := exercise(t, []string{"-h"}, o)

	if got.code != 0 {
		t.Errorf("exit code = %d, want 0 for -h", got.code)
	}
	if o.calls != 0 {
		t.Errorf("opener called %d times, want 0", o.calls)
	}
	for _, flagName := range []string{"-key", "-dsn", "-limit"} {
		if !strings.Contains(got.stderr, flagName) {
			t.Errorf("usage does not document %s:\n%s", flagName, got.stderr)
		}
	}
}

// Both required inputs are checked before the key is read, so an operator who
// forgets one gets a usage error rather than a file-not-found error.
func TestRun_RequiredFlags(t *testing.T) {
	keyFile := writeKey(t, escrowKey)

	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no key", []string{"--dsn", "postgres://offline/vault"}, "recover: --key is required"},
		{"no dsn", []string{"--key", keyFile}, "recover: --dsn (or DATABASE_URL) is required"},
		{"neither", nil, "recover: --key is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := &opened{rows: &fakeRows{}}
			got := exercise(t, tc.args, o)

			if got.code != 1 {
				t.Errorf("exit code = %d, want 1", got.code)
			}
			if !strings.Contains(got.stderr, tc.want) {
				t.Errorf("stderr = %q, want it to contain %q", got.stderr, tc.want)
			}
			if o.calls != 0 {
				t.Errorf("opener called %d times, want 0", o.calls)
			}
			if got.stdout != "" {
				t.Errorf("stdout = %q, want empty", got.stdout)
			}
		})
	}
}

// The documented alternative to --dsn is DATABASE_URL (docs/config.md). A DSN
// carries a password, so an operator putting it in the environment instead of in
// their shell history is the safer habit and has to keep working.
func TestRun_DSNFallsBackToDatabaseURL(t *testing.T) {
	o := &opened{rows: &fakeRows{}}
	t.Setenv("DATABASE_URL", "postgres://env-host/vault?sslmode=require")

	var stdout, stderr strings.Builder
	if code := run([]string{"--key", writeKey(t, escrowKey)}, &stdout, &stderr, o.open); code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", code, stderr.String())
	}
	if o.dsn != "postgres://env-host/vault?sslmode=require" {
		t.Errorf("opener got DSN %q, want the DATABASE_URL value", o.dsn)
	}
}

// An explicit --dsn wins over the environment. Getting this backwards would send
// a recovery run at whatever database the operator's shell happened to point at.
func TestRun_ExplicitDSNOverridesDatabaseURL(t *testing.T) {
	o := &opened{rows: &fakeRows{}}
	t.Setenv("DATABASE_URL", "postgres://env-host/vault")

	var stdout, stderr strings.Builder
	args := []string{"--key", writeKey(t, escrowKey), "--dsn", "postgres://flag-host/vault"}
	if code := run(args, &stdout, &stderr, o.open); code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", code, stderr.String())
	}
	if o.dsn != "postgres://flag-host/vault" {
		t.Errorf("opener got DSN %q, want the --dsn value", o.dsn)
	}
}

// --limit is the only bound on how much personal data one invocation pulls out of
// the escrow log, so it has to arrive at the query verbatim, and its default has
// to stay finite.
func TestRun_LimitReachesTheQuery(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"default", nil, 10000},
		{"explicit", []string{"--limit", "7"}, 7},
		{"single record", []string{"--limit", "1"}, 1},
		{"zero", []string{"--limit", "0"}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o, base := withRows(t)
			got := exercise(t, append(base, tc.args...), o)

			if got.code != 0 {
				t.Fatalf("exit code = %d, want 0\n%s", got.code, got.stderr)
			}
			if o.limit != tc.want {
				t.Errorf("opener got limit %d, want %d", o.limit, tc.want)
			}
		})
	}
}

// A non-numeric --limit is a flag error, not a silent fallback to the default.
// Silently reading 10000 records because the operator typed --limit=all would
// pull far more personal data than they asked for.
func TestRun_NonNumericLimitIsRejected(t *testing.T) {
	o, base := withRows(t)
	got := exercise(t, append(base, "--limit", "all"), o)

	if got.code != 2 {
		t.Errorf("exit code = %d, want 2", got.code)
	}
	if o.calls != 0 {
		t.Errorf("opener called %d times, want 0", o.calls)
	}
}

// ---------------------------------------------------------------------------
// Key loading
// ---------------------------------------------------------------------------

// Every way of handing the tool something that is not a usable recovery key must
// stop it before it opens the escrow log. A tool that connected first and failed
// second would leave an operator staring at a database error while the real
// problem was the key path.
func TestRun_UnusableKeyIsFatalBeforeConnecting(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	ecDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	rsaDER := x509.MarshalPKCS1PrivateKey(escrowKey)
	pubDER, err := x509.MarshalPKIXPublicKey(&escrowKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	tests := []struct {
		name string
		path func(t *testing.T) string
		want string
	}{
		{
			name: "missing file",
			path: func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.pem") },
			want: "recover: read key:",
		},
		{
			name: "path is a directory",
			path: func(t *testing.T) string { return t.TempDir() },
			want: "recover: read key:",
		},
		{
			name: "empty file",
			path: func(t *testing.T) string { return writeFile(t, "empty.pem", nil) },
			want: "recover: parse key:",
		},
		{
			name: "not PEM at all",
			path: func(t *testing.T) string { return writeFile(t, "notes.txt", []byte("the key is in the safe")) },
			want: "recover: parse key:",
		},
		{
			name: "PEM header with garbage body",
			path: func(t *testing.T) string {
				return writeFile(t, "garbage.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not DER")}))
			},
			want: "recover: parse key:",
		},
		{
			name: "elliptic curve key, not RSA",
			path: func(t *testing.T) string {
				return writeFile(t, "ec.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER}))
			},
			want: "recover: parse key:",
		},
		{
			name: "public half of the recovery pair",
			path: func(t *testing.T) string {
				return writeFile(t, "public.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
			},
			want: "recover: parse key:",
		},
		{
			name: "PKCS#1 body mislabelled as PKCS#8 still parses",
			path: func(t *testing.T) string {
				return writeFile(t, "pkcs1.pem", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: rsaDER}))
			},
			want: "", // accepted: LoadRSAPrivateKeyPEM falls back to PKCS#1
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := &opened{rows: &fakeRows{}}
			got := exercise(t, []string{"--key", tc.path(t), "--dsn", "postgres://offline/vault"}, o)

			if tc.want == "" {
				if got.code != 0 {
					t.Fatalf("exit code = %d, want 0: this key is valid\n%s", got.code, got.stderr)
				}
				if o.calls != 1 {
					t.Errorf("opener called %d times, want 1", o.calls)
				}
				return
			}
			if got.code != 1 {
				t.Errorf("exit code = %d, want 1", got.code)
			}
			if !strings.Contains(got.stderr, tc.want) {
				t.Errorf("stderr = %q, want it to contain %q", got.stderr, tc.want)
			}
			if o.calls != 0 {
				t.Errorf("opener called %d times, want 0: an unusable key must not open the escrow log", o.calls)
			}
			if got.stdout != "" {
				t.Errorf("stdout = %q, want empty", got.stdout)
			}
		})
	}
}

// The parse-key diagnostic quotes the error from x509, which is fed bytes the
// operator supplied. It must describe the failure without echoing the file back,
// otherwise a mistyped path that pointed at the real key would print it.
func TestRun_KeyParseErrorDoesNotEchoTheFile(t *testing.T) {
	der, err := x509.MarshalPKCS8PrivateKey(escrowKey)
	if err != nil {
		t.Fatalf("marshal PKCS#8: %v", err)
	}
	// A valid key body under a PEM type x509 will still parse, truncated so the
	// parser fails with the real key material in hand.
	truncated := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der[:len(der)/2]})

	o := &opened{rows: &fakeRows{}}
	got := exercise(t, []string{"--key", writeFile(t, "half.pem", truncated), "--dsn", "postgres://offline/vault"}, o)

	if got.code != 1 {
		t.Fatalf("exit code = %d, want 1", got.code)
	}
	mustNotLeak(t, "key parse error", got.stderr, keyMaterial(t, escrowKey)...)
}

// ---------------------------------------------------------------------------
// Opening the escrow log
// ---------------------------------------------------------------------------

// A database that cannot be reached is fatal and must be reported with its own
// prefix, because on an offline recovery host it usually means the operator
// forgot the tunnel, not that the escrow log is broken.
func TestRun_OpenFailureIsFatal(t *testing.T) {
	o := &opened{err: errors.New("connect: dial tcp 10.0.0.1:5432: connect: no route to host")}
	got := exercise(t, []string{"--key", writeKey(t, escrowKey), "--dsn", "postgres://offline/vault"}, o)

	if got.code != 1 {
		t.Errorf("exit code = %d, want 1", got.code)
	}
	if !strings.Contains(got.stderr, "recover: connect: dial tcp") {
		t.Errorf("stderr = %q, want it to carry the opener error under the recover prefix", got.stderr)
	}
	if got.stdout != "" {
		t.Errorf("stdout = %q, want empty", got.stdout)
	}
	if strings.Contains(got.stderr, "record(s) decrypted") {
		t.Error("a failed open printed a completion summary, which reads as a successful empty restore")
	}
}

// The connection is released exactly once on the way out, including when a row
// aborts the run. The tool holds an offline private key while connected to a
// production replica; leaving that connection open after it returns is the kind
// of thing that keeps a recovery session alive far longer than intended.
func TestRun_ReleasesTheConnection(t *testing.T) {
	tests := []struct {
		name string
		rows []escrowRow
		err  error
	}{
		{"clean run", []escrowRow{goodRow(t, sampleEmail)}, nil},
		{"scan failure", []escrowRow{{scanErr: errors.New("bad column")}}, nil},
		{"iteration failure", []escrowRow{goodRow(t, sampleEmail)}, errors.New("connection reset")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := &opened{rows: &fakeRows{rows: tc.rows, iterErr: tc.err}}
			exercise(t, []string{"--key", writeKey(t, escrowKey), "--dsn", "postgres://offline/vault"}, o)

			if o.rows.closed != 1 {
				t.Errorf("rows closed %d times, want exactly 1", o.rows.closed)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

// The whole point of the tool: an escrow record sealed by the erasure service
// comes back as the profile that was erased, with the audit columns attached.
func TestRun_RecoversAnErasedAccount(t *testing.T) {
	o, args := withRows(t, goodRow(t, sampleEmail))
	got := exercise(t, args, o)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", got.code, got.stderr)
	}
	recs := records(t, got.stdout)
	if len(recs) != 1 {
		t.Fatalf("recovered %d records, want 1: %q", len(recs), got.stdout)
	}
	rec := recs[0]
	if rec.Email != sampleEmail {
		t.Errorf("email = %q, want %q", rec.Email, sampleEmail)
	}
	if rec.DisplayName != sampleDisplayName {
		t.Errorf("display name = %q, want %q", rec.DisplayName, sampleDisplayName)
	}
	if len(rec.Roles) != 1 || rec.Roles[0] != "user" {
		t.Errorf("roles = %v, want [user]", rec.Roles)
	}
	if !rec.CreatedAt.Equal(sampleCreatedAt) {
		t.Errorf("created_at = %s, want %s", rec.CreatedAt, sampleCreatedAt)
	}
	if !rec.DeletedAt.Equal(time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Errorf("deleted_at = %s, want the value from the row, not from the payload", rec.DeletedAt)
	}
	if rec.DeletedBy != "admin:00000000-0000-0000-0000-000000000001" {
		t.Errorf("deleted_by = %q, want the audit column verbatim", rec.DeletedBy)
	}
	if rec.Reason != "user_request" {
		t.Errorf("reason = %q, want user_request", rec.Reason)
	}
	if !strings.Contains(got.stderr, "recover: 1 record(s) decrypted, 0 failure(s)") {
		t.Errorf("summary missing from stderr:\n%s", got.stderr)
	}
}

// deleted_by and reason are nullable. A NULL must come back as an absent field
// rather than as the string "null" or an empty attribution, because these two
// columns are what an investigator uses to decide whether a deletion was the
// user's own request or an admin action.
func TestRun_NullAuditColumnsAreOmitted(t *testing.T) {
	row := goodRow(t, sampleEmail)
	row.deletedBy, row.reason = nil, nil

	o, args := withRows(t, row)
	got := exercise(t, args, o)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", got.code, got.stderr)
	}
	if strings.Contains(got.stdout, "deleted_by") || strings.Contains(got.stdout, "reason") {
		t.Errorf("NULL audit columns were emitted rather than omitted: %s", got.stdout)
	}
	recs := records(t, got.stdout)
	if len(recs) != 1 || recs[0].DeletedBy != "" || recs[0].Reason != "" {
		t.Errorf("want one record with empty attribution, got %+v", recs)
	}
}

// Output is one self-contained JSON object per line so a restore can be driven
// with head, split or jq without a streaming parser.
func TestRun_EmitsOneRecordPerLineInRowOrder(t *testing.T) {
	emails := []string{"first@example.invalid", "second@example.invalid", "third@example.invalid"}
	rows := make([]escrowRow, 0, len(emails))
	for _, email := range emails {
		rows = append(rows, goodRow(t, email))
	}

	o, args := withRows(t, rows...)
	got := exercise(t, args, o)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", got.code, got.stderr)
	}
	recs := records(t, got.stdout)
	if len(recs) != len(emails) {
		t.Fatalf("recovered %d records, want %d", len(recs), len(emails))
	}
	for i, want := range emails {
		if recs[i].Email != want {
			t.Errorf("record %d email = %q, want %q: the query orders by deleted_at DESC and that order must survive", i, recs[i].Email, want)
		}
	}
}

// An empty escrow log is a successful run with nothing to say. It must not look
// like a failure, and it must not print an empty JSON object.
func TestRun_EmptyEscrowLog(t *testing.T) {
	o, args := withRows(t)
	got := exercise(t, args, o)

	if got.code != 0 {
		t.Errorf("exit code = %d, want 0", got.code)
	}
	if got.stdout != "" {
		t.Errorf("stdout = %q, want empty", got.stdout)
	}
	if !strings.Contains(got.stderr, "recover: 0 record(s) decrypted, 0 failure(s)") {
		t.Errorf("summary missing from stderr:\n%s", got.stderr)
	}
}

// ---------------------------------------------------------------------------
// Driver-level failures
// ---------------------------------------------------------------------------

// A row the driver cannot decode is fatal. Unlike a decrypt failure, a scan
// failure means the tool no longer understands the shape of the table it is
// reading, so continuing would silently skip records an operator believes were
// checked.
func TestRun_ScanFailureIsFatal(t *testing.T) {
	o := &opened{rows: &fakeRows{rows: []escrowRow{
		goodRow(t, sampleEmail),
		{scanErr: errors.New("cannot scan NULL into *time.Time")},
		goodRow(t, "never-reached@example.invalid"),
	}}}
	got := exercise(t, []string{"--key", writeKey(t, escrowKey), "--dsn", "postgres://offline/vault"}, o)

	if got.code != 1 {
		t.Errorf("exit code = %d, want 1", got.code)
	}
	if !strings.Contains(got.stderr, "recover: scan: cannot scan NULL") {
		t.Errorf("stderr = %q, want the scan error", got.stderr)
	}
	if strings.Contains(got.stdout, "never-reached@example.invalid") {
		t.Error("iteration continued past a fatal scan error")
	}
	if strings.Contains(got.stderr, "record(s) decrypted") {
		t.Error("an aborted run printed a completion summary")
	}
}

// A failure raised after the last row (a mid-stream server error, a dropped
// connection) is only visible through rows.Err(). Ignoring it would turn a
// partial read into what looks like a complete restore.
func TestRun_IterationErrorIsFatal(t *testing.T) {
	o := &opened{rows: &fakeRows{
		rows:    []escrowRow{goodRow(t, sampleEmail)},
		iterErr: errors.New("unexpected EOF"),
	}}
	got := exercise(t, []string{"--key", writeKey(t, escrowKey), "--dsn", "postgres://offline/vault"}, o)

	if got.code != 1 {
		t.Errorf("exit code = %d, want 1", got.code)
	}
	if !strings.Contains(got.stderr, "recover: iterate: unexpected EOF") {
		t.Errorf("stderr = %q, want the iteration error", got.stderr)
	}
	if strings.Contains(got.stderr, "record(s) decrypted") {
		t.Error("a truncated read printed a completion summary, which reads as a complete restore")
	}
}

// failingWriter fails after letting n bytes through, standing in for a full disk
// or a closed pipe on the redirect an operator set up.
type failingWriter struct {
	n   int
	err error
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.n <= 0 {
		return 0, w.err
	}
	if len(p) > w.n {
		written := w.n
		w.n = 0
		return written, w.err
	}
	w.n -= len(p)
	return len(p), nil
}

// If the destination stops accepting output the run must abort. Continuing would
// count records as recovered that never reached the file the operator is about to
// restore from.
func TestRun_OutputWriteFailureIsFatal(t *testing.T) {
	o := &opened{rows: &fakeRows{rows: []escrowRow{goodRow(t, sampleEmail), goodRow(t, "second@example.invalid")}}}
	t.Setenv("DATABASE_URL", "")

	var stderr strings.Builder
	stdout := &failingWriter{n: 0, err: errors.New("no space left on device")}
	code := run([]string{"--key", writeKey(t, escrowKey), "--dsn", "postgres://offline/vault"}, stdout, &stderr, o.open)

	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "recover: encode: no space left on device") {
		t.Errorf("stderr = %q, want the write error", stderr.String())
	}
	if strings.Contains(stderr.String(), "record(s) decrypted") {
		t.Error("a run that could not write its output printed a completion summary")
	}
}

// ---------------------------------------------------------------------------
// Process wiring
// ---------------------------------------------------------------------------

// main() is one line of wiring, and every one of its parts is a hazard if it is
// wrong: passing os.Args instead of os.Args[1:] would make every flag look like a
// positional argument and silently ignore --key, and dropping the exit code would
// make a failed restore look successful to the calling script. This runs the test
// binary as the recover binary to observe the real exit status.
func TestMainWiring(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"no arguments", nil, 1, "recover: --key is required"},
		{"unknown flag", []string{"--dump-key"}, 2, "not defined"},
		{"help", []string{"-h"}, 0, "-key string"},
		{
			// Proves the flags reach the parser: with os.Args[0] left in place,
			// parsing would stop at the binary path and this would report a
			// missing --key instead of a missing file.
			name:     "flags are parsed",
			args:     []string{"--key", "/nonexistent/recovery.pem", "--dsn", "postgres://offline/vault"},
			wantCode: 1,
			wantErr:  "recover: read key:",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0])
			cmd.Env = []string{subprocessArgsEnv + "=" + strings.Join(tc.args, argSep)}
			var stdout, stderr strings.Builder
			cmd.Stdout, cmd.Stderr = &stdout, &stderr

			err := cmd.Run()
			code := 0
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				code = exitErr.ExitCode()
			} else if err != nil {
				t.Fatalf("run subprocess: %v", err)
			}

			if code != tc.wantCode {
				t.Errorf("exit code = %d, want %d\nstderr: %s", code, tc.wantCode, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tc.wantErr)
			}
			if stdout.String() != "" {
				t.Errorf("stdout = %q, want empty: no run that fails may emit recovered data", stdout.String())
			}
		})
	}
}
