// Security properties of the offline erasure-recovery tool.
//
// The threat model for cmd/recover is not "the operator mistypes a path". It is
// that the escrow log itself is hostile input: the running server holds the
// recovery PUBLIC key and appends rows to auth.account_recovery on every
// erasure, so anyone who compromises the server can choose payload bytes that
// this tool will later decrypt on an offline host. The database can also corrupt
// or truncate a row through nothing more sinister than a bad restore.
//
// Every test below therefore starts from a real escrow blob and damages it the
// way an attacker or a bad backup would, and asserts the same two things: the
// run produces no plaintext, and the diagnostics it does produce carry neither
// the recovered identity nor the private key.
package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// damage names one way an escrow blob can arrive broken. Each returns a blob the
// tool must reject.
type damage struct {
	name string
	make func(t *testing.T, sealed []byte) []byte
	// why records the concrete failure the case guards against, so a future
	// reader knows what breaks if it is deleted.
	why string
}

func damageCases() []damage {
	return []damage{
		{
			name: "sealed to a different recovery key",
			why:  "the operator loaded the wrong PEM, or an old key from before a rotation",
			make: func(t *testing.T, _ []byte) []byte {
				return sealTo(t, &wrongKey.PublicKey, escrowJSON(t, sampleEmail, sampleDisplayName, []string{"user"}))
			},
		},
		{
			name: "empty payload",
			why:  "a BYTEA column that somehow came back zero length",
			make: func(_ *testing.T, _ []byte) []byte { return []byte{} },
		},
		{
			name: "nil payload",
			why:  "a NULL payload scanned into a nil slice",
			make: func(_ *testing.T, _ []byte) []byte { return nil },
		},
		{
			name: "shorter than the length prefix",
			why:  "reading the 4-byte header at all would run off the end of the buffer",
			make: func(_ *testing.T, _ []byte) []byte { return []byte{0x00, 0x00, 0x01} },
		},
		{
			name: "header only",
			why:  "a truncated write that stored the prefix and nothing else",
			make: func(_ *testing.T, sealed []byte) []byte { return slices.Clone(sealed[:4]) },
		},
		{
			name: "truncated mid wrapped key",
			why:  "a partial row from an interrupted restore",
			make: func(_ *testing.T, sealed []byte) []byte { return slices.Clone(sealed[:len(sealed)/3]) },
		},
		{
			name: "truncated mid ciphertext",
			why:  "the RSA half is intact and only the AES half was cut, so the failure has to come from GCM",
			make: func(_ *testing.T, sealed []byte) []byte { return slices.Clone(sealed[:len(sealed)-8]) },
		},
		{
			name: "one byte of the GCM tag removed",
			why:  "the smallest possible truncation, which a length check alone would not catch",
			make: func(_ *testing.T, sealed []byte) []byte { return slices.Clone(sealed[:len(sealed)-1]) },
		},
		{
			name: "length extended",
			why:  "trailing bytes appended to the row; GCM must authenticate the whole ciphertext, not a prefix of it",
			make: func(_ *testing.T, sealed []byte) []byte {
				return append(slices.Clone(sealed), []byte("APPENDED-BY-AN-ATTACKER")...)
			},
		},
		{
			name: "ciphertext bit flipped",
			why:  "a single flipped bit in the encrypted profile must not yield mangled plaintext",
			make: func(_ *testing.T, sealed []byte) []byte {
				out := slices.Clone(sealed)
				out[len(out)-4] ^= 0x01
				return out
			},
		},
		{
			name: "GCM nonce bit flipped",
			why:  "the nonce is unauthenticated framing; changing it must still fail the tag check",
			make: func(_ *testing.T, sealed []byte) []byte {
				out := slices.Clone(sealed)
				out[4+wrappedLen(sealed)] ^= 0x80
				return out
			},
		},
		{
			name: "wrapped key bit flipped",
			why:  "OAEP must reject a tampered key wrap rather than hand back a wrong AES key",
			make: func(_ *testing.T, sealed []byte) []byte {
				out := slices.Clone(sealed)
				out[10] ^= 0x01
				return out
			},
		},
		{
			name: "length prefix claims more than the blob holds",
			why:  "the classic corrupt-header case; trusting it would slice past the end of the buffer",
			make: func(_ *testing.T, sealed []byte) []byte {
				out := slices.Clone(sealed)
				binary.BigEndian.PutUint32(out[:4], 0xFFFFFFFF)
				return out
			},
		},
		{
			name: "length prefix shrunk",
			why:  "shifts the wrapped-key and ciphertext boundary, feeding OAEP a truncated wrap",
			make: func(_ *testing.T, sealed []byte) []byte {
				out := slices.Clone(sealed)
				binary.BigEndian.PutUint32(out[:4], wrappedLen(sealed)-1)
				return out
			},
		},
		{
			name: "length prefix swallows the ciphertext",
			why:  "leaves an empty AES blob, which must be an error and not an empty recovered record",
			make: func(_ *testing.T, sealed []byte) []byte {
				out := slices.Clone(sealed)
				binary.BigEndian.PutUint32(out[:4], uint32(len(out)-4)) // #nosec G115 -- test fixture, blob is a few hundred bytes
				return out
			},
		},
		{
			name: "length prefix zeroed",
			why:  "claims there is no wrapped key at all, so OAEP is handed nothing",
			make: func(_ *testing.T, sealed []byte) []byte {
				out := slices.Clone(sealed)
				binary.BigEndian.PutUint32(out[:4], 0)
				return out
			},
		},
		{
			name: "all zeroes",
			why:  "a zero-filled row from a bad page in the backup",
			make: func(_ *testing.T, sealed []byte) []byte { return make([]byte, len(sealed)) },
		},
	}
}

func wrappedLen(blob []byte) uint32 { return binary.BigEndian.Uint32(blob[:4]) }

// TestRun_RejectedRecordsEmitNoPlaintext is the core fail-closed assertion. For
// every way a record can be wrong the tool must print nothing on stdout, count
// the record as a failure, and keep going: one damaged row must neither abort a
// restore nor contribute to it.
func TestRun_RejectedRecordsEmitNoPlaintext(t *testing.T) {
	sealed := sealTo(t, &escrowKey.PublicKey, escrowJSON(t, sampleEmail, sampleDisplayName, []string{"user", "admin"}))

	for _, tc := range damageCases() {
		t.Run(tc.name, func(t *testing.T) {
			row := goodRow(t, sampleEmail)
			row.payload = tc.make(t, sealed)

			o, args := withRows(t, row)
			got := exercise(t, args, o)

			if got.stdout != "" {
				t.Errorf("stdout is not empty, the tool emitted something for a record it could not verify (%s):\n%s", tc.why, got.stdout)
			}
			if !strings.Contains(got.stderr, "recover: decrypt failed for a record") {
				t.Errorf("no rejection was reported on stderr (%s):\n%s", tc.why, got.stderr)
			}
			if !strings.Contains(got.stderr, "recover: 0 record(s) decrypted, 1 failure(s)") {
				t.Errorf("summary did not count the record as a failure (%s):\n%s", tc.why, got.stderr)
			}
			mustNotLeak(t, "rejection diagnostics", got.stderr, sampleEmail, sampleDisplayName)
			mustNotLeak(t, "rejection diagnostics", got.stderr, keyMaterial(t, escrowKey)...)
		})
	}
}

// A damaged record must not take its neighbours down with it. This is the
// property the continue in the decrypt loop exists for: an operator recovering
// 400 accounts after a bad deletion cannot lose 399 of them to one corrupt row.
//
// The run still ends in exitIncomplete, because it did come back short and the
// caller has to be able to see that. Non-fatal mid-run and non-zero at the end
// are not in tension: the first keeps the restore going, the second stops a
// pipeline reading a partial result as a complete one.
func TestRun_OneBadRecordDoesNotStopTheRest(t *testing.T) {
	bad := goodRow(t, "corrupt@example.invalid")
	bad.payload = sealTo(t, &wrongKey.PublicKey, escrowJSON(t, "corrupt@example.invalid", "Wrong Key", nil))

	o, args := withRows(t,
		goodRow(t, "before@example.invalid"),
		bad,
		goodRow(t, "after@example.invalid"),
	)
	got := exercise(t, args, o)

	if got.code != exitIncomplete {
		t.Fatalf("exit code = %d, want %d: one record was unrecoverable, so the run "+
			"completed short and must not report success\n%s", got.code, exitIncomplete, got.stderr)
	}
	recs := records(t, got.stdout)
	if len(recs) != 2 {
		t.Fatalf("recovered %d records, want the 2 readable ones: %q", len(recs), got.stdout)
	}
	if recs[0].Email != "before@example.invalid" || recs[1].Email != "after@example.invalid" {
		t.Errorf("recovered %q and %q, want before@ and after@", recs[0].Email, recs[1].Email)
	}
	if strings.Contains(got.stdout, "corrupt@example.invalid") {
		t.Error("the unreadable record contributed to the output")
	}
	if !strings.Contains(got.stderr, "recover: 2 record(s) decrypted, 1 failure(s)") {
		t.Errorf("summary did not account for the skipped record:\n%s", got.stderr)
	}
}

// A wrong key is the single most likely operator error, and the one where a
// fail-open would be worst: the tool would emit whatever the mismatched key
// produced. Every record must be refused and stdout must be byte-for-byte empty.
//
// The exit status carries the outcome. It used to be 0, which made a run where
// every record failed indistinguishable by status from a run against an empty
// escrow log, so `recover --key wrong.pem > accounts.jsonl || alert` wrote an
// empty file and reported success. The failure count existed only on stderr,
// which a pipeline does not read.
func TestRun_WrongKeyRecoversNothing(t *testing.T) {
	rows := make([]escrowRow, 0, 3)
	for _, email := range []string{"a@example.invalid", "b@example.invalid", "c@example.invalid"} {
		row := goodRow(t, email)
		row.payload = sealTo(t, &escrowKey.PublicKey, escrowJSON(t, email, sampleDisplayName, nil))
		rows = append(rows, row)
	}

	o := &opened{rows: &fakeRows{rows: rows}}
	got := exercise(t, []string{"--key", writeKey(t, wrongKey), "--dsn", "postgres://offline/vault"}, o)

	if got.stdout != "" {
		t.Errorf("stdout = %q, want empty: a wrong key must recover nothing at all", got.stdout)
	}
	if !strings.Contains(got.stderr, "recover: 0 record(s) decrypted, 3 failure(s)") {
		t.Errorf("summary did not report a total failure:\n%s", got.stderr)
	}
	if got.code != exitIncomplete {
		t.Errorf("exit code = %d, want %d: every record failed to decrypt, which must "+
			"never be reported as a successful restore", got.code, exitIncomplete)
	}
	mustNotLeak(t, "wrong-key diagnostics", got.stderr, "a@example.invalid", "b@example.invalid", "c@example.invalid", sampleDisplayName)
	mustNotLeak(t, "wrong-key diagnostics", got.stderr, keyMaterial(t, wrongKey)...)
}

// Two records sealed to different keys in the same log: only the one matching the
// loaded key may come out. This is what proves the tool decrypts with the key it
// was given rather than with anything cached, derived or guessed.
func TestRun_OnlyRecordsSealedToTheLoadedKeyAreRecovered(t *testing.T) {
	mine := goodRow(t, "mine@example.invalid")
	theirs := goodRow(t, "theirs@example.invalid")
	theirs.payload = sealTo(t, &wrongKey.PublicKey, escrowJSON(t, "theirs@example.invalid", sampleDisplayName, nil))

	o, args := withRows(t, mine, theirs)
	got := exercise(t, args, o)

	recs := records(t, got.stdout)
	if len(recs) != 1 || recs[0].Email != "mine@example.invalid" {
		t.Fatalf("recovered %+v, want only the record sealed to the loaded key", recs)
	}
	mustNotLeak(t, "stdout", got.stdout, "theirs@example.invalid")
}

// ---------------------------------------------------------------------------
// Hostile plaintext
// ---------------------------------------------------------------------------

// A record can decrypt perfectly and still not be a profile: the erasure service
// could have changed format, or whoever held the public key sealed something
// else. Anything that is not the expected object is dropped whole. In particular
// encoding/json fills the fields it managed to parse before returning an error,
// so a half-parsed record must not be mistaken for a recoverable one.
func TestRun_PlaintextThatIsNotAProfileIsDropped(t *testing.T) {
	tests := []struct {
		name    string
		plain   string
		secrets []string
		why     string
	}{
		{
			name:  "not JSON",
			plain: "this escrow record is not json",
			why:   "a format change or a sealed blob from a different producer",
		},
		{
			name:    "truncated object",
			plain:   `{"email":"truncated@example.invalid","display_name":"Half`,
			secrets: []string{"truncated@example.invalid"},
			why:     "a truncated payload whose first field parses cleanly must still be dropped whole",
		},
		{
			name:    "right shape, wrong types",
			plain:   `{"email":"typed@example.invalid","roles":"admin"}`,
			secrets: []string{"typed@example.invalid"},
			why:     "encoding/json populates Email before it fails on roles, and that partial record must not be emitted",
		},
		{
			name:  "JSON array",
			plain: `["email","not-an-object@example.invalid"]`,
			why:   "a valid JSON document of the wrong kind",
		},
		{
			name:  "empty plaintext",
			plain: ``,
			why:   "a zero-length payload that was correctly encrypted",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			row := goodRow(t, sampleEmail)
			row.payload = sealTo(t, &escrowKey.PublicKey, []byte(tc.plain))

			o, args := withRows(t, row)
			got := exercise(t, args, o)

			if got.stdout != "" {
				t.Errorf("stdout is not empty (%s):\n%s", tc.why, got.stdout)
			}
			if !strings.Contains(got.stderr, "recover: 0 record(s) decrypted, 1 failure(s)") {
				t.Errorf("record was not counted as a failure (%s):\n%s", tc.why, got.stderr)
			}
			if len(tc.secrets) > 0 {
				mustNotLeak(t, "malformed-payload diagnostics", got.stderr, tc.secrets...)
			}
		})
	}
}

// A payload that decrypts to a well-formed but empty profile is emitted as a
// recovered record and counted as a success, because the tool checks only that
// json.Unmarshal returned no error and never that a profile actually came back.
//
// This test pins the behaviour rather than endorsing it. It matters because the
// running server holds the recovery public key and appends the rows this tool
// reads: an attacker who reaches it can seal `null` or `{}` into as many escrow
// records as they like, and each one arrives in the recovery output as a
// well-formed record with an empty email and a zero created_at, carrying the real
// audit columns from the row. An operator, or a script, restoring from that
// output is restoring accounts that never existed. The fix is a validity check on
// the decrypted profile (a non-empty email at minimum) before the record is
// encoded and counted. That check now exists, and this test holds it down.
func TestRun_IdentityFreePayloadIsRejected(t *testing.T) {
	for _, plain := range []string{`null`, `{}`, `{"email":""}`} {
		t.Run(plain, func(t *testing.T) {
			by := "admin:real"
			row := escrowRow{
				payload:   sealTo(t, &escrowKey.PublicKey, []byte(plain)),
				deletedAt: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
				deletedBy: &by,
			}

			o, args := withRows(t, row)
			got := exercise(t, args, o)

			if got.stdout != "" {
				t.Fatalf("stdout = %q, want empty: a payload with no identity is not an "+
					"account and must not appear in a restore", got.stdout)
			}
			if !strings.Contains(got.stderr, "recover: 0 record(s) decrypted, 1 failure(s)") {
				t.Errorf("an identity-free record was not counted as a failure:\n%s", got.stderr)
			}
			if !strings.Contains(got.stderr, "carries no identity") {
				t.Errorf("the rejection was not explained on stderr:\n%s", got.stderr)
			}
			if got.code != exitIncomplete {
				t.Errorf("exit code = %d, want %d", got.code, exitIncomplete)
			}
			// The audit columns are what made the forgery convincing, so make sure
			// they did not survive into the output by another route.
			if strings.Contains(got.stdout, "admin:real") {
				t.Error("the row's audit columns reached stdout without an identity to attach to")
			}
		})
	}
}

// The server that writes escrow records holds the public key, so the contents of
// a payload are attacker-controlled under the exact compromise this escrow scheme
// is designed to survive. An email carrying a newline and a forged record must
// not become a second line of output: the JSON-lines contract is what a restore
// script splits on, and breaking it would let a compromised server inject
// accounts into a recovery run.
func TestRun_HostilePayloadCannotForgeAnOutputLine(t *testing.T) {
	forged := "victim@example.invalid\",\"display_name\":\"x\"}\n{\"email\":\"attacker@example.invalid"
	row := goodRow(t, sampleEmail)
	row.payload = sealTo(t, &escrowKey.PublicKey, escrowJSON(t, forged, "Injected\nName", []string{"admin\nroot"}))

	o, args := withRows(t, row)
	got := exercise(t, args, o)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", got.code, got.stderr)
	}
	if lines := strings.Count(strings.TrimSuffix(got.stdout, "\n"), "\n"); lines != 0 {
		t.Errorf("one record produced %d extra lines, so a payload can forge output rows:\n%s", lines, got.stdout)
	}
	recs := records(t, got.stdout)
	if len(recs) != 1 {
		t.Fatalf("recovered %d records from one row: %q", len(recs), got.stdout)
	}
	if recs[0].Email != forged {
		t.Errorf("email = %q, want the payload value escaped and returned intact", recs[0].Email)
	}
}

// Only the four escrowed fields may reach the output. A compromised server can
// seal any JSON it likes into a record; if unknown fields were passed through,
// that JSON would land in whatever a restore script feeds the recovered rows to.
func TestRun_UnknownPayloadFieldsAreNotPassedThrough(t *testing.T) {
	plain := `{"email":"extra@example.invalid","created_at":"2023-04-05T06:07:08Z","roles":["user"],` +
		`"display_name":"Extra","password_hash":"$argon2id$injected","is_admin":true,"totp_secret":"JBSWY3DPEHPK3PXP"}`
	row := goodRow(t, sampleEmail)
	row.payload = sealTo(t, &escrowKey.PublicKey, []byte(plain))

	o, args := withRows(t, row)
	got := exercise(t, args, o)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", got.code, got.stderr)
	}
	// records() decodes with DisallowUnknownFields, so an extra key in the output
	// fails the decode outright; the explicit checks name the offenders.
	recs := records(t, got.stdout)
	if len(recs) != 1 || recs[0].Email != "extra@example.invalid" {
		t.Fatalf("recovered %+v, want the one record", recs)
	}
	mustNotLeak(t, "stdout", got.stdout, "password_hash", "$argon2id$injected", "is_admin", "totp_secret", "JBSWY3DPEHPK3PXP")
}

// A payload whose deleted_at disagrees with the row must not overwrite the audit
// column. The row is append-only in the database; the payload is not
// authenticated as to who deleted the account, only as to its own contents.
func TestRun_PayloadCannotOverrideTheAuditColumns(t *testing.T) {
	plain := `{"email":"audit@example.invalid","created_at":"2023-04-05T06:07:08Z","roles":null,"display_name":"Audit",` +
		`"deleted_at":"1999-01-01T00:00:00Z","deleted_by":"self","reason":"forged"}`
	by, reason := "admin:real", "gdpr_request"
	row := escrowRow{
		payload:   sealTo(t, &escrowKey.PublicKey, []byte(plain)),
		deletedAt: time.Date(2024, 6, 7, 8, 9, 10, 0, time.UTC),
		deletedBy: &by,
		reason:    &reason,
	}

	o, args := withRows(t, row)
	got := exercise(t, args, o)

	recs := records(t, got.stdout)
	if len(recs) != 1 {
		t.Fatalf("recovered %d records, want 1: %q", len(recs), got.stdout)
	}
	if !recs[0].DeletedAt.Equal(time.Date(2024, 6, 7, 8, 9, 10, 0, time.UTC)) {
		t.Errorf("deleted_at = %s, want the database column, not the payload", recs[0].DeletedAt)
	}
	if recs[0].DeletedBy != "admin:real" || recs[0].Reason != "gdpr_request" {
		t.Errorf("attribution = %q/%q, want the database columns", recs[0].DeletedBy, recs[0].Reason)
	}
}

// ---------------------------------------------------------------------------
// Containment
// ---------------------------------------------------------------------------

// Recovered identities go to the stdout the caller supplied and nowhere else. The
// tool runs on an offline host during an incident, often from whatever directory
// the operator happened to be in; a cache file, a debug dump or a partial output
// file left behind would be an unerased copy of data the product just promised to
// erase.
func TestRun_WritesRecoveredDataNowhereButStdout(t *testing.T) {
	workdir := t.TempDir()
	t.Chdir(workdir)

	keyDir := t.TempDir()
	keyPath := filepath.Join(keyDir, "recovery_private.pem")
	if err := os.WriteFile(keyPath, pemFor(t, escrowKey), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	o := &opened{rows: &fakeRows{rows: []escrowRow{goodRow(t, sampleEmail), goodRow(t, "second@example.invalid")}}}
	got := exercise(t, []string{"--key", keyPath, "--dsn", "postgres://offline/vault"}, o)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", got.code, got.stderr)
	}
	if !strings.Contains(got.stdout, sampleEmail) {
		t.Fatalf("the run recovered nothing, so this test would pass vacuously:\n%s", got.stdout)
	}

	assertNoStrayFiles(t, workdir, "working directory", nil)
	assertNoStrayFiles(t, keyDir, "key directory", map[string]bool{keyPath: true})
}

// The key file itself must come back unmodified. The tool has no reason to write
// to it, and a recovery run that rewrote the operator's only copy of the offline
// key would be unrecoverable in the literal sense.
func TestRun_LeavesTheKeyFileUntouched(t *testing.T) {
	keyPath := writeKey(t, escrowKey)
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	beforeInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}

	o := &opened{rows: &fakeRows{rows: []escrowRow{goodRow(t, sampleEmail)}}}
	exercise(t, []string{"--key", keyPath, "--dsn", "postgres://offline/vault"}, o)

	after, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("re-read key: %v", err)
	}
	if string(after) != string(before) {
		t.Error("the recovery key file was modified by a recovery run")
	}
	afterInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("re-stat key: %v", err)
	}
	if afterInfo.Mode() != beforeInfo.Mode() {
		t.Errorf("key file mode changed from %v to %v", beforeInfo.Mode(), afterInfo.Mode())
	}
}

// stdout is the machine-readable channel and stderr is the human one. Duplicating
// a recovered email onto stderr would push it into the operator's terminal
// scrollback and any log collector watching the recovery host, defeating the
// separation the caller relies on when it redirects stdout to an encrypted file.
func TestRun_StderrCarriesNoRecoveredIdentities(t *testing.T) {
	o, args := withRows(t, goodRow(t, sampleEmail), goodRow(t, "second@example.invalid"))
	got := exercise(t, args, o)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", got.code, got.stderr)
	}
	mustNotLeak(t, "stderr", got.stderr, sampleEmail, "second@example.invalid", sampleDisplayName)
	mustNotLeak(t, "stderr", got.stderr, keyMaterial(t, escrowKey)...)
}

// assertNoStrayFiles fails if dir holds anything beyond the allowed paths.
func assertNoStrayFiles(t *testing.T, dir, label string, allowed map[string]bool) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || allowed[path] {
			return nil
		}
		t.Errorf("%s holds an unexpected file after the run: %s", label, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", label, err)
	}
}
