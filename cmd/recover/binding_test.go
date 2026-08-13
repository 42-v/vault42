// How cmd/recover handles the two escrow framings.
//
// The escrow log is append-only in the database but not in the threat model: the
// running server holds the recovery public key and writes every row, and a
// restore can merge backups. Before the payload was bound to its row, moving a
// payload column from one row to another was undetectable - the tool decrypted
// whatever it found and printed it next to that row's deleted_at, deleted_by and
// reason, which is the record an investigator would trust about who was erased,
// when, by whom and why.
//
// Two properties are held down here, and they pull in opposite directions:
//
//   - A bound payload opens for its own row and for no other one. That is the
//     fix.
//   - A record written before the fix still opens, and the tool says out loud
//     that it did. That is the constraint: those rows are the only recoverable
//     copy of the accounts they describe, and refusing them would erase every
//     erasure performed before this shipped.
package main

import (
	"strings"
	"testing"
)

// legacyRow is one row as it exists in a database written before the binding: a
// payload sealed with a nil OAEP label and no AAD, carrying a profile with no
// version stamp and no user id.
func legacyRow(t *testing.T, email string) escrowRow {
	t.Helper()
	row := bareRow(email)
	row.payload = sealLegacy(t, &escrowKey.PublicKey, legacyJSON(t, email))
	return row
}

// legacyJSON is the payload shape the erasure service marshalled before the fix:
// four fields, no "v", no "user_id". Spelled out rather than derived from the
// current struct so that a future change to escrowedPayload cannot quietly
// redefine what "legacy" means.
func legacyJSON(t *testing.T, email string) []byte {
	t.Helper()
	return []byte(`{"email":` + string(jsonValue(t, email)) +
		`,"created_at":` + string(jsonValue(t, sampleCreatedAt)) +
		`,"roles":["user"],"display_name":` + string(jsonValue(t, sampleDisplayName)) + `}`)
}

// ---------------------------------------------------------------------------
// The binding
// ---------------------------------------------------------------------------

// The attack, end to end through the tool: two erasures, then the payload
// columns swapped between the rows. Neither may come out, because either one
// would be printed under the other's audit columns.
func TestRun_SwappedPayloadsAreRefused(t *testing.T) {
	const (
		alice = "alice@example.invalid"
		bob   = "bob@example.invalid"
	)
	aliceRow, bobRow := goodRow(t, alice), goodRow(t, bob)

	// Sanity: unswapped, both records recover. Without this the swap below could
	// pass for the wrong reason.
	o, args := withRows(t, aliceRow, bobRow)
	if got := exercise(t, args, o); got.code != 0 || len(records(t, got.stdout)) != 2 {
		t.Fatalf("the unswapped rows do not recover, so the swap proves nothing: code=%d\n%s\n%s",
			got.code, got.stdout, got.stderr)
	}

	aliceRow.payload, bobRow.payload = bobRow.payload, aliceRow.payload

	o, args = withRows(t, aliceRow, bobRow)
	got := exercise(t, args, o)

	if got.stdout != "" {
		t.Errorf("a swapped payload was recovered and attributed to the wrong erasure:\n%s", got.stdout)
	}
	if !strings.Contains(got.stderr, "recover: 0 record(s) decrypted, 2 failure(s)") {
		t.Errorf("the swap was not counted as two failures:\n%s", got.stderr)
	}
	if got.code != exitIncomplete {
		t.Errorf("exit code = %d, want %d", got.code, exitIncomplete)
	}
	mustNotLeak(t, "swap diagnostics", got.stderr, alice, bob)
}

// The binding covers the record id as well as the subject, so a payload cannot
// be moved even between two escrow rows about the SAME account. The erasure
// service can legitimately write more than one record per user when an
// interrupted erasure is retried, and those rows carry different deleted_at
// values; letting their payloads be exchanged would still misdate an erasure.
func TestRun_PayloadCannotMoveBetweenTwoRowsOfTheSameSubject(t *testing.T) {
	first := goodRow(t, sampleEmail)
	second := goodRow(t, sampleEmail)
	// Same subject, so the same pseudonym; a distinct primary key, as the
	// database enforces.
	second.id = rowIDFor("retry:" + sampleEmail)
	if first.pseudonym != second.pseudonym {
		t.Fatal("the fixture rows are not about the same subject")
	}

	o, args := withRows(t, second)
	got := exercise(t, args, o)

	if got.stdout != "" {
		t.Errorf("a payload sealed for one row opened under another row of the same subject:\n%s", got.stdout)
	}
	if !strings.Contains(got.stderr, "recover: decrypt failed for a record") {
		t.Errorf("the mismatch was not reported:\n%s", got.stderr)
	}
}

// The binding is rebuilt from the columns the query selects, so a row whose id
// or pseudonym was altered no longer opens its own payload. This is what makes
// the escrow tamper-evident rather than merely confidential: an attacker who
// rewrites the pseudonym to point an erasure at a different subject destroys the
// record instead of relabelling it.
func TestRun_AlteredRowIdentityBreaksItsOwnRecord(t *testing.T) {
	tests := map[string]func(escrowRow) escrowRow{
		"record id changed": func(r escrowRow) escrowRow {
			r.id = rowIDFor("some other row")
			return r
		},
		"pseudonym changed": func(r escrowRow) escrowRow {
			r.pseudonym = pseudonymFor("some other subject")
			return r
		},
		"record id emptied": func(r escrowRow) escrowRow {
			r.id = ""
			return r
		},
		"pseudonym emptied": func(r escrowRow) escrowRow {
			r.pseudonym = ""
			return r
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			o, args := withRows(t, mutate(goodRow(t, sampleEmail)))
			got := exercise(t, args, o)

			if got.stdout != "" {
				t.Errorf("the record survived having its binding columns rewritten:\n%s", got.stdout)
			}
			if !strings.Contains(got.stderr, "recover: 0 record(s) decrypted, 1 failure(s)") {
				t.Errorf("the record was not counted as a failure:\n%s", got.stderr)
			}
			mustNotLeak(t, "tamper diagnostics", got.stderr, sampleEmail, sampleDisplayName)
		})
	}
}

// A UUID is case-insensitive and PostgreSQL emits it lowercase. A row whose id
// arrives in a different case is the same row, and must still open: this is the
// difference between a working recovery tool and one that reports every record
// as corrupt after somebody changes how ids are generated.
func TestRun_RecordIDCaseDoesNotBreakRecovery(t *testing.T) {
	row := goodRow(t, sampleEmail)
	row.id = strings.ToUpper(row.id)

	o, args := withRows(t, row)
	got := exercise(t, args, o)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0: a case-shifted UUID is the same UUID\n%s", got.code, got.stderr)
	}
	if recs := records(t, got.stdout); len(recs) != 1 || recs[0].Email != sampleEmail {
		t.Errorf("recovered %+v, want the one record", recs)
	}
}

// The recovered record names its subject, and it names it from inside the sealed
// payload rather than from anything the row could be edited to say. That id is
// what an operator restores the account under.
func TestRun_BoundRecordCarriesItsSubjectAndFormat(t *testing.T) {
	o, args := withRows(t, goodRow(t, sampleEmail))
	got := exercise(t, args, o)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", got.code, got.stderr)
	}
	recs := records(t, got.stdout)
	if len(recs) != 1 {
		t.Fatalf("recovered %d records, want 1: %q", len(recs), got.stdout)
	}
	if recs[0].UserID != userIDFor(sampleEmail) {
		t.Errorf("user_id = %q, want the subject from the sealed payload", recs[0].UserID)
	}
	if recs[0].EscrowFormat != "bound" {
		t.Errorf("escrow_format = %q, want bound: a restore has to be able to tell a verified "+
			"attribution from an unverified one without reading stderr", recs[0].EscrowFormat)
	}
}

// A bound record whose payload does not name a subject is not a profile this
// tool can restore, however cleanly it decrypts. The producer is the server,
// which holds the public key, so the shape of the plaintext is not something the
// tool may assume.
func TestRun_BoundRecordWithoutASubjectIsRejected(t *testing.T) {
	tests := map[string]string{
		"no user id":     `{"v":2,"email":"nosubject@example.invalid","roles":["user"]}`,
		"empty user id":  `{"v":2,"user_id":"","email":"nosubject@example.invalid"}`,
		"no version":     `{"user_id":"user-x","email":"nosubject@example.invalid"}`,
		"wrong version":  `{"v":1,"user_id":"user-x","email":"nosubject@example.invalid"}`,
		"future version": `{"v":99,"user_id":"user-x","email":"nosubject@example.invalid"}`,
	}

	for name, plain := range tests {
		t.Run(name, func(t *testing.T) {
			row := bareRow(sampleEmail)
			row.payload = sealTo(t, &escrowKey.PublicKey, []byte(plain), bindingFor(sampleEmail))

			o, args := withRows(t, row)
			got := exercise(t, args, o)

			if got.stdout != "" {
				t.Errorf("a bound record that does not describe its subject was emitted:\n%s", got.stdout)
			}
			if !strings.Contains(got.stderr, "does not describe its subject") {
				t.Errorf("the rejection was not explained:\n%s", got.stderr)
			}
			if got.code != exitIncomplete {
				t.Errorf("exit code = %d, want %d", got.code, exitIncomplete)
			}
			mustNotLeak(t, "rejection diagnostics", got.stderr, "nosubject@example.invalid")
		})
	}
}

// ---------------------------------------------------------------------------
// The legacy path
// ---------------------------------------------------------------------------

// Records written before the binding are the only recoverable copy of the
// accounts they describe. If this fails, the change has destroyed the
// recoverability of every erasure that happened before it shipped, which is the
// exact opposite of what this tool exists for.
func TestRun_LegacyRecordIsStillRecoverable(t *testing.T) {
	o, args := withRows(t, legacyRow(t, sampleEmail))
	got := exercise(t, args, o)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0: a pre-binding escrow record must still be recoverable\n%s",
			got.code, got.stderr)
	}
	recs := records(t, got.stdout)
	if len(recs) != 1 {
		t.Fatalf("recovered %d records, want 1: %q", len(recs), got.stdout)
	}
	if recs[0].Email != sampleEmail || recs[0].DisplayName != sampleDisplayName {
		t.Errorf("recovered %+v, want the escrowed profile", recs[0])
	}
	if !recs[0].DeletedAt.Equal(bareRow(sampleEmail).deletedAt) {
		t.Errorf("deleted_at = %s, want the row's column", recs[0].DeletedAt)
	}
}

// Reading a legacy record must never be silent. The record's attribution to its
// row is unverified, so anyone acting on the output has to know which records
// carry that caveat - in the machine-readable output, not only in a log line.
func TestRun_LegacyRecordIsReportedAsLegacy(t *testing.T) {
	o, args := withRows(t, legacyRow(t, sampleEmail), goodRow(t, "bound@example.invalid"))
	got := exercise(t, args, o)

	if got.code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", got.code, got.stderr)
	}
	recs := records(t, got.stdout)
	if len(recs) != 2 {
		t.Fatalf("recovered %d records, want 2: %q", len(recs), got.stdout)
	}
	if recs[0].EscrowFormat != "legacy" {
		t.Errorf("escrow_format = %q, want legacy", recs[0].EscrowFormat)
	}
	if recs[0].UserID != "" {
		t.Errorf("user_id = %q, want empty: the legacy payload never carried one", recs[0].UserID)
	}
	if recs[1].EscrowFormat != "bound" {
		t.Errorf("the bound record in the same run was labelled %q", recs[1].EscrowFormat)
	}

	for _, want := range []string{
		"legacy record read",
		"unverified",
		"1 of those came from the legacy pre-binding escrow format",
		"--allow-legacy=false",
	} {
		if !strings.Contains(got.stderr, want) {
			t.Errorf("stderr does not mention %q, so the legacy read is effectively silent:\n%s", want, got.stderr)
		}
	}
	// The per-record line names the row so an operator can find it, and nothing
	// more: stderr ends up in scrollback and tickets.
	mustNotLeak(t, "legacy diagnostics", got.stderr, sampleEmail, sampleDisplayName)
}

// The bound of the legacy path. Once retention has aged the last pre-binding
// record out, an operator flips this flag to prove none remain, and the legacy
// read path can then be deleted from the tree.
func TestRun_LegacyRecordsCanBeRefused(t *testing.T) {
	o, args := withRows(t, legacyRow(t, sampleEmail), goodRow(t, "bound@example.invalid"))
	got := exercise(t, append(args, "--allow-legacy=false"), o)

	if got.code != exitIncomplete {
		t.Fatalf("exit code = %d, want %d: the run came back short\n%s", got.code, exitIncomplete, got.stderr)
	}
	recs := records(t, got.stdout)
	if len(recs) != 1 || recs[0].Email != "bound@example.invalid" {
		t.Fatalf("recovered %+v, want only the bound record", recs)
	}
	if !strings.Contains(got.stderr, "refused a legacy record") {
		t.Errorf("the refusal was not explained:\n%s", got.stderr)
	}
	if !strings.Contains(got.stderr, "recover: 1 record(s) decrypted, 1 failure(s)") {
		t.Errorf("the refused record was not counted as a failure:\n%s", got.stderr)
	}
	// A refusal is not a legacy read, so the retirement summary must not claim
	// one happened.
	if strings.Contains(got.stderr, "came from the legacy pre-binding escrow format") {
		t.Errorf("a refused record was counted as a legacy read:\n%s", got.stderr)
	}
	mustNotLeak(t, "refusal diagnostics", got.stderr, sampleEmail, sampleDisplayName)
}

// A legacy record that fails for any other reason is a failure, not a legacy
// read. Inflating the legacy count would make the decision to retire the legacy
// path harder rather than easier, which is the one thing that count is for.
func TestRun_FailedLegacyRecordIsNotCountedAsALegacyRead(t *testing.T) {
	row := legacyRow(t, sampleEmail)
	row.payload = sealLegacy(t, &wrongKey.PublicKey, legacyJSON(t, sampleEmail))

	o, args := withRows(t, row)
	got := exercise(t, args, o)

	if got.stdout != "" {
		t.Errorf("stdout = %q, want empty", got.stdout)
	}
	if strings.Contains(got.stderr, "came from the legacy pre-binding escrow format") {
		t.Errorf("a legacy record that never decrypted was counted as a legacy read:\n%s", got.stderr)
	}
	if !strings.Contains(got.stderr, "recover: 0 record(s) decrypted, 1 failure(s)") {
		t.Errorf("summary did not count the failure:\n%s", got.stderr)
	}
}

// A legacy payload that decrypts but carries no email is refused exactly like a
// bound one. The legacy path relaxes the binding, not the validity checks: the
// server held the public key then too, so an empty profile is as forgeable in
// the old format as in the new one.
func TestRun_LegacyRecordStillNeedsAnIdentity(t *testing.T) {
	for _, plain := range []string{`null`, `{}`, `{"email":""}`} {
		t.Run(plain, func(t *testing.T) {
			row := bareRow(sampleEmail)
			row.payload = sealLegacy(t, &escrowKey.PublicKey, []byte(plain))

			o, args := withRows(t, row)
			got := exercise(t, args, o)

			if got.stdout != "" {
				t.Errorf("an identity-free legacy record was emitted:\n%s", got.stdout)
			}
			if !strings.Contains(got.stderr, "carries no identity") {
				t.Errorf("the rejection was not explained:\n%s", got.stderr)
			}
			if got.code != exitIncomplete {
				t.Errorf("exit code = %d, want %d", got.code, exitIncomplete)
			}
		})
	}
}

// Legacy records ignore the row's binding columns by construction, so a run in
// which they were tampered with still recovers them. This is not a hole the
// change opened - it is the residual risk the legacy path carries, and it is
// pinned here so that whoever deletes that path can see exactly what they are
// removing.
func TestRun_LegacyRecordIsNotProtectedByTheRowColumns(t *testing.T) {
	row := legacyRow(t, sampleEmail)
	row.id = rowIDFor("a completely different row")
	row.pseudonym = pseudonymFor("a completely different subject")

	o, args := withRows(t, row)
	got := exercise(t, args, o)

	recs := records(t, got.stdout)
	if len(recs) != 1 {
		t.Fatalf("recovered %d records, want 1: %q", len(recs), got.stdout)
	}
	if recs[0].EscrowFormat != "legacy" {
		t.Fatalf("escrow_format = %q, want legacy", recs[0].EscrowFormat)
	}
	if !strings.Contains(got.stderr, "unverified") {
		t.Errorf("the tool recovered an unbindable record without saying its attribution is unverified:\n%s", got.stderr)
	}
}

// The two framings are told apart by the blob, never by a failed decrypt
// followed by a retry. A bound record must not be readable through the legacy
// path even when legacy reads are allowed, or an attacker could strip the
// binding by damaging the header and have the tool fall back to the format that
// checks nothing.
func TestRun_BoundRecordDoesNotFallBackToTheLegacyPath(t *testing.T) {
	row := goodRow(t, sampleEmail)
	// Drop the bound framing, leaving bytes that read as a legacy blob.
	row.payload = row.payload[5:]

	o, args := withRows(t, row)
	got := exercise(t, args, o)

	if got.stdout != "" {
		t.Errorf("a bound record was downgraded to the unbound format and recovered:\n%s", got.stdout)
	}
	if !strings.Contains(got.stderr, "recover: 0 record(s) decrypted, 1 failure(s)") {
		t.Errorf("the downgrade attempt was not counted as a failure:\n%s", got.stderr)
	}
}
