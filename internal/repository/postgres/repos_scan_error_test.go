package postgres

import (
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/42-v/vault42/internal/model"
)

// Four listings in this package feed a security decision rather than a display:
// the unused backup codes a login may still be redeemed against, the password
// hashes a new password is checked for reuse against, the social identities that
// may sign a user in, and the WebAuthn credentials an assertion is verified
// against. Every one of them is read with a rows.Next loop, and a result set can
// stop early: a canceled statement, a recovery conflict, a connection that dies
// mid-stream. pgx reports that as rows the caller already consumed plus a
// non-nil rows.Err() afterwards.
//
// Ignoring rows.Err() there would return the prefix that arrived as if it were
// the whole answer, with no error at all. That is not a degraded read, it is a
// wrong one, and it fails open every time: a backup code missing from the list
// is a code that cannot be redeemed but is also never marked used, a password
// history that stops short lets a user re-set a password the policy forbids, a
// short social-account list unlinks a provider that is still linked, and a
// truncated credential list turns a registered security key into "no such
// credential".
//
// None of this can be provoked against a healthy database, so these talk to the
// scripted Postgres wire-protocol backend: it hands over rows and then an error,
// which is the shape of the failure and nothing else.

func truncatedMidStream() *pgproto3.ErrorResponse {
	return &pgproto3.ErrorResponse{
		Severity: "ERROR", Code: "57014",
		Message: "canceling statement due to conflict with recovery",
	}
}

func backupCodeFields() []pgproto3.FieldDescription {
	return []pgproto3.FieldDescription{
		blobClientField("id", blobClientOIDVarchar),
		blobClientField("user_id", blobClientOIDVarchar),
		blobClientField("code_hash", blobClientOIDVarchar),
		blobClientField("used", blobClientOIDBool),
		blobClientField("used_at", blobClientOIDTimestamptz),
		blobClientField("created_at", blobClientOIDTimestamptz),
	}
}

func backupCodeRow(id, hash string) [][]byte {
	var codeHash []byte
	if hash != "" {
		codeHash = blobClientText(hash)
	}
	return [][]byte{
		blobClientText(id),
		blobClientText("user-1"),
		codeHash,
		blobClientBool(false),
		nil,
		blobClientTimestamptz(time.Now()),
	}
}

// CreateBatch is all-or-nothing on purpose: the codes it inserts are shown to the
// user exactly once, right after the call returns. A commit that failed and was
// reported as success hands over ten recovery codes that are not in the table, and
// the user finds out the next time they are locked out of their account.
func TestBackupCodeRepo_CreateBatchSurfacesAFailedCommit(t *testing.T) {
	db := blobClientFakeDB(t,
		blobClientRowScript{
			match: "INSERT INTO auth.backup_codes",
			paramOIDs: []uint32{
				blobClientOIDText, blobClientOIDText, blobClientOIDText,
				blobClientOIDBool, blobClientOIDTimestamptz,
			},
		},
		blobClientRowScript{
			match: "commit",
			failWith: &pgproto3.ErrorResponse{
				Severity: "ERROR", Code: "40001",
				Message: "could not serialize access due to concurrent update",
			},
		},
	)

	err := NewBackupCodeRepo(db).CreateBatch(blobClientCtx(t), []*model.BackupCode{
		{ID: "bc-1", UserID: "user-1", CodeHash: "$argon2id$a", CreatedAt: time.Now()},
		{ID: "bc-2", UserID: "user-1", CodeHash: "$argon2id$b", CreatedAt: time.Now()},
	})
	if err == nil {
		t.Fatal("a rolled-back batch was reported as stored; the user would be shown codes that do not exist")
	}
	if !strings.Contains(err.Error(), "create backup codes") {
		t.Errorf("err = %v, want the batch insert to be named", err)
	}
	// The inserts themselves are scripted to succeed, so the failure has to be
	// the commit and nothing else: both paths wrap with the same message, and
	// only the SQLSTATE tells them apart.
	if !strings.Contains(err.Error(), "SQLSTATE 40001") {
		t.Errorf("err = %v, want the commit failure rather than a failed insert", err)
	}
}

// code_hash is NOT NULL and is the only thing a redemption compares against. A
// row that does not scan has to take the listing down: a backup code silently
// rebuilt with an empty hash is a credential that matches nothing, and one
// dropped from the list is a code the user still holds on paper.
func TestBackupCodeRepo_ListRefusesUnreadableRow(t *testing.T) {
	db := blobClientFakeDB(t, blobClientRowScript{
		match:  "FROM auth.backup_codes",
		fields: backupCodeFields(),
		rows:   [][][]byte{backupCodeRow("bc-1", "")},
	})

	codes, err := NewBackupCodeRepo(db).ListUnusedByUser(blobClientCtx(t), "user-1")
	if err == nil {
		t.Fatalf("a backup-code row that could not be read was accepted: %+v", codes)
	}
	if !strings.Contains(err.Error(), "scan backup code") {
		t.Errorf("err = %v, want a scan failure", err)
	}
	if codes != nil {
		t.Errorf("a failed listing still returned %d codes", len(codes))
	}
}

func TestBackupCodeRepo_ListRefusesTruncatedResult(t *testing.T) {
	db := blobClientFakeDB(t, blobClientRowScript{
		match:    "FROM auth.backup_codes",
		fields:   backupCodeFields(),
		rows:     [][][]byte{backupCodeRow("bc-1", "$argon2id$a"), backupCodeRow("bc-2", "$argon2id$b")},
		failWith: truncatedMidStream(),
	})

	codes, err := NewBackupCodeRepo(db).ListUnusedByUser(blobClientCtx(t), "user-1")
	if err == nil {
		t.Fatalf("a truncated result set was returned as the complete set of unused codes: %+v", codes)
	}
	if !strings.Contains(err.Error(), "scan backup codes") {
		t.Errorf("err = %v, want the truncated iteration to be surfaced", err)
	}
	if len(codes) != 0 {
		t.Errorf("a failed listing still returned %d codes", len(codes))
	}
}

func passwordHistoryFields() []pgproto3.FieldDescription {
	return []pgproto3.FieldDescription{
		blobClientField("id", blobClientOIDVarchar),
		blobClientField("user_id", blobClientOIDVarchar),
		blobClientField("password_hash", blobClientOIDVarchar),
		blobClientField("created_at", blobClientOIDTimestamptz),
	}
}

func passwordHistoryRow(id, hash string) [][]byte {
	var pwHash []byte
	if hash != "" {
		pwHash = blobClientText(hash)
	}
	return [][]byte{
		blobClientText(id),
		blobClientText("user-1"),
		pwHash,
		blobClientTimestamptz(time.Now()),
	}
}

// The history is what a password change is compared against. An empty hash
// scanned in its place is compared too, and a reuse check that runs against ""
// is a reuse check that passes.
func TestPasswordHistoryRepo_GetRecentRefusesUnreadableRow(t *testing.T) {
	db := blobClientFakeDB(t, blobClientRowScript{
		match:     "FROM auth.password_history",
		paramOIDs: []uint32{blobClientOIDText, blobClientOIDInt4},
		fields:    passwordHistoryFields(),
		rows:      [][][]byte{passwordHistoryRow("ph-1", "")},
	})

	entries, err := NewPasswordHistoryRepo(db).GetRecentByUser(blobClientCtx(t), "user-1", 5)
	if err == nil {
		t.Fatalf("a password-history row that could not be read was accepted: %+v", entries)
	}
	if !strings.Contains(err.Error(), "scan password history") {
		t.Errorf("err = %v, want a scan failure", err)
	}
	if entries != nil {
		t.Errorf("a failed listing still returned %d entries", len(entries))
	}
}

func TestPasswordHistoryRepo_GetRecentRefusesTruncatedResult(t *testing.T) {
	db := blobClientFakeDB(t, blobClientRowScript{
		match:     "FROM auth.password_history",
		paramOIDs: []uint32{blobClientOIDText, blobClientOIDInt4},
		fields:    passwordHistoryFields(),
		rows:      [][][]byte{passwordHistoryRow("ph-1", "$argon2id$a"), passwordHistoryRow("ph-2", "$argon2id$b")},
		failWith:  truncatedMidStream(),
	})

	entries, err := NewPasswordHistoryRepo(db).GetRecentByUser(blobClientCtx(t), "user-1", 5)
	if err == nil {
		t.Fatalf("a truncated history was returned as complete: %+v", entries)
	}
	if !strings.Contains(err.Error(), "scan password history") {
		t.Errorf("err = %v, want the truncated iteration to be surfaced", err)
	}
	if len(entries) != 0 {
		t.Errorf("a failed listing still returned %d entries", len(entries))
	}
}

func socialAccountFields() []pgproto3.FieldDescription {
	return []pgproto3.FieldDescription{
		blobClientField("id", blobClientOIDVarchar),
		blobClientField("user_id", blobClientOIDVarchar),
		blobClientField("provider", blobClientOIDVarchar),
		blobClientField("provider_user_id", blobClientOIDVarchar),
		blobClientField("access_token_enc", blobClientOIDText),
		blobClientField("refresh_token_enc", blobClientOIDText),
		blobClientField("created_at", blobClientOIDTimestamptz),
	}
}

// The linked-account list is what a user unlinks providers from and what the
// data export reports as the identities that can sign in. A list that stops
// halfway shows a provider as unlinked while it still signs the user in.
func TestSocialAccountRepo_ListRefusesTruncatedResult(t *testing.T) {
	row := func(id, provider string) [][]byte {
		return [][]byte{
			blobClientText(id),
			blobClientText("user-1"),
			blobClientText(provider),
			blobClientText("remote-" + id),
			blobClientText("access-ciphertext"),
			blobClientText("refresh-ciphertext"),
			blobClientTimestamptz(time.Now()),
		}
	}

	db := blobClientFakeDB(t, blobClientRowScript{
		match:    "FROM auth.social_accounts",
		fields:   socialAccountFields(),
		rows:     [][][]byte{row("sa-1", "github"), row("sa-2", "google")},
		failWith: truncatedMidStream(),
	})

	accounts, err := NewSocialAccountRepo(db).ListByUser(blobClientCtx(t), "user-1")
	if err == nil {
		t.Fatalf("a truncated list of linked accounts was returned as complete: %+v", accounts)
	}
	if !strings.Contains(err.Error(), "scan social accounts") {
		t.Errorf("err = %v, want the truncated iteration to be surfaced", err)
	}
	if len(accounts) != 0 {
		t.Errorf("a failed listing still returned %d accounts", len(accounts))
	}
}

func webAuthnFields() []pgproto3.FieldDescription {
	return []pgproto3.FieldDescription{
		blobClientField("id", blobClientOIDVarchar),
		blobClientField("user_id", blobClientOIDVarchar),
		blobClientField("credential_id", blobClientOIDBytea),
		blobClientField("public_key", blobClientOIDBytea),
		blobClientField("sign_count", blobClientOIDInt4),
		blobClientField("flags", blobClientOIDInt4),
		blobClientField("friendly_name", blobClientOIDVarchar),
		blobClientField("created_at", blobClientOIDTimestamptz),
	}
}

// The credential list is the allow-list an assertion is matched against. A
// truncated one means a security key the user has registered and is holding in
// their hand is reported as unknown, which locks them out with a message saying
// the credential does not exist.
func TestWebAuthnRepo_ListRefusesTruncatedResult(t *testing.T) {
	row := func(id string) [][]byte {
		return [][]byte{
			blobClientText(id),
			blobClientText("user-1"),
			[]byte("credential-id-" + id),
			[]byte("cose-public-key"),
			blobClientInt4(7),
			blobClientInt4(0x05),
			blobClientText("YubiKey"),
			blobClientTimestamptz(time.Now()),
		}
	}

	db := blobClientFakeDB(t, blobClientRowScript{
		match:    "FROM auth.webauthn_credentials",
		fields:   webAuthnFields(),
		rows:     [][][]byte{row("wa-1"), row("wa-2")},
		failWith: truncatedMidStream(),
	})

	creds, err := NewWebAuthnRepo(db).ListByUser(blobClientCtx(t), "user-1")
	if err == nil {
		t.Fatalf("a truncated credential list was returned as complete: %+v", creds)
	}
	if !strings.Contains(err.Error(), "scan webauthn credentials") {
		t.Errorf("err = %v, want the truncated iteration to be surfaced", err)
	}
	if len(creds) != 0 {
		t.Errorf("a failed listing still returned %d credentials", len(creds))
	}
}
