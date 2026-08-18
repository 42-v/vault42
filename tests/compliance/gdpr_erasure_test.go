package compliance

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
	"github.com/42-v/vault42/internal/service"
)

// =============================================================================
// GDPR Article 17 Compliance Tests -- Right to Erasure, Real Cascade
// =============================================================================
//
// The real ErasureService against a real Postgres with every migration applied.
// Every claim in docs/PRIVACY.md section 5.3 is pinned here with a row count:
// a mock recording "the delete method was called" passes whether or not the row
// is gone, and that is exactly how backup codes once survived erasure.

// gdprSetupPostgres starts a PostgreSQL testcontainer and applies ALL migrations
// in sorted order. The single-migration fixture in this package is not enough
// for erasure: the deleted/roles user columns (003, 004) and the recovery escrow
// table (007) only exist in later migrations.
func gdprSetupPostgres(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()
	skipIfNoDocker(t)
	ctx := context.Background()

	pgContainer, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("vault_test"),
		tcpostgres.WithUsername("vault_test"),
		tcpostgres.WithPassword("vault_test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		pgContainer.Terminate(ctx) //nolint:errcheck
		t.Fatalf("get connection string: %v", err)
	}

	poolCfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		pgContainer.Terminate(ctx) //nolint:errcheck
		t.Fatalf("parse pool config: %v", err)
	}
	poolCfg.MaxConns = 5
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		pgContainer.Terminate(ctx) //nolint:errcheck
		t.Fatalf("create pool: %v", err)
	}

	migConn, err := pgx.Connect(ctx, connStr)
	if err != nil {
		pool.Close()
		pgContainer.Terminate(ctx) //nolint:errcheck
		t.Fatalf("connect for migrations: %v", err)
	}

	migEntries, err := os.ReadDir("../../migrations")
	if err != nil {
		migConn.Close(ctx) //nolint:errcheck
		pool.Close()
		pgContainer.Terminate(ctx) //nolint:errcheck
		t.Fatalf("read migrations dir: %v", err)
	}
	var migFiles []string
	for _, e := range migEntries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			migFiles = append(migFiles, e.Name())
		}
	}
	sort.Strings(migFiles)
	for _, f := range migFiles {
		migSQL, err := os.ReadFile("../../migrations/" + f)
		if err != nil {
			migConn.Close(ctx) //nolint:errcheck
			pool.Close()
			pgContainer.Terminate(ctx) //nolint:errcheck
			t.Fatalf("read migration %s: %v", f, err)
		}
		migStr := stripRoleGrantsInteg(string(migSQL))
		if _, err := migConn.Exec(ctx, migStr); err != nil {
			migConn.Close(ctx) //nolint:errcheck
			pool.Close()
			pgContainer.Terminate(ctx) //nolint:errcheck
			t.Fatalf("run migration %s: %v", f, err)
		}
	}
	migConn.Close(ctx) //nolint:errcheck

	cleanup := func() {
		pool.Close()
		pgContainer.Terminate(ctx) //nolint:errcheck
	}
	return pool, cleanup
}

// gdprCount runs a COUNT(*) query and fails the test on any query error.
func gdprCount(t *testing.T, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count query %q: %v", query, err)
	}
	return n
}

// TestGDPR_Art17_AccountErasure runs one full account erasure through the real
// service and verifies every clause of the Art. 17 contract in docs/PRIVACY.md
// section 5.3 against the database state, clause by clause.
func TestGDPR_Art17_AccountErasure(t *testing.T) {
	pool, cleanup := gdprSetupPostgres(t)
	defer cleanup()
	ctx := context.Background()
	db := &postgres.DB{Pool: pool}

	// The offline recovery keypair. The service only ever sees the public key;
	// the private key stays in the test to prove the escrow record decrypts.
	recoveryKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate recovery key: %v", err)
	}
	hmacSecret := []byte("gdpr-suite-hmac-secret-32-bytes!")

	users := postgres.NewUserRepo(db)
	identity := postgres.NewIdentityRepo(db)
	blobs := postgres.NewBlobRepo(db)
	devices := postgres.NewDeviceRepo(db)
	social := postgres.NewSocialAccountRepo(db)
	pwHistory := postgres.NewPasswordHistoryRepo(db)
	tokens := postgres.NewRefreshTokenRepo(db)
	totp := postgres.NewTOTPRepo(db)
	webauthn := postgres.NewWebAuthnRepo(db)
	backupCodes := postgres.NewBackupCodeRepo(db)
	recovery := postgres.NewAccountRecoveryRepo(db)
	loginCountries := postgres.NewLoginCountryRepo(db)
	// flushEvery=0 selects immediate (unbuffered) mode, so every audit write has
	// hit the table before the next assertion runs.
	auditLog := audit.NewLogger(postgres.NewAuditRepo(db), 0)

	svc := service.NewErasureService(
		users, identity, blobs, devices, social, pwHistory, tokens,
		totp, webauthn, backupCodes,
		recovery, auditLog, &recoveryKey.PublicKey, hmacSecret,
	)
	// The login-country store is attached by setter, not by constructor. Both
	// production planes call this; a suite that skipped it would assert Art. 17
	// against a cascade the product does not run.
	svc.SetLoginCountries(loginCountries)

	// --- Fixture: a user with data in every user-linked store ---

	const email = "erased-subject@example.com"
	const maskedEmail = "e***@example.com" // maskEmail(email), the audit form
	const displayName = "Erased Subject"
	const deletedBy = "admin:compliance-suite"
	const reason = "user_request"

	userID, _ := vaultcrypto.RandomUUID()
	now := time.Now().UTC().Truncate(time.Microsecond)
	user := &model.User{
		ID:            userID,
		Email:         email,
		EmailVerified: true,
		PasswordHash:  "$argon2id$v=19$m=47104,t=1,p=1$dGVzdHNhbHQ$testhash",
		DisplayName:   displayName,
		Locale:        "en",
		Roles:         []string{"user"},
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := users.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// The pseudonym-keyed stores use the same HMAC derivations the identity and
	// blob services use, which are the ones erasure must reproduce to find them.
	identityPseudonym := vaultcrypto.HMACSign([]byte(userID+":identity"), hmacSecret)
	blobPseudonym := vaultcrypto.HMACSign([]byte(userID+":objects"), hmacSecret)
	recoveryPseudonym := vaultcrypto.HMACSign([]byte(userID+":recovery"), hmacSecret)

	if err := identity.Upsert(ctx, &model.IdentityProfile{
		PseudonymID: identityPseudonym, DataEnc: []byte("aes-gcm-ciphertext"),
		Version: 1, UpdatedAt: now, CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed identity profile: %v", err)
	}
	for i := 0; i < 2; i++ {
		id, _ := vaultcrypto.RandomUUID()
		ref, _ := vaultcrypto.RandomUUID()
		if err := blobs.Create(ctx, &model.Blob{
			ID: id, PseudonymID: blobPseudonym, RefHash: ref,
			LabelEnc: []byte("label-ct"), DataEnc: []byte("blob-ct"),
			SizeBytes: 7, StoredBytes: 16, Checksum: "sha256:" + ref, CreatedAt: now,
		}); err != nil {
			t.Fatalf("seed blob %d: %v", i, err)
		}
	}
	deviceID, _ := vaultcrypto.RandomUUID()
	fpHash, _ := vaultcrypto.RandomUUID()
	if err := devices.Create(ctx, &model.Device{
		ID: deviceID, UserID: userID, FingerprintHash: fpHash,
		FriendlyName: "laptop", IP: "203.0.113.7", UserAgent: "ua",
		FirstSeenAt: now, CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	socialID, _ := vaultcrypto.RandomUUID()
	if err := social.Create(ctx, &model.SocialAccount{
		ID: socialID, UserID: userID, Provider: "github",
		ProviderUserID: "gh-4242", Email: email, CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed social account: %v", err)
	}
	for i := 0; i < 2; i++ {
		id, _ := vaultcrypto.RandomUUID()
		if err := pwHistory.Create(ctx, &model.PasswordHistory{
			ID: id, UserID: userID, PasswordHash: "$argon2id$old-hash", CreatedAt: now,
		}); err != nil {
			t.Fatalf("seed password history %d: %v", i, err)
		}
	}
	totpID, _ := vaultcrypto.RandomUUID()
	if err := totp.Create(ctx, &model.TOTPSecret{
		ID: totpID, UserID: userID, SecretEnc: "enc:totp-secret", CreatedAt: now,
	}); err != nil {
		t.Fatalf("seed totp secret: %v", err)
	}
	for i := 0; i < 2; i++ {
		id, _ := vaultcrypto.RandomUUID()
		credID, _ := vaultcrypto.RandomUUID()
		if err := webauthn.Create(ctx, &model.WebAuthnCredential{
			ID: id, UserID: userID, CredentialID: []byte(credID),
			PublicKey: []byte("cose-public-key"), FriendlyName: "key", CreatedAt: now,
		}); err != nil {
			t.Fatalf("seed webauthn credential %d: %v", i, err)
		}
	}
	var codes []*model.BackupCode
	for i := 0; i < 3; i++ {
		id, _ := vaultcrypto.RandomUUID()
		codes = append(codes, &model.BackupCode{
			ID: id, UserID: userID, CodeHash: fmt.Sprintf("$argon2id$code-hash-%d", i), CreatedAt: now,
		})
	}
	if err := backupCodes.CreateBatch(ctx, codes); err != nil {
		t.Fatalf("seed backup codes: %v", err)
	}
	for i := 0; i < 2; i++ {
		id, _ := vaultcrypto.RandomUUID()
		family, _ := vaultcrypto.RandomUUID()
		if err := tokens.Create(ctx, &model.RefreshToken{
			ID: id, UserID: userID, TokenHash: vaultcrypto.SHA256Hex(fmt.Sprintf("raw-%d", i)),
			FamilyID: family, FingerprintHash: fpHash,
			ExpiresAt: now.Add(24 * time.Hour), CreatedAt: now,
		}); err != nil {
			t.Fatalf("seed refresh token %d: %v", i, err)
		}
	}
	// Two login countries. Location data about the person: migration 028 assumed
	// its ON DELETE CASCADE cleared these on erasure, which a tombstoned parent row
	// never triggers, so they survived every erasure until migration 030.
	for _, cc := range []string{"DE", "FR"} {
		if _, _, err := loginCountries.UpsertAndWasNew(ctx, userID, cc); err != nil {
			t.Fatalf("seed login country %s: %v", cc, err)
		}
	}

	// A pre-erasure audit entry. Art. 17(3)(b)/(e) exempts these; clause 5
	// asserts it survives the erasure untouched.
	if err := auditLog.Log(ctx, audit.LoginSuccess, userID, "", "203.0.113.7", "ua", fpHash, deviceID, nil); err != nil {
		t.Fatalf("seed audit entry: %v", err)
	}

	// The ten stores DeleteAccount cascades over, in the order it runs them.
	// The seeded counts double as the vacuous-pass guard: a store that never had
	// rows would make its post-erasure zero meaningless.
	erasableStores := []struct {
		store  string
		query  string
		key    any
		seeded int
	}{
		{"identity.profiles", `SELECT COUNT(*) FROM identity.profiles WHERE pseudonym_id=$1`, identityPseudonym, 1},
		{"objects.blobs", `SELECT COUNT(*) FROM objects.blobs WHERE pseudonym_id=$1`, blobPseudonym, 2},
		{"auth.devices", `SELECT COUNT(*) FROM auth.devices WHERE user_id=$1`, userID, 1},
		{"auth.social_accounts", `SELECT COUNT(*) FROM auth.social_accounts WHERE user_id=$1`, userID, 1},
		{"auth.password_history", `SELECT COUNT(*) FROM auth.password_history WHERE user_id=$1`, userID, 2},
		{"auth.login_countries", `SELECT COUNT(*) FROM auth.login_countries WHERE user_id=$1`, userID, 2},
		{"auth.totp_secrets", `SELECT COUNT(*) FROM auth.totp_secrets WHERE user_id=$1`, userID, 1},
		{"auth.webauthn_credentials", `SELECT COUNT(*) FROM auth.webauthn_credentials WHERE user_id=$1`, userID, 2},
		{"auth.backup_codes", `SELECT COUNT(*) FROM auth.backup_codes WHERE user_id=$1`, userID, 3},
		{"auth.refresh_tokens", `SELECT COUNT(*) FROM auth.refresh_tokens WHERE user_id=$1`, userID, 2},
	}
	for _, s := range erasableStores {
		if n := gdprCount(t, pool, s.query, s.key); n != s.seeded {
			t.Fatalf("precondition: %s has %d rows, want %d seeded", s.store, n, s.seeded)
		}
	}
	if n := gdprCount(t, pool, `SELECT COUNT(*) FROM audit.audit_log WHERE user_id=$1`, userID); n != 1 {
		t.Fatalf("precondition: audit log has %d rows for user, want 1", n)
	}
	if n := gdprCount(t, pool, `SELECT COUNT(*) FROM auth.account_recovery WHERE pseudonym=$1`, recoveryPseudonym); n != 0 {
		t.Fatalf("precondition: escrow already has %d records", n)
	}

	if err := svc.DeleteAccount(ctx, userID, deletedBy, reason); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	tombstoneEmail := "deleted-" + userID + "@deleted.invalid"

	// GDPR Art. 17(1): erasure of personal data means every user-linked store,
	// not just the account row. Each of the ten cascade targets in
	// ErasureService.DeleteAccount must be empty, by row count.
	t.Run("art_17_1_every_user_linked_store_erased", func(t *testing.T) {
		for _, s := range erasableStores {
			if n := gdprCount(t, pool, s.query, s.key); n != 0 {
				t.Errorf("%s: %d rows survived erasure, want 0", s.store, n)
			}
		}
	})

	// GDPR Art. 17(1): the account row is scrubbed in place, not deleted, so
	// foreign keys stay valid. The tombstone must carry the deleted flag and a
	// synthetic address, and the real address must survive in no table at all.
	t.Run("art_17_1_tombstone_scrubbed_email_nowhere", func(t *testing.T) {
		var gotEmail string
		var gotDisplayName *string
		var gotDeleted bool
		if err := pool.QueryRow(ctx,
			`SELECT email, display_name, deleted FROM auth.users WHERE id=$1`, userID).
			Scan(&gotEmail, &gotDisplayName, &gotDeleted); err != nil {
			t.Fatalf("tombstone row must still exist (referential integrity): %v", err)
		}
		if gotEmail != tombstoneEmail {
			t.Errorf("tombstone email = %q, want %q", gotEmail, tombstoneEmail)
		}
		if gotDisplayName != nil {
			t.Errorf("display_name = %q, want scrubbed to NULL", *gotDisplayName)
		}
		if !gotDeleted {
			t.Error("deleted flag not set on tombstone row")
		}

		// Sweep every text column in the data schemas, discovered from the
		// catalog so a future email-bearing column cannot escape the check.
		rows, err := pool.Query(ctx, `
			SELECT c.table_schema, c.table_name, c.column_name
			FROM information_schema.columns c
			JOIN information_schema.tables t
			  ON t.table_schema = c.table_schema AND t.table_name = c.table_name
			WHERE t.table_type = 'BASE TABLE'
			  AND c.table_schema IN ('auth', 'audit', 'identity', 'objects')
			  AND c.data_type IN ('character varying', 'text')
			ORDER BY c.table_schema, c.table_name, c.column_name`)
		if err != nil {
			t.Fatalf("list text columns: %v", err)
		}
		type textCol struct{ schema, table, column string }
		var cols []textCol
		for rows.Next() {
			var c textCol
			if err := rows.Scan(&c.schema, &c.table, &c.column); err != nil {
				t.Fatalf("scan column row: %v", err)
			}
			cols = append(cols, c)
		}
		rows.Close()
		sawUsersEmail := false
		for _, c := range cols {
			if c.schema == "auth" && c.table == "users" && c.column == "email" {
				sawUsersEmail = true
			}
			q := fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE %s LIKE '%%' || $1 || '%%'`,
				pgx.Identifier{c.schema, c.table}.Sanitize(),
				pgx.Identifier{c.column}.Sanitize())
			if n := gdprCount(t, pool, q, email); n != 0 {
				t.Errorf("erased email found in %s.%s.%s (%d rows)", c.schema, c.table, c.column, n)
			}
		}
		if !sawUsersEmail {
			t.Fatal("column sweep did not include auth.users.email; the sweep is broken")
		}
		// The two non-text stores the sweep cannot reach: JSONB audit metadata
		// and the encrypted escrow payload.
		if n := gdprCount(t, pool,
			`SELECT COUNT(*) FROM audit.audit_log WHERE metadata::text LIKE '%' || $1 || '%'`, email); n != 0 {
			t.Errorf("erased email found in audit metadata (%d rows); only the masked form is allowed", n)
		}
		if n := gdprCount(t, pool,
			`SELECT COUNT(*) FROM auth.account_recovery WHERE position($1 in payload) > 0`, []byte(email)); n != 0 {
			t.Errorf("erased email found in plaintext inside the escrow payload (%d rows)", n)
		}
	})

	// docs/PRIVACY.md 5.3: backup codes are purged, not marked used. The
	// regeneration path (DeleteAllForUser) runs UPDATE ... SET used=true and
	// leaves the hash plus the user id behind; erasure must leave zero rows.
	t.Run("backup_codes_purged_not_marked_used", func(t *testing.T) {
		if n := gdprCount(t, pool, `SELECT COUNT(*) FROM auth.backup_codes WHERE user_id=$1`, userID); n != 0 {
			t.Errorf("auth.backup_codes has %d rows for erased user, want 0 (marked used is not erased)", n)
		}
	})

	// docs/PRIVACY.md 5.3: every step is idempotent so an interrupted erasure is
	// completed by re-running it. The re-run happens here in the parent body, not
	// inside a subtest, so every subtest below (including the audit-exemption
	// one, which counts entries from both runs) passes standalone under -run
	// filtering. The re-run must succeed, leave the counts at zero, keep the
	// tombstone byte-identical, and NOT append a second escrow record: the row
	// already holds the tombstone, and escrowing that would overwrite the only
	// recoverable copy with useless data.
	var beforeEmail string
	var beforeDeleted bool
	var beforeDeletedAt time.Time
	if err := pool.QueryRow(ctx,
		`SELECT email, deleted, deleted_at FROM auth.users WHERE id=$1`, userID).
		Scan(&beforeEmail, &beforeDeleted, &beforeDeletedAt); err != nil {
		t.Fatalf("read tombstone before re-run: %v", err)
	}

	if err := svc.DeleteAccount(ctx, userID, deletedBy, reason); err != nil {
		t.Fatalf("second DeleteAccount must return nil, got: %v", err)
	}

	t.Run("second_erasure_idempotent_tombstone_first", func(t *testing.T) {
		for _, s := range erasableStores {
			if n := gdprCount(t, pool, s.query, s.key); n != 0 {
				t.Errorf("%s: %d rows after re-run, want 0", s.store, n)
			}
		}
		var afterEmail string
		var afterDeleted bool
		var afterDeletedAt time.Time
		if err := pool.QueryRow(ctx,
			`SELECT email, deleted, deleted_at FROM auth.users WHERE id=$1`, userID).
			Scan(&afterEmail, &afterDeleted, &afterDeletedAt); err != nil {
			t.Fatalf("read tombstone after re-run: %v", err)
		}
		if afterEmail != beforeEmail || afterDeleted != beforeDeleted || !afterDeletedAt.Equal(beforeDeletedAt) {
			t.Errorf("tombstone changed on re-run: email %q->%q deleted %v->%v deleted_at %v->%v",
				beforeEmail, afterEmail, beforeDeleted, afterDeleted, beforeDeletedAt, afterDeletedAt)
		}
		if n := gdprCount(t, pool, `SELECT COUNT(*) FROM auth.account_recovery WHERE pseudonym=$1`, recoveryPseudonym); n != 1 {
			t.Errorf("escrow has %d records after re-run, want exactly 1 (re-run must not re-escrow the tombstone)", n)
		}
	})

	// GDPR Art. 17(3)(b)/(e): audit entries are exempt from erasure (legal
	// obligation / defense of legal claims) and bounded by retention instead.
	// Two DeleteAccount runs have happened by this point: the pre-erasure entry
	// plus two account_erased entries must all still be present, and the erased
	// address may appear only in masked form.
	t.Run("art_17_3_audit_entries_exempt_and_masked", func(t *testing.T) {
		if n := gdprCount(t, pool,
			`SELECT COUNT(*) FROM audit.audit_log WHERE user_id=$1 AND event_type=$2`, userID, audit.LoginSuccess); n != 1 {
			t.Errorf("pre-erasure audit entry count = %d, want 1 (audit log must survive erasure)", n)
		}
		if n := gdprCount(t, pool,
			`SELECT COUNT(*) FROM audit.audit_log WHERE user_id=$1`, userID); n != 3 {
			t.Errorf("audit rows for user = %d, want 3 (seeded + one per erasure run)", n)
		}
		if n := gdprCount(t, pool,
			`SELECT COUNT(*) FROM audit.audit_log WHERE user_id=$1 AND event_type=$2`, userID, audit.AccountErased); n != 2 {
			t.Errorf("account_erased entries = %d, want 2", n)
		}
		if n := gdprCount(t, pool,
			`SELECT COUNT(*) FROM audit.audit_log
			 WHERE user_id=$1 AND event_type=$2 AND metadata->>'email'=$3 AND metadata->>'deleted_by'=$4`,
			userID, audit.AccountErased, maskedEmail, deletedBy); n != 1 {
			t.Errorf("account_erased entries with masked email %q = %d, want exactly 1", maskedEmail, n)
		}
		if n := gdprCount(t, pool,
			`SELECT COUNT(*) FROM audit.audit_log
			 WHERE user_id=$1 AND event_type=$2 AND metadata->>'retry'='true'`,
			userID, audit.AccountErased); n != 1 {
			t.Errorf("retry-flagged account_erased entries = %d, want exactly 1 (the re-run)", n)
		}
	})

	// Escrow fail-closed: with a recovery key configured, DeleteAccount writes
	// exactly one encrypted recovery record before it deletes anything, keyed by
	// HMAC(userID + ":recovery") so the plaintext identity never hits the table.
	// Only the offline private key can read it back.
	t.Run("recovery_escrow_written_hmac_keyed", func(t *testing.T) {
		var recordID, pseudonym, gotDeletedBy, gotReason string
		var payload []byte
		if err := pool.QueryRow(ctx,
			`SELECT id::text, pseudonym, payload, deleted_by, reason FROM auth.account_recovery WHERE pseudonym=$1`,
			recoveryPseudonym).Scan(&recordID, &pseudonym, &payload, &gotDeletedBy, &gotReason); err != nil {
			t.Fatalf("escrow record keyed by the service's HMAC pseudonym must exist: %v", err)
		}
		if gotDeletedBy != deletedBy || gotReason != reason {
			t.Errorf("escrow provenance = (%q, %q), want (%q, %q)", gotDeletedBy, gotReason, deletedBy, reason)
		}

		// The binding is rebuilt from the columns as they came BACK out of
		// PostgreSQL, which is the round trip that matters: the record id is
		// written as a Go string and read back through the UUID type, and if
		// those two spellings ever disagreed every escrow record in the database
		// would be unrecoverable.
		binding := vaultcrypto.RecoveryBinding(recordID, pseudonym)
		plaintext, err := vaultcrypto.DecryptRecovery(recoveryKey, payload, binding)
		if err != nil {
			t.Fatalf("escrow payload does not decrypt with the recovery private key: %v", err)
		}
		var rec struct {
			Version     int      `json:"v"`
			UserID      string   `json:"user_id"`
			Email       string   `json:"email"`
			Roles       []string `json:"roles"`
			DisplayName string   `json:"display_name"`
		}
		if err := json.Unmarshal(plaintext, &rec); err != nil {
			t.Fatalf("unmarshal recovery payload: %v", err)
		}
		if rec.Email != email {
			t.Errorf("recovered email = %q, want %q (escrow must hold the REAL address, not the tombstone)", rec.Email, email)
		}
		if rec.DisplayName != displayName {
			t.Errorf("recovered display_name = %q, want %q", rec.DisplayName, displayName)
		}
		if rec.UserID != userID {
			t.Errorf("recovered user_id = %q, want %q: a record that does not name its subject "+
				"cannot be restored, because the row identifies it only by HMAC", rec.UserID, userID)
		}

		// The payload is sealed to THIS row and to no other. A second escrow row
		// exists in this database (the retry case above), and the two must not be
		// interchangeable.
		if _, err := vaultcrypto.DecryptRecovery(recoveryKey, payload,
			vaultcrypto.RecoveryBinding(recordID, pseudonym+"x")); err == nil {
			t.Error("the escrow payload opened under a foreign pseudonym: it can be moved between rows")
		}
		if _, err := vaultcrypto.DecryptRecovery(recoveryKey, payload,
			vaultcrypto.RecoveryBinding("00000000-0000-4000-8000-000000000000", pseudonym)); err == nil {
			t.Error("the escrow payload opened under a foreign record id: it can be moved between rows")
		}
	})
}
