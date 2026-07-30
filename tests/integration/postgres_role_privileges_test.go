package integration_test

import (
	"context"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

// applyRealGrants re-applies the migrations' GRANT/REVOKE statements, which the
// shared fixture deliberately strips.
//
// setupPostgres runs every migration through stripRoleGrants(), which deletes
// every GRANT/REVOKE line — so the whole integration suite runs as the container
// owner with the privilege model removed. That is precisely why a live bug went
// unseen: SoftDeleteScrub writes auth.users.email, vault_app was never granted
// UPDATE on that column, and Postgres rejects the entire statement if a single
// target column is denied. Account erasure failed with 42501 on every request in
// a real deployment while the suite stayed green.
//
// This test therefore re-applies the grants verbatim and connects as the real
// role, so the privileges the server actually runs under are exercised.
func applyRealGrants(t *testing.T, adminPool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()

	entries, err := os.ReadDir("../../migrations")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	for _, f := range files {
		raw, err := os.ReadFile("../../migrations/" + f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, stmt := range strings.Split(string(raw), ";") {
			// A statement carries the comment lines that preceded it, so strip them
			// before deciding what it is — otherwise every grant introduced by a
			// comment (which, in these migrations, is most of them) is skipped and
			// the test silently proves nothing.
			var body []string
			for _, line := range strings.Split(stmt, "\n") {
				l := strings.TrimSpace(line)
				if l == "" || strings.HasPrefix(l, "--") {
					continue
				}
				body = append(body, l)
			}
			s := strings.Join(body, " ")
			up := strings.ToUpper(s)
			if !strings.HasPrefix(up, "GRANT ") && !strings.HasPrefix(up, "REVOKE ") {
				continue
			}
			if _, err := adminPool.Exec(ctx, s); err != nil {
				t.Fatalf("apply grant from %s (%.60s): %v", f, s, err)
			}
		}
	}
}

// appRolePool opens a pool authenticated as the real vault_app role.
func appRolePool(t *testing.T, adminPool *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	// Migration 001 creates the role with LOGIN but no password; the container
	// requires one to authenticate over TCP.
	if _, err := adminPool.Exec(ctx, `ALTER ROLE vault_app WITH PASSWORD 'vault_app_test'`); err != nil {
		t.Fatalf("set vault_app password: %v", err)
	}

	cfg := adminPool.Config().ConnConfig
	dsn := (&url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword("vault_app", "vault_app_test"),
		Host:     cfg.Host + ":" + strconv.Itoa(int(cfg.Port)),
		Path:     "/" + cfg.Database,
		RawQuery: "sslmode=disable",
	}).String()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect as vault_app: %v", err)
	}
	t.Cleanup(pool.Close)

	var who string
	if err := pool.QueryRow(ctx, `SELECT current_user`).Scan(&who); err != nil {
		t.Fatalf("verify role: %v", err)
	}
	if who != "vault_app" {
		t.Fatalf("connected as %q, want vault_app — the test would prove nothing", who)
	}
	return pool
}

// The account-erasure cascade must run under the privileges the server actually
// has. This is the test that would have caught the missing UPDATE(email) grant.
// One container for the whole privilege sweep: setupPostgres stands up a fresh
// Postgres per test function and the suite already spins ~40 of them, so these
// share a single database rather than adding three more.
func TestVaultAppRolePrivileges(t *testing.T) {
	adminPool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	applyRealGrants(t, adminPool)
	appPool := appRolePool(t, adminPool)
	db := &postgres.DB{Pool: appPool}

	// Seed the user as the owner; creation is not what is under test here.
	seedRepo := postgres.NewUserRepo(&postgres.DB{Pool: adminPool})
	user := makeUser("role-erasure@test.com")
	if err := seedRepo.Create(ctx, user); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// Everything below runs as vault_app.
	t.Run("SoftDeleteScrub is permitted", func(t *testing.T) {
		repo := postgres.NewUserRepo(db)
		tombstone := "deleted-" + user.ID + "@deleted.invalid"
		if err := repo.SoftDeleteScrub(ctx, user.ID, tombstone); err != nil {
			if strings.Contains(err.Error(), "42501") || strings.Contains(err.Error(), "permission denied") {
				t.Fatalf("vault_app cannot tombstone a user — account erasure is dead in production: %v", err)
			}
			t.Fatalf("SoftDeleteScrub: %v", err)
		}

		got, err := seedRepo.GetByID(ctx, user.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if !got.Deleted || got.Email != tombstone {
			t.Errorf("row not tombstoned: deleted=%v email=%q", got.Deleted, got.Email)
		}
	})

	t.Run("the PII cascade is permitted", func(t *testing.T) {
		now := time.Now().UTC()

		devices := postgres.NewDeviceRepo(db)
		if err := devices.Create(ctx, &model.Device{
			ID: randomID(), UserID: user.ID, FingerprintHash: randomID(),
			FriendlyName: "d", IP: "203.0.113.9", UserAgent: "ua",
			FirstSeenAt: now, CreatedAt: now,
		}); err != nil {
			t.Fatalf("create device: %v", err)
		}
		backups := postgres.NewBackupCodeRepo(db)
		if err := backups.CreateBatch(ctx, []*model.BackupCode{
			{ID: randomID(), UserID: user.ID, CodeHash: "$argon2id$x", CreatedAt: now},
		}); err != nil {
			t.Fatalf("create backup code: %v", err)
		}

		for name, fn := range map[string]func() error{
			"devices":     func() error { return devices.DeleteAllForUser(ctx, user.ID) },
			"backupCodes": func() error { return backups.PurgeAllForUser(ctx, user.ID) },
			"webauthn":    func() error { return postgres.NewWebAuthnRepo(db).DeleteAllForUser(ctx, user.ID) },
			"totp":        func() error { return postgres.NewTOTPRepo(db).DeleteByUserID(ctx, user.ID) },
			"tokens":      func() error { return postgres.NewRefreshTokenRepo(db).DeleteAllForUser(ctx, user.ID) },
			"social":      func() error { return postgres.NewSocialAccountRepo(db).DeleteAllForUser(ctx, user.ID) },
			"pwHistory":   func() error { return postgres.NewPasswordHistoryRepo(db).DeleteAllForUser(ctx, user.ID) },
		} {
			if err := fn(); err != nil {
				t.Errorf("vault_app cannot erase %s: %v", name, err)
			}
		}
	})
	t.Run("every write path the server takes", func(t *testing.T) {
		writePathsUnderVaultApp(t, adminPool)
	})

	t.Run("the pseudonym-keyed stores", func(t *testing.T) {
		pseudonymStoresUnderVaultApp(t, adminPool)
	})

}

// writePathsUnderVaultApp: every write path the running server takes, executed as
// the real vault_app role with the real grants.
//
// This is the generalisation of the erasure bug: a missing grant is invisible to
// the rest of the suite (superuser + stripRoleGrants), so ANY statement whose
// target column or table was never granted fails only in production. Postgres
// checks column privileges per statement, so adding one column to an existing
// UPDATE is enough to break it — which is exactly how account erasure died.
//
// A failure here is not a test problem: it means that operation is broken in
// every deployment.
func writePathsUnderVaultApp(t *testing.T, adminPool *pgxpool.Pool) {
	ctx := context.Background()
	db := &postgres.DB{Pool: appRolePool(t, adminPool)}

	users := postgres.NewUserRepo(db)
	user := makeUser("role-writes@test.com")
	if err := users.Create(ctx, user); err != nil {
		t.Fatalf("vault_app cannot create a user: %v", err)
	}

	now := time.Now().UTC()
	deviceID, tokenID, socialID, credID := randomID(), randomID(), randomID(), randomID()

	devices := postgres.NewDeviceRepo(db)
	tokens := postgres.NewRefreshTokenRepo(db)
	totp := postgres.NewTOTPRepo(db)
	webauthn := postgres.NewWebAuthnRepo(db)
	backups := postgres.NewBackupCodeRepo(db)
	pwHistory := postgres.NewPasswordHistoryRepo(db)
	social := postgres.NewSocialAccountRepo(db)

	// Seeded rows the mutating calls below operate on.
	if err := devices.Create(ctx, &model.Device{
		ID: deviceID, UserID: user.ID, FingerprintHash: randomID(),
		FriendlyName: "dev", IP: "203.0.113.4", UserAgent: "ua",
		FirstSeenAt: now, CreatedAt: now,
	}); err != nil {
		t.Fatalf("create device: %v", err)
	}
	if err := tokens.Create(ctx, &model.RefreshToken{
		ID: tokenID, UserID: user.ID, TokenHash: randomID(),
		FamilyID: randomID(), FingerprintHash: randomID(),
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	if err := totp.Create(ctx, &model.TOTPSecret{
		ID: randomID(), UserID: user.ID, SecretEnc: "enc", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create totp: %v", err)
	}
	if err := webauthn.Create(ctx, &model.WebAuthnCredential{
		ID: credID, UserID: user.ID, CredentialID: []byte(randomID()),
		PublicKey: []byte("pk"), FriendlyName: "key", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create webauthn credential: %v", err)
	}
	if err := backups.CreateBatch(ctx, []*model.BackupCode{
		{ID: randomID(), UserID: user.ID, CodeHash: "$argon2id$h", CreatedAt: now},
	}); err != nil {
		t.Fatalf("create backup codes: %v", err)
	}
	if err := pwHistory.Create(ctx, &model.PasswordHistory{
		ID: randomID(), UserID: user.ID, PasswordHash: "$argon2id$h", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create password history: %v", err)
	}
	if err := social.Create(ctx, &model.SocialAccount{
		ID: socialID, UserID: user.ID, Provider: "github",
		ProviderUserID: "gh-1", Email: "role-writes@test.com", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create social account: %v", err)
	}

	// Each of these is a statement whose column/table privileges must be granted.
	writes := []struct {
		name string
		fn   func() error
	}{
		{"users.Update", func() error {
			user.DisplayName = "renamed"
			return users.Update(ctx, user)
		}},
		{"users.UpdatePassword", func() error { return users.UpdatePassword(ctx, user.ID, "$argon2id$new") }},
		{"users.IncrementFailedLogin", func() error { return users.IncrementFailedLogin(ctx, user.ID) }},
		{"users.ResetFailedLogin", func() error { return users.ResetFailedLogin(ctx, user.ID) }},
		{"users.LockUntil", func() error { return users.LockUntil(ctx, user.ID, now.Add(time.Minute)) }},
		{"users.Unlock", func() error { return users.Unlock(ctx, user.ID) }},
		{"users.VerifyEmail", func() error { return users.VerifyEmail(ctx, user.ID) }},
		{"users.SetLastLogin", func() error { return users.SetLastLogin(ctx, user.ID) }},

		{"devices.UpdateLastSeen", func() error { return devices.UpdateLastSeen(ctx, deviceID, "203.0.113.5") }},
		{"devices.UpdateFriendlyName", func() error { return devices.UpdateFriendlyName(ctx, deviceID, "laptop") }},
		{"devices.Trust", func() error { return devices.Trust(ctx, deviceID, now.Add(time.Hour)) }},

		{"tokens.MarkUsed", func() error { _, err := tokens.MarkUsed(ctx, tokenID); return err }},
		{"tokens.RevokeByID", func() error { return tokens.RevokeByID(ctx, tokenID) }},
		{"tokens.RevokeByDeviceID", func() error { return tokens.RevokeByDeviceID(ctx, deviceID) }},
		{"tokens.RevokeAllForUser", func() error { return tokens.RevokeAllForUser(ctx, user.ID) }},
		{"tokens.DeleteExpired", func() error { _, err := tokens.DeleteExpired(ctx); return err }},

		{"webauthn.UpdateSignCount", func() error { return webauthn.UpdateSignCount(ctx, credID, 7) }},
		{"webauthn.UpdateFlags", func() error { return webauthn.UpdateFlags(ctx, credID, 0x1d) }},
		{"webauthn.Delete", func() error { return webauthn.Delete(ctx, credID, user.ID) }},

		{"backups.DeleteAllForUser", func() error { return backups.DeleteAllForUser(ctx, user.ID) }},
		{"backups.PurgeAllForUser", func() error { return backups.PurgeAllForUser(ctx, user.ID) }},

		{"social.Delete", func() error { return social.Delete(ctx, socialID, user.ID) }},
		{"devices.Delete", func() error { return devices.Delete(ctx, deviceID, user.ID) }},
		{"totp.DeleteByUserID", func() error { return totp.DeleteByUserID(ctx, user.ID) }},
		{"pwHistory.DeleteAllForUser", func() error { return pwHistory.DeleteAllForUser(ctx, user.ID) }},

		// The erasure tail, in the order DeleteAccount runs it.
		{"users.SoftDeleteScrub", func() error {
			return users.SoftDeleteScrub(ctx, user.ID, "deleted-"+user.ID+"@deleted.invalid")
		}},
		{"tokens.DeleteAllForUser", func() error { return tokens.DeleteAllForUser(ctx, user.ID) }},
		{"devices.DeleteAllForUser", func() error { return devices.DeleteAllForUser(ctx, user.ID) }},
		{"social.DeleteAllForUser", func() error { return social.DeleteAllForUser(ctx, user.ID) }},
		{"webauthn.DeleteAllForUser", func() error { return webauthn.DeleteAllForUser(ctx, user.ID) }},
	}

	for _, w := range writes {
		if err := w.fn(); err != nil {
			t.Errorf("vault_app cannot run %s — broken in every deployment: %v", w.name, err)
		}
	}
}

// pseudonymStoresUnderVaultApp: the pseudonym-keyed stores, likewise under the real role.
func pseudonymStoresUnderVaultApp(t *testing.T, adminPool *pgxpool.Pool) {
	ctx := context.Background()
	db := &postgres.DB{Pool: appRolePool(t, adminPool)}

	identity := postgres.NewIdentityRepo(db)
	blobs := postgres.NewBlobRepo(db)
	pseudo := randomID()
	now := time.Now().UTC()

	profile := &model.IdentityProfile{
		PseudonymID: pseudo, DataEnc: []byte("ciphertext"), Version: 1,
		UpdatedAt: now, CreatedAt: now,
	}
	if err := identity.Upsert(ctx, profile); err != nil {
		t.Fatalf("vault_app cannot upsert an identity profile: %v", err)
	}

	// The compare-and-set path the consent writes depend on.
	stored, err := identity.GetByPseudonym(ctx, pseudo)
	if err != nil {
		t.Fatalf("GetByPseudonym: %v", err)
	}
	ok, err := identity.UpsertCAS(ctx, &model.IdentityProfile{
		PseudonymID: pseudo, DataEnc: []byte("ciphertext-2"), Version: 1,
		UpdatedAt: now.Add(time.Second), CreatedAt: now,
	}, stored.UpdatedAt)
	if err != nil {
		t.Fatalf("vault_app cannot compare-and-set an identity profile: %v", err)
	}
	if !ok {
		t.Error("CAS should have won against the row it just read")
	}

	blobID := randomID()
	if err := blobs.Create(ctx, &model.Blob{
		ID: blobID, PseudonymID: pseudo, DataEnc: []byte("blob"), SizeBytes: 4,
		RefHash: randomID(), CreatedAt: now,
	}); err != nil {
		t.Fatalf("vault_app cannot create a blob: %v", err)
	}
	if err := blobs.Delete(ctx, blobID, pseudo); err != nil {
		t.Errorf("vault_app cannot delete a blob: %v", err)
	}
	if err := blobs.DeleteAllForPseudonym(ctx, pseudo); err != nil {
		t.Errorf("vault_app cannot erase blobs: %v", err)
	}
	if err := identity.Delete(ctx, pseudo); err != nil {
		t.Errorf("vault_app cannot erase an identity profile: %v", err)
	}
}
