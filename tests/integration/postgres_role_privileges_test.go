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
func TestErasureUnderVaultAppRole(t *testing.T) {
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
}
