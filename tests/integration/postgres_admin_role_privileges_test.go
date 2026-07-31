package integration_test

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

// adminRolePool opens a pool authenticated as the real vault_admin role, the
// counterpart of appRolePool for the admin gateway.
func adminRolePool(t *testing.T, adminPool *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	if _, err := adminPool.Exec(ctx, `ALTER ROLE vault_admin WITH PASSWORD 'vault_admin_test'`); err != nil {
		t.Fatalf("set vault_admin password: %v", err)
	}

	cfg := adminPool.Config().ConnConfig
	dsn := (&url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword("vault_admin", "vault_admin_test"),
		Host:     cfg.Host + ":" + strconv.Itoa(int(cfg.Port)),
		Path:     "/" + cfg.Database,
		RawQuery: "sslmode=disable",
	}).String()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect as vault_admin: %v", err)
	}
	t.Cleanup(pool.Close)

	var who string
	if err := pool.QueryRow(ctx, `SELECT current_user`).Scan(&who); err != nil {
		t.Fatalf("verify role: %v", err)
	}
	if who != "vault_admin" {
		t.Fatalf("connected as %q, want vault_admin: the test would prove nothing", who)
	}
	return pool
}

// The admin gateway's write paths under the privileges it actually has.
//
// cmd/admin-gateway connects as vault_admin, and every table added after 001 has
// to be granted to that role explicitly. Four endpoints shipped against tables it
// had no privilege on, and the rest of the suite cannot see it: setupPostgres
// connects as the container owner and stripRoleGrants() removes every GRANT and
// REVOKE before the migrations are applied. A failure here means the endpoint is
// broken in every deployment, exactly as account erasure was.
func TestVaultAdminRolePrivileges(t *testing.T) {
	adminPool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	applyRealGrants(t, adminPool)
	gatewayPool := adminRolePool(t, adminPool)
	db := &postgres.DB{Pool: gatewayPool}
	ownerDB := &postgres.DB{Pool: adminPool}

	t.Run("the custom roles catalog", func(t *testing.T) {
		roles := postgres.NewAppRoleRepo(db)
		if _, err := roles.List(ctx); err != nil {
			t.Fatalf("GET /admin/roles is broken in every deployment: %v", err)
		}
		if _, err := roles.ListNames(ctx); err != nil {
			t.Fatalf("ListNames: %v", err)
		}
		created := &model.AppRole{Name: "gateway_probe", Namespace: "app", Description: "probe"}
		if err := roles.Create(ctx, created); err != nil {
			t.Fatalf("POST /admin/roles is broken in every deployment: %v", err)
		}
		got, err := roles.Get(ctx, created.Name)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got == nil {
			t.Fatal("the role the gateway just created is not readable back")
		}
		if err := roles.Delete(ctx, created.Name); err != nil {
			t.Fatalf("DELETE /admin/roles/{name} is broken in every deployment: %v", err)
		}
	})

	t.Run("user import", func(t *testing.T) {
		users := postgres.NewUserRepo(db)
		imported := makeUser("gateway-import@test.com")
		imported.Roles = []string{"viewer"}
		if err := users.CreateImported(ctx, imported); err != nil {
			t.Fatalf("POST /admin/users/import is broken in every deployment: %v", err)
		}
		got, err := users.GetByID(ctx, imported.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got == nil {
			t.Fatal("the imported user was not written")
		}
	})

	t.Run("admin config delete", func(t *testing.T) {
		cfg := postgres.NewAdminConfigRepo(db)
		if err := cfg.Set(ctx, "gateway_probe_key", "v"); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if err := cfg.Delete(ctx, "gateway_probe_key"); err != nil {
			t.Fatalf("DELETE /admin/config/{key} is broken in every deployment: %v", err)
		}
	})

	// DELETE /admin/users/{id}. 009 granted DELETE on the cascade tables, which is
	// not enough: each repository issues `DELETE ... WHERE user_id = $1`, and
	// PostgreSQL requires SELECT on every column read in the condition. The
	// tombstone runs first, so a denial here leaves a dead account whose MFA
	// material was never removed.
	t.Run("the erasure cascade", func(t *testing.T) {
		user := makeUser("gateway-erasure@test.com")
		if err := postgres.NewUserRepo(ownerDB).Create(ctx, user); err != nil {
			t.Fatalf("seed user: %v", err)
		}
		now := time.Now().UTC()
		seed := &postgres.DB{Pool: adminPool}
		if err := postgres.NewDeviceRepo(seed).Create(ctx, &model.Device{
			ID: randomID(), UserID: user.ID, FingerprintHash: randomID(),
			FriendlyName: "d", IP: "203.0.113.11", UserAgent: "ua",
			FirstSeenAt: now, CreatedAt: now,
		}); err != nil {
			t.Fatalf("seed device: %v", err)
		}
		if err := postgres.NewSocialAccountRepo(seed).Create(ctx, &model.SocialAccount{
			ID: randomID(), UserID: user.ID, Provider: "github",
			ProviderUserID: "gw-1", Email: user.Email, CreatedAt: now,
		}); err != nil {
			t.Fatalf("seed social account: %v", err)
		}
		if err := postgres.NewPasswordHistoryRepo(seed).Create(ctx, &model.PasswordHistory{
			ID: randomID(), UserID: user.ID, PasswordHash: "$argon2id$h", CreatedAt: now,
		}); err != nil {
			t.Fatalf("seed password history: %v", err)
		}
		if err := postgres.NewTOTPRepo(seed).Create(ctx, &model.TOTPSecret{
			ID: randomID(), UserID: user.ID, SecretEnc: "enc", CreatedAt: now,
		}); err != nil {
			t.Fatalf("seed totp: %v", err)
		}
		if err := postgres.NewWebAuthnRepo(seed).Create(ctx, &model.WebAuthnCredential{
			ID: randomID(), UserID: user.ID, CredentialID: []byte(randomID()),
			PublicKey: []byte("pk"), FriendlyName: "key", CreatedAt: now,
		}); err != nil {
			t.Fatalf("seed webauthn credential: %v", err)
		}
		if err := postgres.NewBackupCodeRepo(seed).CreateBatch(ctx, []*model.BackupCode{
			{ID: randomID(), UserID: user.ID, CodeHash: "$argon2id$h", CreatedAt: now},
		}); err != nil {
			t.Fatalf("seed backup codes: %v", err)
		}

		steps := []struct {
			name string
			fn   func() error
		}{
			{"users.SoftDeleteScrub", func() error {
				return postgres.NewUserRepo(db).SoftDeleteScrub(ctx, user.ID, "deleted-"+user.ID+"@deleted.invalid")
			}},
			{"devices", func() error { return postgres.NewDeviceRepo(db).DeleteAllForUser(ctx, user.ID) }},
			{"social", func() error { return postgres.NewSocialAccountRepo(db).DeleteAllForUser(ctx, user.ID) }},
			{"pwHistory", func() error { return postgres.NewPasswordHistoryRepo(db).DeleteAllForUser(ctx, user.ID) }},
			{"totp", func() error { return postgres.NewTOTPRepo(db).DeleteByUserID(ctx, user.ID) }},
			{"webauthn", func() error { return postgres.NewWebAuthnRepo(db).DeleteAllForUser(ctx, user.ID) }},
			{"backupCodes", func() error { return postgres.NewBackupCodeRepo(db).PurgeAllForUser(ctx, user.ID) }},
			{"tokens", func() error { return postgres.NewRefreshTokenRepo(db).DeleteAllForUser(ctx, user.ID) }},
		}
		for _, s := range steps {
			if err := s.fn(); err != nil {
				t.Errorf("vault_admin cannot erase %s, so admin erasure dies mid-cascade: %v", s.name, err)
			}
		}
	})

	// Widening the role to make erasure work must not turn it into a reader of the
	// secrets it is allowed to destroy: the grants above are column-level on
	// user_id for exactly that reason.
	t.Run("it still cannot read the secrets it may delete", func(t *testing.T) {
		for _, q := range []string{
			`SELECT secret_enc FROM auth.totp_secrets LIMIT 1`,
			`SELECT code_hash FROM auth.backup_codes LIMIT 1`,
			`SELECT password_hash FROM auth.password_history LIMIT 1`,
			`SELECT public_key FROM auth.webauthn_credentials LIMIT 1`,
			`SELECT access_token_enc FROM auth.social_accounts LIMIT 1`,
		} {
			if _, err := gatewayPool.Exec(ctx, q); err == nil {
				t.Errorf("vault_admin can read %q: the cascade grants leaked more than DELETE", q)
			}
		}
	})

	t.Run("it still cannot rewrite the audit log", func(t *testing.T) {
		if _, err := gatewayPool.Exec(ctx, `DELETE FROM audit.audit_log`); err == nil {
			t.Error("vault_admin deleted audit rows: the log is not append-only")
		}
		if _, err := gatewayPool.Exec(ctx, `UPDATE audit.audit_log SET ip = '203.0.113.0'`); err == nil {
			t.Error("vault_admin rewrote audit rows: the log is not append-only")
		}
	})
}

// permissionDenied reports whether err is PostgreSQL's insufficient_privilege.
func permissionDenied(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "42501") || strings.Contains(err.Error(), "permission denied"))
}
