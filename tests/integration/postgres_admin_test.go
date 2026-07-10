package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

// mustListActive returns the repo's active sessions or fails the test.
func mustListActive(t *testing.T, repo *postgres.AdminSessionRepo) []*model.AdminSession {
	t.Helper()
	active, err := repo.ListActive(context.Background())
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}
	return active
}

// makeAdmin builds an admin user with the given username. role must be a seeded
// auth.admin_roles value (viewer/operator/super_admin).
func makeAdmin(username, role string) *model.AdminUser {
	return &model.AdminUser{
		ID:           randomID(),
		Username:     username,
		PasswordHash: "$argon2id$v=19$m=47104,t=1,p=1$dGVzdHNhbHQ$testhash",
		Role:         role,
	}
}

// TestPostgresAdminUserRepo exercises the admin-gateway user repo, including the
// lockout counters and the lock/revoke lifecycle.
func TestPostgresAdminUserRepo(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	repo := postgres.NewAdminUserRepo(db)
	ctx := context.Background()

	admin := makeAdmin("root", "super_admin")
	if err := repo.Create(ctx, admin); err != nil {
		t.Fatalf("Create: %v", err)
	}

	t.Run("GetByID and GetByUsername", func(t *testing.T) {
		byID, err := repo.GetByID(ctx, admin.ID)
		if err != nil || byID == nil || byID.Username != "root" {
			t.Fatalf("GetByID = %+v, err=%v", byID, err)
		}
		byName, err := repo.GetByUsername(ctx, "root")
		if err != nil || byName == nil || byName.ID != admin.ID {
			t.Fatalf("GetByUsername = %+v, err=%v", byName, err)
		}
	})

	t.Run("GetByID absent returns nil", func(t *testing.T) {
		got, err := repo.GetByID(ctx, randomID())
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got != nil {
			t.Fatalf("GetByID(absent) = %+v, want nil", got)
		}
	})

	t.Run("Count and List", func(t *testing.T) {
		if err := repo.Create(ctx, makeAdmin("viewer1", "viewer")); err != nil {
			t.Fatalf("Create viewer1: %v", err)
		}
		n, err := repo.Count(ctx)
		if err != nil || n != 2 {
			t.Fatalf("Count = %d, err=%v, want 2", n, err)
		}
		list, err := repo.List(ctx)
		if err != nil || len(list) != 2 {
			t.Fatalf("List = %d rows, err=%v, want 2", len(list), err)
		}
	})

	t.Run("failed-login counter increments and resets", func(t *testing.T) {
		n1, err := repo.IncrementFailedLogin(ctx, admin.ID)
		if err != nil {
			t.Fatalf("IncrementFailedLogin: %v", err)
		}
		n2, err := repo.IncrementFailedLogin(ctx, admin.ID)
		if err != nil {
			t.Fatalf("IncrementFailedLogin: %v", err)
		}
		if n2 != n1+1 {
			t.Fatalf("counter did not advance: %d -> %d", n1, n2)
		}
		if err := repo.ResetFailedLogin(ctx, admin.ID); err != nil {
			t.Fatalf("ResetFailedLogin: %v", err)
		}
		got, _ := repo.GetByID(ctx, admin.ID)
		if got.FailedLoginCount != 0 {
			t.Fatalf("FailedLoginCount = %d after reset, want 0", got.FailedLoginCount)
		}
	})

	t.Run("LockUntil is observable", func(t *testing.T) {
		until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
		if err := repo.LockUntil(ctx, admin.ID, until); err != nil {
			t.Fatalf("LockUntil: %v", err)
		}
		got, _ := repo.GetByID(ctx, admin.ID)
		if got.LockedUntil == nil || got.LockedUntil.Before(time.Now()) {
			t.Fatalf("LockedUntil = %v, want a future time", got.LockedUntil)
		}
	})

	t.Run("TOTP counter and last-login updates", func(t *testing.T) {
		if err := repo.UpdateLastTOTPCounter(ctx, admin.ID, 42); err != nil {
			t.Fatalf("UpdateLastTOTPCounter: %v", err)
		}
		if err := repo.UpdateLastLogin(ctx, admin.ID); err != nil {
			t.Fatalf("UpdateLastLogin: %v", err)
		}
		got, _ := repo.GetByID(ctx, admin.ID)
		if got.LastTOTPCounter != 42 {
			t.Fatalf("LastTOTPCounter = %d, want 42", got.LastTOTPCounter)
		}
		if got.LastLoginAt == nil {
			t.Fatal("LastLoginAt not set")
		}
	})

	t.Run("Update mutates role and totp", func(t *testing.T) {
		admin.Role = "operator"
		admin.TOTPVerified = true
		admin.TOTPSecretEnc = "enc-secret"
		if err := repo.Update(ctx, admin); err != nil {
			t.Fatalf("Update: %v", err)
		}
		got, _ := repo.GetByID(ctx, admin.ID)
		if got.Role != "operator" || !got.TOTPVerified {
			t.Fatalf("Update not persisted: %+v", got)
		}
	})

	t.Run("Revoke removes the admin", func(t *testing.T) {
		target := makeAdmin("doomed", "viewer")
		if err := repo.Create(ctx, target); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := repo.Revoke(ctx, target.ID); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if got, _ := repo.GetByID(ctx, target.ID); got != nil {
			t.Fatal("admin still present after Revoke")
		}
	})
}

// TestPostgresAdminSessionRepo exercises the admin session repo lifecycle.
func TestPostgresAdminSessionRepo(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	adminRepo := postgres.NewAdminUserRepo(db)
	repo := postgres.NewAdminSessionRepo(db)
	ctx := context.Background()

	admin := makeAdmin("sess-owner", "operator")
	if err := adminRepo.Create(ctx, admin); err != nil {
		t.Fatalf("Create admin: %v", err)
	}

	mkSession := func(hash string, expires time.Time) *model.AdminSession {
		return &model.AdminSession{
			ID: randomID(), AdminID: admin.ID, TokenHash: hash,
			IP: "203.0.113.7", UserAgent: "test-agent", ExpiresAt: expires,
		}
	}

	t.Run("Create then GetByTokenHash", func(t *testing.T) {
		s := mkSession("hash-1", time.Now().Add(time.Hour))
		if err := repo.Create(ctx, s); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.GetByTokenHash(ctx, "hash-1")
		if err != nil || got == nil || got.AdminID != admin.ID {
			t.Fatalf("GetByTokenHash = %+v, err=%v", got, err)
		}
	})

	t.Run("GetByTokenHash returns the raw row; expiry is a caller check", func(t *testing.T) {
		// The repo is a thin lookup: it returns the row regardless of expiry, and
		// the admin middleware enforces ExpiresAt/Revoked. Assert that contract so
		// the two layers stay in sync.
		exp := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
		if err := repo.Create(ctx, mkSession("hash-expired", exp)); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.GetByTokenHash(ctx, "hash-expired")
		if err != nil {
			t.Fatalf("GetByTokenHash: %v", err)
		}
		if got == nil {
			t.Fatal("GetByTokenHash dropped an expired row; middleware relies on it to check ExpiresAt")
		}
		if !time.Now().After(got.ExpiresAt) {
			t.Fatalf("ExpiresAt = %v, want it in the past so the caller rejects it", got.ExpiresAt)
		}
	})

	t.Run("unknown hash returns nil", func(t *testing.T) {
		got, err := repo.GetByTokenHash(ctx, "no-such-hash")
		if err != nil {
			t.Fatalf("GetByTokenHash: %v", err)
		}
		if got != nil {
			t.Fatalf("GetByTokenHash(unknown) = %+v, want nil", got)
		}
	})

	t.Run("ListByAdmin and ListActive", func(t *testing.T) {
		if err := repo.Create(ctx, mkSession("hash-2", time.Now().Add(time.Hour))); err != nil {
			t.Fatalf("Create: %v", err)
		}
		byAdmin, err := repo.ListByAdmin(ctx, admin.ID)
		if err != nil {
			t.Fatalf("ListByAdmin: %v", err)
		}
		if len(byAdmin) < 2 {
			t.Fatalf("ListByAdmin = %d, want >= 2", len(byAdmin))
		}
		active, err := repo.ListActive(ctx)
		if err != nil {
			t.Fatalf("ListActive: %v", err)
		}
		if len(active) < 2 {
			t.Fatalf("ListActive = %d, want >= 2", len(active))
		}
	})

	t.Run("Revoke flips the revoked flag and drops it from ListActive", func(t *testing.T) {
		if err := repo.Create(ctx, mkSession("hash-revoke", time.Now().Add(time.Hour))); err != nil {
			t.Fatalf("Create: %v", err)
		}
		s, _ := repo.GetByTokenHash(ctx, "hash-revoke")
		if err := repo.Revoke(ctx, s.ID); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		got, _ := repo.GetByTokenHash(ctx, "hash-revoke")
		if got == nil || !got.Revoked {
			t.Fatalf("Revoke did not set revoked=true (got %+v)", got)
		}
		for _, a := range mustListActive(t, repo) {
			if a.ID == s.ID {
				t.Fatal("revoked session still appears in ListActive")
			}
		}
	})

	t.Run("RevokeAllForAdmin", func(t *testing.T) {
		if err := repo.RevokeAllForAdmin(ctx, admin.ID); err != nil {
			t.Fatalf("RevokeAllForAdmin: %v", err)
		}
		for _, s := range mustListActive(t, repo) {
			if s.AdminID == admin.ID {
				t.Fatal("admin still has an active session after RevokeAllForAdmin")
			}
		}
	})

	t.Run("DeleteExpired reaps stale rows", func(t *testing.T) {
		if err := repo.Create(ctx, mkSession("hash-stale", time.Now().Add(-2*time.Hour))); err != nil {
			t.Fatalf("Create: %v", err)
		}
		n, err := repo.DeleteExpired(ctx)
		if err != nil {
			t.Fatalf("DeleteExpired: %v", err)
		}
		if n < 1 {
			t.Fatalf("DeleteExpired removed %d rows, want >= 1", n)
		}
	})
}
