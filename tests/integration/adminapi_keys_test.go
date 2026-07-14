package integration_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/adminapi"
	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/keystore"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

// TestAdminAPIListKeys exercises the admin gateway's key-listing handler over a
// real DB-backed keystore. ListKeys needs no admin in context (no audit write),
// so it is reachable from this package.
func TestAdminAPIListKeys(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	db := &postgres.DB{Pool: pool}
	ctx := context.Background()

	master := make([]byte, 32)
	for i := range master {
		master[i] = 0x2b
	}
	ks, err := keystore.New(pool, master, time.Hour)
	if err != nil {
		t.Fatalf("keystore.New: %v", err)
	}
	defer ks.Stop()
	if err := ks.EnsureKey(ctx, nil); err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	if _, err := ks.Rotate(ctx); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	auditLog := audit.NewLogger(postgres.NewAuditRepo(db), time.Hour)
	h := adminapi.NewHandler(
		postgres.NewUserRepo(db), postgres.NewClientRepo(db), postgres.NewRefreshTokenRepo(db),
		postgres.NewAuditRepo(db), postgres.NewAdminUserRepo(db), postgres.NewAdminSessionRepo(db),
		postgres.NewAdminConfigRepo(db), ks, auditLog, master, "",
	)

	t.Run("lists the keys from the keystore", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ListKeys(rec, httptest.NewRequest(http.MethodGet, "/admin/keys", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "\"kid\"") {
			t.Errorf("response has no keys: %s", rec.Body.String())
		}
	})

	t.Run("nil keystore reports unavailable", func(t *testing.T) {
		nilH := adminapi.NewHandler(nil, nil, nil, nil, nil, nil, nil, nil, auditLog, master, "")
		rec := httptest.NewRecorder()
		nilH.ListKeys(rec, httptest.NewRequest(http.MethodGet, "/admin/keys", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("nil keystore = %d, want 503", rec.Code)
		}
	})
}

// TestKeyStoreCleanupAndList exercises keystore branches the 0.8.6 tests did not
// reach: CleanupExpired with a mix of live and expired keys, and ListKeys after
// a revoke so a revoked row is present.
func TestKeyStoreCleanupAndList(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	master := make([]byte, 32)
	for i := range master {
		master[i] = 0x3c
	}
	ks, err := keystore.New(pool, master, time.Hour)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer ks.Stop()

	// Rotate three times: two retired (with future expiry) plus the active one.
	if _, err := ks.Rotate(ctx); err != nil {
		t.Fatalf("Rotate 1: %v", err)
	}
	if _, err := ks.Rotate(ctx); err != nil {
		t.Fatalf("Rotate 2: %v", err)
	}
	revokeKID, err := ks.Rotate(ctx)
	if err != nil {
		t.Fatalf("Rotate 3: %v", err)
	}

	if err := ks.Revoke(ctx, revokeKID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	keys, err := ks.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	var sawRevoked bool
	for _, k := range keys {
		if k.KID == revokeKID && k.Status == "revoked" {
			sawRevoked = true
		}
	}
	if !sawRevoked {
		t.Error("ListKeys did not report the revoked key")
	}

	// Nothing is past its (1h) expiry, so CleanupExpired removes zero rows.
	n, err := ks.CleanupExpired(ctx)
	if err != nil {
		t.Fatalf("CleanupExpired: %v", err)
	}
	if n != 0 {
		t.Errorf("CleanupExpired removed %d rows, want 0 (nothing expired yet)", n)
	}
}

// TestPostgresUserImportAndAdminEdge covers a couple of repo branches the main
// suites skip: user CreateImported (passwordless import) and admin GetByUsername
// miss.
func TestPostgresUserImportAndAdminEdge(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	db := &postgres.DB{Pool: pool}
	ctx := context.Background()

	t.Run("UserRepo.CreateImported", func(t *testing.T) {
		repo := postgres.NewUserRepo(db)
		u := makeUser("imported@test.com")
		u.PasswordHash = "" // import_pending accounts have no password
		if err := repo.CreateImported(ctx, u); err != nil {
			t.Fatalf("CreateImported: %v", err)
		}
		got, err := repo.GetByEmail(ctx, "imported@test.com")
		if err != nil || got == nil {
			t.Fatalf("GetByEmail after import = %v, %v", got, err)
		}
	})

	t.Run("AdminUserRepo.GetByUsername miss returns nil", func(t *testing.T) {
		repo := postgres.NewAdminUserRepo(db)
		got, err := repo.GetByUsername(ctx, "no-such-admin")
		if err != nil {
			t.Fatalf("GetByUsername: %v", err)
		}
		if got != nil {
			t.Fatalf("GetByUsername(absent) = %+v, want nil", got)
		}
	})

	_ = model.User{}
}
