package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/adminapi"
	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/keystore"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

// Rotating and revoking the JWT signing keys is what an operator does when a key is
// suspected compromised, and it is the one action they most need to be able to prove
// afterwards. Both handlers write an audit record naming the admin who did it and the kid
// they touched — and that write is on the success path, which is exactly the path a
// unit test with a dead keystore can never reach.
//
// So this runs the real handlers over a real DB-backed keystore. It asserts the key
// actually moves (a new kid comes back, and a revoked key stops being active) rather
// than just that the endpoint answers 200: an endpoint that returns "rotated" while the
// old key keeps signing is the failure this whole surface exists to prevent.
func TestAdminAPIRotateAndRevokeKey(t *testing.T) {
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

	_, originalKID := ks.ActiveKey()
	if originalKID == "" {
		t.Fatal("no active key after EnsureKey")
	}

	auditLog := audit.NewLogger(postgres.NewAuditRepo(db), time.Hour)
	h := adminapi.NewHandler(
		postgres.NewUserRepo(db), postgres.NewClientRepo(db), postgres.NewRefreshTokenRepo(db),
		postgres.NewAuditRepo(db), postgres.NewAdminUserRepo(db), postgres.NewAdminSessionRepo(db),
		postgres.NewAdminConfigRepo(db), ks, auditLog, master, "",
	)

	admin := &model.AdminUser{ID: "adm-1", Username: "root"}
	withAdmin := func(r *http.Request) *http.Request {
		return r.WithContext(adminapi.WithAdmin(r.Context(), admin))
	}

	var rotatedKID string

	t.Run("rotate installs a new active key", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.RotateKey(rec, withAdmin(httptest.NewRequest(http.MethodPost, "/admin/keys/rotate", nil)))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
		}

		var resp map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		rotatedKID = resp["kid"]

		if rotatedKID == "" {
			t.Fatal("rotate reported success but named no new key")
		}
		if rotatedKID == originalKID {
			t.Fatal("rotate reported success while the old key is still the active one")
		}

		if _, active := ks.ActiveKey(); active != rotatedKID {
			t.Errorf("active key is %s, want the rotated one %s", active, rotatedKID)
		}
	})

	t.Run("revoke retires a key", func(t *testing.T) {
		// Revoke the key that rotation displaced.
		req := httptest.NewRequest(http.MethodDelete, "/admin/keys/"+originalKID, nil)
		req.SetPathValue("kid", originalKID)
		rec := httptest.NewRecorder()

		h.RevokeKey(rec, withAdmin(req))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
		}

		keys, err := ks.ListKeys(ctx)
		if err != nil {
			t.Fatalf("ListKeys: %v", err)
		}
		for _, k := range keys {
			if k.KID == originalKID && k.Status == "active" {
				t.Error("revoke reported success but the key is still active — it would keep signing valid tokens")
			}
		}
	})

	t.Run("revoking an unknown key is not reported as success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/admin/keys/no-such-kid", nil)
		req.SetPathValue("kid", "no-such-kid")
		rec := httptest.NewRecorder()

		h.RevokeKey(rec, withAdmin(req))

		if rec.Code == http.StatusOK {
			t.Error("revoking a key that does not exist reported success")
		}
	})
}
