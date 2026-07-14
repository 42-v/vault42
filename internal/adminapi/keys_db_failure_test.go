package adminapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/keystore"
	"github.com/42-v/vault42/tests/mocks"
)

// handlerWithDeadKeystore wires a real KeyStore whose database is unreachable. The
// nil-keystore case is already covered; this is the harder one, where the keystore
// exists and is wired correctly but the database behind it is down.
func handlerWithDeadKeystore(t *testing.T) *Handler {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://vault:vault@127.0.0.1:1/vault?connect_timeout=1")
	if err != nil {
		t.Fatalf("build pool: %v", err)
	}
	t.Cleanup(pool.Close)

	ks, err := keystore.New(pool, make([]byte, 32), time.Hour)
	if err != nil {
		t.Fatalf("keystore.New: %v", err)
	}
	return &Handler{
		keyStore: ks,
		auditLog: audit.NewLogger(&mocks.MockAuditRepo{}, 0),
	}
}

// These endpoints are what an operator reaches for during a suspected key compromise.
// A rotate or revoke that returns 200 while the database never took the write is the
// worst possible answer: the operator closes the incident believing the signing key
// has been replaced, and the compromised key keeps signing valid tokens.
func TestKeyEndpoints_DatabaseFailureIsNotReportedAsSuccess(t *testing.T) {
	t.Run("ListKeys", func(t *testing.T) {
		h := handlerWithDeadKeystore(t)
		rec := httptest.NewRecorder()
		h.ListKeys(rec, httptest.NewRequest(http.MethodGet, "/admin/keys", nil))

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500 — an empty key list would read as 'this vault has no signing keys'", rec.Code)
		}
	})

	t.Run("RotateKey", func(t *testing.T) {
		h := handlerWithDeadKeystore(t)
		rec := httptest.NewRecorder()
		h.RotateKey(rec, httptest.NewRequest(http.MethodPost, "/admin/keys/rotate", nil))

		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 — the operator would believe a compromised key was retired", rec.Code)
		}
		if body := rec.Body.String(); !strings.Contains(body, "key_rotation_failed") {
			t.Errorf("body = %s, want key_rotation_failed", body)
		}
	})

	t.Run("RevokeKey", func(t *testing.T) {
		h := handlerWithDeadKeystore(t)
		req := httptest.NewRequest(http.MethodDelete, "/admin/keys/kid-1", nil)
		req.SetPathValue("kid", "kid-1")
		rec := httptest.NewRecorder()
		h.RevokeKey(rec, req)

		if rec.Code == http.StatusOK {
			t.Fatal("revoke reported success — a stolen key would keep signing valid tokens")
		}
	})
}
