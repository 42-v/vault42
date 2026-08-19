package integration_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/adminapi"
	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/keystore"
	"github.com/42-v/vault42/internal/repository/postgres"
)

// A keystore with no keys in it is a legitimate state — a vault that has not booted far
// enough to mint one. Listing it must answer with an empty array rather than a JSON null,
// which is what a nil slice serializes to and what an admin UI would choke on.
func TestAdminAPIListKeys_EmptyKeystoreSerialisesAsEmptyArray(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()
	db := &postgres.DB{Pool: pool}

	master := make([]byte, 32)
	for i := range master {
		master[i] = 0x2b
	}
	ks, err := keystore.New(pool, master, time.Hour)
	if err != nil {
		t.Fatalf("keystore.New: %v", err)
	}
	defer ks.Stop()
	// Deliberately no EnsureKey: the store is empty.

	auditLog := audit.NewLogger(postgres.NewAuditRepo(db), time.Hour)
	h := adminapi.NewHandler(
		postgres.NewUserRepo(db), postgres.NewClientRepo(db), postgres.NewRefreshTokenRepo(db),
		postgres.NewAuditRepo(db), postgres.NewAdminUserRepo(db), postgres.NewAdminSessionRepo(db),
		postgres.NewAdminConfigRepo(db), ks, auditLog, master, "",
	)

	rec := httptest.NewRecorder()
	h.ListKeys(rec, httptest.NewRequest(http.MethodGet, "/admin/keys", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "null") {
		t.Errorf("an empty keystore serialized as null rather than []: %s", body)
	}
	if !strings.Contains(body, "[]") {
		t.Errorf("an empty keystore did not serialize as []: %s", body)
	}
}
