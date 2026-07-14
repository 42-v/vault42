package adminapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// The admin lockout counter lives in the database, and the counter write is the thing an
// attacker most benefits from breaking: if the increment fails and the handler simply gave
// up, the count would never advance and the break-glass account could be brute-forced
// indefinitely, with the failures never adding up to a lock.
//
// So the handler falls back to the count it already holds in memory. That fallback is
// best-effort and it is not perfect — but it means an attacker cannot buy unlimited guesses
// by knocking over the counter write. It had no test.
func TestAdminLogin_LockoutStillFiresWhenTheCounterWriteFails(t *testing.T) {
	hash, err := vaultcrypto.HashPassword("the-real-admin-password", "")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	repo := newFakeAdminRepo()
	repo.users["adm-1"] = &model.AdminUser{
		ID: "adm-1", Username: "root", PasswordHash: hash,
		// One short of the limit: the next failure must lock the account.
		FailedLoginCount: 4,
	}
	repo.errIncr = errors.New("db down") // the counter write is broken

	h := NewAuthHandler(repo, &stubAdminSessionRepo{}, audit.NewLogger(&mocks.MockAuditRepo{}, 0),
		make([]byte, 32), "", time.Hour, 5, time.Hour)

	body := strings.NewReader(`{"username":"root","password":"wrong-password"}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/login", body)
	req.RemoteAddr = "203.0.113.1:5000"
	rec := httptest.NewRecorder()

	h.Login(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("a wrong password was accepted")
	}

	locked := repo.users["adm-1"].LockedUntil
	if locked == nil || !locked.After(time.Now()) {
		t.Error("the account did not lock — with the counter write broken, an attacker would get unlimited guesses at the break-glass admin")
	}
}

// EnsureFirstAdmin runs at boot and decides whether this deployment needs a bootstrap
// admin. If the count query fails and the error were swallowed, it would read as "zero
// admins exist" and mint a brand-new bootstrap admin — printing its password to the logs —
// on a vault that already has admins. That is a fresh privileged account created by a
// database blip.
func TestEnsureFirstAdmin_CountFailureDoesNotBootstrapAnAdmin(t *testing.T) {
	repo := newFakeAdminRepo()
	repo.errCount = errors.New("db down")

	err := EnsureFirstAdmin(context.Background(), repo, "")

	if err == nil {
		t.Fatal("EnsureFirstAdmin reported success while it could not count the existing admins")
	}
	if len(repo.users) != 0 {
		t.Error("a bootstrap admin was created on a vault whose admin count could not be read")
	}
}
