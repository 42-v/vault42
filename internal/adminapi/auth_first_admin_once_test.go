package adminapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// F-16. EnsureFirstAdmin gated bootstrap on "auth.admin_users is empty", and
// that table can return to empty: AdminUserRepo.Revoke is a hard DELETE, not a
// disable, and RevokeAdmin only refuses self-revocation, so two concurrent
// super_admin sessions revoking each other empty it — as does anything reaching
// the database as vault_admin. The next gateway restart then minted a fresh
// super_admin, which is a second bootstrap admin created long after the system
// went live. Migration 016's created_by-NULL carve-out reopens with it, and
// migration 023 leans on that window never reopening.
func TestEnsureFirstAdmin_RefusesASecondBootstrapAfterTheTableIsEmptied(t *testing.T) {
	firstBootSink(t)
	ctx := context.Background()
	repo := newFakeAdminRepo()
	marker := newStoringAdminConfig()

	if err := EnsureFirstAdmin(ctx, repo, marker, ""); err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	if len(repo.users) != 1 {
		t.Fatalf("first bootstrap created %d admins, want 1", len(repo.users))
	}

	// The system is live. Now empty the table the way a hard DELETE does.
	for id := range repo.users {
		delete(repo.users, id)
	}

	err := EnsureFirstAdmin(ctx, repo, marker, "")
	if err == nil {
		t.Fatal("EnsureFirstAdmin bootstrapped a second super_admin after the admin table was emptied")
	}
	if len(repo.users) != 0 {
		t.Errorf("a second bootstrap super_admin was minted: %d rows", len(repo.users))
	}
	if !strings.Contains(err.Error(), "already bootstrapped") {
		t.Errorf("error does not say why it refused: %v", err)
	}
}

// A deployment that upgrades into this code already has admins and no marker.
// The window has to close for it too, so a non-empty table records the fact on
// the next boot rather than leaving the deployment one revocation away from the
// re-entry above.
func TestEnsureFirstAdmin_RecordsTheBootstrapOfAnAlreadyPopulatedDeployment(t *testing.T) {
	ctx := context.Background()
	repo := newFakeAdminRepo()
	repo.users["existing"] = &model.AdminUser{ID: "existing", Username: "admin"}
	marker := newStoringAdminConfig()

	if err := EnsureFirstAdmin(ctx, repo, marker, ""); err != nil {
		t.Fatalf("EnsureFirstAdmin: %v", err)
	}
	if marker.values[firstAdminMarkerKey] == "" {
		t.Fatal("a populated deployment did not record that it is past bootstrap")
	}

	for id := range repo.users {
		delete(repo.users, id)
	}
	if err := EnsureFirstAdmin(ctx, repo, marker, ""); err == nil {
		t.Error("an upgraded deployment still re-bootstrapped after its admins were removed")
	}
}

// If the marker cannot be read, EnsureFirstAdmin cannot tell a genuine first
// boot from a re-entry. Minting a super_admin on a guess is the failure this
// finding is about, so the ambiguous case fails closed.
func TestEnsureFirstAdmin_MarkerReadFailureBootstrapsNothing(t *testing.T) {
	firstBootSink(t)
	repo := newFakeAdminRepo()
	marker := newStoringAdminConfig()
	marker.getErr = errors.New("db down")

	if err := EnsureFirstAdmin(context.Background(), repo, marker, ""); err == nil {
		t.Fatal("EnsureFirstAdmin bootstrapped although it could not tell whether it already had")
	}
	if len(repo.users) != 0 {
		t.Errorf("an admin was created on an unreadable marker: %d rows", len(repo.users))
	}
}

// The marker write is what makes the next boot refuse. A silent failure there
// leaves the window open on a deployment that believes it is closed, so the
// error is surfaced; the following boot sees a non-empty table and records it.
func TestEnsureFirstAdmin_MarkerWriteFailureIsReported(t *testing.T) {
	firstBootSink(t)
	repo := newFakeAdminRepo()
	marker := newStoringAdminConfig()
	marker.setErr = errors.New("db down")

	err := EnsureFirstAdmin(context.Background(), repo, marker, "")
	if err == nil {
		t.Fatal("a failed marker write was not reported")
	}
	if len(repo.users) != 1 {
		t.Errorf("the admin itself should still exist: %d rows", len(repo.users))
	}
}

// storingAdminConfig is an AdminConfigRepository that keeps what it is given,
// which is what a once-only guard has to be judged against.
type storingAdminConfig struct {
	values map[string]string
	getErr error
	setErr error
}

func newStoringAdminConfig() *storingAdminConfig {
	return &storingAdminConfig{values: map[string]string{}}
}

func (s *storingAdminConfig) List(context.Context) (map[string]string, error) {
	return s.values, nil
}

func (s *storingAdminConfig) Get(_ context.Context, key string) (string, error) {
	if s.getErr != nil {
		return "", s.getErr
	}
	return s.values[key], nil
}

func (s *storingAdminConfig) Set(_ context.Context, key, value string) error {
	if s.setErr != nil {
		return s.setErr
	}
	s.values[key] = value
	return nil
}

func (s *storingAdminConfig) Delete(_ context.Context, key string) error {
	delete(s.values, key)
	return nil
}

// The steady state: the marker is set and the admins are there. Every gateway
// boot after the first takes this path, and it must be silent.
func TestEnsureFirstAdmin_IsANoOpOnceBootstrappedAndPopulated(t *testing.T) {
	firstBootSink(t)
	ctx := context.Background()
	repo := newFakeAdminRepo()
	marker := newStoringAdminConfig()

	if err := EnsureFirstAdmin(ctx, repo, marker, ""); err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	if err := EnsureFirstAdmin(ctx, repo, marker, ""); err != nil {
		t.Fatalf("second boot: %v", err)
	}
	if len(repo.users) != 1 {
		t.Errorf("admin count = %d after a second boot, want 1", len(repo.users))
	}
}

// The upgrade path writes the marker for a deployment that already has admins.
// If that write fails the window is still open, so the boot says so rather than
// reporting a guard it did not install.
func TestEnsureFirstAdmin_UpgradeMarkerWriteFailureIsReported(t *testing.T) {
	repo := newFakeAdminRepo()
	repo.users["existing"] = &model.AdminUser{ID: "existing", Username: "admin"}
	marker := newStoringAdminConfig()
	marker.setErr = errors.New("db down")

	if err := EnsureFirstAdmin(context.Background(), repo, marker, ""); err == nil {
		t.Fatal("a failed upgrade-path marker write was not reported")
	}
}
