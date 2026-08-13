package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

// TestPostgresAdminSessionDeleteExpiredReapsUnrevoked pins the retention contract
// of AdminSessionRepo.DeleteExpired: an admin session that expired without ever
// being explicitly revoked is dead (the middleware rejects it on ExpiresAt) and
// must be collected. It is the common case: sessions that simply time out are
// never revoked. If the reaper only removes rows that are both expired AND
// revoked, those rows accumulate forever, keeping token_hash, ip and user_agent
// past their purpose.
func TestPostgresAdminSessionDeleteExpiredReapsUnrevoked(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	adminRepo := postgres.NewAdminUserRepo(db)
	repo := postgres.NewAdminSessionRepo(db)
	ctx := context.Background()

	admin := makeAdmin("retention-owner", "operator")
	if err := adminRepo.Create(ctx, admin); err != nil {
		t.Fatalf("Create admin: %v", err)
	}

	// Expired two hours ago, never revoked: the natural end-of-life of a session.
	expired := &model.AdminSession{
		ID: randomID(), AdminID: admin.ID, TokenHash: "hash-expired-unrevoked",
		IP: "203.0.113.9", UserAgent: "reaper-test", Revoked: false,
		ExpiresAt: time.Now().Add(-2 * time.Hour),
	}
	if err := repo.Create(ctx, expired); err != nil {
		t.Fatalf("Create expired session: %v", err)
	}

	if _, err := repo.DeleteExpired(ctx); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}

	got, err := repo.GetByTokenHash(ctx, "hash-expired-unrevoked")
	if err != nil {
		t.Fatalf("GetByTokenHash: %v", err)
	}
	if got != nil {
		t.Fatalf("expired unrevoked session survived DeleteExpired: %+v; it grows the table and retains ip/user_agent for good", got)
	}
}
