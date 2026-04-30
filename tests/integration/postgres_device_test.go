package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

func TestPostgresDeviceRepo(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	userRepo := postgres.NewUserRepo(db)
	repo := postgres.NewDeviceRepo(db)
	ctx := context.Background()

	// Create a user that devices will reference
	user := makeUser("device-owner@test.com")
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	makeDevice := func(fpHash string) *model.Device {
		now := time.Now().UTC().Truncate(time.Microsecond)
		return &model.Device{
			ID:              randomID(),
			UserID:          user.ID,
			FingerprintHash: fpHash,
			FriendlyName:    "Test Device",
			Trusted:         false,
			IP:              "192.168.1.1",
			UserAgent:       "TestAgent/1.0",
			LastSeenAt:      &now,
			FirstSeenAt:     now,
			CreatedAt:       now,
		}
	}

	t.Run("Create and GetByID", func(t *testing.T) {
		d := makeDevice("fp-create-getbyid")
		if err := repo.Create(ctx, d); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.GetByID(ctx, d.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got == nil {
			t.Fatal("GetByID returned nil")
		}
		if got.ID != d.ID {
			t.Errorf("ID = %q, want %q", got.ID, d.ID)
		}
		if got.UserID != user.ID {
			t.Errorf("UserID = %q, want %q", got.UserID, user.ID)
		}
		if got.FingerprintHash != d.FingerprintHash {
			t.Errorf("FingerprintHash = %q, want %q", got.FingerprintHash, d.FingerprintHash)
		}
		if got.FriendlyName != "Test Device" {
			t.Errorf("FriendlyName = %q, want %q", got.FriendlyName, "Test Device")
		}
		if got.IP != "192.168.1.1" {
			t.Errorf("IP = %q, want %q", got.IP, "192.168.1.1")
		}
		if got.UserAgent != "TestAgent/1.0" {
			t.Errorf("UserAgent = %q, want %q", got.UserAgent, "TestAgent/1.0")
		}
		if got.Trusted {
			t.Error("Trusted = true, want false")
		}
	})

	t.Run("GetByID not found returns nil", func(t *testing.T) {
		got, err := repo.GetByID(ctx, randomID())
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("GetByFingerprint", func(t *testing.T) {
		d := makeDevice("fp-getbyfp-unique")
		if err := repo.Create(ctx, d); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.GetByFingerprint(ctx, user.ID, "fp-getbyfp-unique")
		if err != nil {
			t.Fatalf("GetByFingerprint: %v", err)
		}
		if got == nil {
			t.Fatal("GetByFingerprint returned nil")
		}
		if got.ID != d.ID {
			t.Errorf("ID = %q, want %q", got.ID, d.ID)
		}
	})

	t.Run("GetByFingerprint not found returns nil", func(t *testing.T) {
		got, err := repo.GetByFingerprint(ctx, user.ID, "nonexistent-fp")
		if err != nil {
			t.Fatalf("GetByFingerprint: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("GetByFingerprint wrong user returns nil", func(t *testing.T) {
		d := makeDevice("fp-wrong-user")
		if err := repo.Create(ctx, d); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.GetByFingerprint(ctx, randomID(), "fp-wrong-user")
		if err != nil {
			t.Fatalf("GetByFingerprint: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil for wrong user, got %+v", got)
		}
	})

	t.Run("ListByUser", func(t *testing.T) {
		// Create a second user to isolate
		user2 := makeUser("device-owner2@test.com")
		if err := userRepo.Create(ctx, user2); err != nil {
			t.Fatalf("create user2: %v", err)
		}
		d1 := &model.Device{
			ID:              randomID(),
			UserID:          user2.ID,
			FingerprintHash: "fp-list-1",
			IP:              "10.0.0.1",
			FirstSeenAt:     time.Now().UTC().Truncate(time.Microsecond),
			CreatedAt:       time.Now().UTC().Truncate(time.Microsecond),
		}
		d2 := &model.Device{
			ID:              randomID(),
			UserID:          user2.ID,
			FingerprintHash: "fp-list-2",
			IP:              "10.0.0.2",
			FirstSeenAt:     time.Now().UTC().Truncate(time.Microsecond),
			CreatedAt:       time.Now().UTC().Truncate(time.Microsecond),
		}
		if err := repo.Create(ctx, d1); err != nil {
			t.Fatalf("Create d1: %v", err)
		}
		if err := repo.Create(ctx, d2); err != nil {
			t.Fatalf("Create d2: %v", err)
		}
		devices, err := repo.ListByUser(ctx, user2.ID)
		if err != nil {
			t.Fatalf("ListByUser: %v", err)
		}
		if len(devices) != 2 {
			t.Errorf("len = %d, want 2", len(devices))
		}
	})

	t.Run("ListByUser empty", func(t *testing.T) {
		user3 := makeUser("no-devices@test.com")
		if err := userRepo.Create(ctx, user3); err != nil {
			t.Fatalf("create user3: %v", err)
		}
		devices, err := repo.ListByUser(ctx, user3.ID)
		if err != nil {
			t.Fatalf("ListByUser: %v", err)
		}
		if len(devices) != 0 {
			t.Errorf("len = %d, want 0", len(devices))
		}
	})

	t.Run("UpdateLastSeen", func(t *testing.T) {
		d := makeDevice("fp-updatelastseen")
		if err := repo.Create(ctx, d); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := repo.UpdateLastSeen(ctx, d.ID, "10.0.0.99"); err != nil {
			t.Fatalf("UpdateLastSeen: %v", err)
		}
		got, err := repo.GetByID(ctx, d.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.IP != "10.0.0.99" {
			t.Errorf("IP = %q, want %q", got.IP, "10.0.0.99")
		}
		if got.LastSeenAt == nil {
			t.Error("LastSeenAt should not be nil after UpdateLastSeen")
		}
	})

	t.Run("UpdateFriendlyName", func(t *testing.T) {
		d := makeDevice("fp-updatename")
		if err := repo.Create(ctx, d); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := repo.UpdateFriendlyName(ctx, d.ID, "My Laptop"); err != nil {
			t.Fatalf("UpdateFriendlyName: %v", err)
		}
		got, err := repo.GetByID(ctx, d.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.FriendlyName != "My Laptop" {
			t.Errorf("FriendlyName = %q, want %q", got.FriendlyName, "My Laptop")
		}
	})

	t.Run("Trust", func(t *testing.T) {
		d := makeDevice("fp-trust")
		if err := repo.Create(ctx, d); err != nil {
			t.Fatalf("Create: %v", err)
		}
		trustUntil := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Microsecond)
		if err := repo.Trust(ctx, d.ID, trustUntil); err != nil {
			t.Fatalf("Trust: %v", err)
		}
		got, err := repo.GetByID(ctx, d.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if !got.Trusted {
			t.Error("Trusted = false, want true")
		}
		if got.TrustedUntil == nil {
			t.Fatal("TrustedUntil should not be nil")
		}
		if !got.TrustedUntil.Truncate(time.Microsecond).Equal(trustUntil) {
			t.Errorf("TrustedUntil = %v, want %v", got.TrustedUntil, trustUntil)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		d := makeDevice("fp-delete")
		if err := repo.Create(ctx, d); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := repo.Delete(ctx, d.ID, user.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		got, err := repo.GetByID(ctx, d.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil after delete, got %+v", got)
		}
	})

	t.Run("Create with empty optional fields", func(t *testing.T) {
		d := &model.Device{
			ID:              randomID(),
			UserID:          user.ID,
			FingerprintHash: "fp-minimal",
			FirstSeenAt:     time.Now().UTC().Truncate(time.Microsecond),
			CreatedAt:       time.Now().UTC().Truncate(time.Microsecond),
		}
		if err := repo.Create(ctx, d); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.GetByID(ctx, d.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.FriendlyName != "" {
			t.Errorf("FriendlyName = %q, want empty", got.FriendlyName)
		}
		if got.IP != "" {
			t.Errorf("IP = %q, want empty", got.IP)
		}
		if got.UserAgent != "" {
			t.Errorf("UserAgent = %q, want empty", got.UserAgent)
		}
	})
}
