package integration_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	// Format as UUID v4
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return hex.EncodeToString(b[:4]) + "-" +
		hex.EncodeToString(b[4:6]) + "-" +
		hex.EncodeToString(b[6:8]) + "-" +
		hex.EncodeToString(b[8:10]) + "-" +
		hex.EncodeToString(b[10:])
}

func makeUser(email string) *model.User {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &model.User{
		ID:           randomID(),
		Email:        email,
		PasswordHash: "$argon2id$v=19$m=47104,t=1,p=1$dGVzdHNhbHQ$testhash",
		Locale:       "en",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

func TestPostgresUserRepo(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	repo := postgres.NewUserRepo(db)
	ctx := context.Background()

	t.Run("Create and GetByID", func(t *testing.T) {
		u := makeUser("create-getbyid@test.com")
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got == nil {
			t.Fatal("GetByID returned nil")
		}
		if got.ID != u.ID {
			t.Errorf("ID = %q, want %q", got.ID, u.ID)
		}
		if got.Email != u.Email {
			t.Errorf("Email = %q, want %q", got.Email, u.Email)
		}
		if got.PasswordHash != u.PasswordHash {
			t.Errorf("PasswordHash = %q, want %q", got.PasswordHash, u.PasswordHash)
		}
		if got.Locale != "en" {
			t.Errorf("Locale = %q, want %q", got.Locale, "en")
		}
	})

	t.Run("Create and GetByEmail", func(t *testing.T) {
		u := makeUser("create-getbyemail@test.com")
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.GetByEmail(ctx, u.Email)
		if err != nil {
			t.Fatalf("GetByEmail: %v", err)
		}
		if got == nil {
			t.Fatal("GetByEmail returned nil")
		}
		if got.ID != u.ID {
			t.Errorf("ID = %q, want %q", got.ID, u.ID)
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

	t.Run("GetByEmail not found returns nil", func(t *testing.T) {
		got, err := repo.GetByEmail(ctx, "nonexistent@test.com")
		if err != nil {
			t.Fatalf("GetByEmail: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil, got %+v", got)
		}
	})

	t.Run("Duplicate email returns error", func(t *testing.T) {
		email := "duplicate@test.com"
		u1 := makeUser(email)
		if err := repo.Create(ctx, u1); err != nil {
			t.Fatalf("Create first: %v", err)
		}
		u2 := makeUser(email)
		err := repo.Create(ctx, u2)
		if err == nil {
			t.Fatal("expected error for duplicate email, got nil")
		}
	})

	t.Run("Update", func(t *testing.T) {
		u := makeUser("update@test.com")
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create: %v", err)
		}

		u.Email = "updated@test.com"
		u.DisplayName = "Updated Name"
		u.AvatarURL = "https://example.com/avatar.png"
		u.Locale = "sk"
		u.MFARequired = true

		if err := repo.Update(ctx, u); err != nil {
			t.Fatalf("Update: %v", err)
		}

		got, err := repo.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.Email != "updated@test.com" {
			t.Errorf("Email = %q, want %q", got.Email, "updated@test.com")
		}
		if got.DisplayName != "Updated Name" {
			t.Errorf("DisplayName = %q, want %q", got.DisplayName, "Updated Name")
		}
		if got.AvatarURL != "https://example.com/avatar.png" {
			t.Errorf("AvatarURL = %q, want %q", got.AvatarURL, "https://example.com/avatar.png")
		}
		if got.Locale != "sk" {
			t.Errorf("Locale = %q, want %q", got.Locale, "sk")
		}
		if !got.MFARequired {
			t.Error("MFARequired = false, want true")
		}
	})

	t.Run("UpdatePassword", func(t *testing.T) {
		u := makeUser("updatepw@test.com")
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create: %v", err)
		}
		newHash := "$argon2id$v=19$m=47104,t=1,p=1$bmV3c2FsdA$newhash"
		if err := repo.UpdatePassword(ctx, u.ID, newHash); err != nil {
			t.Fatalf("UpdatePassword: %v", err)
		}
		got, err := repo.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.PasswordHash != newHash {
			t.Errorf("PasswordHash = %q, want %q", got.PasswordHash, newHash)
		}
	})

	t.Run("IncrementFailedLogin", func(t *testing.T) {
		u := makeUser("faillogin@test.com")
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create: %v", err)
		}
		for i := 0; i < 3; i++ {
			if err := repo.IncrementFailedLogin(ctx, u.ID); err != nil {
				t.Fatalf("IncrementFailedLogin %d: %v", i, err)
			}
		}
		got, err := repo.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.FailedLoginCount != 3 {
			t.Errorf("FailedLoginCount = %d, want 3", got.FailedLoginCount)
		}
	})

	t.Run("ResetFailedLogin", func(t *testing.T) {
		u := makeUser("resetfail@test.com")
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := repo.IncrementFailedLogin(ctx, u.ID); err != nil {
			t.Fatalf("IncrementFailedLogin: %v", err)
		}
		if err := repo.ResetFailedLogin(ctx, u.ID); err != nil {
			t.Fatalf("ResetFailedLogin: %v", err)
		}
		got, err := repo.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.FailedLoginCount != 0 {
			t.Errorf("FailedLoginCount = %d, want 0", got.FailedLoginCount)
		}
	})

	t.Run("LockUntil and Unlock", func(t *testing.T) {
		u := makeUser("lockuntil@test.com")
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create: %v", err)
		}

		lockTime := time.Now().UTC().Add(1 * time.Hour).Truncate(time.Microsecond)
		if err := repo.LockUntil(ctx, u.ID, lockTime); err != nil {
			t.Fatalf("LockUntil: %v", err)
		}
		got, err := repo.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.LockedUntil == nil {
			t.Fatal("LockedUntil is nil after LockUntil")
		}
		if !got.LockedUntil.Truncate(time.Microsecond).Equal(lockTime) {
			t.Errorf("LockedUntil = %v, want %v", got.LockedUntil, lockTime)
		}

		if err := repo.Unlock(ctx, u.ID); err != nil {
			t.Fatalf("Unlock: %v", err)
		}
		got, err = repo.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.LockedUntil != nil {
			t.Errorf("LockedUntil = %v, want nil", got.LockedUntil)
		}
		if got.FailedLoginCount != 0 {
			t.Errorf("FailedLoginCount = %d, want 0 after Unlock", got.FailedLoginCount)
		}
	})

	t.Run("VerifyEmail", func(t *testing.T) {
		u := makeUser("verifyemail@test.com")
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if u.EmailVerified {
			t.Fatal("EmailVerified should be false initially")
		}
		if err := repo.VerifyEmail(ctx, u.ID); err != nil {
			t.Fatalf("VerifyEmail: %v", err)
		}
		got, err := repo.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if !got.EmailVerified {
			t.Error("EmailVerified = false, want true")
		}
	})

	t.Run("Create with empty optional fields", func(t *testing.T) {
		u := &model.User{
			ID:        randomID(),
			Email:     "minimal@test.com",
			Locale:    "en",
			CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
			UpdatedAt: time.Now().UTC().Truncate(time.Microsecond),
		}
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.GetByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if got.PasswordHash != "" {
			t.Errorf("PasswordHash = %q, want empty", got.PasswordHash)
		}
		if got.DisplayName != "" {
			t.Errorf("DisplayName = %q, want empty", got.DisplayName)
		}
		if got.AvatarURL != "" {
			t.Errorf("AvatarURL = %q, want empty", got.AvatarURL)
		}
	})

	t.Run("Unlock resets failed count", func(t *testing.T) {
		u := makeUser("unlock-resets@test.com")
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create: %v", err)
		}
		for i := 0; i < 5; i++ {
			_ = repo.IncrementFailedLogin(ctx, u.ID)
		}
		_ = repo.LockUntil(ctx, u.ID, time.Now().UTC().Add(time.Hour))

		if err := repo.Unlock(ctx, u.ID); err != nil {
			t.Fatalf("Unlock: %v", err)
		}
		got, _ := repo.GetByID(ctx, u.ID)
		if got.LockedUntil != nil {
			t.Errorf("LockedUntil should be nil after unlock")
		}
		if got.FailedLoginCount != 0 {
			t.Errorf("FailedLoginCount = %d, want 0", got.FailedLoginCount)
		}
	})
}
