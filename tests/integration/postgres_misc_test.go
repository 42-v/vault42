package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

// =============================================================================
// TOTP Repository
// =============================================================================

func TestPostgresTOTPRepo(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	userRepo := postgres.NewUserRepo(db)
	repo := postgres.NewTOTPRepo(db)
	ctx := context.Background()

	user := makeUser("totp-owner@test.com")
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	t.Run("Create and GetByUserID", func(t *testing.T) {
		s := &model.TOTPSecret{
			ID:        randomID(),
			UserID:    user.ID,
			SecretEnc: "encrypted-totp-secret-base64",
			Verified:  false,
			CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
		}
		if err := repo.Create(ctx, s); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.GetByUserID(ctx, user.ID)
		if err != nil {
			t.Fatalf("GetByUserID: %v", err)
		}
		if got == nil {
			t.Fatal("GetByUserID returned nil")
		}
		if got.ID != s.ID {
			t.Errorf("ID = %q, want %q", got.ID, s.ID)
		}
		if got.SecretEnc != "encrypted-totp-secret-base64" {
			t.Errorf("SecretEnc = %q, want %q", got.SecretEnc, "encrypted-totp-secret-base64")
		}
		if got.Verified {
			t.Error("Verified = true, want false")
		}
	})

	t.Run("GetByUserID not found returns nil", func(t *testing.T) {
		got, err := repo.GetByUserID(ctx, randomID())
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if got != nil {
			t.Errorf("expected nil result, got %+v", got)
		}
	})

	t.Run("MarkVerified", func(t *testing.T) {
		user2 := makeUser("totp-verify@test.com")
		if err := userRepo.Create(ctx, user2); err != nil {
			t.Fatalf("create user2: %v", err)
		}
		s := &model.TOTPSecret{
			ID:        randomID(),
			UserID:    user2.ID,
			SecretEnc: "encrypted-secret-2",
			Verified:  false,
			CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
		}
		if err := repo.Create(ctx, s); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := repo.MarkVerified(ctx, s.ID); err != nil {
			t.Fatalf("MarkVerified: %v", err)
		}
		got, _ := repo.GetByUserID(ctx, user2.ID)
		if !got.Verified {
			t.Error("Verified = false after MarkVerified")
		}
	})

	t.Run("DeleteByUserID", func(t *testing.T) {
		user3 := makeUser("totp-delete@test.com")
		if err := userRepo.Create(ctx, user3); err != nil {
			t.Fatalf("create user3: %v", err)
		}
		s := &model.TOTPSecret{
			ID:        randomID(),
			UserID:    user3.ID,
			SecretEnc: "encrypted-secret-3",
			Verified:  true,
			CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
		}
		if err := repo.Create(ctx, s); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := repo.DeleteByUserID(ctx, user3.ID); err != nil {
			t.Fatalf("DeleteByUserID: %v", err)
		}
		got, err := repo.GetByUserID(ctx, user3.ID)
		if err != nil {
			t.Fatalf("expected nil error after delete, got %v", err)
		}
		if got != nil {
			t.Errorf("expected nil result after delete, got %+v", got)
		}
	})

	t.Run("DeleteByUserID idempotent", func(t *testing.T) {
		if err := repo.DeleteByUserID(ctx, randomID()); err != nil {
			t.Fatalf("DeleteByUserID on nonexistent: %v", err)
		}
	})
}

// =============================================================================
// Backup Code Repository
// =============================================================================

func TestPostgresBackupCodeRepo(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	userRepo := postgres.NewUserRepo(db)
	repo := postgres.NewBackupCodeRepo(db)
	ctx := context.Background()

	user := makeUser("backup-owner@test.com")
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	t.Run("CreateBatch and ListUnusedByUser", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		codes := make([]*model.BackupCode, 10)
		for i := range codes {
			codes[i] = &model.BackupCode{
				ID:        randomID(),
				UserID:    user.ID,
				CodeHash:  "hash-" + randomID(),
				CreatedAt: now,
			}
		}
		if err := repo.CreateBatch(ctx, codes); err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		unused, err := repo.ListUnusedByUser(ctx, user.ID)
		if err != nil {
			t.Fatalf("ListUnusedByUser: %v", err)
		}
		if len(unused) != 10 {
			t.Errorf("len = %d, want 10", len(unused))
		}
		for _, c := range unused {
			if c.Used {
				t.Error("unused code has Used=true")
			}
		}
	})

	t.Run("MarkUsed", func(t *testing.T) {
		unused, _ := repo.ListUnusedByUser(ctx, user.ID)
		if len(unused) == 0 {
			t.Fatal("no unused codes to mark")
		}
		codeID := unused[0].ID
		ok, err := repo.MarkUsed(ctx, codeID)
		if err != nil {
			t.Fatalf("MarkUsed: %v", err)
		}
		if !ok {
			t.Fatal("MarkUsed returned false for unused code")
		}
		remaining, _ := repo.ListUnusedByUser(ctx, user.ID)
		if len(remaining) != len(unused)-1 {
			t.Errorf("remaining = %d, want %d", len(remaining), len(unused)-1)
		}
	})

	t.Run("DeleteAllForUser marks all as used", func(t *testing.T) {
		user2 := makeUser("backup-delete@test.com")
		if err := userRepo.Create(ctx, user2); err != nil {
			t.Fatalf("create user2: %v", err)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		codes := []*model.BackupCode{
			{ID: randomID(), UserID: user2.ID, CodeHash: "delhash1", CreatedAt: now},
			{ID: randomID(), UserID: user2.ID, CodeHash: "delhash2", CreatedAt: now},
			{ID: randomID(), UserID: user2.ID, CodeHash: "delhash3", CreatedAt: now},
		}
		if err := repo.CreateBatch(ctx, codes); err != nil {
			t.Fatalf("CreateBatch: %v", err)
		}
		if err := repo.DeleteAllForUser(ctx, user2.ID); err != nil {
			t.Fatalf("DeleteAllForUser: %v", err)
		}
		unused, _ := repo.ListUnusedByUser(ctx, user2.ID)
		if len(unused) != 0 {
			t.Errorf("len = %d, want 0 after DeleteAllForUser", len(unused))
		}
	})

	t.Run("ListUnusedByUser empty", func(t *testing.T) {
		user3 := makeUser("backup-empty@test.com")
		if err := userRepo.Create(ctx, user3); err != nil {
			t.Fatalf("create user3: %v", err)
		}
		unused, err := repo.ListUnusedByUser(ctx, user3.ID)
		if err != nil {
			t.Fatalf("ListUnusedByUser: %v", err)
		}
		if len(unused) != 0 {
			t.Errorf("len = %d, want 0", len(unused))
		}
	})

	t.Run("CreateBatch empty", func(t *testing.T) {
		if err := repo.CreateBatch(ctx, []*model.BackupCode{}); err != nil {
			t.Fatalf("CreateBatch empty: %v", err)
		}
	})

	t.Run("CreateBatch is all-or-nothing on mid-batch failure", func(t *testing.T) {
		user4 := makeUser("backup-batch-fail@test.com")
		if err := userRepo.Create(ctx, user4); err != nil {
			t.Fatalf("create user4: %v", err)
		}
		dupID := randomID()
		now := time.Now().UTC().Truncate(time.Microsecond)
		codes := []*model.BackupCode{
			{ID: dupID, UserID: user4.ID, CodeHash: "failhash1", CreatedAt: now},
			{ID: dupID, UserID: user4.ID, CodeHash: "failhash2", CreatedAt: now},
		}
		if err := repo.CreateBatch(ctx, codes); err == nil {
			t.Fatal("CreateBatch reported success for a batch with a duplicate primary key")
		}
		unused, err := repo.ListUnusedByUser(ctx, user4.ID)
		if err != nil {
			t.Fatalf("ListUnusedByUser: %v", err)
		}
		if len(unused) != 0 {
			t.Errorf("%d codes of a failed batch were committed, want 0", len(unused))
		}
	})
}

// =============================================================================
// Social Account Repository
// =============================================================================

func TestPostgresSocialAccountRepo(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	userRepo := postgres.NewUserRepo(db)
	repo := postgres.NewSocialAccountRepo(db)
	ctx := context.Background()

	user := makeUser("social-owner@test.com")
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	t.Run("Create and GetByProviderAndID", func(t *testing.T) {
		a := &model.SocialAccount{
			ID:              randomID(),
			UserID:          user.ID,
			Provider:        "google",
			ProviderUserID:  "google-user-123",
			AccessTokenEnc:  "enc-access-token",
			RefreshTokenEnc: "enc-refresh-token",
			CreatedAt:       time.Now().UTC().Truncate(time.Microsecond),
		}
		if err := repo.Create(ctx, a); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.GetByProviderAndID(ctx, "google", "google-user-123")
		if err != nil {
			t.Fatalf("GetByProviderAndID: %v", err)
		}
		if got == nil {
			t.Fatal("GetByProviderAndID returned nil")
		}
		if got.ID != a.ID {
			t.Errorf("ID = %q, want %q", got.ID, a.ID)
		}
		if got.Provider != "google" {
			t.Errorf("Provider = %q, want %q", got.Provider, "google")
		}
		if got.ProviderUserID != "google-user-123" {
			t.Errorf("ProviderUserID = %q, want %q", got.ProviderUserID, "google-user-123")
		}
	})

	t.Run("GetByProviderAndID not found returns nil", func(t *testing.T) {
		got, err := repo.GetByProviderAndID(ctx, "github", "nonexistent")
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if got != nil {
			t.Errorf("expected nil result, got %+v", got)
		}
	})

	t.Run("ListByUser", func(t *testing.T) {
		// Add a second social account
		a2 := &model.SocialAccount{
			ID:              randomID(),
			UserID:          user.ID,
			Provider:        "github",
			ProviderUserID:  "github-user-456",
			AccessTokenEnc:  "enc-access-2",
			RefreshTokenEnc: "enc-refresh-2",
			CreatedAt:       time.Now().UTC().Truncate(time.Microsecond),
		}
		if err := repo.Create(ctx, a2); err != nil {
			t.Fatalf("Create second: %v", err)
		}
		accounts, err := repo.ListByUser(ctx, user.ID)
		if err != nil {
			t.Fatalf("ListByUser: %v", err)
		}
		if len(accounts) < 2 {
			t.Errorf("len = %d, want >= 2", len(accounts))
		}
	})

	t.Run("ListByUser empty", func(t *testing.T) {
		user2 := makeUser("social-empty@test.com")
		if err := userRepo.Create(ctx, user2); err != nil {
			t.Fatalf("create user2: %v", err)
		}
		accounts, err := repo.ListByUser(ctx, user2.ID)
		if err != nil {
			t.Fatalf("ListByUser: %v", err)
		}
		if len(accounts) != 0 {
			t.Errorf("len = %d, want 0", len(accounts))
		}
	})

	t.Run("ListByUser surfaces a NULL access_token_enc", func(t *testing.T) {
		user3 := makeUser("social-null@test.com")
		if err := userRepo.Create(ctx, user3); err != nil {
			t.Fatalf("create user3: %v", err)
		}
		// access_token_enc is nullable in the schema but scanned into a plain
		// string. The repo never writes NULL, so this models an out-of-band write;
		// the list must fail loudly rather than return partial data.
		_, err := pool.Exec(ctx, `
			INSERT INTO auth.social_accounts (id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc)
			VALUES ($1, $2, 'google', $3, NULL, '')`,
			randomID(), user3.ID, "google-null-"+randomID())
		if err != nil {
			t.Fatalf("insert NULL row: %v", err)
		}
		accounts, err := repo.ListByUser(ctx, user3.ID)
		if err == nil {
			t.Fatal("ListByUser returned no error for a row with NULL access_token_enc")
		}
		if accounts != nil {
			t.Errorf("ListByUser returned %d accounts alongside an error", len(accounts))
		}
	})

	t.Run("Delete", func(t *testing.T) {
		a := &model.SocialAccount{
			ID:              randomID(),
			UserID:          user.ID,
			Provider:        "facebook",
			ProviderUserID:  "fb-user-789",
			AccessTokenEnc:  "enc-access-3",
			RefreshTokenEnc: "enc-refresh-3",
			CreatedAt:       time.Now().UTC().Truncate(time.Microsecond),
		}
		if err := repo.Create(ctx, a); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := repo.Delete(ctx, a.ID, user.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		got, err := repo.GetByProviderAndID(ctx, "facebook", "fb-user-789")
		if err != nil {
			t.Fatalf("expected nil error after delete, got %v", err)
		}
		if got != nil {
			t.Errorf("expected nil result after delete, got %+v", got)
		}
	})

	t.Run("Duplicate provider+user returns error", func(t *testing.T) {
		a := &model.SocialAccount{
			ID:              randomID(),
			UserID:          user.ID,
			Provider:        "twitter",
			ProviderUserID:  "tw-user-dup",
			AccessTokenEnc:  "enc1",
			RefreshTokenEnc: "enc1",
			CreatedAt:       time.Now().UTC().Truncate(time.Microsecond),
		}
		if err := repo.Create(ctx, a); err != nil {
			t.Fatalf("Create first: %v", err)
		}
		a2 := &model.SocialAccount{
			ID:              randomID(),
			UserID:          user.ID,
			Provider:        "twitter",
			ProviderUserID:  "tw-user-dup",
			AccessTokenEnc:  "enc2",
			RefreshTokenEnc: "enc2",
			CreatedAt:       time.Now().UTC().Truncate(time.Microsecond),
		}
		err := repo.Create(ctx, a2)
		if err == nil {
			t.Error("expected error for duplicate provider+user, got nil")
		}
	})
}

// =============================================================================
// Password History Repository
// =============================================================================

func TestPostgresPasswordHistoryRepo(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	userRepo := postgres.NewUserRepo(db)
	repo := postgres.NewPasswordHistoryRepo(db)
	ctx := context.Background()

	user := makeUser("pwhist-owner@test.com")
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	t.Run("Create and GetRecentByUser", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		for i := 0; i < 5; i++ {
			e := &model.PasswordHistory{
				ID:           randomID(),
				UserID:       user.ID,
				PasswordHash: "hash-" + randomID(),
				CreatedAt:    now.Add(time.Duration(i) * time.Second),
			}
			if err := repo.Create(ctx, e); err != nil {
				t.Fatalf("Create %d: %v", i, err)
			}
		}
		entries, err := repo.GetRecentByUser(ctx, user.ID, 3)
		if err != nil {
			t.Fatalf("GetRecentByUser: %v", err)
		}
		if len(entries) != 3 {
			t.Errorf("len = %d, want 3", len(entries))
		}
		// Should be in descending order (most recent first)
		for i := 1; i < len(entries); i++ {
			if entries[i].CreatedAt.After(entries[i-1].CreatedAt) {
				t.Errorf("not in descending order at index %d", i)
			}
		}
	})

	t.Run("GetRecentByUser empty", func(t *testing.T) {
		user2 := makeUser("pwhist-empty@test.com")
		if err := userRepo.Create(ctx, user2); err != nil {
			t.Fatalf("create user2: %v", err)
		}
		entries, err := repo.GetRecentByUser(ctx, user2.ID, 10)
		if err != nil {
			t.Fatalf("GetRecentByUser: %v", err)
		}
		if len(entries) != 0 {
			t.Errorf("len = %d, want 0", len(entries))
		}
	})

	t.Run("GetRecentByUser limit exceeds count", func(t *testing.T) {
		entries, err := repo.GetRecentByUser(ctx, user.ID, 100)
		if err != nil {
			t.Fatalf("GetRecentByUser: %v", err)
		}
		if len(entries) != 5 {
			t.Errorf("len = %d, want 5 (all entries)", len(entries))
		}
	})
}

// =============================================================================
// WebAuthn Repository
// =============================================================================

func TestPostgresWebAuthnRepo(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	userRepo := postgres.NewUserRepo(db)
	repo := postgres.NewWebAuthnRepo(db)
	ctx := context.Background()

	user := makeUser("webauthn-owner@test.com")
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	t.Run("Create and GetByCredentialID", func(t *testing.T) {
		credID := []byte("credential-id-bytes-123")
		c := &model.WebAuthnCredential{
			ID:           randomID(),
			UserID:       user.ID,
			CredentialID: credID,
			PublicKey:    []byte("public-key-bytes-456"),
			SignCount:    0,
			FriendlyName: "YubiKey 5",
			CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
		}
		if err := repo.Create(ctx, c); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.GetByCredentialID(ctx, credID)
		if err != nil {
			t.Fatalf("GetByCredentialID: %v", err)
		}
		if got == nil {
			t.Fatal("GetByCredentialID returned nil")
		}
		if got.ID != c.ID {
			t.Errorf("ID = %q, want %q", got.ID, c.ID)
		}
		if string(got.CredentialID) != string(credID) {
			t.Errorf("CredentialID mismatch")
		}
		if string(got.PublicKey) != "public-key-bytes-456" {
			t.Errorf("PublicKey mismatch")
		}
		if got.SignCount != 0 {
			t.Errorf("SignCount = %d, want 0", got.SignCount)
		}
		if got.FriendlyName != "YubiKey 5" {
			t.Errorf("FriendlyName = %q, want %q", got.FriendlyName, "YubiKey 5")
		}
	})

	t.Run("GetByCredentialID not found returns nil", func(t *testing.T) {
		got, err := repo.GetByCredentialID(ctx, []byte("nonexistent"))
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if got != nil {
			t.Errorf("expected nil result, got %+v", got)
		}
	})

	t.Run("ListByUser", func(t *testing.T) {
		// Create a second credential
		c2 := &model.WebAuthnCredential{
			ID:           randomID(),
			UserID:       user.ID,
			CredentialID: []byte("credential-id-bytes-second"),
			PublicKey:    []byte("public-key-bytes-second"),
			SignCount:    0,
			FriendlyName: "Touch ID",
			CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
		}
		if err := repo.Create(ctx, c2); err != nil {
			t.Fatalf("Create second: %v", err)
		}
		creds, err := repo.ListByUser(ctx, user.ID)
		if err != nil {
			t.Fatalf("ListByUser: %v", err)
		}
		if len(creds) < 2 {
			t.Errorf("len = %d, want >= 2", len(creds))
		}
	})

	t.Run("ListByUser empty", func(t *testing.T) {
		user2 := makeUser("webauthn-empty@test.com")
		if err := userRepo.Create(ctx, user2); err != nil {
			t.Fatalf("create user2: %v", err)
		}
		creds, err := repo.ListByUser(ctx, user2.ID)
		if err != nil {
			t.Fatalf("ListByUser: %v", err)
		}
		if len(creds) != 0 {
			t.Errorf("len = %d, want 0", len(creds))
		}
	})

	t.Run("ListByUser surfaces a NULL friendly_name", func(t *testing.T) {
		user3 := makeUser("webauthn-null@test.com")
		if err := userRepo.Create(ctx, user3); err != nil {
			t.Fatalf("create user3: %v", err)
		}
		// friendly_name is nullable in the schema but scanned into a plain string.
		// The repo never writes NULL, so this models an out-of-band write; the list
		// must fail loudly rather than return partial data.
		_, err := pool.Exec(ctx, `
			INSERT INTO auth.webauthn_credentials (id, user_id, credential_id, public_key, sign_count, friendly_name)
			VALUES ($1, $2, $3, $4, 0, NULL)`,
			randomID(), user3.ID, []byte("null-name-cred"), []byte("pk"))
		if err != nil {
			t.Fatalf("insert NULL row: %v", err)
		}
		creds, err := repo.ListByUser(ctx, user3.ID)
		if err == nil {
			t.Fatal("ListByUser returned no error for a row with NULL friendly_name")
		}
		if creds != nil {
			t.Errorf("ListByUser returned %d credentials alongside an error", len(creds))
		}
	})

	t.Run("UpdateSignCount", func(t *testing.T) {
		credID := []byte("credential-for-signcount")
		c := &model.WebAuthnCredential{
			ID:           randomID(),
			UserID:       user.ID,
			CredentialID: credID,
			PublicKey:    []byte("pk-signcount"),
			SignCount:    0,
			FriendlyName: "Test Key",
			CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
		}
		if err := repo.Create(ctx, c); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := repo.UpdateSignCount(ctx, c.ID, 42); err != nil {
			t.Fatalf("UpdateSignCount: %v", err)
		}
		got, _ := repo.GetByCredentialID(ctx, credID)
		if got.SignCount != 42 {
			t.Errorf("SignCount = %d, want 42", got.SignCount)
		}
	})

	t.Run("Flags round-trip", func(t *testing.T) {
		credID := []byte("credential-for-flags")
		c := &model.WebAuthnCredential{
			ID:           randomID(),
			UserID:       user.ID,
			CredentialID: credID,
			PublicKey:    []byte("pk-flags"),
			SignCount:    0,
			Flags:        0x4d,
			FriendlyName: "Synced Passkey",
			CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
		}
		if err := repo.Create(ctx, c); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := repo.GetByCredentialID(ctx, credID)
		if err != nil {
			t.Fatalf("GetByCredentialID: %v", err)
		}
		if got.Flags != 0x4d {
			t.Errorf("Flags = %#x after Create, want 0x4d -- a lost BackupEligible flag locks the passkey out", got.Flags)
		}
		if err := repo.UpdateFlags(ctx, c.ID, 0x1d); err != nil {
			t.Fatalf("UpdateFlags: %v", err)
		}
		got, _ = repo.GetByCredentialID(ctx, credID)
		if got.Flags != 0x1d {
			t.Errorf("Flags = %#x after UpdateFlags, want 0x1d", got.Flags)
		}
	})

	t.Run("Delete", func(t *testing.T) {
		credID := []byte("credential-for-delete")
		c := &model.WebAuthnCredential{
			ID:           randomID(),
			UserID:       user.ID,
			CredentialID: credID,
			PublicKey:    []byte("pk-delete"),
			SignCount:    0,
			FriendlyName: "Delete Me",
			CreatedAt:    time.Now().UTC().Truncate(time.Microsecond),
		}
		if err := repo.Create(ctx, c); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := repo.Delete(ctx, c.ID, user.ID); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		got, err := repo.GetByCredentialID(ctx, credID)
		if err != nil {
			t.Fatalf("expected nil error after delete, got %v", err)
		}
		if got != nil {
			t.Errorf("expected nil result after delete, got %+v", got)
		}
	})
}

// =============================================================================
// Rate Limit Repository
// =============================================================================

func TestPostgresRateLimitRepo(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	repo := postgres.NewRateLimitRepo(db)
	ctx := context.Background()

	t.Run("Increment creates new entry", func(t *testing.T) {
		key := "rate-limit:" + randomID()
		window := time.Now().UTC().Truncate(time.Minute)
		count, err := repo.Increment(ctx, key, window)
		if err != nil {
			t.Fatalf("Increment: %v", err)
		}
		if count != 1 {
			t.Errorf("count = %d, want 1", count)
		}
	})

	t.Run("Increment increments existing", func(t *testing.T) {
		key := "rate-limit:" + randomID()
		window := time.Now().UTC().Truncate(time.Minute)

		count1, _ := repo.Increment(ctx, key, window)
		if count1 != 1 {
			t.Errorf("first count = %d, want 1", count1)
		}

		count2, _ := repo.Increment(ctx, key, window)
		if count2 != 2 {
			t.Errorf("second count = %d, want 2", count2)
		}

		count3, _ := repo.Increment(ctx, key, window)
		if count3 != 3 {
			t.Errorf("third count = %d, want 3", count3)
		}
	})

	t.Run("Get returns count", func(t *testing.T) {
		key := "rate-limit:" + randomID()
		window := time.Now().UTC().Truncate(time.Minute)

		for i := 0; i < 5; i++ {
			repo.Increment(ctx, key, window)
		}

		count, err := repo.Get(ctx, key, window)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if count != 5 {
			t.Errorf("count = %d, want 5", count)
		}
	})

	t.Run("Get returns 0 for nonexistent", func(t *testing.T) {
		count, err := repo.Get(ctx, "nonexistent-key", time.Now().UTC())
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if count != 0 {
			t.Errorf("count = %d, want 0", count)
		}
	})

	t.Run("DeleteExpired", func(t *testing.T) {
		key := "rate-limit-old:" + randomID()
		oldWindow := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Minute)
		repo.Increment(ctx, key, oldWindow)

		err := repo.DeleteExpired(ctx, time.Now().UTC().Add(-1*time.Hour))
		if err != nil {
			t.Fatalf("DeleteExpired: %v", err)
		}

		count, _ := repo.Get(ctx, key, oldWindow)
		if count != 0 {
			t.Errorf("count = %d after delete, want 0", count)
		}
	})

	t.Run("DeleteExpired preserves current entries", func(t *testing.T) {
		key := "rate-limit-current:" + randomID()
		currentWindow := time.Now().UTC().Truncate(time.Minute)
		repo.Increment(ctx, key, currentWindow)

		// Delete entries older than 1 hour ago
		err := repo.DeleteExpired(ctx, time.Now().UTC().Add(-1*time.Hour))
		if err != nil {
			t.Fatalf("DeleteExpired: %v", err)
		}

		count, _ := repo.Get(ctx, key, currentWindow)
		if count != 1 {
			t.Errorf("count = %d, want 1 (should be preserved)", count)
		}
	})
}

// =============================================================================
// Admin Config Repository
// =============================================================================

func TestPostgresAdminConfigRepo(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	db := &postgres.DB{Pool: pool}
	repo := postgres.NewAdminConfigRepo(db)
	ctx := context.Background()

	t.Run("Get nonexistent returns empty string", func(t *testing.T) {
		val, err := repo.Get(ctx, "nonexistent-key")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if val != "" {
			t.Errorf("val = %q, want empty", val)
		}
	})

	t.Run("Set and Get", func(t *testing.T) {
		key := "test-config-" + randomID()
		if err := repo.Set(ctx, key, "some-value"); err != nil {
			t.Fatalf("Set: %v", err)
		}
		val, err := repo.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if val != "some-value" {
			t.Errorf("val = %q, want %q", val, "some-value")
		}
	})

	t.Run("Set upserts on conflict", func(t *testing.T) {
		key := "test-upsert-" + randomID()
		if err := repo.Set(ctx, key, "value1"); err != nil {
			t.Fatalf("Set first: %v", err)
		}
		if err := repo.Set(ctx, key, "value2"); err != nil {
			t.Fatalf("Set second: %v", err)
		}
		val, _ := repo.Get(ctx, key)
		if val != "value2" {
			t.Errorf("val = %q, want %q", val, "value2")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		key := "test-delete-" + randomID()
		if err := repo.Set(ctx, key, "to-delete"); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if err := repo.Delete(ctx, key); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		val, _ := repo.Get(ctx, key)
		if val != "" {
			t.Errorf("val = %q after delete, want empty", val)
		}
	})

	t.Run("Delete nonexistent does not error", func(t *testing.T) {
		if err := repo.Delete(ctx, "nonexistent-delete-key"); err != nil {
			t.Fatalf("Delete nonexistent: %v", err)
		}
	})

	t.Run("Set with empty value", func(t *testing.T) {
		key := "test-empty-val-" + randomID()
		// The column is NOT NULL, so empty string should work
		if err := repo.Set(ctx, key, ""); err != nil {
			t.Fatalf("Set empty: %v", err)
		}
		val, _ := repo.Get(ctx, key)
		if val != "" {
			t.Errorf("val = %q, want empty", val)
		}
	})
}

// =============================================================================
// DB (New and Close)
// =============================================================================

func TestPostgresDB(t *testing.T) {
	pool, _, cleanup := setupPostgres(t)
	defer cleanup()

	ctx := context.Background()

	// Get connection string from pool config
	connStr := pool.Config().ConnString()

	t.Run("New creates working pool", func(t *testing.T) {
		db, err := postgres.New(ctx, connStr, 3)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer db.Close()

		// Verify pool works
		var one int
		if err := db.Pool.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
			t.Fatalf("QueryRow: %v", err)
		}
		if one != 1 {
			t.Errorf("got %d, want 1", one)
		}
	})

	t.Run("New with invalid connection string", func(t *testing.T) {
		_, err := postgres.New(ctx, "postgres://invalid:5432/nonexistent?sslmode=disable&connect_timeout=1", 3)
		if err == nil {
			t.Error("expected error for invalid connection")
		}
	})

	t.Run("Close is idempotent", func(t *testing.T) {
		db, err := postgres.New(ctx, connStr, 3)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		db.Close()
		// Second close should not panic
		db.Close()
	})

	t.Run("New with zero maxConns uses default", func(t *testing.T) {
		db, err := postgres.New(ctx, connStr, 0)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer db.Close()

		var one int
		if err := db.Pool.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
			t.Fatalf("QueryRow: %v", err)
		}
	})
}
