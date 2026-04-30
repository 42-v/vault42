package service

import (
	"context"
	"errors"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
)

// ---------------------------------------------------------------------------
// Mock repo for identity tests
// ---------------------------------------------------------------------------

type mockIdentityRepo struct {
	upsertFn         func(ctx context.Context, profile *model.IdentityProfile) error
	getByPseudonymFn func(ctx context.Context, pseudonymID string) (*model.IdentityProfile, error)
	deleteFn         func(ctx context.Context, pseudonymID string) error
}

func (m *mockIdentityRepo) Upsert(ctx context.Context, profile *model.IdentityProfile) error {
	if m.upsertFn != nil {
		return m.upsertFn(ctx, profile)
	}
	return nil
}

func (m *mockIdentityRepo) GetByPseudonym(ctx context.Context, pseudonymID string) (*model.IdentityProfile, error) {
	if m.getByPseudonymFn != nil {
		return m.getByPseudonymFn(ctx, pseudonymID)
	}
	return nil, nil
}

func (m *mockIdentityRepo) Delete(ctx context.Context, pseudonymID string) error {
	if m.deleteFn != nil {
		return m.deleteFn(ctx, pseudonymID)
	}
	return nil
}

var (
	testKey  = []byte("01234567890123456789012345678901") // 32 bytes
	testHMAC = []byte("test-hmac-secret-key-32-bytes!!")
)

// ---------------------------------------------------------------------------
// Pseudonym
// ---------------------------------------------------------------------------

func TestIdentityService_Pseudonym(t *testing.T) {
	svc := NewIdentityService(&mockIdentityRepo{}, testKey, testHMAC)

	p1 := svc.Pseudonym("user-1")
	p2 := svc.Pseudonym("user-2")
	p1Again := svc.Pseudonym("user-1")

	if p1 == "" {
		t.Fatal("expected non-empty pseudonym")
	}
	if p1 == p2 {
		t.Fatal("different users should have different pseudonyms")
	}
	if p1 != p1Again {
		t.Fatal("same user should always get the same pseudonym")
	}
}

// ---------------------------------------------------------------------------
// Upsert
// ---------------------------------------------------------------------------

func TestIdentityService_Upsert_Success(t *testing.T) {
	var captured *model.IdentityProfile
	repo := &mockIdentityRepo{
		upsertFn: func(_ context.Context, p *model.IdentityProfile) error {
			captured = p
			return nil
		},
	}
	svc := NewIdentityService(repo, testKey, testHMAC)

	data := &IdentityData{
		GivenName:   "Jane",
		FamilyName:  "Doe",
		Country:     "SK",
		DateOfBirth: "1990-01-15",
	}

	err := svc.Upsert(context.Background(), "user-123", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if captured == nil {
		t.Fatal("expected profile to be captured")
	}
	if captured.PseudonymID == "" {
		t.Error("expected non-empty pseudonym ID")
	}
	if len(captured.DataEnc) == 0 {
		t.Error("expected non-empty encrypted data")
	}
	if captured.Version != 1 {
		t.Errorf("expected version=1, got %d", captured.Version)
	}
}

func TestIdentityService_Upsert_WithBilling(t *testing.T) {
	repo := &mockIdentityRepo{
		upsertFn: func(_ context.Context, _ *model.IdentityProfile) error { return nil },
	}
	svc := NewIdentityService(repo, testKey, testHMAC)

	data := &IdentityData{
		GivenName: "Test",
		Billing: &BillingInfo{
			AddressLine1: "Main St 1",
			City:         "Bratislava",
			Country:      "SK",
		},
	}

	err := svc.Upsert(context.Background(), "user-456", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIdentityService_Upsert_RepoError(t *testing.T) {
	repo := &mockIdentityRepo{
		upsertFn: func(_ context.Context, _ *model.IdentityProfile) error {
			return errors.New("db error")
		},
	}
	svc := NewIdentityService(repo, testKey, testHMAC)

	err := svc.Upsert(context.Background(), "user-123", &IdentityData{GivenName: "Test"})
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// Get
// ---------------------------------------------------------------------------

func TestIdentityService_Get_Success(t *testing.T) {
	// First upsert to get proper encrypted data
	var stored *model.IdentityProfile
	svc := NewIdentityService(&mockIdentityRepo{
		upsertFn: func(_ context.Context, p *model.IdentityProfile) error {
			stored = p
			return nil
		},
	}, testKey, testHMAC)

	data := &IdentityData{
		GivenName:   "Jane",
		FamilyName:  "Doe",
		Country:     "SK",
		DateOfBirth: "1990-01-15",
		Sex:         "female",
	}
	if err := svc.Upsert(context.Background(), "user-123", data); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Now create a service with a repo that returns the stored data
	svc2 := NewIdentityService(&mockIdentityRepo{
		getByPseudonymFn: func(_ context.Context, _ string) (*model.IdentityProfile, error) {
			return stored, nil
		},
	}, testKey, testHMAC)

	result, updatedAt, err := svc2.Get(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil identity data")
	}
	if result.GivenName != "Jane" {
		t.Errorf("expected GivenName=Jane, got %q", result.GivenName)
	}
	if result.FamilyName != "Doe" {
		t.Errorf("expected FamilyName=Doe, got %q", result.FamilyName)
	}
	if updatedAt.IsZero() {
		t.Error("expected non-zero updated_at")
	}
}

func TestIdentityService_Get_NotFound(t *testing.T) {
	svc := NewIdentityService(&mockIdentityRepo{}, testKey, testHMAC)

	data, updatedAt, err := svc.Get(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data != nil {
		t.Error("expected nil data for not-found")
	}
	if !updatedAt.IsZero() {
		t.Error("expected zero time for not-found")
	}
}

func TestIdentityService_Get_RepoError(t *testing.T) {
	repo := &mockIdentityRepo{
		getByPseudonymFn: func(_ context.Context, _ string) (*model.IdentityProfile, error) {
			return nil, errors.New("db error")
		},
	}
	svc := NewIdentityService(repo, testKey, testHMAC)

	_, _, err := svc.Get(context.Background(), "user-123")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestIdentityService_Get_DecryptError(t *testing.T) {
	repo := &mockIdentityRepo{
		getByPseudonymFn: func(_ context.Context, _ string) (*model.IdentityProfile, error) {
			return &model.IdentityProfile{
				PseudonymID: "pseudo",
				DataEnc:     []byte("not-encrypted-data"),
				Version:     1,
				UpdatedAt:   time.Now(),
			}, nil
		},
	}
	svc := NewIdentityService(repo, testKey, testHMAC)

	_, _, err := svc.Get(context.Background(), "user-123")
	if err == nil {
		t.Fatal("expected decrypt error")
	}
}

func TestIdentityService_Get_InvalidJSON(t *testing.T) {
	svc := NewIdentityService(&mockIdentityRepo{}, testKey, testHMAC)
	pseudo := svc.Pseudonym("user-123")

	// Encrypt invalid JSON with matching AAD
	enc, err := vaultcrypto.Encrypt([]byte("not json"), testKey, []byte(pseudo))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	repo := &mockIdentityRepo{
		getByPseudonymFn: func(_ context.Context, _ string) (*model.IdentityProfile, error) {
			return &model.IdentityProfile{
				PseudonymID: pseudo,
				DataEnc:     enc,
				Version:     1,
				UpdatedAt:   time.Now(),
			}, nil
		},
	}
	svc2 := NewIdentityService(repo, testKey, testHMAC)

	_, _, err = svc2.Get(context.Background(), "user-123")
	if err == nil {
		t.Fatal("expected unmarshal error")
	}
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

func TestIdentityService_Delete_Success(t *testing.T) {
	var deletedPseudo string
	repo := &mockIdentityRepo{
		deleteFn: func(_ context.Context, pseudonymID string) error {
			deletedPseudo = pseudonymID
			return nil
		},
	}
	svc := NewIdentityService(repo, testKey, testHMAC)

	err := svc.Delete(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deletedPseudo == "" {
		t.Error("expected delete to be called with pseudonym")
	}
}

func TestIdentityService_Delete_RepoError(t *testing.T) {
	repo := &mockIdentityRepo{
		deleteFn: func(_ context.Context, _ string) error {
			return errors.New("db error")
		},
	}
	svc := NewIdentityService(repo, testKey, testHMAC)

	err := svc.Delete(context.Background(), "user-123")
	if err == nil {
		t.Fatal("expected error")
	}
}
