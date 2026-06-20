package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

func newTestDataExportHandler(
	users *mocks.MockUserRepo,
	devices *mocks.MockDeviceRepo,
	social *mocks.MockSocialAccountRepo,
	auditEvents *mocks.MockAuditRepo,
	identity *mocks.MockIdentityRepo,
	blobs *mocks.MockBlobRepo,
) *DataExportHandler {
	idSvc := service.NewIdentityService(identity, identityMasterKey(), identityHMACSecret())
	blobSvc := service.NewBlobService(blobs, identityMasterKey(), identityHMACSecret(), service.BlobConfig{
		MaxBlobSize:     1024 * 1024,
		MaxBlobsPerUser: 10,
		QuotaBytes:      10 * 1024 * 1024,
	})
	return NewDataExportHandler(users, devices, social, auditEvents, idSvc, blobSvc, newTestAuditLogger())
}

func TestDataExport_Aggregate(t *testing.T) {
	const userID = "user-123"
	now := time.Now()

	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{
				ID:            id,
				Email:         "subject@example.com",
				EmailVerified: true,
				DisplayName:   "Data Subject",
				Locale:        "sk",
				Roles:         []string{"user"},
				CreatedAt:     now,
				UpdatedAt:     now,
			}, nil
		},
	}

	idData := &service.IdentityData{GivenName: "Jane", FamilyName: "Doe", Country: "SK"}
	plaintext, _ := json.Marshal(idData)
	identity := &mocks.MockIdentityRepo{
		GetByPseudonymFn: func(_ context.Context, _ string) (*model.IdentityProfile, error) {
			return &model.IdentityProfile{DataEnc: encryptTestData(t, plaintext, userID), UpdatedAt: now}, nil
		},
	}

	devices := &mocks.MockDeviceRepo{
		ListByUserFn: func(_ context.Context, _ string) ([]*model.Device, error) {
			return []*model.Device{{ID: "device-1", UserID: userID, FriendlyName: "Laptop", FirstSeenAt: now}}, nil
		},
	}

	blobs := &mocks.MockBlobRepo{
		ListByPseudonymFn: func(_ context.Context, _ string) ([]*model.Blob, error) {
			return []*model.Blob{{ID: "blob-1", SizeBytes: 42, Checksum: "sha256:abc", CreatedAt: now}}, nil
		},
	}

	social := &mocks.MockSocialAccountRepo{
		ListByUserFn: func(_ context.Context, _ string) ([]*model.SocialAccount, error) {
			return []*model.SocialAccount{{Provider: "github", ProviderUserID: "gh-99", Email: "subject@example.com", CreatedAt: now}}, nil
		},
	}

	var gotFilter repository.AuditFilter
	auditEvents := &mocks.MockAuditRepo{
		QueryFn: func(_ context.Context, f repository.AuditFilter) ([]*model.AuditEntry, error) {
			gotFilter = f
			return []*model.AuditEntry{{EventType: "login_success", UserID: userID, IP: "203.0.113.7", Timestamp: now}}, nil
		},
	}

	h := newTestDataExportHandler(users, devices, social, auditEvents, identity, blobs)

	req := httptest.NewRequest(http.MethodGet, "/user/data-export", nil)
	req = setAuthContext(req, userID)
	rec := httptest.NewRecorder()

	h.Export(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var resp DataExportResponse
	decodeResponse(t, rec, &resp)

	if resp.Account.Email != "subject@example.com" {
		t.Fatalf("account email = %q", resp.Account.Email)
	}
	if resp.Identity == nil || resp.Identity.GivenName != "Jane" || resp.Identity.Country != "SK" {
		t.Fatalf("identity not exported correctly: %+v", resp.Identity)
	}
	if len(resp.Devices) != 1 || resp.Devices[0].FriendlyName != "Laptop" {
		t.Fatalf("devices not exported: %+v", resp.Devices)
	}
	if len(resp.Blobs) != 1 || resp.Blobs[0].SizeBytes != 42 {
		t.Fatalf("blob metadata not exported: %+v", resp.Blobs)
	}
	if len(resp.SocialAccounts) != 1 || resp.SocialAccounts[0].Provider != "github" {
		t.Fatalf("social accounts not exported: %+v", resp.SocialAccounts)
	}
	if len(resp.AuditEvents) != 1 || resp.AuditEvents[0].EventType != "login_success" {
		t.Fatalf("audit events not exported: %+v", resp.AuditEvents)
	}
	if gotFilter.UserID != userID {
		t.Fatalf("audit query was not scoped to the user: %+v", gotFilter)
	}

	// Blob contents must never appear in the export.
	if bytes.Contains(rec.Body.Bytes(), []byte("data_enc")) {
		t.Fatal("export response leaked blob ciphertext field")
	}
}

func TestDataExport_Unauthenticated(t *testing.T) {
	h := newTestDataExportHandler(
		&mocks.MockUserRepo{}, &mocks.MockDeviceRepo{}, &mocks.MockSocialAccountRepo{},
		&mocks.MockAuditRepo{}, &mocks.MockIdentityRepo{}, &mocks.MockBlobRepo{},
	)

	req := httptest.NewRequest(http.MethodGet, "/user/data-export", nil)
	// No auth context set.
	rec := httptest.NewRecorder()

	h.Export(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d; body: %s", rec.Code, rec.Body.String())
	}
}
