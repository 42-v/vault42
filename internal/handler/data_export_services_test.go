package handler

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/service"
	"github.com/42-v/vault42/tests/mocks"
)

// The identity profile and the blob list are two of the sections the Art. 15 export is
// supposed to contain. The existing tests cover the repositories behind the export; these
// cover the two *services*, which were wired as nil and therefore never exercised.
//
// The failure they guard is the same and it is the worst one this endpoint has: a 200
// carrying an export with a section quietly missing. The user reads it as "this is
// everything you hold about me", and the operator answering a subject-access request
// forwards it as a complete answer. It has to be all or nothing.
func TestDataExport_ServiceFailuresNeverReturnAPartialExport(t *testing.T) {
	boom := errors.New("db down")
	masterKey := bytes.Repeat([]byte{0x42}, 32)
	hmacSecret := []byte("test-hmac-secret")

	liveUser := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com"}, nil
		},
	}

	t.Run("the identity profile cannot be read", func(t *testing.T) {
		identitySvc := service.NewIdentityService(
			&mocks.MockIdentityRepo{
				GetByPseudonymFn: func(context.Context, string) (*model.IdentityProfile, error) {
					return nil, boom
				},
			}, masterKey, hmacSecret)

		h := NewDataExportHandler(liveUser, &mocks.MockDeviceRepo{}, &mocks.MockSocialAccountRepo{},
			&mocks.MockAuditRepo{}, identitySvc, nil, newTestAuditLogger())

		req := setAuthContext(httptest.NewRequest(http.MethodGet, "/user/data-export", nil), "user-1")
		rec := httptest.NewRecorder()

		h.Export(rec, req)

		if rec.Code == http.StatusOK {
			t.Fatal("a 200 export was returned with the identity profile silently missing")
		}
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500", rec.Code)
		}
	})

	t.Run("the blob list cannot be read", func(t *testing.T) {
		blobSvc := service.NewBlobService(
			&mocks.MockBlobRepo{
				ListByPseudonymFn: func(context.Context, string) ([]*model.Blob, error) {
					return nil, boom
				},
			}, masterKey, hmacSecret, service.BlobConfig{})

		h := NewDataExportHandler(liveUser, &mocks.MockDeviceRepo{}, &mocks.MockSocialAccountRepo{},
			&mocks.MockAuditRepo{}, nil, blobSvc, newTestAuditLogger())

		req := setAuthContext(httptest.NewRequest(http.MethodGet, "/user/data-export", nil), "user-1")
		rec := httptest.NewRecorder()

		h.Export(rec, req)

		if rec.Code == http.StatusOK {
			t.Fatal("a 200 export was returned with the document list silently missing")
		}
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500", rec.Code)
		}
	})
}
