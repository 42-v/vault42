package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
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
			&mocks.MockAuditRepo{}, identitySvc, nil, nil, newTestAuditLogger())

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
			&mocks.MockAuditRepo{}, nil, blobSvc, nil, newTestAuditLogger())

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

	t.Run("the service documents cannot be read", func(t *testing.T) {
		store := &exportSvcDocStore{failListAll: boom}
		svcDocSvc := service.NewDocumentService(store, nil, masterKey, hmacSecret,
			service.DocumentConfig{MaxDocumentBytes: 64 << 10, MaxDocsPerSubject: 32, QuotaBytesPerSubject: 1 << 20}, nil)

		h := NewDataExportHandler(liveUser, &mocks.MockDeviceRepo{}, &mocks.MockSocialAccountRepo{},
			&mocks.MockAuditRepo{}, nil, nil, svcDocSvc, newTestAuditLogger())

		req := setAuthContext(httptest.NewRequest(http.MethodGet, "/user/data-export", nil), "user-1")
		rec := httptest.NewRecorder()

		h.Export(rec, req)

		if rec.Code == http.StatusOK {
			t.Fatal("a 200 export was returned with the service documents silently missing")
		}
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500", rec.Code)
		}
	})
}

// exportSvcDocStore is an in-memory service-document store. The export path is
// tested through the real DocumentService rather than a stubbed one, so
// the rows it reads are genuinely encrypted under the AAD the service binds them
// with: a subject, client or key mismatch fails to decrypt exactly as it would
// in the database.
type exportSvcDocStore struct {
	rows        []*repository.ServiceDocument
	failListAll error
}

func (s *exportSvcDocStore) Upsert(_ context.Context, doc *repository.ServiceDocument) (bool, error) {
	cp := *doc
	s.rows = append(s.rows, &cp)
	return true, nil
}

func (s *exportSvcDocStore) ListAllForSubject(_ context.Context, subjectHash string) ([]*repository.ServiceDocument, error) {
	if s.failListAll != nil {
		return nil, s.failListAll
	}
	var out []*repository.ServiceDocument
	for _, d := range s.rows {
		if d.SubjectHash == subjectHash {
			cp := *d
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *exportSvcDocStore) Get(context.Context, string, string, string) (*repository.ServiceDocument, error) {
	return nil, nil
}

func (s *exportSvcDocStore) ListSharedByKey(context.Context, string, string, string) ([]*repository.ServiceDocument, error) {
	return nil, nil
}

func (s *exportSvcDocStore) Delete(context.Context, string, string, string) (bool, error) {
	return false, nil
}

func (s *exportSvcDocStore) ListByOwner(context.Context, string, string) ([]*repository.ServiceDocument, error) {
	return nil, nil
}

func (s *exportSvcDocStore) ListSharedForSubject(context.Context, string, string) ([]*repository.ServiceDocument, error) {
	return nil, nil
}

func (s *exportSvcDocStore) CountForOwner(context.Context, string, string) (int, error) {
	return 0, nil
}

func (s *exportSvcDocStore) SumBytesForSubject(context.Context, string) (int, error) { return 0, nil }

func (s *exportSvcDocStore) DeleteAllForSubject(context.Context, string) error { return nil }

// Service documents are the one export section that carries decrypted bodies:
// they are records another service wrote ABOUT the user, and Art. 15 covers the
// personal data itself, not a list of its filenames. Two failures matter here
// and both are silent. Omitting the section answers a subject access request
// with less than the service holds; including documents filed under the global
// sentinel hands one service's own configuration to every user who asks for
// their data.
func TestDataExport_IncludesServiceDocumentBodiesButNotGlobalOnes(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x42}, 32)
	hmacSecret := []byte("test-hmac-secret")
	const clientID = "11111111-1111-1111-1111-111111111111"

	store := &exportSvcDocStore{}
	svcDocSvc := service.NewDocumentService(store, nil, masterKey, hmacSecret,
		service.DocumentConfig{MaxDocumentBytes: 64 << 10, MaxDocsPerSubject: 32, QuotaBytesPerSubject: 1 << 20}, nil)

	ctx := context.Background()
	if _, _, err := svcDocSvc.Put(ctx, clientID, "user-1", "loyalty", []byte(`{"tier":"gold"}`), repository.VisibilityPrivate); err != nil {
		t.Fatalf("seed subject document: %v", err)
	}
	if _, _, err := svcDocSvc.Put(ctx, clientID, service.GlobalSubject, "settings", []byte(`{"region":"eu"}`), repository.VisibilityPrivate); err != nil {
		t.Fatalf("seed global document: %v", err)
	}
	// A document about a different user, to prove the export is subject-keyed.
	if _, _, err := svcDocSvc.Put(ctx, clientID, "user-2", "loyalty", []byte(`{"tier":"silver"}`), repository.VisibilityPrivate); err != nil {
		t.Fatalf("seed other subject: %v", err)
	}

	users := &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "user@example.com"}, nil
		},
	}
	h := NewDataExportHandler(users, &mocks.MockDeviceRepo{}, &mocks.MockSocialAccountRepo{},
		&mocks.MockAuditRepo{}, nil, nil, svcDocSvc, newTestAuditLogger())

	rec := httptest.NewRecorder()
	h.Export(rec, setAuthContext(httptest.NewRequest(http.MethodGet, "/user/data-export", nil), "user-1"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	var resp DataExportResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode export: %v", err)
	}

	if len(resp.ServiceDocuments) != 1 {
		t.Fatalf("export carries %d service documents, want exactly the one held about this user: %+v",
			len(resp.ServiceDocuments), resp.ServiceDocuments)
	}
	got := resp.ServiceDocuments[0]
	if got.Key != "loyalty" || got.OwnerID != clientID {
		t.Errorf("exported document = %s/%s, want %s/loyalty", got.OwnerID, got.Key, clientID)
	}
	if string(got.Document) != `{"tier":"gold"}` {
		t.Errorf("exported body = %s, want the decrypted document; a metadata-only entry does not satisfy Art. 15", got.Document)
	}
	for _, d := range resp.ServiceDocuments {
		if strings.Contains(string(d.Document), "region") {
			t.Error("a document filed under the global sentinel was exported to a user; it belongs to the service, not to them")
		}
		if strings.Contains(string(d.Document), "silver") {
			t.Error("another user's document was included in this user's export")
		}
	}
}
