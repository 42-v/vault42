package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// namedBlobRefName is deliberately unusual so a substring search over the
// serialized audit entry cannot match by accident.
const namedBlobRefName = "qzx-private-ref-9182"

// newCapturingBlobHandler returns a blob handler whose audit logger records
// every entry it would have written to the database.
func newCapturingBlobHandler(repo *mocks.MockBlobRepo, captured *[]*model.AuditEntry) *BlobHandler {
	auditRepo := &mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, entry *model.AuditEntry) error {
			*captured = append(*captured, entry)
			return nil
		},
	}
	return NewBlobHandler(newTestBlobService(repo), audit.NewLogger(auditRepo, 0), 0, 1024*1024)
}

// TestNamedBlobAuditNeverCarriesPlaintextName pins the docs/PRIVACY.md 3.1
// guarantee: the plaintext reference name of a named blob must not reach the
// database, and audit rows outlive account erasure.
func TestNamedBlobAuditNeverCarriesPlaintextName(t *testing.T) {
	stored := map[string]*model.Blob{}
	repo := &mocks.MockBlobRepo{
		GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
			return &model.BlobQuota{}, nil
		},
		CreateFn: func(_ context.Context, b *model.Blob) error {
			stored[b.RefHash] = b
			return nil
		},
		GetByRefAndPseudonymFn: func(_ context.Context, refHash, _ string) (*model.Blob, error) {
			b, ok := stored[refHash]
			if !ok {
				return nil, nil
			}
			return b, nil
		},
		DeleteByRefAndPseudonymFn: func(_ context.Context, refHash, _ string) error {
			delete(stored, refHash)
			return nil
		},
	}

	var captured []*model.AuditEntry
	h := newCapturingBlobHandler(repo, &captured)

	ops := []struct {
		name   string
		invoke http.HandlerFunc
		method string
		body   string
	}{
		{"upload", h.UploadNamed, http.MethodPut, strings.Repeat("x", 128)},
		{"download", h.DownloadNamed, http.MethodGet, ""},
		{"delete", h.DeleteNamed, http.MethodDelete, ""},
	}

	for _, op := range ops {
		req := httptest.NewRequest(op.method, "/user/blobs/named/"+namedBlobRefName, strings.NewReader(op.body))
		req.SetPathValue("name", namedBlobRefName)
		req = setAuthContext(req, "user-123")
		rec := httptest.NewRecorder()

		op.invoke(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d: %s", op.name, rec.Code, rec.Body.String())
		}
	}

	if len(captured) != len(ops) {
		t.Fatalf("expected %d audit entries, got %d", len(ops), len(captured))
	}

	for _, entry := range captured {
		serialized, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("marshal audit entry: %v", err)
		}
		if strings.Contains(string(serialized), namedBlobRefName) {
			t.Errorf("audit entry %q leaks the plaintext blob name: %s", entry.EventType, serialized)
		}
	}
}

// TestUploadNamedRejectsCharsetViolation pins the [a-zA-Z0-9_-]+ constraint
// documented in docs/spec.md and docs/api.md.
func TestUploadNamedRejectsCharsetViolation(t *testing.T) {
	tests := []struct {
		name     string
		refName  string
		wantCode int
		wantErr  string
	}{
		{"dot", "config.json", http.StatusBadRequest, "invalid_name"},
		{"slash", "a/b", http.StatusBadRequest, "invalid_name"},
		{"space", "my ref", http.StatusBadRequest, "invalid_name"},
		{"non ascii", "réf", http.StatusBadRequest, "invalid_name"},
		{"control char", "ref\x00", http.StatusBadRequest, "invalid_name"},
		{"allowed charset", "Ref_9-x", http.StatusOK, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mocks.MockBlobRepo{
				GetQuotaFn: func(_ context.Context, _ string) (*model.BlobQuota, error) {
					return &model.BlobQuota{}, nil
				},
			}
			h := newTestBlobHandler(repo)

			req := httptest.NewRequest(http.MethodPut, "/user/blobs/named/x", strings.NewReader(strings.Repeat("x", 128)))
			req.SetPathValue("name", tt.refName)
			req = setAuthContext(req, "user-123")
			rec := httptest.NewRecorder()

			h.UploadNamed(rec, req)

			if rec.Code != tt.wantCode {
				t.Fatalf("code = %d, want %d: %s", rec.Code, tt.wantCode, rec.Body.String())
			}
			if tt.wantErr != "" {
				var body map[string]string
				decodeResponse(t, rec, &body)
				if body["error"] != tt.wantErr {
					t.Errorf("error = %q, want %q", body["error"], tt.wantErr)
				}
			}
		})
	}
}
