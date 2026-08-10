package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/tests/mocks"
)

// GET /user/data-export is the Art. 15/20 right of access: it is the one response
// that is supposed to contain everything held about a person. A partial export
// that still returns 200 is the dangerous failure — the user, and the operator
// answering a subject-access request, would take it as complete. Every store that
// cannot be read must fail the whole request instead.
func TestDataExport_PartialFailureNeverReturns200(t *testing.T) {
	boom := errors.New("db down")

	tests := []struct {
		name string
		wire func() *DataExportHandler
		want int
	}{
		{
			name: "user lookup fails",
			want: http.StatusUnauthorized,
			wire: func() *DataExportHandler {
				users := &mocks.MockUserRepo{
					GetByIDFn: func(context.Context, string) (*model.User, error) { return nil, boom },
				}
				return NewDataExportHandler(users, &mocks.MockDeviceRepo{}, &mocks.MockSocialAccountRepo{},
					&mocks.MockAuditRepo{}, nil, nil, nil, newTestAuditLogger())
			},
		},
		{
			// A caller whose account is gone must not receive an empty export that
			// reads as "we hold nothing about you".
			name: "user not found",
			want: http.StatusUnauthorized,
			wire: func() *DataExportHandler {
				users := &mocks.MockUserRepo{
					GetByIDFn: func(context.Context, string) (*model.User, error) { return nil, nil },
				}
				return NewDataExportHandler(users, &mocks.MockDeviceRepo{}, &mocks.MockSocialAccountRepo{},
					&mocks.MockAuditRepo{}, nil, nil, nil, newTestAuditLogger())
			},
		},
		{
			name: "device listing fails",
			want: http.StatusInternalServerError,
			wire: func() *DataExportHandler {
				devices := &mocks.MockDeviceRepo{
					ListByUserFn: func(context.Context, string) ([]*model.Device, error) { return nil, boom },
				}
				return NewDataExportHandler(exportUserRepo(), devices, &mocks.MockSocialAccountRepo{},
					&mocks.MockAuditRepo{}, nil, nil, nil, newTestAuditLogger())
			},
		},
		{
			name: "social account listing fails",
			want: http.StatusInternalServerError,
			wire: func() *DataExportHandler {
				social := &mocks.MockSocialAccountRepo{
					ListByUserFn: func(context.Context, string) ([]*model.SocialAccount, error) { return nil, boom },
				}
				return NewDataExportHandler(exportUserRepo(), &mocks.MockDeviceRepo{}, social,
					&mocks.MockAuditRepo{}, nil, nil, nil, newTestAuditLogger())
			},
		},
		{
			name: "audit query fails",
			want: http.StatusInternalServerError,
			wire: func() *DataExportHandler {
				auditRepo := &mocks.MockAuditRepo{
					QueryFn: func(context.Context, repository.AuditFilter) ([]*model.AuditEntry, error) {
						return nil, boom
					},
				}
				return NewDataExportHandler(exportUserRepo(), &mocks.MockDeviceRepo{}, &mocks.MockSocialAccountRepo{},
					auditRepo, nil, nil, nil, newTestAuditLogger())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.wire().Export(rec, socialAuthedRequest(http.MethodGet, "/user/data-export", "user-1"))

			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d — an incomplete export must not look complete", rec.Code, tc.want)
			}
		})
	}
}

func TestDataExport_RequiresAuth(t *testing.T) {
	h := NewDataExportHandler(exportUserRepo(), &mocks.MockDeviceRepo{}, &mocks.MockSocialAccountRepo{},
		&mocks.MockAuditRepo{}, nil, nil, nil, newTestAuditLogger())

	rec := httptest.NewRecorder()
	h.Export(rec, httptest.NewRequest(http.MethodGet, "/user/data-export", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func exportUserRepo() *mocks.MockUserRepo {
	return &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "u@example.com", Roles: []string{"user"}}, nil
		},
	}
}
