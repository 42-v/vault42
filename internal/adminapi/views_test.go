package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/tests/mocks"
)

// The admin surface projects database rows into response views, and the projection is
// the security boundary: the row carries secrets, the view is supposed to drop them.
// Until now the only tests drove these endpoints with an error or an empty result, so
// the projection code — the part that decides what an operator's browser actually
// receives — never ran.
//
// An admin session row holds TokenHash, the hash of the live session token. It is
// deliberately absent from sessionView. If it were ever projected, every admin listing
// their own sessions would be shipping the credential material for all the others to
// their browser, and into whatever logs and proxies sit in front of it.
func TestListSessions_DoesNotLeakTheSessionTokenHash(t *testing.T) {
	const tokenHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	h := &Handler{
		sessions: &stubAdminSessionRepo{
			listActiveFn: func(context.Context) ([]*model.AdminSession, error) {
				return []*model.AdminSession{{
					ID:        "sess-1",
					AdminID:   "adm-1",
					TokenHash: tokenHash,
					IP:        "203.0.113.7",
					UserAgent: "curl/8",
					CreatedAt: time.Now(),
					ExpiresAt: time.Now().Add(time.Hour),
				}}, nil
			},
		},
	}

	rec := httptest.NewRecorder()
	h.ListSessions(rec, httptest.NewRequest(http.MethodGet, "/admin/sessions", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "sess-1") {
		t.Errorf("the session was not returned at all: %s", body)
	}
	if strings.Contains(body, tokenHash) {
		t.Error("the session token hash was serialized to the admin — live credential material sent to the browser")
	}
}

// The same boundary on the user side: a user row carries PasswordHash, and userSummary
// omits it. Admin user-search is the one place an operator pulls a full user row out of
// the database, so it is the one place that projection has to be right.
func TestListUsers_SearchDoesNotLeakThePasswordHash(t *testing.T) {
	const pwHash = "$argon2id$v=19$m=47104,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	user := &model.User{
		ID:            "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
		Email:         "alice@example.com",
		PasswordHash:  pwHash,
		EmailVerified: true,
		DisplayName:   "Alice",
	}

	cases := []struct {
		name  string
		query string
		repo  *mocks.MockUserRepo
	}{
		{
			name:  "by UUID",
			query: user.ID,
			repo: &mocks.MockUserRepo{
				GetByIDFn: func(context.Context, string) (*model.User, error) { return user, nil },
			},
		},
		{
			name:  "by email",
			query: user.Email,
			repo: &mocks.MockUserRepo{
				GetByEmailFn: func(context.Context, string) (*model.User, error) { return user, nil },
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{users: tc.repo}

			rec := httptest.NewRecorder()
			h.ListUsers(rec, httptest.NewRequest(http.MethodGet, "/admin/users?q="+tc.query, nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}

			body := rec.Body.String()
			if !strings.Contains(body, user.ID) {
				t.Errorf("the user was not found by %s: %s", tc.name, body)
			}
			if strings.Contains(body, pwHash) {
				t.Error("the password hash was serialized to the admin — an offline cracking target handed out over HTTP")
			}
			if strings.Contains(body, "argon2") {
				t.Error("password hash material leaked into the admin response")
			}
		})
	}
}

// A search that matches nothing must be an empty list, not a 404 and not a null: the
// operator asked a question and the answer is "no such user", which is a successful
// query with no rows.
func TestListUsers_NoMatchIsAnEmptyList(t *testing.T) {
	h := &Handler{
		users: &mocks.MockUserRepo{
			GetByEmailFn: func(context.Context, string) (*model.User, error) { return nil, nil },
		},
	}

	rec := httptest.NewRecorder()
	h.ListUsers(rec, httptest.NewRequest(http.MethodGet, "/admin/users?q=nobody@example.com", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "[]") {
		t.Errorf("an empty search did not serialize as []: %s", body)
	}
}

// GET /admin/audit was serializing []*model.AuditEntry directly, so the wire
// format was Go field names, PascalCase in an API that is snake_case
// everywhere else, and it carried FingerprintHash: an HMAC that correlates
// events across accounts. The projection is what fixes both, and it is only a
// fix as long as nothing serializes the row again.
func TestQueryAudit_ProjectsSnakeCaseAndDropsTheFingerprint(t *testing.T) {
	const fingerprint = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

	auditRepo := &mocks.MockAuditRepo{
		QueryFn: func(context.Context, repository.AuditFilter) ([]*model.AuditEntry, error) {
			return []*model.AuditEntry{{
				ID:              "evt-1",
				Timestamp:       time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
				EventType:       "login",
				UserID:          "usr-1",
				IP:              "203.0.113.7",
				FingerprintHash: fingerprint,
				DeviceID:        "dev-1",
				RiskScore:       3,
			}}, nil
		},
	}

	h := newTestHandler(nil, nil, nil, auditRepo)
	rec := httptest.NewRecorder()
	h.QueryAudit(rec, httptest.NewRequest(http.MethodGet, "/admin/audit", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	if strings.Contains(body, fingerprint) {
		t.Error("the device fingerprint hash was returned to the admin, putting a cross-account correlator on the wire")
	}
	for _, goName := range []string{`"ID"`, `"Timestamp"`, `"EventType"`, `"FingerprintHash"`, `"RiskScore"`} {
		if strings.Contains(body, goName) {
			t.Errorf("Go field name %s reached the wire: %s", goName, body)
		}
	}
	if strings.Contains(body, `"filter"`) {
		t.Errorf("the internal repository filter struct was echoed back to the client: %s", body)
	}

	var resp struct {
		Entries []map[string]any `json:"entries"`
		Total   int              `json:"total"`
		Limit   int              `json:"limit"`
		Offset  int              `json:"offset"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(resp.Entries))
	}
	if resp.Total != 1 || resp.Limit != defaultListLimit || resp.Offset != 0 {
		t.Errorf("envelope = {total:%d limit:%d offset:%d}, want the standard list envelope", resp.Total, resp.Limit, resp.Offset)
	}
	for _, key := range []string{"id", "timestamp", "event_type", "user_id", "ip", "device_id", "risk_score"} {
		if _, ok := resp.Entries[0][key]; !ok {
			t.Errorf("entry is missing %q: %v", key, resp.Entries[0])
		}
	}
}

// An empty audit query is an empty array, never null: a strongly-typed client
// that models entries as a list cannot decode null into one.
func TestQueryAudit_NoResultsIsAnEmptyArray(t *testing.T) {
	auditRepo := &mocks.MockAuditRepo{
		QueryFn: func(context.Context, repository.AuditFilter) ([]*model.AuditEntry, error) { return nil, nil },
	}

	h := newTestHandler(nil, nil, nil, auditRepo)
	rec := httptest.NewRecorder()
	h.QueryAudit(rec, httptest.NewRequest(http.MethodGet, "/admin/audit", nil))

	if body := rec.Body.String(); !strings.Contains(body, `"entries":[]`) {
		t.Errorf("an empty audit query did not serialize entries as []: %s", body)
	}
}

// GET /admin/clients/{id} returned the model.Client row itself, which carries
// SecretHash, the argon2id hash of the client secret. An operator's browser,
// and everything in front of it, was being handed offline-crackable credential
// material for every service client.
func TestGetClient_DoesNotLeakTheClientSecretHash(t *testing.T) {
	const secretHash = "$argon2id$v=19$m=47104,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

	h := &Handler{clients: &mocks.MockClientRepo{
		GetByIDFn: func(context.Context, string) (*model.Client, error) {
			return &model.Client{ID: "c1", Name: "billing", SecretHash: secretHash, Active: true}, nil
		},
	}}

	rec := httptest.NewRecorder()
	h.GetClient(rec, withPathValue(adminReq(http.MethodGet, "/admin/clients/c1", ""), map[string]string{"id": "c1"}))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "billing") {
		t.Errorf("the client was not returned at all: %s", body)
	}
	if strings.Contains(body, secretHash) || strings.Contains(body, "argon2") {
		t.Error("the client secret hash was serialized to the admin, handing an offline cracking target out over HTTP")
	}
	if strings.Contains(body, `"SecretHash"`) || strings.Contains(body, `"ID"`) {
		t.Errorf("Go field names reached the wire: %s", body)
	}
	if !strings.Contains(body, `"scopes":[]`) || !strings.Contains(body, `"redirect_uris":[]`) {
		t.Errorf("an unset scope or redirect list serialized as null rather than []: %s", body)
	}
}
