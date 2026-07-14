package adminapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
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
		t.Error("the session token hash was serialised to the admin — live credential material sent to the browser")
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
				t.Error("the password hash was serialised to the admin — an offline cracking target handed out over HTTP")
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
		t.Errorf("an empty search did not serialise as []: %s", body)
	}
}
