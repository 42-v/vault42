package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/rbac"
	"github.com/42-v/vault42/tests/mocks"
)

// The operator half of the forced-password-reset feature (migration 039).
//
// POST /admin/users/import could already create an account carrying
// must_reset_password, which covers the migration that motivated the flag. It
// could not touch an account that already exists, so the general case the flag
// was built for -- an operator with reason to distrust one account's stored
// password -- had no write surface at all. These two routes are that surface.
//
// What they must not become is a second, quieter lock. The flag refuses the
// password path and mails a reset link; it does not ban the account, and a
// social or passkey login is deliberately left working. So the assertions below
// pin what the routes do (the column, the sessions, the audit row) and, just as
// deliberately, what they do not.

// forcedResetRecorder is a user repository that records the calls the routes
// make on it, over a single account whose state the test can inspect.
//
// It is a hand-written fake rather than mocks.MockUserRepo because both routes
// read the account before writing it, and the ordering between the read and the
// write is part of what is being tested: a 404 must mean nothing was written.
type forcedResetRecorder struct {
	*mocks.MockUserRepo
	setCalls   []string
	clearCalls []string
}

func newForcedResetRecorder(user *model.User) *forcedResetRecorder {
	rec := &forcedResetRecorder{}
	rec.MockUserRepo = &mocks.MockUserRepo{
		GetByIDFn: func(context.Context, string) (*model.User, error) { return user, nil },
		SetMustResetPwFn: func(_ context.Context, id string, required bool) error {
			if required {
				rec.setCalls = append(rec.setCalls, id)
			} else {
				rec.clearCalls = append(rec.clearCalls, id)
			}
			return nil
		},
	}
	return rec
}

// auditCapture returns a logger that keeps the last entry written, and a
// pointer to it. flushEvery is zero so the write is synchronous and the test
// reads a row rather than a race.
func auditCapture() (*audit.Logger, *[]*model.AuditEntry) {
	var rows []*model.AuditEntry
	logger := audit.NewLogger(&mocks.MockAuditRepo{
		InsertFn: func(_ context.Context, e *model.AuditEntry) error {
			rows = append(rows, e)
			return nil
		},
	}, 0)
	return logger, &rows
}

// forcedResetReq builds a request already carrying {id} and an authenticated
// operator, which is what the router hands the handler.
func forcedResetReq(method, path, id, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if id != "" {
		r.SetPathValue("id", id)
	}
	return r.WithContext(WithAdmin(r.Context(), &model.AdminUser{
		ID: "adm-1", Username: "root", Role: string(rbac.RoleOperator),
	}))
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return body
}

// ---------------------------------------------------------------------------
// Imposing the reset
// ---------------------------------------------------------------------------

// The whole point of the route: the column moves, and the audit trail carries
// the operator's reason for moving it.
//
// The reason is not decoration. This flag refuses an account's password login
// and mails its holder, so an operator reading the trail six weeks later has to
// be able to tell "migrated from the legacy platform" from "we believe this
// credential is in someone else's hands", which are the same row otherwise.
func TestRequirePasswordReset_SetsTheFlagAndAuditsTheReason(t *testing.T) {
	users := newForcedResetRecorder(&model.User{ID: "u-1", Email: "rider@legacy.test"})
	logger, rows := auditCapture()
	h := &Handler{users: users, tokens: &mocks.MockRefreshTokenRepo{}, auditLog: logger}

	rec := httptest.NewRecorder()
	h.RequirePasswordReset(rec, forcedResetReq(http.MethodPost,
		"/admin/users/u-1/require-password-reset", "u-1", `{"reason":"credential believed compromised"}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body %s", rec.Code, rec.Body.String())
	}
	if len(users.setCalls) != 1 || users.setCalls[0] != "u-1" {
		t.Fatalf("SetMustResetPassword calls = %v, want exactly [u-1]: the route answered 200 "+
			"without imposing anything, so the operator stops looking", users.setCalls)
	}
	if body := decodeBody(t, rec); body["status"] != "password_reset_required" {
		t.Errorf("status = %v, want password_reset_required", body["status"])
	}
	if len(*rows) != 1 {
		t.Fatalf("wrote %d audit rows, want 1", len(*rows))
	}
	row := (*rows)[0]
	if row.EventType != audit.AdminUserResetRequired {
		t.Errorf("event = %q, want %q", row.EventType, audit.AdminUserResetRequired)
	}
	if row.UserID != "adm-1" {
		t.Errorf("actor = %q, want adm-1: the row has to name the admin who imposed it", row.UserID)
	}
	if row.Metadata["target_user"] != "u-1" {
		t.Errorf("target_user = %v, want u-1", row.Metadata["target_user"])
	}
	if row.Metadata["reason"] != "credential believed compromised" {
		t.Errorf("reason = %v, want the operator's reason verbatim", row.Metadata["reason"])
	}
}

// A forced reset that leaves the account's live sessions rotating has refused a
// login nobody was about to attempt.
//
// POST /auth/refresh does not consult must_reset_password -- the flag gates the
// password, and refresh presents a token instead -- so a user who is already
// signed in keeps rotating indefinitely and never meets the reset. That makes
// the revocation the difference between a control that works on the next login
// and one that works now, which is the same argument LockUser records at its own
// call to RevokeAllForUser.
func TestRequirePasswordReset_TerminatesTheAccountsLiveSessions(t *testing.T) {
	users := newForcedResetRecorder(&model.User{ID: "u-1"})
	var revokedFor []string
	tokens := &mocks.MockRefreshTokenRepo{
		RevokeAllForUserFn: func(_ context.Context, id string) error {
			revokedFor = append(revokedFor, id)
			return nil
		},
	}
	logger, rows := auditCapture()
	h := &Handler{users: users, tokens: tokens, auditLog: logger}

	rec := httptest.NewRecorder()
	h.RequirePasswordReset(rec, forcedResetReq(http.MethodPost,
		"/admin/users/u-1/require-password-reset", "u-1", `{"reason":"takeover"}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(revokedFor) != 1 || revokedFor[0] != "u-1" {
		t.Fatalf("RevokeAllForUser calls = %v, want [u-1]: refresh never reads this flag, so a "+
			"session that already exists outlives the forced reset entirely", revokedFor)
	}
	if body := decodeBody(t, rec); body["sessions_revoked"] != true {
		t.Errorf("sessions_revoked = %v, want true: the operator learns the blast radius from "+
			"the response, not from reading this handler", body["sessions_revoked"])
	}
	if (*rows)[0].Metadata["sessions_revoked"] != true {
		t.Errorf("audited sessions_revoked = %v, want true", (*rows)[0].Metadata["sessions_revoked"])
	}
}

// The revocation is best-effort and runs after the flag is written, so a
// failure must be reported rather than turned into "the reset was not imposed".
// The response and the audit row are the only places that outcome exists.
func TestRequirePasswordReset_ReportsAFailedRevocationInsteadOfClaimingIt(t *testing.T) {
	users := newForcedResetRecorder(&model.User{ID: "u-1"})
	tokens := &mocks.MockRefreshTokenRepo{
		RevokeAllForUserFn: func(context.Context, string) error {
			return errors.New("refresh store unavailable")
		},
	}
	logger, rows := auditCapture()
	h := &Handler{users: users, tokens: tokens, auditLog: logger}

	rec := httptest.NewRecorder()
	h.RequirePasswordReset(rec, forcedResetReq(http.MethodPost,
		"/admin/users/u-1/require-password-reset", "u-1", `{"reason":"takeover"}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: the flag committed, so the request must not report failure", rec.Code)
	}
	if len(users.setCalls) != 1 {
		t.Fatalf("the flag was not written: %v", users.setCalls)
	}
	if body := decodeBody(t, rec); body["sessions_revoked"] != false {
		t.Errorf("sessions_revoked = %v, want false: the sessions are still alive and the "+
			"operator has to be told so", body["sessions_revoked"])
	}
	if (*rows)[0].Metadata["sessions_revoked"] != false {
		t.Errorf("audited sessions_revoked = %v, want false", (*rows)[0].Metadata["sessions_revoked"])
	}
}

// The token repository arrives as a positional argument and cmd/admin-gateway
// has passed nil for it before, on LockUser, where the panic landed after the
// write had committed. The same shape of mistake here must not turn an imposed
// reset into a 500 that reads as "nothing happened".
func TestRequirePasswordReset_NilTokenRepoStillImposesTheReset(t *testing.T) {
	users := newForcedResetRecorder(&model.User{ID: "u-1"})
	logger, rows := auditCapture()
	h := &Handler{users: users, tokens: nil, auditLog: logger}

	rec := httptest.NewRecorder()
	h.RequirePasswordReset(rec, forcedResetReq(http.MethodPost,
		"/admin/users/u-1/require-password-reset", "u-1", `{"reason":"takeover"}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(users.setCalls) != 1 {
		t.Fatalf("the flag was not written: %v", users.setCalls)
	}
	if (*rows)[0].Metadata["sessions_revoked"] != false {
		t.Errorf("audited sessions_revoked = %v, want false: an unwired repository revoked "+
			"nothing, and saying otherwise is the lie this assertion exists to catch",
			(*rows)[0].Metadata["sessions_revoked"])
	}
}

// An operator reaches this route from a script or a bare curl, exactly as they
// reach the lock route, and a body that carries no usable reason must still
// leave a row that says what happened. The default names the action rather than
// leaving the field absent, so a trail query on reason never silently skips a
// forced reset.
func TestRequirePasswordReset_AnUnusableBodyStillRecordsAReason(t *testing.T) {
	for _, body := range []string{"", "not json", `{}`, `{"reason":"   "}`} {
		t.Run(body, func(t *testing.T) {
			users := newForcedResetRecorder(&model.User{ID: "u-1"})
			logger, rows := auditCapture()
			h := &Handler{users: users, tokens: &mocks.MockRefreshTokenRepo{}, auditLog: logger}

			rec := httptest.NewRecorder()
			h.RequirePasswordReset(rec, forcedResetReq(http.MethodPost,
				"/admin/users/u-1/require-password-reset", "u-1", body))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if got := (*rows)[0].Metadata["reason"]; got != defaultRequireResetReason {
				t.Errorf("reason = %v, want %q", got, defaultRequireResetReason)
			}
		})
	}
}

// The reason is operator free text on its way into a JSONB column that survives
// account erasure, so it is bounded and stripped of the characters that turn an
// audit row into something else when it is rendered.
func TestRequirePasswordReset_TheReasonIsBoundedAndSanitized(t *testing.T) {
	users := newForcedResetRecorder(&model.User{ID: "u-1"})
	logger, rows := auditCapture()
	h := &Handler{users: users, tokens: &mocks.MockRefreshTokenRepo{}, auditLog: logger}

	long, err := json.Marshal(map[string]string{"reason": "<b>" + strings.Repeat("x", 4000)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	rec := httptest.NewRecorder()
	h.RequirePasswordReset(rec, forcedResetReq(http.MethodPost,
		"/admin/users/u-1/require-password-reset", "u-1", string(long)))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// The bound is a literal here, not maxResetReasonLen. Comparing the constant
	// against itself passes for any value it holds, including one large enough to
	// be no bound at all, which is exactly the mutation this assertion has to see.
	const wantAtMost = 200
	reason, _ := (*rows)[0].Metadata["reason"].(string)
	if len([]rune(reason)) > wantAtMost {
		t.Errorf("reason is %d runes, want at most %d", len([]rune(reason)), wantAtMost)
	}
	if strings.Contains(reason, "<b>") {
		t.Errorf("reason = %q: the markup reached the row verbatim", reason)
	}
}

// ---------------------------------------------------------------------------
// The account has to exist, and has to still be an account
// ---------------------------------------------------------------------------

// GET /admin/users/{id} and DELETE /admin/users/{id} both answer an unknown id
// with 404 user_not_found. This route answers it the same way rather than
// inventing a code, and -- the part that matters -- writes nothing on the way
// out. LockUser's silent 200 on an unknown id is the shape being avoided here,
// not the shape being copied.
//
// An erased account takes the same answer. Its row survives as a tombstone with
// a deleted-<id>@<domain>.invalid address, Login refuses it on account_deleted
// long before it reaches the forced-reset branch, and there is no mailbox left
// to send a reset link to. Imposing the flag there would write a row that can
// never mean anything and report success for it.
func TestRequirePasswordReset_AnUnknownOrErasedAccountIs404AndWritesNothing(t *testing.T) {
	cases := map[string]*model.User{
		"unknown": nil,
		"erased":  {ID: "u-1", Email: "deleted-u-1@vault.invalid", Deleted: true},
	}
	for name, user := range cases {
		t.Run(name, func(t *testing.T) {
			users := newForcedResetRecorder(user)
			logger, rows := auditCapture()
			h := &Handler{users: users, tokens: &mocks.MockRefreshTokenRepo{}, auditLog: logger}

			rec := httptest.NewRecorder()
			h.RequirePasswordReset(rec, forcedResetReq(http.MethodPost,
				"/admin/users/u-1/require-password-reset", "u-1", `{"reason":"takeover"}`))

			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404: body %s", rec.Code, rec.Body.String())
			}
			if body := decodeBody(t, rec); body["error"] != "user_not_found" {
				t.Errorf("error = %v, want user_not_found, the code the other user routes use", body["error"])
			}
			if len(users.setCalls) != 0 {
				t.Errorf("wrote the flag anyway: %v", users.setCalls)
			}
			if len(*rows) != 0 {
				t.Errorf("audited a reset that did not happen: %+v", *rows)
			}
		})
	}
}

// A pattern-less registration, or a route reached some other way, must not
// reach the repository with an empty id: an UPDATE whose WHERE clause matches
// on the empty string is a statement nobody meant to issue.
func TestForcedResetRoutes_MissingIDIs400(t *testing.T) {
	users := newForcedResetRecorder(&model.User{ID: "u-1"})
	logger, _ := auditCapture()
	h := &Handler{users: users, tokens: &mocks.MockRefreshTokenRepo{}, auditLog: logger}

	for name, call := range map[string]func(http.ResponseWriter, *http.Request){
		"require": h.RequirePasswordReset,
		"clear":   h.ClearPasswordReset,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			call(rec, forcedResetReq(http.MethodPost, "/admin/users//require-password-reset", "", `{}`))

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if body := decodeBody(t, rec); body["error"] != "missing_id" {
				t.Errorf("error = %v, want missing_id", body["error"])
			}
		})
	}
}

// A lookup failure is not "no such user": answering 404 would tell an operator
// the account is gone when the database is merely unreachable, and the honest
// answer is the 500 the routes beside it give.
func TestForcedResetRoutes_ALookupFailureIs500AndWritesNothing(t *testing.T) {
	for name, call := range map[string]string{"require": "require", "clear": "clear"} {
		t.Run(name, func(t *testing.T) {
			var wrote bool
			users := &mocks.MockUserRepo{
				GetByIDFn: func(context.Context, string) (*model.User, error) {
					return nil, errors.New("database unreachable")
				},
				SetMustResetPwFn: func(context.Context, string, bool) error { wrote = true; return nil },
			}
			logger, rows := auditCapture()
			h := &Handler{users: users, tokens: &mocks.MockRefreshTokenRepo{}, auditLog: logger}

			rec := httptest.NewRecorder()
			req := forcedResetReq(http.MethodPost, "/admin/users/u-1/x", "u-1", `{}`)
			if call == "require" {
				h.RequirePasswordReset(rec, req)
			} else {
				h.ClearPasswordReset(rec, req)
			}

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500", rec.Code)
			}
			if body := decodeBody(t, rec); body["error"] != "internal_error" {
				t.Errorf("error = %v, want internal_error", body["error"])
			}
			if wrote {
				t.Error("wrote the column after failing to read the account")
			}
			if len(*rows) != 0 {
				t.Errorf("audited a write that never happened: %+v", *rows)
			}
		})
	}
}

// A failed write must not leave an audit row saying it succeeded, and must not
// revoke the account's sessions: an operator reading "forced reset imposed" and
// a signed-out user would both be wrong about the account's state.
func TestRequirePasswordReset_AFailedWriteIs500WithNoAuditRowAndNoRevocation(t *testing.T) {
	var revoked bool
	users := &mocks.MockUserRepo{
		GetByIDFn: func(context.Context, string) (*model.User, error) { return &model.User{ID: "u-1"}, nil },
		SetMustResetPwFn: func(_ context.Context, _ string, required bool) error {
			if !required {
				t.Fatal("the require route cleared the flag")
			}
			return errors.New("refused by the trigger")
		},
	}
	logger, rows := auditCapture()
	h := &Handler{
		users: users,
		tokens: &mocks.MockRefreshTokenRepo{RevokeAllForUserFn: func(context.Context, string) error {
			revoked = true
			return nil
		}},
		auditLog: logger,
	}

	rec := httptest.NewRecorder()
	h.RequirePasswordReset(rec, forcedResetReq(http.MethodPost,
		"/admin/users/u-1/require-password-reset", "u-1", `{"reason":"takeover"}`))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if len(*rows) != 0 {
		t.Errorf("audited a forced reset the database refused: %+v", *rows)
	}
	if revoked {
		t.Error("signed the user out of every session over a reset that was never imposed")
	}
}

// ---------------------------------------------------------------------------
// Lifting the reset
// ---------------------------------------------------------------------------

func TestClearPasswordReset_LiftsTheFlagAndAuditsTheReason(t *testing.T) {
	users := newForcedResetRecorder(&model.User{ID: "u-1", MustResetPassword: true})
	logger, rows := auditCapture()
	h := &Handler{users: users, tokens: &mocks.MockRefreshTokenRepo{}, auditLog: logger}

	rec := httptest.NewRecorder()
	h.ClearPasswordReset(rec, forcedResetReq(http.MethodDelete,
		"/admin/users/u-1/clear-password-reset", "u-1", `{"reason":"set by mistake"}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body %s", rec.Code, rec.Body.String())
	}
	if len(users.clearCalls) != 1 || users.clearCalls[0] != "u-1" {
		t.Fatalf("clearing calls = %v, want [u-1]: the operator was told the demand "+
			"was withdrawn and the account is still refused", users.clearCalls)
	}
	if body := decodeBody(t, rec); body["status"] != "password_reset_not_required" {
		t.Errorf("status = %v, want password_reset_not_required", body["status"])
	}
	if len(*rows) != 1 {
		t.Fatalf("wrote %d audit rows, want 1", len(*rows))
	}
	row := (*rows)[0]
	if row.EventType != audit.AdminUserResetCleared {
		t.Errorf("event = %q, want %q", row.EventType, audit.AdminUserResetCleared)
	}
	if row.UserID != "adm-1" || row.Metadata["target_user"] != "u-1" {
		t.Errorf("actor = %q target_user = %v, want adm-1 / u-1", row.UserID, row.Metadata["target_user"])
	}
	if row.Metadata["reason"] != "set by mistake" {
		t.Errorf("reason = %v, want the operator's reason verbatim", row.Metadata["reason"])
	}
}

// Lifting a demand is not a containment action, so it revokes nothing. The
// asymmetry with the route above is the point: imposing the flag distrusts what
// is already issued, lifting it says the account is ordinary again, and signing
// the holder out on the way to telling them that would be gratuitous.
func TestClearPasswordReset_LeavesTheAccountsSessionsAlone(t *testing.T) {
	users := newForcedResetRecorder(&model.User{ID: "u-1", MustResetPassword: true})
	var revoked bool
	logger, _ := auditCapture()
	h := &Handler{
		users: users,
		tokens: &mocks.MockRefreshTokenRepo{RevokeAllForUserFn: func(context.Context, string) error {
			revoked = true
			return nil
		}},
		auditLog: logger,
	}

	rec := httptest.NewRecorder()
	h.ClearPasswordReset(rec, forcedResetReq(http.MethodDelete,
		"/admin/users/u-1/clear-password-reset", "u-1", `{}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if revoked {
		t.Error("lifting the demand signed the account out of every session it holds")
	}
}

func TestClearPasswordReset_AnUnknownOrErasedAccountIs404AndWritesNothing(t *testing.T) {
	cases := map[string]*model.User{
		"unknown": nil,
		"erased":  {ID: "u-1", Deleted: true},
	}
	for name, user := range cases {
		t.Run(name, func(t *testing.T) {
			users := newForcedResetRecorder(user)
			logger, rows := auditCapture()
			h := &Handler{users: users, tokens: &mocks.MockRefreshTokenRepo{}, auditLog: logger}

			rec := httptest.NewRecorder()
			h.ClearPasswordReset(rec, forcedResetReq(http.MethodDelete,
				"/admin/users/u-1/clear-password-reset", "u-1", `{}`))

			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404: body %s", rec.Code, rec.Body.String())
			}
			if len(users.clearCalls) != 0 {
				t.Errorf("wrote the column anyway: %v", users.clearCalls)
			}
			if len(*rows) != 0 {
				t.Errorf("audited a lift that did not happen: %+v", *rows)
			}
		})
	}
}

func TestClearPasswordReset_AFailedWriteIs500WithNoAuditRow(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByIDFn: func(context.Context, string) (*model.User, error) { return &model.User{ID: "u-1"}, nil },
		SetMustResetPwFn: func(_ context.Context, _ string, required bool) error {
			if required {
				t.Fatal("the clear route imposed the flag")
			}
			return errors.New("database unreachable")
		},
	}
	logger, rows := auditCapture()
	h := &Handler{users: users, tokens: &mocks.MockRefreshTokenRepo{}, auditLog: logger}

	rec := httptest.NewRecorder()
	h.ClearPasswordReset(rec, forcedResetReq(http.MethodDelete,
		"/admin/users/u-1/clear-password-reset", "u-1", `{}`))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if len(*rows) != 0 {
		t.Errorf("audited a lift the database refused: %+v", *rows)
	}
}

func TestClearPasswordReset_AnUnusableBodyStillRecordsAReason(t *testing.T) {
	users := newForcedResetRecorder(&model.User{ID: "u-1", MustResetPassword: true})
	logger, rows := auditCapture()
	h := &Handler{users: users, tokens: &mocks.MockRefreshTokenRepo{}, auditLog: logger}

	rec := httptest.NewRecorder()
	h.ClearPasswordReset(rec, forcedResetReq(http.MethodDelete,
		"/admin/users/u-1/clear-password-reset", "u-1", "not json"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := (*rows)[0].Metadata["reason"]; got != defaultClearResetReason {
		t.Errorf("reason = %v, want %q", got, defaultClearResetReason)
	}
}

// ---------------------------------------------------------------------------
// The routes through the real router and the real permission gate
// ---------------------------------------------------------------------------

// routerWithSessionAndUser is routerWithSession with a user repository the
// forced-reset routes can actually resolve an account through, so the success
// half of the gate is a 200 from the handler rather than a 404 from an empty
// repository.
func routerWithSessionAndUser(t *testing.T, role rbac.Role, user *model.User) (http.Handler, string, *forcedResetRecorder) {
	t.Helper()

	admins := newFakeAdminRepo()
	admin := &model.AdminUser{
		ID:           "00000000-0000-0000-0000-0000000000ab",
		Username:     "someone",
		Role:         string(role),
		TOTPVerified: true,
	}
	admins.users[admin.ID] = admin

	const token = "session-token-for-the-forced-reset-gate"
	sessions := newFakeSessionRepo()
	sessions.sessions["s1"] = &model.AdminSession{
		ID:        "s1",
		AdminID:   admin.ID,
		TokenHash: hashSessionToken(token),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	users := newForcedResetRecorder(user)
	api := newTestHandler(admins, users, nil, nil)
	api.sessions = sessions

	return NewRouter(newTestAuth(admins, sessions), api, RouterOpts{DevMode: true}), token, users
}

// Both directions of the lever are operator-tier containment, and the read-only
// role must not reach either. A viewer who could impose a forced reset could
// refuse an account's password login and mail its holder, which is a
// state-changing power on an account and exactly what the tier exists to deny.
func TestForcedResetRoutesDenyTheViewerTier(t *testing.T) {
	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodPost, "/admin/users/u-1/require-password-reset"},
		{http.MethodPost, "/admin/users/u-1/clear-password-reset"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			router, token, users := routerWithSessionAndUser(t, rbac.RoleViewer, &model.User{ID: "u-1"})

			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{"reason":"x"}`))
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403: a read-only admin moved an account's "+
					"password-reset state. Body: %s", rec.Code, rec.Body.String())
			}
			if len(users.setCalls)+len(users.clearCalls) != 0 {
				t.Errorf("the denial did not stop the write: set=%v clear=%v", users.setCalls, users.clearCalls)
			}
		})
	}
}

// The other direction, so the gate above cannot pass by refusing everyone.
func TestForcedResetRoutesAreAvailableToTheOperatorTier(t *testing.T) {
	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodPost, "/admin/users/u-1/require-password-reset"},
		{http.MethodPost, "/admin/users/u-1/clear-password-reset"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			router, token, _ := routerWithSessionAndUser(t, rbac.RoleOperator, &model.User{ID: "u-1"})

			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{"reason":"x"}`))
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: body %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// A caller with no admin session at all never reaches the handler. The routes
// are mounted behind SessionAuth like every other guarded route, so an
// unauthenticated request is refused before the account id is even read.
func TestForcedResetRoutesRejectAnUnauthenticatedCaller(t *testing.T) {
	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodPost, "/admin/users/u-1/require-password-reset"},
		{http.MethodPost, "/admin/users/u-1/clear-password-reset"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			router, _, users := routerWithSessionAndUser(t, rbac.RoleOperator, &model.User{ID: "u-1"})

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{"reason":"x"}`)))

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401: body %s", rec.Code, rec.Body.String())
			}
			if len(users.setCalls)+len(users.clearCalls) != 0 {
				t.Errorf("an unauthenticated request reached the repository: set=%v clear=%v",
					users.setCalls, users.clearCalls)
			}
		})
	}
}
