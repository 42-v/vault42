package adminapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// The operator half of the ban feature (migration 043).
//
// The read side has worked since 004: login answers 403 account_banned and the
// frontend renders it. What did not exist was a writer. 024 revoked the columns
// from vault_app and recorded that ban_reason then had none at all, and the only
// thing that has set either since is the import path, which carries the flag in
// its INSERT. So an account could arrive banned and never be unbanned.
//
// What these routes must not become is a second lock. A lock expires; a ban
// holds until an operator lifts it, and it is the state login answers with its
// own error code. The assertions below pin what the routes do -- the columns,
// the sessions, the audit row -- and, as deliberately, what they do not: unban
// revokes nothing, and neither route touches any other account-state flag.

// banRecorder is a user repository that records the SetBanned calls the routes
// make, over a single account whose state the test can inspect.
//
// Hand-written rather than a bare mocks.MockUserRepo because both routes read
// the account before writing it, and the ordering is part of what is tested: a
// 404 must mean nothing was written.
type banRecorder struct {
	*mocks.MockUserRepo
	calls []banCall
	err   error
}

type banCall struct {
	id     string
	banned bool
	reason string
}

func newBanRecorder(user *model.User) *banRecorder {
	rec := &banRecorder{}
	rec.MockUserRepo = &mocks.MockUserRepo{
		GetByIDFn: func(context.Context, string) (*model.User, error) { return user, nil },
		SetBannedFn: func(_ context.Context, id string, banned bool, reason string) error {
			if rec.err != nil {
				return rec.err
			}
			rec.calls = append(rec.calls, banCall{id: id, banned: banned, reason: reason})
			return nil
		},
	}
	return rec
}

// banReq builds a request already carrying {id} and an authenticated operator,
// which is what the router hands the handler.
func banReq(path, id, body string) *http.Request {
	return forcedResetReq(http.MethodPost, path, id, body)
}

// ---------------------------------------------------------------------------
// Imposing the ban
// ---------------------------------------------------------------------------

// The whole point of the route: both columns move, the sessions go, and the
// audit trail carries the operator's reason for it.
//
// The reason is not decoration. A ban holds until somebody lifts it, so an
// operator reading the trail months later has to be able to tell "payment fraud,
// ticket OPS-4471" from "test account", which are the same row otherwise. It is
// also persisted, which is what separates this from the forced-reset pair: the
// reason is on the account, not only in the trail.
func TestBanUser_SetsTheFlagWithAReasonAndRevokesSessions(t *testing.T) {
	users := newBanRecorder(&model.User{ID: "u-1", Email: "rider@example.test"})
	logger, rows := auditCapture()
	revoked := 0
	tokens := &mocks.MockRefreshTokenRepo{
		RevokeAllForUserFn: func(context.Context, string) error { revoked++; return nil },
	}
	h := &Handler{users: users, tokens: tokens, auditLog: logger}

	rec := httptest.NewRecorder()
	h.BanUser(rec, banReq("/admin/users/u-1/ban", "u-1", `{"reason":"payment fraud, ticket OPS-4471"}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body %s", rec.Code, rec.Body.String())
	}
	if len(users.calls) != 1 {
		t.Fatalf("SetBanned calls = %v, want exactly one", users.calls)
	}
	got := users.calls[0]
	if got.id != "u-1" || !got.banned {
		t.Fatalf("SetBanned(%q, %v), want (u-1, true)", got.id, got.banned)
	}
	if got.reason != "payment fraud, ticket OPS-4471" {
		t.Errorf("persisted reason = %q, want the operator's. It goes to auth.users.ban_reason, "+
			"which is where an operator reads back why the account is shut.", got.reason)
	}
	if revoked != 1 {
		t.Errorf("RevokeAllForUser called %d times, want 1. Nothing on the refresh path reads "+
			"banned, so without this the account keeps rotating its family and never meets the "+
			"ban -- containment the route reports and does not deliver.", revoked)
	}

	body := decodeBody(t, rec)
	if body["status"] != "banned" || body["sessions_revoked"] != true {
		t.Errorf("body = %v, want status=banned and sessions_revoked=true so the operator reads "+
			"the blast radius off the answer", body)
	}

	if len(*rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(*rows))
	}
	row := (*rows)[0]
	if row.EventType != audit.AdminUserBan {
		t.Errorf("event = %q, want %q", row.EventType, audit.AdminUserBan)
	}
	if row.Metadata["target_user"] != "u-1" ||
		row.Metadata["reason"] != "payment fraud, ticket OPS-4471" ||
		row.Metadata["sessions_revoked"] != true {
		t.Errorf("audit metadata = %v, want the target, the reason and the revocation outcome", row.Metadata)
	}
}

// A bare curl with no body is the operator responding to an incident at speed.
// Refusing it would answer 400 where a ban was wanted, so the route bans anyway
// and records a reason that names the action -- never an absent field, or a
// query over the trail filtering on reason would silently skip it.
func TestBanUser_NoBodyStillBansAndRecordsANamedReason(t *testing.T) {
	users := newBanRecorder(&model.User{ID: "u-1"})
	logger, rows := auditCapture()
	h := &Handler{users: users, tokens: &mocks.MockRefreshTokenRepo{}, auditLog: logger}

	rec := httptest.NewRecorder()
	h.BanUser(rec, banReq("/admin/users/u-1/ban", "u-1", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(users.calls) != 1 || users.calls[0].reason != defaultBanReason {
		t.Fatalf("SetBanned calls = %v, want one carrying %q", users.calls, defaultBanReason)
	}
	if (*rows)[0].Metadata["reason"] != defaultBanReason {
		t.Errorf("audit reason = %v, want %q", (*rows)[0].Metadata["reason"], defaultBanReason)
	}
}

// The operator's text is free-form and lands in two places that outlive the
// account: a VARCHAR(500) column and a JSONB audit row. sanitize.String bounds
// and neutralizes it, and the assertion here is on the boundary rather than the
// constant, so a change to either has to be made deliberately.
func TestBanUser_TheReasonIsSanitizedAndBounded(t *testing.T) {
	users := newBanRecorder(&model.User{ID: "u-1"})
	logger, _ := auditCapture()
	h := &Handler{users: users, tokens: &mocks.MockRefreshTokenRepo{}, auditLog: logger}

	long := strings.Repeat("é", 400) + "<script>"
	rec := httptest.NewRecorder()
	h.BanUser(rec, banReq("/admin/users/u-1/ban", "u-1", `{"reason":"`+long+`"}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	stored := users.calls[0].reason
	if n := len([]rune(stored)); n > 200 {
		t.Errorf("persisted reason is %d runes; the bound is 200. The column is VARCHAR(500) and "+
			"counts characters, so an unbounded reason fails the whole UPDATE rather than "+
			"truncating, and the ban never lands.", n)
	}
	if strings.Contains(stored, "<script>") {
		t.Errorf("persisted reason carries raw markup: %q", stored)
	}
}

// An id that resolves to nothing must write nothing. LockUser hands an unknown
// id straight to the repository and reports success; these routes read first,
// through the same liveUser the forced-reset pair uses, so an operator who
// mistypes an id learns it here rather than from the account that never got
// banned.
func TestBanUser_UnknownOrErasedAccountWritesNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		user *model.User
	}{
		{"no such account", nil},
		{
			"an erased account is a tombstone, not a person to sanction",
			&model.User{ID: "u-1", Deleted: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			users := newBanRecorder(tc.user)
			logger, rows := auditCapture()
			h := &Handler{users: users, tokens: &mocks.MockRefreshTokenRepo{}, auditLog: logger}

			rec := httptest.NewRecorder()
			h.BanUser(rec, banReq("/admin/users/u-1/ban", "u-1", `{"reason":"x"}`))

			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", rec.Code)
			}
			if len(users.calls) != 0 {
				t.Errorf("SetBanned was called %v on an account the route refused", users.calls)
			}
			if len(*rows) != 0 {
				t.Errorf("a refused ban wrote an audit row: %v", *rows)
			}
		})
	}
}

// The write failing is the one case where the operator must not be told the
// account is banned. It is the opposite of the revocation below, which is
// best-effort precisely because the ban has already committed by then.
func TestBanUser_AFailedWriteIs500AndAuditsNothing(t *testing.T) {
	users := newBanRecorder(&model.User{ID: "u-1"})
	users.err = errors.New("42501: permission denied for column banned")
	logger, rows := auditCapture()
	h := &Handler{users: users, tokens: &mocks.MockRefreshTokenRepo{}, auditLog: logger}

	rec := httptest.NewRecorder()
	h.BanUser(rec, banReq("/admin/users/u-1/ban", "u-1", `{"reason":"x"}`))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if len(*rows) != 0 {
		t.Errorf("a ban that did not land wrote an audit row saying it did: %v", *rows)
	}
}

// Revocation is best-effort and is REPORTED rather than performed quietly. Both
// ways it can fail have to reach the operator as sessions_revoked=false: a
// repository that is not wired at all, and one whose call returns an error.
//
// The nil case is not hypothetical. This repository arrives as a positional
// argument, cmd/admin-gateway has passed nil for it before, and the dereference
// landed after the write had committed on exactly this kind of route.
func TestBanUser_ReportsAFailedRevocationRatherThanFailingTheBan(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tokens *mocks.MockRefreshTokenRepo
	}{
		{"the repository is not wired", nil},
		{"the revocation itself fails", &mocks.MockRefreshTokenRepo{
			RevokeAllForUserFn: func(context.Context, string) error {
				return errors.New("connection reset")
			},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			users := newBanRecorder(&model.User{ID: "u-1"})
			logger, rows := auditCapture()
			h := &Handler{users: users, auditLog: logger}
			if tc.tokens != nil {
				h.tokens = tc.tokens
			}

			rec := httptest.NewRecorder()
			h.BanUser(rec, banReq("/admin/users/u-1/ban", "u-1", `{"reason":"x"}`))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200: the ban committed, and failing here would tell "+
					"the operator no ban was imposed when one was", rec.Code)
			}
			if len(users.calls) != 1 || !users.calls[0].banned {
				t.Fatalf("SetBanned calls = %v, want the ban to have landed", users.calls)
			}
			if body := decodeBody(t, rec); body["sessions_revoked"] != false {
				t.Errorf("sessions_revoked = %v, want false so the operator knows the account is "+
					"banned but its live sessions are not gone", body["sessions_revoked"])
			}
			if (*rows)[0].Metadata["sessions_revoked"] != false {
				t.Errorf("audit sessions_revoked = %v, want false",
					(*rows)[0].Metadata["sessions_revoked"])
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Lifting the ban
// ---------------------------------------------------------------------------

// Unban clears both columns and revokes nothing. The asymmetry is the whole of
// the design: imposing a sanction says the access already issued is not to be
// trusted; lifting one says the account is ordinary again, and signing the
// holder out on the way to telling them so would attach a containment action to
// the one verb here that is not one.
func TestUnbanUser_ClearsTheFlagAndTheReasonAndRevokesNothing(t *testing.T) {
	users := newBanRecorder(&model.User{ID: "u-1", Banned: true, BanReason: "payment fraud"})
	logger, rows := auditCapture()
	revoked := 0
	tokens := &mocks.MockRefreshTokenRepo{
		RevokeAllForUserFn: func(context.Context, string) error { revoked++; return nil },
	}
	h := &Handler{users: users, tokens: tokens, auditLog: logger}

	rec := httptest.NewRecorder()
	h.UnbanUser(rec, banReq("/admin/users/u-1/unban", "u-1", `{"reason":"appeal upheld"}`))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: body %s", rec.Code, rec.Body.String())
	}
	if len(users.calls) != 1 {
		t.Fatalf("SetBanned calls = %v, want exactly one", users.calls)
	}
	got := users.calls[0]
	if got.banned {
		t.Fatalf("SetBanned(banned=%v), want false", got.banned)
	}
	if got.reason != "" {
		t.Errorf("SetBanned reason = %q, want empty. A reason left attached to a lifted ban reads "+
			"as an account that is still sanctioned.", got.reason)
	}
	if revoked != 0 {
		t.Errorf("RevokeAllForUser called %d times; lifting a ban is not a containment action", revoked)
	}
	if body := decodeBody(t, rec); body["status"] != "not_banned" {
		t.Errorf("status = %v, want not_banned", body["status"])
	}

	row := (*rows)[0]
	if row.EventType != audit.AdminUserUnban {
		t.Errorf("event = %q, want %q", row.EventType, audit.AdminUserUnban)
	}
	// The reason on THIS row is why the ban was lifted. Why it was imposed is on
	// the imposing row, which is the only place it survives once the column is
	// cleared.
	if row.Metadata["reason"] != "appeal upheld" || row.Metadata["target_user"] != "u-1" {
		t.Errorf("audit metadata = %v, want the target and why the ban was lifted", row.Metadata)
	}
	if _, ok := row.Metadata["sessions_revoked"]; ok {
		t.Errorf("the unban row carries sessions_revoked: %v. It revokes nothing, and a field "+
			"reading false would read as a revocation that failed.", row.Metadata)
	}
}

func TestUnbanUser_NoBodyRecordsANamedReason(t *testing.T) {
	users := newBanRecorder(&model.User{ID: "u-1", Banned: true})
	logger, rows := auditCapture()
	h := &Handler{users: users, tokens: &mocks.MockRefreshTokenRepo{}, auditLog: logger}

	rec := httptest.NewRecorder()
	h.UnbanUser(rec, banReq("/admin/users/u-1/unban", "u-1", ""))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if (*rows)[0].Metadata["reason"] != defaultUnbanReason {
		t.Errorf("audit reason = %v, want %q", (*rows)[0].Metadata["reason"], defaultUnbanReason)
	}
}

func TestUnbanUser_UnknownAccountWritesNothing(t *testing.T) {
	users := newBanRecorder(nil)
	logger, rows := auditCapture()
	h := &Handler{users: users, tokens: &mocks.MockRefreshTokenRepo{}, auditLog: logger}

	rec := httptest.NewRecorder()
	h.UnbanUser(rec, banReq("/admin/users/u-1/unban", "u-1", ""))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if len(users.calls) != 0 || len(*rows) != 0 {
		t.Errorf("a refused unban wrote: calls=%v rows=%v", users.calls, *rows)
	}
}

func TestUnbanUser_AFailedWriteIs500AndAuditsNothing(t *testing.T) {
	users := newBanRecorder(&model.User{ID: "u-1", Banned: true})
	users.err = errors.New("42501: permission denied for column ban_reason")
	logger, rows := auditCapture()
	h := &Handler{users: users, tokens: &mocks.MockRefreshTokenRepo{}, auditLog: logger}

	rec := httptest.NewRecorder()
	h.UnbanUser(rec, banReq("/admin/users/u-1/unban", "u-1", ""))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if len(*rows) != 0 {
		t.Errorf("an unban that did not land wrote an audit row saying it did: %v", *rows)
	}
}
