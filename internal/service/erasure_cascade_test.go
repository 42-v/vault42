package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// The cascade spans nine stores and the repositories are pool-backed, so there is
// no transaction to roll back with — every step must surface its own failure. A
// swallowed error anywhere here is the worst outcome this service has: DeleteAccount
// returns nil, the caller reports the account erased, the audit log records an
// erasure, and the user's data is still in the database. docs/PRIVACY.md §5.3 states
// otherwise, and under Art. 17 that statement is one a regulator would rely on.
//
// Each subtest fails exactly one step and asserts three things: the error surfaces,
// it names the step that failed, and the cascade stops rather than carrying on with
// the remaining deletes.
func TestDeleteAccount_EveryCascadeStepFailsClosed(t *testing.T) {
	boom := errors.New("db down")

	steps := []struct {
		name string
		want string
		fail func(*erasureMocks)
	}{
		{
			name: "loading the user",
			want: "load user",
			fail: func(m *erasureMocks) {
				m.users.GetByIDFn = func(context.Context, string) (*model.User, error) { return nil, boom }
			},
		},
		{
			name: "scrubbing the user row",
			want: "scrub user",
			fail: func(m *erasureMocks) {
				m.users.SoftDeleteScrubFn = func(context.Context, string, string) error { return boom }
			},
		},
		{
			name: "the identity profile",
			want: "delete identity",
			fail: func(m *erasureMocks) {
				m.identity.DeleteFn = func(context.Context, string) error { return boom }
			},
		},
		{
			name: "encrypted blobs",
			want: "delete blobs",
			fail: func(m *erasureMocks) {
				m.blobs.DeleteAllForPseudonymFn = func(context.Context, string) error { return boom }
			},
		},
		{
			name: "devices",
			want: "delete devices",
			fail: func(m *erasureMocks) {
				m.devices.DeleteAllForUserFn = func(context.Context, string) error { return boom }
			},
		},
		{
			name: "linked social accounts",
			want: "delete social accounts",
			fail: func(m *erasureMocks) {
				m.social.DeleteAllForUserFn = func(context.Context, string) error { return boom }
			},
		},
		{
			name: "password history",
			want: "delete password history",
			fail: func(m *erasureMocks) {
				m.pwHistory.DeleteAllForUserFn = func(context.Context, string) error { return boom }
			},
		},
	}

	for _, tc := range steps {
		t.Run(tc.name, func(t *testing.T) {
			m := newErasureMocks()

			// The refresh-token purge is the last step of the cascade. If it runs, the
			// erasure carried on past a store it had already failed to clear.
			var reachedEnd bool
			m.tokens.DeleteAllForUserFn = func(context.Context, string) error {
				reachedEnd = true
				return nil
			}
			tc.fail(m)

			// recoveryPub nil: recovery escrow is disabled, so this exercises the cascade
			// itself rather than the escrow that guards it.
			svc := newErasureService(t, nil, m)

			err := svc.DeleteAccount(context.Background(), "user-1", "self", "user_request")

			if err == nil {
				t.Fatalf("%s failed, but DeleteAccount reported the account erased", tc.name)
			}
			if !errors.Is(err, boom) {
				t.Errorf("error does not wrap the underlying failure, so the caller cannot tell what went wrong: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name the step that failed (want it to mention %q)", err, tc.want)
			}
			if reachedEnd {
				t.Error("the cascade ran to completion despite a failed step — a partial erasure reported as a whole one")
			}
		})
	}
}
