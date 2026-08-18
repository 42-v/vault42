package httputil

import (
	"errors"
	"fmt"
	"testing"
)

func TestRedactDSN(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want string
	}{
		"postgres scheme": {
			in:   "failed to connect to `postgres://vault_app:hunter2@db:5432/vault`: timeout",
			want: "failed to connect to `postgres://***:***@db:5432/vault`: timeout",
		},
		"postgresql scheme": {
			in:   "failed to connect to `postgresql://vault_app:hunter2@db:5432/vault`: timeout",
			want: "failed to connect to `postgresql://***:***@db:5432/vault`: timeout",
		},
		"a password containing a space": {
			in:   "connect: postgres://vault_app:hunter 2@db:5432/vault refused",
			want: "connect: postgres://***:***@db:5432/vault refused",
		},
		"nothing that looks like a DSN": {
			in:   "relation \"auth.account_recovery\" does not exist",
			want: "relation \"auth.account_recovery\" does not exist",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := RedactDSN(errors.New(tc.in)).Error(); got != tc.want {
				t.Errorf("RedactDSN =\n%q\nwant\n%q", got, tc.want)
			}
		})
	}
}

func TestRedactDSN_NilStaysNil(t *testing.T) {
	if RedactDSN(nil) != nil {
		t.Error("RedactDSN(nil) is not nil")
	}
}

// The cause is deliberately dropped rather than wrapped: leaving it in the chain
// would let errors.As reach the original and print the DSN the redaction just
// removed.
func TestRedactDSN_DoesNotKeepTheUnredactedCauseInTheChain(t *testing.T) {
	cause := errors.New("failed to connect to `postgres://vault_app:hunter2@db:5432/vault`")
	got := RedactDSN(fmt.Errorf("connect: %w", cause))
	if errors.Is(got, cause) {
		t.Error("the unredacted cause is still reachable through the error chain")
	}
}
