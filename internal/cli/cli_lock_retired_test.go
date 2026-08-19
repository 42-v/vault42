package cli

import (
	"context"
	"strings"
	"testing"
	"time"
)

// lock-user and unlock-user used to run as the vault_app role and write
// auth.users.locked_until directly: no audit row, no session revocation, and
// because vault_app writes the same column the admin plane uses for containment,
// able to release or override a lock an admin had imposed. Both are retired in
// favor of POST /admin/users/{id}/lock and /unlock on the admin gateway, which
// audits the action, revokes the target's refresh tokens, and runs as
// vault_admin. The CLI must refuse the action, name the admin route, stay a
// recognized command (so cmd/vault does not fall through to booting the
// server), and never touch the users repository.

func TestLockUser_RetiredDoesNotWriteAndPointsAtAdminPlane(t *testing.T) {
	c, _, users, _, _, token := setupAuthenticatedCLI(t)
	called := false
	users.LockUntilFn = func(_ context.Context, _ string, _ time.Time) error {
		called = true
		return nil
	}

	args := []string{"vault", "lock-user", "--admin-token", token, "--id", "user-42"}
	stderr := captureStderr(t, func() {
		if handled := c.Run(context.Background(), args); !handled {
			t.Error("lock-user must stay a recognized command so it does not fall through to booting the server")
		}
	})

	if called {
		t.Error("lock-user issued a vault_app LockUntil write; the admin lock must not be settable from cmd/vault")
	}
	if !strings.Contains(stderr, "/admin/users") || !strings.Contains(stderr, "lock") {
		t.Errorf("lock-user did not point the operator at the admin route: %q", stderr)
	}
}

func TestUnlockUser_RetiredDoesNotWriteAndPointsAtAdminPlane(t *testing.T) {
	c, _, users, _, _, token := setupAuthenticatedCLI(t)
	called := false
	users.UnlockFn = func(_ context.Context, _ string) error {
		called = true
		return nil
	}

	args := []string{"vault", "unlock-user", "--admin-token", token, "--id", "user-42"}
	stderr := captureStderr(t, func() {
		if handled := c.Run(context.Background(), args); !handled {
			t.Error("unlock-user must stay a recognized command so it does not fall through to booting the server")
		}
	})

	if called {
		t.Error("unlock-user issued a vault_app Unlock write; releasing an admin lock must not be possible from cmd/vault")
	}
	if !strings.Contains(stderr, "/admin/users") || !strings.Contains(stderr, "unlock") {
		t.Errorf("unlock-user did not point the operator at the admin route: %q", stderr)
	}
}
