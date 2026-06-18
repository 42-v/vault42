package service

import (
	"context"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// WS3: an import_pending account's first login must NOT verify the password and
// must return ImportClaimRequired with no session issued (a magic claim link is
// emailed asynchronously).
func TestLogin_ImportPendingMintsClaimLink(t *testing.T) {
	var pwPathHit bool
	svc, o := newMockAuthService(t)
	o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
		return &model.User{
			ID: "u-imp", Email: "rider@beon3.test", EmailVerified: true,
			ImportPending: true, ImportedFrom: "beon3", // no password hash
		}, nil
	}
	// IncrementFailedLogin only fires on a wrong-password verify — it must not be
	// reached for an import-pending account.
	o.userRepo.IncrementFailedLoginFn = func(_ context.Context, _ string) error { pwPathHit = true; return nil }

	res, err := svc.Login(context.Background(), LoginInput{Email: "rider@beon3.test", Password: "anything"}, "1.2.3.4", "UA")
	if err != nil {
		t.Fatalf("import-pending login should not error, got %v", err)
	}
	if res == nil || !res.ImportClaimRequired {
		t.Fatalf("expected ImportClaimRequired, got %+v", res)
	}
	if res.AccessToken != "" || res.RefreshToken != "" || res.Requires2FA {
		t.Error("no session/challenge must be issued for an import-pending login")
	}
	if pwPathHit {
		t.Error("password verification path must not run for an import-pending account")
	}
}
