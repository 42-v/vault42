package service

import (
	"context"
	"errors"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
)

// Detecting a replay is worth nothing if the family survives it.
//
// The revocation used to run on the request's own context and its error went
// nowhere, while ErrReplayDetected and an audit row reading
// reason=replay_detected were returned unconditionally. That put the single
// containment the rotation design rests on in the hands of the party being
// contained: replay a used token, drop the connection before the UPDATE
// commits, and RevokeFamily returns context.Canceled with the family still
// live -- and the trail says it was revoked.

func TestReplayRevocationSurvivesTheCallerHangingUp(t *testing.T) {
	var sawCanceled bool
	var revokedFamily string

	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
				Used:      true,
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		}
		o.tokenRepo.RevokeFamilyFn = func(ctx context.Context, familyID string) error {
			// The store sees a live context even though the caller's is dead.
			// A repository that honors cancellation -- pgx does -- would
			// otherwise refuse this write.
			if ctx.Err() != nil {
				sawCanceled = true
				return ctx.Err()
			}
			revokedFamily = familyID
			return nil
		}
	})

	// The client hangs up before the service is even entered, which is the
	// strongest form of the race: everything downstream sees a dead context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := svc.Refresh(ctx, "used-token", "1.2.3.4", "TestAgent", vaultcrypto.FingerprintInput{})

	if !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("err = %v, want ErrReplayDetected", err)
	}
	if sawCanceled {
		t.Error("the revocation ran on a canceled context. The attacker replaying the token " +
			"decides whether the family it belongs to is revoked, which is the one thing " +
			"replay detection exists to take away from them.")
	}
	if revokedFamily != "fam-1" {
		t.Errorf("family revoked = %q, want fam-1: the replay was detected and the family "+
			"it belongs to survived it", revokedFamily)
	}
}

// A revocation that fails must not change the answer to the caller. The replay
// is still a replay, and the token is still refused -- what changes is only
// what the trail records, which is asserted where the audit repository is
// reachable rather than here.
func TestReplayIsStillRefusedWhenTheRevocationFails(t *testing.T) {
	svc, _ := newMockAuthService(t, func(o *mockAuthOpts) {
		o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
			return &model.RefreshToken{
				ID: "rt-1", UserID: "user-1", FamilyID: "fam-1",
				Used:      true,
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		}
		o.tokenRepo.RevokeFamilyFn = func(context.Context, string) error {
			return errors.New("connection reset")
		}
	})

	if _, err := svc.Refresh(context.Background(), "used-token", "1.2.3.4", "TestAgent",
		vaultcrypto.FingerprintInput{}); !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("err = %v, want ErrReplayDetected: a failed containment must not turn a "+
			"replayed token into an accepted one", err)
	}
}
