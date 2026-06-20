package service

import (
	"context"
	"errors"
	"testing"
)

// L1: on a session-count query error, the default fails open (login allowed),
// but strict mode fails closed (ErrTooManySessions).
func TestCheckSessionLimit_CountErrorFailMode(t *testing.T) {
	svc, o := newMockAuthService(t)
	svc.SetMaxSessionsPerUser(5)
	o.tokenRepo.CountActiveFamiliesFn = func(_ context.Context, _ string) (int, error) {
		return 0, errors.New("db down")
	}

	t.Run("default fails open", func(t *testing.T) {
		if err := svc.checkSessionLimit(context.Background(), "u1"); err != nil {
			t.Fatalf("default mode should fail open, got %v", err)
		}
	})

	t.Run("strict fails closed", func(t *testing.T) {
		svc.SetStrictSessionLimit(true)
		if err := svc.checkSessionLimit(context.Background(), "u1"); !errors.Is(err, ErrTooManySessions) {
			t.Fatalf("strict mode should fail closed, got %v", err)
		}
	})
}
