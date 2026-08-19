package compliance

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/repository/postgres"
)

// TestASVS_V2_3_4_ConcurrentSessionCapIsLocked is the evidence for OWASP ASVS
// V2.3.4: a limited-quantity resource, here the per-user concurrent-session cap,
// cannot be pushed past its bound by racing the application's logic.
//
// The cap is a distinct-active-family count that a login reads and then inserts
// against. Read and insert as two separate statements, simultaneous logins each
// see the same free slot and each insert, so a cap of N admits N+k for k racing
// logins. AuthService.storeRefreshToken issues the insert through
// RefreshTokenRepository.CreateWithinCap, which counts and inserts under one
// per-user advisory lock so the two steps are a single unit of work. This test
// drives that method exactly as the login path does, from many goroutines
// released together, and asserts the committed family count is the cap and not a
// row more.
func TestASVS_V2_3_4_ConcurrentSessionCapIsLocked(t *testing.T) {
	pool, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	repo := postgres.NewRefreshTokenRepo(&postgres.DB{Pool: pool})

	userID, _ := vaultcrypto.RandomUUID()
	userHash, _ := vaultcrypto.HashPassword("correct-horse-battery-staple")
	if _, err := pool.Exec(ctx, `
		INSERT INTO auth.users (id, email, email_verified, password_hash, display_name, created_at, updated_at)
		VALUES ($1, $2, true, $3, 'cap', NOW(), NOW())`, userID, "cap-race@test.com", userHash); err != nil {
		t.Fatalf("insert test user: %v", err)
	}

	const (
		sessionCap = 3
		goroutines = 12
	)

	var (
		wg         sync.WaitGroup
		admitted   int64
		refused    int64
		unexpected int64
		start      = make(chan struct{})
	)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			id, _ := vaultcrypto.RandomUUID()
			fam, _ := vaultcrypto.RandomUUID()
			token := &model.RefreshToken{
				ID: id, UserID: userID, TokenHash: vaultcrypto.SHA256Hex(id + fam),
				FamilyID: fam, ExpiresAt: time.Now().Add(24 * time.Hour), CreatedAt: time.Now(),
			}

			<-start // release every goroutine into the cap at once
			switch err := repo.CreateWithinCap(ctx, token, sessionCap); {
			case err == nil:
				atomic.AddInt64(&admitted, 1)
			case errors.Is(err, repository.ErrSessionLimitReached):
				atomic.AddInt64(&refused, 1)
			default:
				atomic.AddInt64(&unexpected, 1)
			}
		}()
	}

	close(start)
	wg.Wait()

	if n := atomic.LoadInt64(&unexpected); n != 0 {
		t.Fatalf("%d logins failed for a reason other than the cap", n)
	}
	if got := atomic.LoadInt64(&admitted); got != sessionCap {
		t.Fatalf("admitted %d families, want exactly the cap of %d", got, sessionCap)
	}
	if got := atomic.LoadInt64(&refused); got != goroutines-sessionCap {
		t.Fatalf("refused %d logins, want %d", got, goroutines-sessionCap)
	}

	active, err := repo.CountActiveFamilies(ctx, userID)
	if err != nil {
		t.Fatalf("count active families: %v", err)
	}
	if active != sessionCap {
		t.Fatalf("committed %d active families, want the cap of %d; the cap was overshot under concurrency", active, sessionCap)
	}
}
