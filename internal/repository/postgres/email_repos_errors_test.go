package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/42-v/vault42/internal/model"
)

// deadPool returns a pool whose connections can never be established. pgxpool
// connects lazily, so construction succeeds and every query fails — which is
// exactly the shape of a database outage at runtime.
func deadPool(t *testing.T) *DB {
	t.Helper()
	// Port 1 is reserved and nothing listens there.
	pool, err := pgxpool.New(context.Background(), "postgres://vault:vault@127.0.0.1:1/vault?connect_timeout=1")
	if err != nil {
		t.Fatalf("build pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return &DB{Pool: pool}
}

// The white-label email repositories decide what a tenant's mail looks like and
// who it comes from. If a read failure returned a nil branding with a nil error,
// the mailer would silently fall back to the global template and send under the
// operator's own From address — a tenant's mail going out branded as somebody
// else's, with no error anywhere to explain it. Every one of these must surface
// the failure instead of degrading quietly.
func TestEmailBrandingRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewEmailBrandingRepo(deadPool(t))
	ctx := context.Background()

	if _, err := repo.Get(ctx, "beon3"); err == nil {
		t.Error("Get returned no error against an unreachable database")
	}
	if _, err := repo.List(ctx); err == nil {
		t.Error("List returned no error against an unreachable database")
	}
	if err := repo.Upsert(ctx, &model.EmailBranding{App: "beon3", AppName: "BeOn3"}); err == nil {
		t.Error("Upsert reported success against an unreachable database")
	}
	if err := repo.Delete(ctx, "beon3"); err == nil {
		t.Error("Delete reported success against an unreachable database")
	}
}

func TestEmailTemplateRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewEmailTemplateRepo(deadPool(t))
	ctx := context.Background()

	if _, err := repo.Get(ctx, "beon3", "verify_email"); err == nil {
		t.Error("Get returned no error against an unreachable database")
	}
	if _, err := repo.ListByApp(ctx, "beon3"); err == nil {
		t.Error("ListByApp returned no error against an unreachable database")
	}
	if _, err := repo.List(ctx); err == nil {
		t.Error("List returned no error against an unreachable database")
	}
	if err := repo.Upsert(ctx, &model.EmailTemplate{App: "beon3", TemplateName: "verify_email"}); err == nil {
		t.Error("Upsert reported success against an unreachable database")
	}
	if err := repo.Delete(ctx, "beon3", "verify_email"); err == nil {
		t.Error("Delete reported success against an unreachable database")
	}
}

// A malformed connection string must be rejected at construction. Returning a
// usable *DB here would defer the failure to the first query, long after the
// process has reported itself healthy.
func TestNew_RejectsMalformedConnString(t *testing.T) {
	if _, err := New(context.Background(), "://not a dsn", 5); err == nil {
		t.Error("New accepted a malformed connection string")
	}
}

// The TOTP secret is the MFA seed. A write that fails must say so — a silent
// failure here enrols a user in TOTP whose secret was never stored, locking them
// out of their own account at the next login.
func TestTOTPRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewTOTPRepo(deadPool(t))
	ctx := context.Background()

	err := repo.Create(ctx, &model.TOTPSecret{
		ID: "t-1", UserID: "u-1", SecretEnc: "enc",
	})
	if err == nil {
		t.Error("Create reported success against an unreachable database")
	}
	if _, err := repo.GetByUserID(ctx, "u-1"); err == nil {
		t.Error("GetByUserID returned no error, an enrolled user would look like they have no TOTP")
	}
	if err := repo.MarkVerified(ctx, "t-1"); err == nil {
		t.Error("MarkVerified reported success against an unreachable database")
	}
	if err := repo.DeleteByUserID(ctx, "u-1"); err == nil {
		t.Error("DeleteByUserID reported success, a user disabling TOTP would keep the old secret")
	}
}

// The admin-user repository backs the break-glass gateway. A write that fails
// silently here is the worst kind: an operator locks an admin out, or revokes a
// compromised admin, is told it worked, and it did not. Every one of these must
// surface the failure.
func TestAdminUserRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewAdminUserRepo(deadPool(t))
	ctx := context.Background()
	admin := &model.AdminUser{ID: "a-1", Username: "root", PasswordHash: "$argon2id$h"}

	if err := repo.Create(ctx, admin); err == nil {
		t.Error("Create reported success against an unreachable database")
	}
	if _, err := repo.GetByID(ctx, "a-1"); err == nil {
		t.Error("GetByID returned no error against an unreachable database")
	}
	if _, err := repo.GetByUsername(ctx, "root"); err == nil {
		t.Error("GetByUsername returned no error against an unreachable database")
	}
	if _, err := repo.List(ctx); err == nil {
		t.Error("List returned no error against an unreachable database")
	}
	if _, err := repo.Count(ctx); err == nil {
		t.Error("Count returned no error against an unreachable database")
	}
	if err := repo.Update(ctx, admin); err == nil {
		t.Error("Update reported success against an unreachable database")
	}
	if _, err := repo.IncrementFailedLogin(ctx, "a-1"); err == nil {
		t.Error("IncrementFailedLogin returned no error — lockout counting would silently stop")
	}
	if err := repo.ResetFailedLogin(ctx, "a-1"); err == nil {
		t.Error("ResetFailedLogin reported success against an unreachable database")
	}
	if err := repo.LockUntil(ctx, "a-1", time.Now().Add(time.Hour)); err == nil {
		t.Error("LockUntil reported success — an admin believed locked would still be able to log in")
	}
	if err := repo.UpdateLastTOTPCounter(ctx, "a-1", 42); err == nil {
		t.Error("UpdateLastTOTPCounter reported success — TOTP replay protection depends on this persisting")
	}
	if err := repo.UpdateLastLogin(ctx, "a-1"); err == nil {
		t.Error("UpdateLastLogin reported success against an unreachable database")
	}
	if err := repo.Revoke(ctx, "a-1"); err == nil {
		t.Error("Revoke reported success — a compromised admin would remain active")
	}
}

// admin_config holds the admin token hash. A Set that fails silently would leave
// the operator holding a rotated token the server has never seen.
func TestAdminConfigRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewAdminConfigRepo(deadPool(t))
	ctx := context.Background()

	if _, err := repo.List(ctx); err == nil {
		t.Error("List returned no error against an unreachable database")
	}
	if _, err := repo.Get(ctx, "admin_token_hash"); err == nil {
		t.Error("Get returned no error against an unreachable database")
	}
	if err := repo.Set(ctx, "admin_token_hash", "$argon2id$h"); err == nil {
		t.Error("Set reported success — the operator would save a token the server never stored")
	}
	if err := repo.Delete(ctx, "admin_token_hash"); err == nil {
		t.Error("Delete reported success against an unreachable database")
	}
	// ClaimIfAbsent answers the cross-plane HMAC_SECRET check. Returning ("",
	// nil) here would read as "the other plane recorded an empty fingerprint",
	// a value no plane ever records, so the caller would report a disagreement
	// that is really a database outage and refuse to start over it.
	if _, err := repo.ClaimIfAbsent(ctx, "hmac_secret_fingerprint", "deadbeef"); err == nil {
		t.Error("ClaimIfAbsent reported success against an unreachable database")
	}
}

// The recovery escrow is the only copy of an erased account's details, and
// erasure fails closed on it: if Append silently reported success while writing
// nothing, DeleteAccount would proceed to destroy the account with no recoverable
// record at all. The whole fail-closed design rests on this error surfacing.
func TestAccountRecoveryRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewAccountRecoveryRepo(deadPool(t))
	ctx := context.Background()

	err := repo.Append(ctx, &model.AccountRecovery{
		ID: "r-1", Pseudonym: "p-1", Payload: []byte("ciphertext"),
	})
	if err == nil {
		t.Error("Append reported success against an unreachable database — erasure would proceed with no escrow")
	}

	if _, err := repo.List(ctx, 10, 0); err == nil {
		t.Error("List returned no error against an unreachable database")
	}
}

// The Postgres rate-limit backend is the fallback when Redis is absent. If
// Increment silently returned a zero count on failure, every request would look
// like the first one in its window and the limiter would stop limiting — the
// login endpoint would be wide open to brute force with no error anywhere.
func TestRateLimitRepo_SurfacesDatabaseFailures(t *testing.T) {
	repo := NewRateLimitRepo(deadPool(t))
	ctx := context.Background()

	n, err := repo.Increment(ctx, "login:203.0.113.1", time.Now())
	if err == nil {
		t.Error("Increment reported success against an unreachable database — the rate limiter would fail open")
	}
	if n > 0 {
		t.Errorf("a failed Increment returned a count of %d", n)
	}

	got, err := repo.Get(ctx, "login:203.0.113.1", time.Now())
	if err == nil {
		t.Error("Get returned no error, every window would read as empty and the limiter would fail open")
	}
	if got > 0 {
		t.Errorf("a failed Get returned a count of %d", got)
	}

	if err := repo.DeleteExpired(ctx, time.Now()); err == nil {
		t.Error("DeleteExpired reported success against an unreachable database")
	}
}
