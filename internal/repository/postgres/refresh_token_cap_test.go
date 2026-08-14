package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
)

// capInsertUser writes the account row the refresh_tokens foreign key requires.
func capInsertUser(t *testing.T, db *DB, id, email string) {
	t.Helper()
	hash, _ := vaultcrypto.HashPassword("correct-horse-battery-staple")
	if _, err := db.Pool.Exec(context.Background(), `
		INSERT INTO auth.users (id, email, email_verified, password_hash, display_name, created_at, updated_at)
		VALUES ($1, $2, true, $3, 'cap', NOW(), NOW())`, id, email, hash); err != nil {
		t.Fatalf("insert user: %v", err)
	}
}

// capToken builds a first-of-family token for user u.
func capToken(u string) *model.RefreshToken {
	id, _ := vaultcrypto.RandomUUID()
	fam, _ := vaultcrypto.RandomUUID()
	return &model.RefreshToken{
		ID: id, UserID: u, TokenHash: vaultcrypto.SHA256Hex(id + fam),
		FamilyID: fam, ExpiresAt: time.Now().Add(24 * time.Hour), CreatedAt: time.Now(),
	}
}

// CreateWithinCap enforces the concurrent-session cap as one unit of work. These
// cases pin the reachable outcomes against a real Postgres: a free slot inserts,
// a full one is refused without inserting, and a zero cap inserts unconditionally.
func TestRefreshTokenRepo_CreateWithinCap(t *testing.T) {
	db := svcDocPostgres(t)
	repo := NewRefreshTokenRepo(db)
	ctx := context.Background()

	t.Run("inserts while under the cap", func(t *testing.T) {
		u, _ := vaultcrypto.RandomUUID()
		capInsertUser(t, db, u, u+"@under.test")

		if err := repo.CreateWithinCap(ctx, capToken(u), 3); err != nil {
			t.Fatalf("CreateWithinCap under the cap: %v", err)
		}
		if n, _ := repo.CountActiveFamilies(ctx, u); n != 1 {
			t.Fatalf("active families = %d, want 1", n)
		}
	})

	t.Run("a zero cap disables the check", func(t *testing.T) {
		u, _ := vaultcrypto.RandomUUID()
		capInsertUser(t, db, u, u+"@zero.test")

		if err := repo.CreateWithinCap(ctx, capToken(u), 0); err != nil {
			t.Fatalf("CreateWithinCap with no cap: %v", err)
		}
		if n, _ := repo.CountActiveFamilies(ctx, u); n != 1 {
			t.Fatalf("active families = %d, want 1", n)
		}
	})

	t.Run("refuses at the cap and inserts nothing", func(t *testing.T) {
		u, _ := vaultcrypto.RandomUUID()
		capInsertUser(t, db, u, u+"@full.test")
		for i := 0; i < 2; i++ {
			if err := repo.Create(ctx, capToken(u)); err != nil {
				t.Fatalf("seed family %d: %v", i, err)
			}
		}

		err := repo.CreateWithinCap(ctx, capToken(u), 2)
		if !errors.Is(err, repository.ErrSessionLimitReached) {
			t.Fatalf("err = %v, want ErrSessionLimitReached", err)
		}
		if n, _ := repo.CountActiveFamilies(ctx, u); n != 2 {
			t.Fatalf("active families = %d, want the cap of 2 held", n)
		}
	})
}

// Every step of the capped write is a database round trip that can fail, and a
// failure at any of them must abort the write rather than let a login proceed
// with the cap unenforced. These script each round trip to fail in turn.
func TestRefreshTokenRepo_CreateWithinCap_FailsAtEveryStep(t *testing.T) {
	beginOK := apPGRule{match: "begin", reply: func(string) []byte {
		return append(apMsg('C', apCStr("BEGIN")), apReadyInTx()...)
	}}
	lockOK := apPGRule{match: "pg_advisory_xact_lock", reply: func(string) []byte {
		return append(apMsg('C', apCStr("SELECT 1")), apReadyInTx()...)
	}}
	countOK := apPGRule{match: "COUNT(DISTINCT family_id)", reply: func(string) []byte {
		out := apRowDesc(apCol{name: "count", oid: apOIDInt8, size: 8})
		out = append(out, apDataRow(apText("0"))...)
		out = append(out, apMsg('C', apCStr("SELECT 1"))...)
		return append(out, apReadyInTx()...)
	}}

	tests := []struct {
		name  string
		rules []apPGRule
		want  string
		is    error
	}{
		{
			name: "the transaction never starts",
			want: "begin session cap tx",
			rules: []apPGRule{{match: "begin", reply: func(string) []byte {
				return append(apErrorResponse("53300", "too many connections for role"), apReadyIdle()...)
			}}},
		},
		{
			name: "the per-user lock is refused",
			want: "lock user sessions",
			rules: []apPGRule{beginOK, {match: "pg_advisory_xact_lock", reply: func(string) []byte {
				return append(apErrorResponse("57014", "canceling statement due to statement timeout"), apReadyTxFailed()...)
			}}},
		},
		{
			name: "the count cannot be read",
			want: "count active families",
			rules: []apPGRule{beginOK, lockOK, {match: "COUNT(DISTINCT family_id)", reply: func(string) []byte {
				return append(apErrorResponse("57014", "canceling statement due to statement timeout"), apReadyTxFailed()...)
			}}},
		},
		{
			name: "the insert fails",
			want: "insert refresh token within cap",
			rules: []apPGRule{beginOK, lockOK, countOK, {match: "INSERT INTO auth.refresh_tokens", reply: func(string) []byte {
				return append(apErrorResponse("40001", "could not serialize access"), apReadyTxFailed()...)
			}}},
		},
		{
			name: "the guarded insert writes no row",
			is:   repository.ErrFamilyRevoked,
			rules: []apPGRule{beginOK, lockOK, countOK, {match: "INSERT INTO auth.refresh_tokens", reply: func(string) []byte {
				return append(apMsg('C', apCStr("INSERT 0 0")), apReadyInTx()...)
			}}},
		},
		{
			name: "the commit is refused after the row was written",
			want: "commit session cap tx",
			rules: []apPGRule{
				beginOK, lockOK, countOK,
				{match: "INSERT INTO auth.refresh_tokens", reply: func(string) []byte {
					return append(apMsg('C', apCStr("INSERT 0 1")), apReadyInTx()...)
				}},
				{match: "commit", reply: func(string) []byte {
					return append(apErrorResponse("40001", "could not serialize access"), apReadyIdle()...)
				}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := NewRefreshTokenRepo(apStartPG(t, tc.rules...))
			err := repo.CreateWithinCap(context.Background(),
				&model.RefreshToken{
					ID: "11111111-1111-1111-1111-111111111111", UserID: "22222222-2222-2222-2222-222222222222",
					TokenHash: "h", FamilyID: "33333333-3333-3333-3333-333333333333",
					ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
				}, 3)
			if err == nil {
				t.Fatal("CreateWithinCap reported a capped, committed write that never committed")
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Fatalf("err = %v, want %v", err, tc.is)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to name the %q step", err, tc.want)
			}
		})
	}
}
