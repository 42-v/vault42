package integration_test

// The capability scopes on auth.clients, under the roles the services connect as.
//
// 001 grants vault_app SELECT and INSERT on auth.clients so cmd/vault can seed
// clients at startup, and scopes is a plain TEXT[]. Nothing between the grant and
// the column asks what is in the array. A statement reaching the database as
// vault_app can therefore write a client row carrying mint:token and kms:unwrap,
// with a secret_hash of its choosing, and then authenticate as that client at
// POST /client/token: the handler reads active, verifies the secret against the
// hash in the row, and issues a token carrying the row's scopes verbatim.
//
// That is the whole of the trust model behind POST /mint and POST /kms/unwrap,
// reachable by INSERT. MintAllowedScopes does not touch it. That allow-list, and
// service.mintDeniedScopes behind it, govern what a minted token may carry; they
// are read inside the mint handler and never on the way into a client row.
//
// These tests exercise the real roles with the real grants, because the shared
// fixture strips the privilege model before a test can see it. They are the pair
// to tests/attack/atk_db_*, which cannot be extended from here.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository/postgres"
)

// capabilityScopeRefused reports whether err is the guard refusing to write a
// capability scope. A permission error (42501) is a different, weaker control and
// must not count: the seed path needs INSERT on this table and keeps it.
func capabilityScopeRefused(err error) bool {
	return err != nil && strings.Contains(err.Error(), "capability scope denied")
}

// clientWithScopes builds a client row shaped exactly as seed.seedClient builds
// one, so what these tests write is what the seeder writes.
func clientWithScopes(name string, scopes []string) *model.Client {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &model.Client{
		ID:           randomID(),
		Name:         name,
		SecretHash:   "$argon2id$v=19$m=47104,t=1,p=1$c2VjcmV0$attackerchosen",
		Role:         "service",
		Scopes:       scopes,
		RedirectURIs: []string{},
		Active:       true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

func TestVaultAppCannotGrantItselfACapabilityScopeThroughAClientRow(t *testing.T) {
	adminPool, _, cleanup := setupPostgres(t)
	defer cleanup()
	ctx := context.Background()

	applyRealGrants(t, adminPool)
	app := postgres.NewClientRepo(&postgres.DB{Pool: appRolePool(t, adminPool)})
	gateway := postgres.NewClientRepo(&postgres.DB{Pool: adminRolePool(t, adminPool)})

	// The seeding path 001 made the grant for. It has to keep working, which is
	// why the guard cannot be a blanket REVOKE of INSERT.
	t.Run("an ordinary client is still seeded by the application role", func(t *testing.T) {
		c := clientWithScopes("cap-ordinary", []string{"user:read", "token:refresh"})
		if err := app.Create(ctx, c); err != nil {
			t.Fatalf("vault_app can no longer seed an ordinary client, so declarative seeding is dead: %v", err)
		}
		got, err := gateway.GetByID(ctx, c.ID)
		if err != nil || got == nil {
			t.Fatalf("seeded client not readable: %v", err)
		}
		if len(got.Scopes) != 2 {
			t.Errorf("seeded scopes were altered: %v", got.Scopes)
		}
	})

	// A client carrying mint:token can assert any subject to every relying party
	// in the estate. A client carrying kms:unwrap can open every envelope the KMS
	// oracle will decrypt. Both are one INSERT away for anything holding vault_app.
	for _, tc := range []struct {
		name  string
		scope string
	}{
		{"mint", "mint:token"},
		{"kms", "kms:unwrap"},
		{"svcdoc read", "svcdoc:read"},
		{"svcdoc write", "svcdoc:write"},
	} {
		t.Run("the application role cannot mint itself a "+tc.name+" client", func(t *testing.T) {
			c := clientWithScopes("cap-"+strings.ReplaceAll(tc.scope, ":", "-"), []string{tc.scope})
			err := app.Create(ctx, c)
			if !capabilityScopeRefused(err) {
				t.Fatalf("vault_app wrote a client row carrying %s: err = %v.\n"+
					"Authenticating as that client at POST /client/token yields a token with the "+
					"scope, which is the whole authorization behind the privileged endpoints.", tc.scope, err)
			}
		})
	}

	// The scope does not have to be alone in the array. A guard that looked at
	// scopes[1] only, or at a single-element row, would miss this.
	t.Run("a capability scope hidden among ordinary ones is still refused", func(t *testing.T) {
		c := clientWithScopes("cap-smuggled", []string{"user:read", "mint:token", "token:refresh"})
		if err := app.Create(ctx, c); !capabilityScopeRefused(err) {
			t.Fatalf("vault_app smuggled mint:token past the guard in a mixed scope list: err = %v", err)
		}
	})

	// The admin plane is the sanctioned writer and must stay one. 001 grants
	// vault_admin INSERT and UPDATE on this table, POST /admin/clients is gated on
	// the clients:create permission, and the creation is audited.
	t.Run("the admin plane may still create a privileged client", func(t *testing.T) {
		c := clientWithScopes("cap-gateway-mint", []string{"mint:token", "kms:unwrap"})
		if err := gateway.Create(ctx, c); err != nil {
			t.Fatalf("vault_admin cannot create a privileged client, so POST /admin/clients is "+
				"broken in every deployment and the capability has no writer left: %v", err)
		}
		got, err := gateway.GetByID(ctx, c.ID)
		if err != nil || got == nil {
			t.Fatalf("admin-created client not readable: %v", err)
		}
		if len(got.Scopes) != 2 {
			t.Errorf("the admin plane's scopes were altered: %v", got.Scopes)
		}
	})

	// Control: UPDATE was never vault_app's, so promoting an existing ordinary
	// client is refused by the grant before any trigger runs. This is what makes
	// INSERT the only path the guard has to cover.
	//
	// The same absence is why `vault revoke-client` and `vault rotate-client-secret`
	// have failed with 42501 in every deployment since 001: both are UPDATE
	// statements issued from cmd/vault, which connects as vault_app. Deactivate is
	// asserted here alongside Update so that claim is pinned rather than asserted
	// in a comment.
	t.Run("the application role cannot promote an existing client by update", func(t *testing.T) {
		c := clientWithScopes("cap-promote-target", []string{"user:read"})
		if err := gateway.Create(ctx, c); err != nil {
			t.Fatalf("seed target client: %v", err)
		}
		c.Scopes = []string{"user:read", "mint:token"}
		if err := app.Update(ctx, c); !permissionDenied(err) {
			t.Fatalf("vault_app updated a client row: 001 reserves UPDATE for the admin gateway: err = %v", err)
		}
		if err := app.Deactivate(ctx, c.ID); !permissionDenied(err) {
			t.Fatalf("vault_app deactivated a client row: err = %v", err)
		}
	})
}
