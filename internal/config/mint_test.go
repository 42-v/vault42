package config

import "testing"

// The allow-lists are the only thing between a mint caller and any role or scope
// it cares to name. Absent must mean empty, never "everything": a signing oracle
// that grants nothing is the safe failure, so Load substitutes no default.
func TestLoadMintAllowListsAbsentGrantsNothing(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.MintAllowedRoles) != 0 {
		t.Errorf("MintAllowedRoles = %v, want empty: an unconfigured mint must grant no role", cfg.MintAllowedRoles)
	}
	if len(cfg.MintAllowedScopes) != 0 {
		t.Errorf("MintAllowedScopes = %v, want empty: an unconfigured mint must grant no scope", cfg.MintAllowedScopes)
	}
}

// Operators write these lists by hand in a Helm value, so the parse has to
// survive the shapes hand-written lists actually take: padding around entries
// and a trailing comma. A stray empty element must be dropped rather than become
// an allow-list entry for the empty role, which would widen the policy silently.
func TestLoadMintAllowListsCommaSplit(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")
	t.Setenv("VAULT_MINT_ROLES", " member , , beon3:coach ,")
	t.Setenv("VAULT_MINT_SCOPES", "profile:read, profile:write ,,")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	wantRoles := []string{"member", "beon3:coach"}
	if len(cfg.MintAllowedRoles) != len(wantRoles) {
		t.Fatalf("MintAllowedRoles = %v, want %v", cfg.MintAllowedRoles, wantRoles)
	}
	for i, want := range wantRoles {
		if cfg.MintAllowedRoles[i] != want {
			t.Errorf("MintAllowedRoles[%d] = %q, want %q", i, cfg.MintAllowedRoles[i], want)
		}
	}

	wantScopes := []string{"profile:read", "profile:write"}
	if len(cfg.MintAllowedScopes) != len(wantScopes) {
		t.Fatalf("MintAllowedScopes = %v, want %v", cfg.MintAllowedScopes, wantScopes)
	}
	for i, want := range wantScopes {
		if cfg.MintAllowedScopes[i] != want {
			t.Errorf("MintAllowedScopes[%d] = %q, want %q", i, cfg.MintAllowedScopes[i], want)
		}
	}
}

// A value that is nothing but separators and padding parses to no entries at
// all. The distinction matters: []string{""} would allow-list the empty role,
// and the mint compares requested roles against the list by exact match.
func TestLoadMintAllowListsBlankEntriesOnly(t *testing.T) {
	t.Setenv("VAULT_PROFILE", "dev")
	t.Setenv("VAULT_MINT_ROLES", " , , ")
	t.Setenv("VAULT_MINT_SCOPES", ",")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.MintAllowedRoles) != 0 {
		t.Errorf("MintAllowedRoles = %#v, want empty: blank entries must not become allow-list members", cfg.MintAllowedRoles)
	}
	if len(cfg.MintAllowedScopes) != 0 {
		t.Errorf("MintAllowedScopes = %#v, want empty: blank entries must not become allow-list members", cfg.MintAllowedScopes)
	}
}

// A minted token carrying vault42's own audience passes vault42's own audience
// validation, so the mint would become account takeover for any subject the
// caller cares to name. Validate refuses to start on that configuration, and the
// check sits ahead of the dev short-circuit on purpose: the hazard is not
// production-only, and a dev deployment that teaches the wrong configuration is
// the one that gets copied into production.
func TestValidateMintAudience(t *testing.T) {
	t.Run("mint off leaves the audience unconstrained", func(t *testing.T) {
		c := prodConfig()
		c.MintEnabled = false
		c.MintAudience = ""

		if err := c.Validate(); err != nil {
			t.Fatalf("an unconfigured mint must not constrain the audience: %v", err)
		}
	})

	t.Run("mint on with no audience is refused", func(t *testing.T) {
		c := prodConfig()
		c.MintEnabled = true
		c.MintAudience = ""

		err := c.Validate()
		if err == nil {
			t.Fatal("minting was enabled with no audience and the server was allowed to start")
		}
		if !contains(err.Error(), "VAULT_MINT_AUDIENCE") {
			t.Errorf("error = %v, want it to name VAULT_MINT_AUDIENCE", err)
		}
	})

	t.Run("mint on with vault42's own origin as audience is refused", func(t *testing.T) {
		c := prodConfig()
		c.MintEnabled = true
		c.MintAudience = c.Origin

		err := c.Validate()
		if err == nil {
			t.Fatal("a mint audience equal to VAULT_ORIGIN was accepted: every minted token would authenticate against vault42 itself")
		}
		if !contains(err.Error(), "VAULT_ORIGIN") {
			t.Errorf("error = %v, want it to name VAULT_ORIGIN", err)
		}
	})

	t.Run("mint on with a distinct audience is accepted", func(t *testing.T) {
		c := prodConfig()
		c.MintEnabled = true
		c.MintAudience = "https://life42.test"

		if err := c.Validate(); err != nil {
			t.Fatalf("a mint addressed to a foreign audience is the supported configuration: %v", err)
		}
	})

	// The dev profile short-circuits every other fail-closed check. This one is
	// deliberately placed before that return, so all three outcomes must be
	// identical in dev.
	t.Run("the rule survives the dev profile short-circuit", func(t *testing.T) {
		empty := &Config{Profile: ProfileDev, MintEnabled: true, Origin: "https://vault.test"}
		if err := empty.Validate(); err == nil {
			t.Error("dev profile accepted an enabled mint with no audience")
		}

		self := &Config{Profile: ProfileDev, MintEnabled: true, Origin: "https://vault.test", MintAudience: "https://vault.test"}
		if err := self.Validate(); err == nil {
			t.Error("dev profile accepted a mint audience equal to the origin")
		}

		ok := &Config{Profile: ProfileDev, MintEnabled: true, Origin: "https://vault.test", MintAudience: "https://life42.test"}
		if err := ok.Validate(); err != nil {
			t.Errorf("dev profile rejected a valid mint configuration: %v", err)
		}
	})
}
