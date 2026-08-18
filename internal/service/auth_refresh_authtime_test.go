package service

import (
	"context"
	"errors"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/model"
)

// auth_time on a rotation is the family origin, and the family origin comes
// back from enforceSessionLifetime — a function written for a different feature,
// which short-circuits to the zero time whenever the absolute session bound is
// off. VAULT_MAX_SESSION_LIFETIME=0 is documented and supported (docs/config.md:
// "0 disables the bound"), so on those deployments the login token carried
// auth_time and every rotation after it did not, silently.
//
// The two features are independent: whether a deployment caps session age has
// nothing to do with whether its tokens can state when the user authenticated.
//
// Both existing auth_time tests call IssueRotatedPair directly with an explicit
// non-zero origin, so neither drives the path that produces one.

// rotatedClaims runs one refresh and returns the claims of the access token it
// issued.
func rotatedClaims(t *testing.T, svc *AuthService) *vaultcrypto.VaultClaims {
	t.Helper()
	res, err := svc.Refresh(context.Background(), "raw-refresh-token", "1.2.3.4", "UA", vaultcrypto.FingerprintInput{})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	claims, err := vaultcrypto.ParseAndValidate(res.AccessToken, func(_ *vjwt.Token) (any, error) {
		return &svc.tokenSvc.privateKey.PublicKey, nil
	}, svc.tokenSvc.issuer, svc.tokenSvc.audience)
	if err != nil {
		t.Fatalf("parse the rotated access token: %v", err)
	}
	return claims
}

func TestRotationCarriesAuthTimeWhetherOrNotAnAbsoluteBoundIsConfigured(t *testing.T) {
	origin := time.Now().Add(-3 * time.Hour).Truncate(time.Second)

	for _, tc := range []struct {
		name  string
		bound time.Duration
	}{
		// The control: with a bound configured the origin is looked up to
		// enforce it, so auth_time has always survived here.
		{"bound configured", 7 * 24 * time.Hour},
		{"bound disabled", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := refreshFixture(t, tc.bound, origin)
			claims := rotatedClaims(t, svc)

			if claims.AuthTime != origin.Unix() {
				t.Fatalf("auth_time = %d, want the family origin %d; a rotation that cannot state "+
					"when the user authenticated drops the claim its predecessor carried",
					claims.AuthTime, origin.Unix())
			}
			// A rotation observes no authenticators, so it must not restate them.
			if claims.ACR != "" || len(claims.AMR) != 0 {
				t.Errorf("rotation asserted acr=%q amr=%v", claims.ACR, claims.AMR)
			}
		})
	}
}

// The origin lookup is now unconditional, so its failure has to stay harmless
// where there is no bound to enforce: a store that cannot date a family, or one
// that errors, must cost a deployment with no bound its auth_time claim and
// nothing else. Turning that into ErrSessionAgeUnknown would make an
// unconfigured feature reject every refresh.
func TestAnUnboundedRotationSurvivesAFailedOriginLookup(t *testing.T) {
	svc, repo := refreshFixture(t, 0, time.Time{})
	repo.originErr = errors.New("family origin unavailable")

	claims := rotatedClaims(t, svc)
	if claims.AuthTime != 0 {
		t.Errorf("auth_time = %d, want none: the origin could not be read", claims.AuthTime)
	}
}

// The same, for a store that does not implement familyOriginReader at all.
// tests/mocks.MockRefreshTokenRepo is exactly that, which is why the unit
// fixtures could not see this in the first place.
func TestAnUnboundedRotationSurvivesAStoreThatCannotDateFamilies(t *testing.T) {
	svc, o := newMockAuthService(t)
	o.tokenRepo.GetByTokenHashFn = func(_ context.Context, _ string) (*model.RefreshToken, error) {
		return storedToken("raw-refresh-token"), nil
	}
	o.tokenRepo.MarkUsedFn = func(_ context.Context, _ string) (bool, error) { return true, nil }
	svc.tokenSvc.SetMaxSessionLifetime(0)

	if _, ok := any(o.tokenRepo).(familyOriginReader); ok {
		t.Fatal("this test needs a store that cannot date families")
	}

	claims := rotatedClaims(t, svc)
	if claims.AuthTime != 0 {
		t.Errorf("auth_time = %d, want none: the store cannot date the family", claims.AuthTime)
	}
}
