package jwt

import (
	"errors"
	"fmt"
	"time"
)

// validationConfig holds all parse-time validation options.
type validationConfig struct {
	validMethods   []string
	expectedIssuer string
	expectedAud    string
	requireExp     bool
	verifyIat      bool
	skipValidation bool
}

// validateClaims checks registered claims according to the config.
// All errors are collected (not short-circuited).
//
// No clock skew leeway is applied to any time-based claim, and the exp
// comparison is inclusive: a token whose exp equals the current second is
// already expired. This is a policy choice, not an oversight: leeway extends
// the life of a stolen token past the TTL an operator configured. The
// deployment obligation that follows is that clock skew between the issuing
// and verifying pods must stay well below the token TTL, which for the access
// token TTLs vault42 issues means NTP, not a hand-set clock.
func validateClaims(claims Claims, cfg *validationConfig) error {
	now := time.Now()
	var errs []error

	// Check exp required + exp >= now
	exp := claims.GetExpirationTime()
	if exp == nil {
		if cfg.requireExp {
			errs = append(errs, fmt.Errorf("%w: exp", ErrTokenRequiredClaimMissing))
		}
	} else if !now.Before(exp.Time) {
		errs = append(errs, ErrTokenExpired)
	}

	// Check nbf: now >= nbf
	nbf := claims.GetNotBefore()
	if nbf != nil && now.Before(nbf.Time) {
		errs = append(errs, ErrTokenNotValidYet)
	}

	// Check iat: now >= iat
	if cfg.verifyIat {
		iat := claims.GetIssuedAt()
		if iat != nil && now.Before(iat.Time) {
			errs = append(errs, ErrTokenUsedBeforeIssued)
		}
	}

	// Check iss
	if cfg.expectedIssuer != "" {
		if claims.GetIssuer() != cfg.expectedIssuer {
			errs = append(errs, ErrTokenInvalidIssuer)
		}
	}

	// Check aud
	if cfg.expectedAud != "" {
		aud := claims.GetAudience()
		found := false
		for _, a := range aud {
			if a == cfg.expectedAud {
				found = true
				break
			}
		}
		if !found {
			errs = append(errs, ErrTokenInvalidAudience)
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}
