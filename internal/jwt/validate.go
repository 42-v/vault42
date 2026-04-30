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
