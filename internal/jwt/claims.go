package jwt

import "time"

// Claims is satisfied by any type that can return the registered JWT claims.
// Unlike golang-jwt, getters return values directly (no error return) since
// we only use typed struct claims where errors are impossible.
type Claims interface {
	// GetExpirationTime returns the exp claim, or nil when the token carries
	// none. Returning nil is not the same as returning a zero time: nil means
	// "no expiry claimed", which validateClaims rejects only when the caller
	// required exp, whereas a zero time would read as long expired.
	GetExpirationTime() *NumericDate
	// GetIssuedAt returns the iat claim, or nil when it is absent.
	GetIssuedAt() *NumericDate
	// GetNotBefore returns the nbf claim, or nil when the token has no
	// not-before bound.
	GetNotBefore() *NumericDate
	// GetIssuer returns the iss claim, or "" when it is absent. An
	// implementation must return "" rather than a placeholder, since "" can
	// never equal a configured issuer and therefore fails the check closed.
	GetIssuer() string
	// GetSubject returns the sub claim, or "" when it is absent. This package
	// never validates it.
	GetSubject() string
	// GetAudience returns the aud claim as a list, or nil when it is absent.
	// Audience checks test membership of this list, so an implementation must
	// not collapse a multi-valued aud to its first element.
	GetAudience() ClaimStrings
}

// RegisteredClaims implements Claims with standard RFC 7519 fields. Every
// field is omitempty, so an absent claim and a zero value are indistinguishable
// on the wire; validation therefore treats a nil timestamp as "claim absent"
// rather than as the epoch.
type RegisteredClaims struct {
	// Issuer is the iss claim. Checked only when the caller passes WithIssuer.
	Issuer string `json:"iss,omitempty"`
	// Subject is the sub claim, the identity the token speaks for. This package
	// never validates it; that is the consuming service's decision.
	Subject string `json:"sub,omitempty"`
	// Audience is the aud claim. Serialized as an array, accepted as either a
	// string or an array. Checked only when the caller passes WithAudience, and
	// then by membership, not equality.
	Audience ClaimStrings `json:"aud,omitempty"`
	// ExpiresAt is the exp claim. Nil means the token carries no expiry, which
	// is rejected only when the caller passes WithExpirationRequired.
	ExpiresAt *NumericDate `json:"exp,omitempty"`
	// NotBefore is the nbf claim. Nil means the token is valid immediately.
	NotBefore *NumericDate `json:"nbf,omitempty"`
	// IssuedAt is the iat claim. Checked only when the caller passes
	// WithIssuedAt.
	IssuedAt *NumericDate `json:"iat,omitempty"`
	// ID is the jti claim, the unique token identifier used for replay
	// tracking. This package carries it; revocation lookups happen elsewhere.
	ID string `json:"jti,omitempty"`
}

// GetExpirationTime returns the exp claim, or nil when the token carries no
// expiry.
func (c RegisteredClaims) GetExpirationTime() *NumericDate { return c.ExpiresAt }

// GetIssuedAt returns the iat claim, or nil when it is absent.
func (c RegisteredClaims) GetIssuedAt() *NumericDate { return c.IssuedAt }

// GetNotBefore returns the nbf claim, or nil when the token has no
// not-before bound.
func (c RegisteredClaims) GetNotBefore() *NumericDate { return c.NotBefore }

// GetIssuer returns the iss claim, or "" when it is absent.
func (c RegisteredClaims) GetIssuer() string { return c.Issuer }

// GetSubject returns the sub claim, or "" when it is absent.
func (c RegisteredClaims) GetSubject() string { return c.Subject }

// GetAudience returns the aud claim as a list, or nil when it is absent.
func (c RegisteredClaims) GetAudience() ClaimStrings { return c.Audience }

// MapClaims is a generic claims type for test code that needs arbitrary claim maps.
// Production code should use typed claims structs instead.
type MapClaims map[string]any

// GetExpirationTime returns the exp claim. It returns nil when the claim is
// absent or is not a number, so a token whose exp arrived as a string is treated
// as carrying no expiry rather than as expired. A numeric zero is a real
// timestamp, the epoch, and reads as long expired.
func (m MapClaims) GetExpirationTime() *NumericDate { return mapNumericDate(m, "exp") }

// GetIssuedAt returns the iat claim, with the same absent-or-untyped-is-nil
// behavior as GetExpirationTime.
func (m MapClaims) GetIssuedAt() *NumericDate { return mapNumericDate(m, "iat") }

// GetNotBefore returns the nbf claim, with the same absent-or-untyped-is-nil
// behavior as GetExpirationTime.
func (m MapClaims) GetNotBefore() *NumericDate { return mapNumericDate(m, "nbf") }

// GetIssuer returns the iss claim, or "" when it is absent or not a string.
// An issuer check against "" never matches a configured issuer, so a
// wrong-typed claim is rejected rather than skipped.
func (m MapClaims) GetIssuer() string { s, _ := m["iss"].(string); return s }

// GetSubject returns the sub claim, or "" when it is absent or not a string.
func (m MapClaims) GetSubject() string { s, _ := m["sub"].(string); return s }

// GetAudience returns the aud claim as a list, accepting the single-string and
// array forms RFC 7519 allows. Non-string members are dropped, and any other
// shape yields nil, which fails an audience check rather than passing it.
func (m MapClaims) GetAudience() ClaimStrings {
	switch v := m["aud"].(type) {
	case string:
		return ClaimStrings{v}
	case []string:
		return ClaimStrings(v)
	case []any:
		var out ClaimStrings
		for _, a := range v {
			if s, ok := a.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// mapNumericDate reads a timestamp claim, distinguishing a claim that is absent
// from one whose value is the epoch.
//
// The distinction decides whether the claim is checked at all: validateClaims
// reads a nil exp as "this token carries no expiry" and skips the expiry
// comparison. Treating the number 0 as absent therefore turned the most expired
// timestamp a token can carry into a token that never expires, and made
// MapClaims disagree with RegisteredClaims, which parses the same payload into a
// *NumericDate at the epoch and calls it expired.
//
// A value of the wrong JSON type still reads as absent. That is the safe
// reading for a claim vault42 does not mint: exp arriving as a string is not a
// deadline this package can compare, and callers that cannot tolerate a missing
// deadline pass WithExpirationRequired, which rejects it.
func mapNumericDate(m MapClaims, key string) *NumericDate {
	raw, present := m[key]
	if !present {
		return nil
	}
	switch v := raw.(type) {
	case float64:
		// Same range refusal as NumericDate.UnmarshalJSON, and for the same
		// reason: an out-of-range float64 converts to MinInt64 on amd64 and
		// time.Unix wraps it to an instant a validator will happily call past.
		// Returning nil here reads as "the claim is absent", which is the
		// direction that fails closed for exp and is checked for nbf.
		if !(v >= minNumericDate && v <= maxNumericDate) {
			return nil
		}
		return NewNumericDate(time.Unix(int64(v), 0))
	case int64:
		if v < minNumericDate || v > maxNumericDate {
			return nil
		}
		return NewNumericDate(time.Unix(v, 0))
	case *NumericDate:
		return v
	default:
		return nil
	}
}
