package jwt

import "time"

// Claims is satisfied by any type that can return the registered JWT claims.
// Unlike golang-jwt, getters return values directly (no error return) since
// we only use typed struct claims where errors are impossible.
type Claims interface {
	GetExpirationTime() *NumericDate
	GetIssuedAt() *NumericDate
	GetNotBefore() *NumericDate
	GetIssuer() string
	GetSubject() string
	GetAudience() ClaimStrings
}

// RegisteredClaims implements Claims with standard RFC 7519 fields.
type RegisteredClaims struct {
	Issuer    string       `json:"iss,omitempty"`
	Subject   string       `json:"sub,omitempty"`
	Audience  ClaimStrings `json:"aud,omitempty"`
	ExpiresAt *NumericDate `json:"exp,omitempty"`
	NotBefore *NumericDate `json:"nbf,omitempty"`
	IssuedAt  *NumericDate `json:"iat,omitempty"`
	ID        string       `json:"jti,omitempty"`
}

func (c RegisteredClaims) GetExpirationTime() *NumericDate { return c.ExpiresAt }
func (c RegisteredClaims) GetIssuedAt() *NumericDate       { return c.IssuedAt }
func (c RegisteredClaims) GetNotBefore() *NumericDate      { return c.NotBefore }
func (c RegisteredClaims) GetIssuer() string               { return c.Issuer }
func (c RegisteredClaims) GetSubject() string              { return c.Subject }
func (c RegisteredClaims) GetAudience() ClaimStrings       { return c.Audience }

// MapClaims is a generic claims type for test code that needs arbitrary claim maps.
// Production code should use typed claims structs instead.
type MapClaims map[string]any

func (m MapClaims) GetExpirationTime() *NumericDate { return mapNumericDate(m, "exp") }
func (m MapClaims) GetIssuedAt() *NumericDate       { return mapNumericDate(m, "iat") }
func (m MapClaims) GetNotBefore() *NumericDate      { return mapNumericDate(m, "nbf") }
func (m MapClaims) GetIssuer() string               { s, _ := m["iss"].(string); return s }
func (m MapClaims) GetSubject() string              { s, _ := m["sub"].(string); return s }

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

func mapNumericDate(m MapClaims, key string) *NumericDate {
	switch v := m[key].(type) {
	case float64:
		if v == 0 {
			return nil
		}
		return NewNumericDate(time.Unix(int64(v), 0))
	case int64:
		if v == 0 {
			return nil
		}
		return NewNumericDate(time.Unix(v, 0))
	case *NumericDate:
		return v
	default:
		return nil
	}
}
