package jwt

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"
)

// NumericDate wraps time.Time with UNIX-epoch JSON serialization.
type NumericDate struct {
	time.Time
}

// NewNumericDate creates a NumericDate from a time.Time, truncated to seconds.
func NewNumericDate(t time.Time) *NumericDate {
	return &NumericDate{t.Truncate(time.Second)}
}

// MarshalJSON outputs the UNIX epoch as an integer (no fractional seconds).
func (d NumericDate) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(d.Truncate(time.Second).Unix(), 10)), nil
}

// UnmarshalJSON parses a UNIX epoch number (integer or float) back to time.Time.
func (d *NumericDate) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("could not parse NumericDate: %w", err)
	}

	f, err := n.Float64()
	if err != nil {
		return fmt.Errorf("could not convert json number to float: %w", err)
	}

	// Refuse a value that will not survive the conversion below. Converting a
	// float64 outside int64's range is implementation-defined in Go, and on
	// amd64 it yields MinInt64, which time.Unix then wraps to an instant tens of
	// thousands of years away. An "nbf" of 1e99 therefore stopped meaning "not
	// before the heat death of the universe" and started meaning a moment the
	// validator was happy to call past, so a token that is not yet valid
	// verified.
	//
	// That is reachable with fully attacker-controlled input rather than only
	// from a token this service minted: a DPoP proof is self-signed by a key the
	// sender invents, and crypto.ValidateDPoPProof parses it with claim
	// validation on. The same conversion in claims.go is what internal/oauth2
	// had to cap for auth_time, one hazard at three call sites.
	//
	// NaN fails the comparison in both directions and is refused with the rest.
	if !(f >= minNumericDate && f <= maxNumericDate) {
		return fmt.Errorf("NumericDate %v is outside the range of representable instants", f)
	}

	whole, frac := math.Modf(f)
	*d = NumericDate{time.Unix(int64(whole), int64(frac*1e9)).Truncate(time.Second)}
	return nil
}

// The range a NumericDate may name, in seconds since the epoch.
//
// Bounded well inside int64 rather than at its edge: the conversion is only half
// the hazard, because time.Unix overflows internally long before int64 does.
// Year 1 to year 9999 covers every instant a token can sensibly assert and
// leaves no representation to be clever with.
const (
	minNumericDate = -62135596800 // 0001-01-01T00:00:00Z
	maxNumericDate = 253402300799 // 9999-12-31T23:59:59Z
)

// ClaimStrings is []string that unmarshals from either "string" or ["array"].
type ClaimStrings []string

// UnmarshalJSON handles both a single string and an array of strings.
func (s *ClaimStrings) UnmarshalJSON(data []byte) error {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}

	switch v := value.(type) {
	case string:
		*s = ClaimStrings{v}
	case []any:
		aud := make([]string, 0, len(v))
		for _, vv := range v {
			str, ok := vv.(string)
			if !ok {
				return fmt.Errorf("invalid type in audience array")
			}
			aud = append(aud, str)
		}
		*s = aud
	case nil:
		return nil
	default:
		return fmt.Errorf("invalid type for audience claim")
	}
	return nil
}

// MarshalJSON always marshals as a JSON array.
func (s ClaimStrings) MarshalJSON() ([]byte, error) {
	return json.Marshal([]string(s))
}
