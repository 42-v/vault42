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

	whole, frac := math.Modf(f)
	*d = NumericDate{time.Unix(int64(whole), int64(frac*1e9)).Truncate(time.Second)}
	return nil
}

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
