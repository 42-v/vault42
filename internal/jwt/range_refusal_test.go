package jwt

import (
	"errors"
	"strings"
	"testing"
)

// The refusals these cover were added in 1.0.3 and shipped with their accept
// paths tested and their refuse paths not, which is the wrong half to leave
// uncovered: a range check nobody exercises is a range check that can be
// deleted without any test noticing.
//
// MapClaims is the untyped path. A token whose claims are decoded into a map
// rather than a struct reaches mapNumericDate, and an out-of-range float64
// converts to MinInt64 on amd64, which time.Unix wraps to an instant in the
// distant past. Returning nil reads as "the claim is absent", which fails
// closed for exp and is checked for nbf.

func TestMapNumericDateRefusesValuesOutsideTheRepresentableRange(t *testing.T) {
	// json.Unmarshal produces float64 for every JSON number, so that is the
	// case an attacker actually reaches; int64 is reachable when a caller
	// builds MapClaims in Go.
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"float64 far past", -1e99},
		{"float64 far future", 1e99},
		{"float64 just below the floor", float64(minNumericDate) - 1},
		{"float64 just above the ceiling", float64(maxNumericDate) + 1},
		{"int64 below the floor", int64(minNumericDate) - 1},
		{"int64 above the ceiling", int64(maxNumericDate) + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := MapClaims{"exp": tc.value}
			if got := mapNumericDate(claims, "exp"); got != nil {
				t.Errorf("mapNumericDate(%v) = %v, want nil. An out-of-range value that "+
					"survives here becomes an instant the validator will accept.",
					tc.value, got.Time)
			}
		})
	}
}

// The counterweight: the refusal must reject only what it cannot represent. A
// range check that also refused ordinary timestamps would stop every token in
// production verifying, and would look identical in a test that only feeds it
// hostile input.
func TestMapNumericDateStillAcceptsRepresentableInstants(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
		unix  int64
	}{
		{"float64 recent", float64(1755000000), 1755000000},
		{"float64 at the floor", float64(minNumericDate), minNumericDate},
		{"float64 at the ceiling", float64(maxNumericDate), maxNumericDate},
		{"int64 recent", int64(1755000000), 1755000000},
		{"int64 at the floor", int64(minNumericDate), minNumericDate},
		{"int64 at the ceiling", int64(maxNumericDate), maxNumericDate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mapNumericDate(MapClaims{"nbf": tc.value}, "nbf")
			if got == nil {
				t.Fatalf("mapNumericDate(%v) = nil; the bound is inclusive and this value is "+
					"inside it", tc.value)
			}
			if got.Unix() != tc.unix {
				t.Errorf("mapNumericDate(%v).Unix() = %d, want %d",
					tc.value, got.Unix(), tc.unix)
			}
		})
	}
}

// refuseAmbiguousClaimNames walks the payload with a streaming decoder before
// the struct unmarshal, because encoding/json matches tags case-insensitively
// and takes the LAST match: a payload carrying both "exp" and "EXP" has the
// checked field silently replaced by the one nobody validated.
//
// Its error paths are what these cover. They answer ErrTokenMalformed rather
// than a decoder error, so a caller that switches on the sentinel treats a
// truncated payload the same way it treats any other malformed token.
func TestRefuseAmbiguousClaimNamesRejectsMalformedPayloads(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
	}{
		{"truncated before a member name", `{"exp":1,`},
		{"garbage where a member name belongs", `{"exp":1,%%}`},
		{"member with no value", `{"exp":}`},
		{"truncated inside a value", `{"exp":{"a":`},
		{"unterminated string value", `{"exp":"abc`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := refuseAmbiguousClaimNames([]byte(tc.payload))
			if err == nil {
				t.Fatalf("refuseAmbiguousClaimNames(%q) = nil; a payload this decoder cannot "+
					"walk is one whose member names were never checked for collision",
					tc.payload)
			}
			if !errors.Is(err, ErrTokenMalformed) {
				t.Errorf("refuseAmbiguousClaimNames(%q) = %v, want ErrTokenMalformed so a "+
					"caller switching on the sentinel sees a malformed token",
					tc.payload, err)
			}
		})
	}
}

// A non-object payload is not this function's to reject: it carries no member
// names to collide, and the unmarshal that follows produces the better message.
func TestRefuseAmbiguousClaimNamesPassesOverNonObjects(t *testing.T) {
	for _, payload := range []string{`[]`, `"a string"`, `42`, `null`, `true`} {
		if err := refuseAmbiguousClaimNames([]byte(payload)); err != nil {
			t.Errorf("refuseAmbiguousClaimNames(%q) = %v, want nil; rejecting here would "+
				"replace the unmarshal's specific error with a vaguer one", payload, err)
		}
	}
}

// The property the whole walk exists for, kept beside its error paths so a
// change that breaks the walk cannot pass by breaking only the collision check.
func TestRefuseAmbiguousClaimNamesRejectsCaseCollisions(t *testing.T) {
	err := refuseAmbiguousClaimNames([]byte(`{"exp":1,"EXP":2}`))
	if err == nil {
		t.Fatal("a payload carrying both exp and EXP was accepted; encoding/json takes the " +
			"last match, so the validated claim would be the one nobody checked")
	}
	if !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("err = %v, want ErrTokenMalformed", err)
	}
	// The message has to name both spellings, or an operator reading a log
	// cannot tell which claim was duplicated.
	for _, want := range []string{"exp", "EXP"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q: %v", want, err)
		}
	}
}
