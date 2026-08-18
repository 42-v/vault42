package dpop

import (
	"context"
	"testing"
)

// A request that carried no proof must be indistinguishable from one this package
// never touched, because issuance reads the empty string as "not
// sender-constrained" and omits cnf.jkt.
func TestAContextWithNoProofCarriesNoThumbprint(t *testing.T) {
	if got := Thumbprint(context.Background()); got != "" {
		t.Errorf("Thumbprint of a bare context = %q, want empty", got)
	}
}

func TestTheThumbprintSurvivesTheContextHop(t *testing.T) {
	const jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
	ctx := WithThumbprint(context.Background(), jkt)
	if got := Thumbprint(ctx); got != jkt {
		t.Errorf("Thumbprint = %q, want %q", got, jkt)
	}
	// A derived context keeps it, which is what makes the middleware-to-issuance
	// hop work across the handler's own context wrapping.
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	if got := Thumbprint(child); got != jkt {
		t.Errorf("Thumbprint of a derived context = %q, want %q", got, jkt)
	}
}

// The key type is unexported and empty, so no other package can plant a
// thumbprint under it — including by using the same string as a key, which is
// how context keys collide in practice.
func TestAStringKeyCannotImpersonateTheThumbprintKey(t *testing.T) {
	//nolint:staticcheck // SA1029 is the point: a string key must NOT be readable here.
	ctx := context.WithValue(context.Background(), "dpop-thumbprint", "planted")
	if got := Thumbprint(ctx); got != "" {
		t.Errorf("a string-keyed value was read as a validated thumbprint: %q", got)
	}
}

// A non-string value under the key is not a thumbprint. The type assertion has to
// answer "no proof" rather than panic, because a panic here happens inside token
// issuance.
func TestANonStringValueIsNotAThumbprint(t *testing.T) {
	ctx := context.WithValue(context.Background(), thumbprintKey, 42)
	if got := Thumbprint(ctx); got != "" {
		t.Errorf("Thumbprint = %q, want empty for a non-string value", got)
	}
}
