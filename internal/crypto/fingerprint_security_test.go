package crypto

import "testing"

// A fingerprint that collides across field boundaries is a fingerprint an
// attacker can hit without matching the victim's device: move a character from
// one field into the next and a naively concatenated digest is unchanged. The
// length prefix is what stops it, and every row below is a pair that a
// separator-joined encoding would have hashed identically.
func TestFingerprintDistinguishesFieldBoundaries(t *testing.T) {
	tests := []struct {
		name string
		a, b FingerprintInput
	}{
		{
			// The literal separator the old encoding used, moved across a boundary.
			name: "a pipe carried from the user agent into the language",
			a:    FingerprintInput{IP: "192.168.1.1", UserAgent: "Mozilla|5.0", AcceptLanguage: "en"},
			b:    FingerprintInput{IP: "192.168.1.1", UserAgent: "Mozilla", AcceptLanguage: "5.0|en"},
		},
		{
			name: "one character shifted from the address into the user agent",
			a:    FingerprintInput{IP: "ab", UserAgent: "c"},
			b:    FingerprintInput{IP: "a", UserAgent: "bc"},
		},
		{
			name: "two field values swapped outright",
			a:    FingerprintInput{IP: "valueA", UserAgent: "valueB"},
			b:    FingerprintInput{IP: "valueB", UserAgent: "valueA"},
		},
		{
			name: "nothing at all against a single field",
			a:    FingerprintInput{},
			b:    FingerprintInput{IP: "1.2.3.4"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if fpA, fpB := ComputeFingerprint(tt.a), ComputeFingerprint(tt.b); fpA == fpB {
				t.Errorf("%+v and %+v both fingerprint as %s, so one device passes as the other", tt.a, tt.b, fpA)
			}
		})
	}
}

func TestFingerprintEmptyFields(t *testing.T) {
	fp := ComputeFingerprint(FingerprintInput{})
	if len(fp) != 64 {
		t.Errorf("empty input fingerprint should be 64 hex chars, got %d", len(fp))
	}
}
