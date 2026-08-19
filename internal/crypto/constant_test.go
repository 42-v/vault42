package crypto

import "testing"

func TestSecureCompare(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{"equal", "hello", "hello", true},
		{"not equal", "hello", "world", false},
		{"empty both", "", "", true},
		{"empty one", "hello", "", false},
		{"different lengths", "short", "much longer string", false},
		{"similar", "password1", "password2", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SecureCompare(tt.a, tt.b); got != tt.want {
				t.Errorf("SecureCompare(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
