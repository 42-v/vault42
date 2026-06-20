package handler

import "testing"

func TestIsSafeAuthorizeRedirect(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"github https", "https://github.com/login/oauth/authorize?client_id=x", true},
		{"facebook https", "https://www.facebook.com/v19.0/dialog/oauth?state=y", true},
		{"http not allowed", "http://github.com/login/oauth/authorize", false},
		{"relative path (open redirect vector)", "/auth/evil", false},
		{"scheme-relative (open redirect vector)", "//evil.example.com/x", false},
		{"javascript scheme", "javascript:alert(1)", false},
		{"empty", "", false},
		{"garbage", "://nope", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isSafeAuthorizeRedirect(tt.url); got != tt.want {
				t.Errorf("isSafeAuthorizeRedirect(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}
