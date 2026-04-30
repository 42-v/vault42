package sanitize

import "testing"

func TestString(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{"empty", "", 100, ""},
		{"trims whitespace", "  hello  ", 100, "hello"},
		{"escapes angle brackets", "<script>alert(1)</script>", 100, "&lt;script&gt;alert(1)&lt;/script&gt;"},
		{"escapes quotes", `he said "hello" & 'bye'`, 100, `he said &quot;hello&quot; & &#39;bye&#39;`},
		{"truncates to maxLen", "abcdef", 3, "abc"},
		{"exact maxLen", "abc", 3, "abc"},
		{"under maxLen", "ab", 3, "ab"},
		{"zero maxLen", "abc", 0, ""},
		{"trims then escapes", "  <b>  ", 100, "&lt;b&gt;"},
		{"truncates after escape", "<", 4, "&lt;"},
		{"unicode preserved", "caf\u00e9", 10, "caf\u00e9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := String(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("String(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestLocale(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty returns en", "", "en"},
		{"whitespace returns en", "   ", "en"},
		{"valid locale", "sk", "sk"},
		{"uppercase normalized", "EN-US", "en-us"},
		{"underscore allowed", "en_US", "en_us"},
		{"too long returns en", "abcdefghijk", "en"},
		{"numbers rejected", "en1", "en"},
		{"special chars rejected", "en;rm -rf", "en"},
		{"dot rejected", "en.UTF-8", "en"},
		{"slash rejected", "../../etc", "en"},
		{"max valid length", "abcdefghij", "abcdefghij"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Locale(tt.input)
			if got != tt.want {
				t.Errorf("Locale(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRedirectPath(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty returns empty", "", ""},
		{"valid root", "/", "/"},
		{"valid path", "/dashboard", "/dashboard"},
		{"valid nested", "/auth/callback?code=abc", "/auth/callback?code=abc"},
		{"no leading slash", "dashboard", ""},
		{"double slash (open redirect)", "//evil.com", ""},
		{"protocol in path", "/foo://bar", ""},
		{"backslash", "/foo\\bar", ""},
		{"absolute URL", "https://evil.com", ""},
		{"too long", "/" + string(make([]byte, 256)), ""},
		{"max valid length", "/" + string(make([]byte, 255)), "/" + string(make([]byte, 255))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedirectPath(tt.input)
			if got != tt.want {
				t.Errorf("RedirectPath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestAvatarURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty returns empty", "", ""},
		{"whitespace returns empty", "   ", ""},
		{"valid https", "https://example.com/avatar.png", "https://example.com/avatar.png"},
		{"http rejected", "http://example.com/avatar.png", ""},
		{"no protocol", "example.com/avatar.png", ""},
		{"javascript rejected", "javascript:alert(1)", ""},
		{"data rejected", "data:image/png;base64,abc", ""},
		{"too long", "https://" + string(make([]byte, 2048)), ""},
		{"max valid length", "https://x" + string(make([]byte, 2038)), "https://x" + string(make([]byte, 2038))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AvatarURL(tt.input)
			if got != tt.want {
				t.Errorf("AvatarURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestEmail(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid email", "user@example.com", true},
		{"valid with plus", "user+tag@example.com", true},
		{"valid with dots", "first.last@example.com", true},
		{"valid subdomain", "user@sub.example.com", true},
		{"empty", "", false},
		{"no at sign", "userexample.com", false},
		{"no domain", "user@", false},
		{"no local", "@example.com", false},
		{"spaces", "user @example.com", false},
		{"too long", string(make([]byte, 250)) + "@a.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Email(tt.input)
			if got != tt.want {
				t.Errorf("Email(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
