package useragent

import (
	"strings"
	"testing"
)

// TestParseBrowser_EdgeVariants covers Edge browser detection.
func TestParseBrowser_EdgeVariants(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want string
	}{
		{
			"Edge Chromium Windows",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
			"Edge",
		},
		{
			"Edge Legacy",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.18362",
			"Edge",
		},
		{
			"Edge on macOS",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
			"Edge",
		},
		{
			"Edge on Android",
			"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36 Edg/121.0.0.0",
			"Edge",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseBrowser(tt.ua)
			if got != tt.want {
				t.Errorf("parseBrowser(%q) = %q, want %q", tt.ua, got, tt.want)
			}
		})
	}
}

// TestParseBrowser_Opera covers Opera browser detection.
func TestParseBrowser_Opera(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want string
	}{
		{
			"Opera Chromium",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 OPR/107.0.0.0",
			"Opera",
		},
		{
			"Opera Presto",
			"Opera/9.80 (Windows NT 6.1; WOW64) Presto/2.12.388 Version/12.18",
			"Opera",
		},
		{
			"Opera Mini",
			"Opera/9.80 (Android; Opera Mini/7.5.54678/28.2555; U; en) Presto/2.8.119 Version/11.10",
			"Opera",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseBrowser(tt.ua)
			if got != tt.want {
				t.Errorf("parseBrowser(%q) = %q, want %q", tt.ua, got, tt.want)
			}
		})
	}
}

// TestParseBrowser_SafariOnIOS covers Safari on iOS devices.
func TestParseBrowser_SafariOnIOS(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want string
	}{
		{
			"Safari on iPhone",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
			"Safari on iPhone",
		},
		{
			"Safari on iPad",
			"Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
			"Safari on iPad",
		},
		{
			"Safari on macOS",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
			"Safari on macOS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FriendlyName(tt.ua)
			if got != tt.want {
				t.Errorf("FriendlyName(%q) = %q, want %q", tt.ua, got, tt.want)
			}
		})
	}
}

// TestParseBrowser_Brave covers Brave browser detection.
func TestParseBrowser_Brave(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Brave/121"
	got := parseBrowser(ua)
	if got != "Brave" {
		t.Errorf("parseBrowser() = %q, want %q", got, "Brave")
	}
}

// TestParseBrowser_SamsungInternet covers Samsung Internet browser.
func TestParseBrowser_SamsungInternet(t *testing.T) {
	ua := "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36"
	got := parseBrowser(ua)
	if got != "Samsung Internet" {
		t.Errorf("parseBrowser() = %q, want %q", got, "Samsung Internet")
	}
}

// TestParseBrowser_Vivaldi covers Vivaldi browser detection.
func TestParseBrowser_Vivaldi(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Vivaldi/6.5.3206.50"
	got := parseBrowser(ua)
	if got != "Vivaldi" {
		t.Errorf("parseBrowser() = %q, want %q", got, "Vivaldi")
	}
}

// TestParseBrowser_Yandex covers Yandex browser detection.
func TestParseBrowser_Yandex(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 YaBrowser/24.1.0.0 Safari/537.36"
	got := parseBrowser(ua)
	if got != "Yandex" {
		t.Errorf("parseBrowser() = %q, want %q", got, "Yandex")
	}
}

// TestParseBrowser_BotAgents covers bot and tool user agents.
func TestParseBrowser_BotAgents(t *testing.T) {
	tests := []struct {
		name        string
		ua          string
		wantBrowser string
	}{
		{
			"Googlebot",
			"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			"",
		},
		{
			"Bingbot",
			"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
			"",
		},
		{
			"curl",
			"curl/8.5.0",
			"curl",
		},
		{
			"Wget",
			"Wget/1.21.4",
			"Wget",
		},
		{
			"python-requests",
			"python-requests/2.31.0",
			"",
		},
		{
			"Postman",
			"PostmanRuntime/7.36.0",
			"Postman",
		},
		{
			"Insomnia",
			"insomnia/2023.5.8",
			"Insomnia",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseBrowser(tt.ua)
			if got != tt.wantBrowser {
				t.Errorf("parseBrowser(%q) = %q, want %q", tt.ua, got, tt.wantBrowser)
			}
		})
	}
}

// TestParseBrowser_InternetExplorer covers IE detection.
func TestParseBrowser_InternetExplorer(t *testing.T) {
	tests := []struct {
		name string
		ua   string
	}{
		{
			"IE 11",
			"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
		},
		{
			"IE 10",
			"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",
		},
		{
			"IE 9",
			"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseBrowser(tt.ua)
			if got != "Internet Explorer" {
				t.Errorf("parseBrowser(%q) = %q, want %q", tt.ua, got, "Internet Explorer")
			}
		})
	}
}

// TestParseBrowser_Chromium covers Chromium vs Chrome detection.
func TestParseBrowser_Chromium(t *testing.T) {
	ua := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chromium/121.0.0.0 Chrome/121.0.0.0 Safari/537.36"
	got := parseBrowser(ua)
	if got != "Chromium" {
		t.Errorf("parseBrowser() = %q, want %q", got, "Chromium")
	}
}

// TestFriendlyName_EmptyAndEdgeCases covers edge cases.
func TestFriendlyName_EmptyAndEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want string
	}{
		{"empty string", "", "Unknown Device"},
		{"whitespace only", "   ", "Unknown Device"},
		{"null byte", "\x00", "Unknown Device"},
		{"single character", "X", "Unknown Device"},
		{"no match at all", "completely-unknown-agent/1.0", "Unknown Device"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FriendlyName(tt.ua)
			if got != tt.want {
				t.Errorf("FriendlyName(%q) = %q, want %q", tt.ua, got, tt.want)
			}
		})
	}
}

// TestFriendlyName_VeryLongString verifies handling of extremely long user agent strings.
func TestFriendlyName_VeryLongString(t *testing.T) {
	// 1000+ character user agent with a valid browser buried inside
	longUA := strings.Repeat("X", 500) + "Chrome/" + strings.Repeat("Y", 500)
	got := FriendlyName(longUA)
	if got != "Chrome" {
		t.Errorf("FriendlyName(long string) = %q, want %q", got, "Chrome")
	}
}

// TestFriendlyName_VeryLongStringNoMatch verifies handling of very long strings with no match.
func TestFriendlyName_VeryLongStringNoMatch(t *testing.T) {
	longUA := strings.Repeat("A", 2000)
	got := FriendlyName(longUA)
	if got != "Unknown Device" {
		t.Errorf("FriendlyName(long no-match) = %q, want %q", got, "Unknown Device")
	}
}

// TestFriendlyName_NullBytes verifies handling of null bytes in user agent.
func TestFriendlyName_NullBytes(t *testing.T) {
	ua := "Mozilla/5.0\x00Chrome/121.0.0.0"
	got := FriendlyName(ua)
	// Chrome/ is still detectable via strings.Contains despite the null byte
	if got != "Chrome" {
		t.Errorf("FriendlyName(null byte) = %q, want %q", got, "Chrome")
	}
}

// TestFriendlyName_MobileDesktopDetection covers mobile vs desktop OS identification.
func TestFriendlyName_MobileDesktopDetection(t *testing.T) {
	tests := []struct {
		name     string
		ua       string
		wantOS   string
		isMobile bool
	}{
		{
			"iPhone mobile",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
			"iPhone", true,
		},
		{
			"iPad tablet",
			"Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
			"iPad", true,
		},
		{
			"Android mobile",
			"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
			"Android", true,
		},
		{
			"Windows desktop",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
			"Windows", false,
		},
		{
			"macOS desktop",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
			"macOS", false,
		},
		{
			"Linux desktop",
			"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
			"Linux", false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOS := parseOS(tt.ua)
			if gotOS != tt.wantOS {
				t.Errorf("parseOS(%q) = %q, want %q", tt.ua, gotOS, tt.wantOS)
			}
		})
	}
}

// TestParseOS_Variants covers additional OS detection.
func TestParseOS_Variants(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want string
	}{
		{
			"ChromeOS",
			"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36",
			"ChromeOS",
		},
		{
			"FreeBSD",
			"Mozilla/5.0 (X11; FreeBSD amd64; rv:121.0) Gecko/20100101 Firefox/121.0",
			"FreeBSD",
		},
		{
			"OpenBSD",
			"Mozilla/5.0 (X11; OpenBSD amd64; rv:121.0) Gecko/20100101 Firefox/121.0",
			"OpenBSD",
		},
		{
			"unknown OS",
			"curl/8.5.0",
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseOS(tt.ua)
			if got != tt.want {
				t.Errorf("parseOS(%q) = %q, want %q", tt.ua, got, tt.want)
			}
		})
	}
}

// TestFriendlyName_BrowserOnly tests user agents with browser but no OS.
func TestFriendlyName_BrowserOnly(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want string
	}{
		{"curl no OS", "curl/8.5.0", "curl"},
		{"Wget no OS", "Wget/1.21.4", "Wget"},
		{"Postman no OS", "PostmanRuntime/7.36.0", "Postman"},
		{"Insomnia no OS", "insomnia/2023.5.8", "Insomnia"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FriendlyName(tt.ua)
			if got != tt.want {
				t.Errorf("FriendlyName(%q) = %q, want %q", tt.ua, got, tt.want)
			}
		})
	}
}

// TestFriendlyName_OSOnly tests user agents with OS but no recognized browser.
func TestFriendlyName_OSOnly(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want string
	}{
		{"Windows only", "Some-App/1.0 (Windows NT 10.0)", "Windows"},
		{"Linux only", "CustomClient/2.0 (Linux x86_64)", "Linux"},
		{"Android only", "SomeSDK/1.0 (Android 14)", "Android"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FriendlyName(tt.ua)
			if got != tt.want {
				t.Errorf("FriendlyName(%q) = %q, want %q", tt.ua, got, tt.want)
			}
		})
	}
}

// TestFriendlyName_CombinedBrowserOS tests the "browser on OS" format.
func TestFriendlyName_CombinedBrowserOS(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want string
	}{
		{
			"Firefox on Windows",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
			"Firefox on Windows",
		},
		{
			"Chrome on Linux",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
			"Chrome on Linux",
		},
		{
			"Vivaldi on macOS",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Vivaldi/6.5",
			"Vivaldi on macOS",
		},
		{
			"Yandex on Windows",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 YaBrowser/24.1.0.0 Safari/537.36",
			"Yandex on Windows",
		},
		{
			"Firefox on Android (FxiOS)",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/121.0 Mobile/15E148 Safari/605.1.15",
			"Firefox on iPhone",
		},
		{
			"Chrome on iPhone (CriOS)",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/121.0.6167.171 Mobile/15E148 Safari/604.1",
			"Chrome on iPhone",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FriendlyName(tt.ua)
			if got != tt.want {
				t.Errorf("FriendlyName(%q) = %q, want %q", tt.ua, got, tt.want)
			}
		})
	}
}

// TestContains verifies the internal contains helper.
func TestContains(t *testing.T) {
	tests := []struct {
		s      string
		substr string
		want   bool
	}{
		{"hello world", "world", true},
		{"hello world", "xyz", false},
		{"", "", true},
		{"abc", "", true},
		{"", "abc", false},
	}

	for _, tt := range tests {
		got := contains(tt.s, tt.substr)
		if got != tt.want {
			t.Errorf("contains(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
		}
	}
}

// TestParseBrowser_Priority verifies that specific browsers are detected over generic ones.
func TestParseBrowser_Priority(t *testing.T) {
	// Edge contains "Chrome" — should detect Edge, not Chrome
	edgeUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
	if got := parseBrowser(edgeUA); got != "Edge" {
		t.Errorf("Edge UA detected as %q instead of Edge", got)
	}

	// Opera contains "Chrome" — should detect Opera, not Chrome
	operaUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36 OPR/107.0.0.0"
	if got := parseBrowser(operaUA); got != "Opera" {
		t.Errorf("Opera UA detected as %q instead of Opera", got)
	}

	// Vivaldi contains "Chrome" — should detect Vivaldi, not Chrome
	vivaldiUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36 Vivaldi/6.5"
	if got := parseBrowser(vivaldiUA); got != "Vivaldi" {
		t.Errorf("Vivaldi UA detected as %q instead of Vivaldi", got)
	}

	// Samsung Internet contains "Chrome" — should detect Samsung Internet
	samsungUA := "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36"
	if got := parseBrowser(samsungUA); got != "Samsung Internet" {
		t.Errorf("Samsung UA detected as %q instead of Samsung Internet", got)
	}

	// Yandex contains "Chrome" — should detect Yandex
	yandexUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 YaBrowser/24.1.0.0 Safari/537.36"
	if got := parseBrowser(yandexUA); got != "Yandex" {
		t.Errorf("Yandex UA detected as %q instead of Yandex", got)
	}
}

// TestParseOS_MacOSVariants covers both "Macintosh" and "Mac OS" OS strings.
func TestParseOS_MacOSVariants(t *testing.T) {
	tests := []struct {
		name string
		ua   string
	}{
		{"Macintosh keyword", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2)"},
		{"Mac OS keyword", "SomeApp/1.0 (Mac OS X 10.15)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseOS(tt.ua)
			if got != "macOS" {
				t.Errorf("parseOS(%q) = %q, want %q", tt.ua, got, "macOS")
			}
		})
	}
}
