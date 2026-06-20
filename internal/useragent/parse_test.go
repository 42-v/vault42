package useragent

import "testing"

func TestFriendlyName(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want string
	}{
		{
			"Chrome on Windows",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Chrome on Windows",
		},
		{
			"Firefox on Linux",
			"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
			"Firefox on Linux",
		},
		{
			"Safari on macOS",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
			"Safari on macOS",
		},
		{
			"Safari on iPhone",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
			"Safari on iPhone",
		},
		{
			"Chrome on Android",
			"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
			"Chrome on Android",
		},
		{
			"Edge on Windows",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			"Edge on Windows",
		},
		{
			"Opera on Windows",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
			"Opera on Windows",
		},
		{
			"Chrome on iPad",
			"Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1",
			"Chrome on iPad",
		},
		{
			"Firefox on iPhone",
			"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/120.0 Mobile/15E148 Safari/605.1.15",
			"Firefox on iPhone",
		},
		{
			"curl",
			"curl/8.4.0",
			"curl",
		},
		{
			"Postman",
			"PostmanRuntime/7.35.0",
			"Postman",
		},
		{"empty", "", "Unknown Device"},
		{"gibberish", "some-random-client/1.0", "Unknown Device"},
		{
			"Samsung Internet on Android",
			"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
			"Samsung Internet on Android",
		},
		{
			"Chrome on ChromeOS",
			"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			"Chrome on ChromeOS",
		},
		{"ie", "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1)", "Internet Explorer on Windows"},
		{"wget", "Wget/1.21", "Wget"},
		{"insomnia", "insomnia/1.0", "Insomnia"},
		{"vivaldi", "Mozilla/5.0 (X11; Linux) Vivaldi/1", "Vivaldi on Linux"},
		{"yandex", "Mozilla/5.0 (X11) YaBrowser/1", "Yandex"},
		{"chromium", "Mozilla/5.0 Chromium/1 (Linux)", "Chromium on Linux"},
		{"no browser os match", "SomeApp/1 (UnknownOS)", "Unknown Device"},
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

// TestFriendlyName_MoreEdges_Table adds coverage for additional browser/OS combos.
func TestFriendlyName_MoreEdges_Table(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want string
	}{
		{"brave", "Mozilla/5.0 (X11; Linux) AppleWebKit/537.36 Brave/120", "Brave on Linux"},
		{"freebsd", "Mozilla/5.0 (X11; FreeBSD) Firefox/100", "Firefox on FreeBSD"},
		{"openbsd", "curl/8.4.0", "curl"},
		{"ipad", "Mozilla/5.0 (iPad; CPU OS 16 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1", "Safari on iPad"},
		{"edge chromium", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120", "Edge on Windows"},
		{"opera", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/537.36 OPR/100", "Opera on macOS"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FriendlyName(tt.ua); got != tt.want {
				t.Errorf("FriendlyName(%q)=%q want %q", tt.ua, got, tt.want)
			}
		})
	}
}
