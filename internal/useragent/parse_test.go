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
