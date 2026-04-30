package main

import (
	"testing"
	"time"
)

func TestScoreAutomationUA(t *testing.T) {
	tests := []struct {
		ua    string
		score int
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", 0},
		{"curl/7.68.0", 30},
		{"sqlmap/1.5", 30},
		{"python-requests/2.28.0", 30},
		{"Nikto/2.1.6", 30},
		{"Mozilla/5.0 (compatible; Googlebot/2.1)", 30},
		{"", 0},
		{"Go-http-client/1.1", 30},
		{"Nuclei - Open-source scanner", 30},
	}

	for _, tt := range tests {
		t.Run(tt.ua, func(t *testing.T) {
			got := ScoreAutomationUA(tt.ua)
			if got != tt.score {
				t.Errorf("ScoreAutomationUA(%q) = %d, want %d", tt.ua, got, tt.score)
			}
		})
	}
}

func TestRateTracker(t *testing.T) {
	rt := NewRateTracker(100 * time.Millisecond)

	// Record several requests
	for i := 0; i < 5; i++ {
		rt.Record("1.2.3.4")
	}

	if got := rt.Count("1.2.3.4"); got != 5 {
		t.Errorf("Count = %d, want 5", got)
	}

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	if got := rt.Count("1.2.3.4"); got != 0 {
		t.Errorf("Count after expiry = %d, want 0", got)
	}
}

func TestRateTrackerReap(t *testing.T) {
	rt := NewRateTracker(50 * time.Millisecond)
	rt.Record("1.1.1.1")
	rt.Record("2.2.2.2")

	time.Sleep(120 * time.Millisecond)
	rt.Reap()

	rt.mu.Lock()
	count := len(rt.buckets)
	rt.mu.Unlock()

	if count != 0 {
		t.Errorf("Reap: %d buckets remain, want 0", count)
	}
}

func TestLoginFailTracker(t *testing.T) {
	lft := NewLoginFailTracker(100 * time.Millisecond)

	for i := 1; i <= 3; i++ {
		got := lft.Record("10.0.0.1")
		if got != i {
			t.Errorf("Record() = %d, want %d", got, i)
		}
	}

	time.Sleep(150 * time.Millisecond)

	// After window expiry, next record should be 1
	if got := lft.Record("10.0.0.1"); got != 1 {
		t.Errorf("Record after expiry = %d, want 1", got)
	}
}
