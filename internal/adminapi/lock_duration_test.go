package adminapi

import (
	"testing"
	"time"
)

// L7: an admin lock duration is clamped to 24h unless it's a sane positive
// value <= 30 days.
func TestClampLockDuration(t *testing.T) {
	day := 24 * time.Hour
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"1h", time.Hour},
		{"720h", 720 * time.Hour}, // exactly 30d, allowed
		{"1000000h", day},         // absurd → clamp
		{"721h", day},             // > 30d → clamp
		{"0s", day},               // non-positive → clamp
		{"-5h", day},              // negative → clamp
		{"garbage", day},          // unparseable → clamp
		{"", day},                 // empty → clamp
	}
	for _, tt := range tests {
		if got := clampLockDuration(tt.in); got != tt.want {
			t.Errorf("clampLockDuration(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
