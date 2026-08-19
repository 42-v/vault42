package service

import (
	"testing"

	"github.com/42-v/vault42/internal/honeypot"
	"github.com/42-v/vault42/internal/metrics"
)

func TestAuthServiceSetters(t *testing.T) {
	s := &AuthService{}

	s.SetRateLimitRepo(nil)
	if s.rateLimits != nil {
		t.Fatal("SetRateLimitRepo(nil) did not store nil")
	}

	alerter := &honeypot.Alerter{}
	s.SetHoneypotAlerter(alerter)
	if s.honeypotAlert != alerter {
		t.Fatal("SetHoneypotAlerter did not store the alerter")
	}

	m := &metrics.Collector{}
	s.SetMetrics(m)
	if s.metrics != m {
		t.Fatal("SetMetrics did not store the collector")
	}

	s.SetMaxSessionsPerUser(7)
	if s.maxSessionsPerUser != 7 {
		t.Fatalf("SetMaxSessionsPerUser stored %d, want 7", s.maxSessionsPerUser)
	}
	if s.MaxSessionsPerUser() != 7 {
		t.Fatalf("MaxSessionsPerUser() = %d, want 7", s.MaxSessionsPerUser())
	}
}
