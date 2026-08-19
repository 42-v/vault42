package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// apUnserializableProfile is a profile that passes Validate but cannot be
// encoded: time.Time refuses to marshal a year outside [0,9999], and the consent
// record carries one. Validate checks field bounds, not encodability, so this is
// exactly the shape that reaches the marshal step and fails there.
func apUnserializableProfile() *IdentityData {
	return &IdentityData{
		GivenName: "Ada",
		MarketingConsent: &ConsentRecord{
			Granted: true,
			At:      time.Date(-1, time.January, 1, 0, 0, 0, 0, time.UTC),
			Source:  ConsentSourceRegistration,
		},
	}
}

// Both write paths encrypt before they store, and encryption of a half-encoded
// profile would be indistinguishable from encryption of a whole one: the
// ciphertext is opaque, so a partially serialized blob would be written, stored
// and only discovered on the next read, by which time the real profile is gone.
// A profile that cannot be marshaled must stop before the repository is touched.
func TestIdentityWritePaths_UnserializableProfileNeverReachesTheStore(t *testing.T) {
	tests := []struct {
		name  string
		write func(*IdentityService) error
	}{
		{
			name: "Upsert",
			write: func(s *IdentityService) error {
				return s.Upsert(context.Background(), "user-1", apUnserializableProfile())
			},
		},
		{
			name: "the compare-and-set write",
			write: func(s *IdentityService) error {
				_, err := s.upsertCAS(context.Background(), "user-1", apUnserializableProfile(), time.Time{})
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wrote := false
			repo := &mocks.MockIdentityRepo{
				UpsertFn: func(context.Context, *model.IdentityProfile) error {
					wrote = true
					return nil
				},
				UpsertCASFn: func(context.Context, *model.IdentityProfile, time.Time) (bool, error) {
					wrote = true
					return true, nil
				},
			}

			err := tc.write(testIdentitySvc(repo))
			if err == nil {
				t.Fatal("a profile that cannot be encoded was reported as stored")
			}
			if !strings.Contains(err.Error(), "identity marshal") {
				t.Errorf("err = %v, want it to name the marshal step", err)
			}
			if wrote {
				t.Error("the repository was written with a profile that never serialized")
			}
		})
	}
}
