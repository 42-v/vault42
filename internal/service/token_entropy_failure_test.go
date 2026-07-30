package service

import (
	"errors"
	"strings"
	"testing"
)

// IssueTokenPair draws three independent pieces of random material: the access
// token JTI, the refresh token itself, and the family ID for a brand new
// session. A generator failure at any of the three must abort issuance. The
// assertion that matters is that no TokenPair comes back: a partially filled
// pair would be a session with an empty refresh token or an empty family, and
// an empty family cannot be revoked when replay is later detected.
func TestIssueTokenPairEntropyFailureIssuesNothing(t *testing.T) {
	tests := []struct {
		name     string
		budget   int64
		familyID string
		wantMsg  string
	}{
		{name: "access token JTI", budget: 0, familyID: "fam-1", wantMsg: "generate JTI"},
		{name: "refresh token", budget: 1, familyID: "fam-1", wantMsg: "crypto/rand"},
		{name: "family ID for a new session", budget: 2, familyID: "", wantMsg: "generate family ID"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newTestTokenService(t)
			serviceAuthStarveEntropy(t, tc.budget)

			pair, err := svc.IssueTokenPair("user-1", []string{"user"}, []string{"read"},
				"client-1", "fp-hash", tc.familyID, false)

			if !errors.Is(err, errServiceAuthEntropy) {
				t.Fatalf("err = %v, want the entropy failure to surface", err)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("err = %v, want it to contain %q", err, tc.wantMsg)
			}
			if pair != nil {
				t.Fatalf("a token pair was returned despite the failure: refresh=%q family=%q",
					pair.RefreshToken, pair.FamilyID)
			}
		})
	}
}

// The 2FA challenge token carries the user ID and the device fingerprint that
// the MFA verify endpoints trust. Without a JTI it has no single-use identity,
// so it must not be minted at all.
func TestIssueChallengeTokenEntropyFailureIssuesNothing(t *testing.T) {
	svc, _ := newTestTokenService(t)
	serviceAuthStarveEntropy(t, 0)

	token, err := svc.IssueChallengeToken("user-1", "fp-hash")

	if !errors.Is(err, errServiceAuthEntropy) {
		t.Fatalf("err = %v, want the entropy failure to surface", err)
	}
	if !strings.Contains(err.Error(), "generate challenge JTI") {
		t.Errorf("err = %v, want it to name the challenge JTI step", err)
	}
	if token != "" {
		t.Errorf("challenge token = %q, want empty when it has no JTI", token)
	}
}
