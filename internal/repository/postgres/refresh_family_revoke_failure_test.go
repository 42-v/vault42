package postgres

import (
	"context"
	"strings"
	"testing"
)

// RevokeFamily is the response to a detected refresh-token replay: every token
// descended from the stolen one has to stop working, right now. It runs as
// three statements in one transaction (lock the family's rows, update them,
// commit), and a nil error from a run where any of those failed is the worst
// answer it can give. The caller has already decided the family is compromised
// and logged replay_detected; told the revoke succeeded, an operator reads the
// audit log and believes the session is dead while the thief keeps rotating.
//
// Each case below kills one step and pins two things: the error names the step
// that failed, and no later step ran. The second half is what stops a future
// refactor from dropping the pre-lock: the UPDATE takes its snapshot when it
// starts, so running it after a failed lock would revoke every row except the
// successor a concurrent rotation just inserted, which is the one row the
// attacker is holding.
func TestRefreshTokenRepo_RevokeFamilyFailsLoudlyAtEveryStep(t *testing.T) {
	beginOK := apPGRule{match: "begin", reply: func(string) []byte {
		return append(apMsg('C', apCStr("BEGIN")), apReadyInTx()...)
	}}

	tests := []struct {
		name string
		// Which statement the scripted server refuses.
		lockFails   bool
		updateFails bool
		commitFails bool
		wantStep    string
		wantDetail  string
		wantUpdated bool
		wantCommit  bool
	}{
		{
			name:       "the family rows cannot be locked",
			lockFails:  true,
			wantStep:   "lock family",
			wantDetail: "deadlock detected",
		},
		{
			name:        "the update is refused after the rows were locked",
			updateFails: true,
			wantStep:    "revoke family",
			wantDetail:  "canceling statement due to statement timeout",
			wantUpdated: true,
		},
		{
			name:        "the commit is refused after the update succeeded",
			commitFails: true,
			wantStep:    "revoke family",
			wantDetail:  "could not serialize access",
			wantUpdated: true,
			wantCommit:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var locked, updated, committed bool

			rules := []apPGRule{
				{match: "FOR UPDATE", reply: func(string) []byte {
					locked = true
					if tc.lockFails {
						return append(apErrorResponse("40P01", tc.wantDetail), apReadyTxFailed()...)
					}
					return append(apMsg('C', apCStr("SELECT 3")), apReadyInTx()...)
				}},
				{match: "UPDATE auth.refresh_tokens", reply: func(string) []byte {
					updated = true
					if tc.updateFails {
						return append(apErrorResponse("57014", tc.wantDetail), apReadyTxFailed()...)
					}
					return append(apMsg('C', apCStr("UPDATE 3")), apReadyInTx()...)
				}},
				{match: "commit", reply: func(string) []byte {
					committed = true
					if tc.commitFails {
						return append(apErrorResponse("40001", tc.wantDetail), apReadyIdle()...)
					}
					return append(apMsg('C', apCStr("COMMIT")), apReadyIdle()...)
				}},
				beginOK,
			}

			err := NewRefreshTokenRepo(apStartPG(t, rules...)).
				RevokeFamily(context.Background(), "fam-1")
			if err == nil {
				t.Fatal("RevokeFamily reported the family revoked; the stolen token keeps rotating")
			}
			if !strings.Contains(err.Error(), tc.wantStep) {
				t.Errorf("err = %v, want it to name the %s step", err, tc.wantStep)
			}
			if !strings.Contains(err.Error(), tc.wantDetail) {
				t.Errorf("err = %v, want the database's own reason kept for the operator", err)
			}
			if !locked {
				t.Error("the family rows were never locked; the update would run on a snapshot taken before a concurrent rotation committed")
			}
			if updated != tc.wantUpdated {
				t.Errorf("update statement sent = %v, want %v", updated, tc.wantUpdated)
			}
			if committed != tc.wantCommit {
				t.Errorf("commit sent = %v, want %v", committed, tc.wantCommit)
			}
		})
	}
}
