package postgres

import (
	"context"
	"strings"
	"testing"
)

// WithSubjectWriteLock is the whole reason the document quota holds under
// concurrency: the service counts what a subject already holds and then writes,
// and those two statements are one unit of work only because this transaction
// and this advisory lock make them one.
//
// So the closure must not run unless the lock was actually taken. A step that
// failed and returned nil anyway would run the quota decision with no lock held
// in this process and none in the database, which is exactly the write-skew the
// lock exists to close: two writers count the same pre-write state, write
// different keys, and the unique index never fires. A refused COMMIT is the
// same defect one statement later, with the caller told its document was
// stored.
func TestServiceDocumentRepo_SubjectLockFailsTheWriteAtEveryStep(t *testing.T) {
	beginOK := apPGRule{match: "begin", reply: func(string) []byte {
		return append(apMsg('C', apCStr("BEGIN")), apReadyInTx()...)
	}}
	lockOK := apPGRule{match: "pg_advisory_xact_lock", reply: func(string) []byte {
		return append(apMsg('C', apCStr("SELECT 1")), apReadyInTx()...)
	}}

	tests := []struct {
		name    string
		rules   []apPGRule
		want    string
		wantRan bool
	}{
		{
			name: "the transaction never starts",
			want: "begin service document subject lock",
			rules: []apPGRule{
				{match: "begin", reply: func(string) []byte {
					return append(apErrorResponse("53300", "too many connections for role"), apReadyIdle()...)
				}},
			},
		},
		{
			name: "the advisory lock is refused",
			want: "lock service document subject",
			rules: []apPGRule{
				beginOK,
				{match: "pg_advisory_xact_lock", reply: func(string) []byte {
					return append(apErrorResponse("57014", "canceling statement due to statement timeout"), apReadyTxFailed()...)
				}},
			},
		},
		{
			name:    "the commit is refused after the closure wrote",
			want:    "commit service document write",
			wantRan: true,
			rules: []apPGRule{
				beginOK, lockOK,
				{match: "commit", reply: func(string) []byte {
					return append(apErrorResponse("40001", "could not serialize access"), apReadyIdle()...)
				}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ran bool
			err := NewServiceDocumentRepo(apStartPG(t, tc.rules...)).
				WithSubjectWriteLock(context.Background(), "subject-hash", func(context.Context) error {
					ran = true
					return nil
				})
			if err == nil {
				t.Fatal("WithSubjectWriteLock reported a locked, committed write")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to name the %q step", err, tc.want)
			}
			if ran != tc.wantRan {
				t.Errorf("the closure ran = %v, want %v; a quota decision outside the lock is the anomaly this exists to prevent", ran, tc.wantRan)
			}
		})
	}
}
