package audit

import (
	"context"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// ctxCheckingRepo refuses a done context the way pgxpool does: Acquire returns
// ctx.Err() before it touches the network.
type ctxCheckingRepo struct {
	mockAuditRepo
}

func (r *ctxCheckingRepo) Insert(ctx context.Context, e *model.AuditEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return r.mockAuditRepo.Insert(ctx, e)
}

// A client that hangs up after the action committed must not take the audit
// row with it. Handlers pass r.Context(), which net/http cancels on
// disconnect, and Log runs after the side effect; inserting on that context
// recorded nothing for an import, a ban or a key revocation whose caller simply
// closed the connection at the right moment.
func TestLogSurvivesTheCallerHangingUp(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	t.Run("immediate mode", func(t *testing.T) {
		repo := &ctxCheckingRepo{}
		if err := NewLogger(repo, 0).Log(canceled, AdminAction, "", "", "", "", "", "",
			map[string]interface{}{"action": "users_import"}); err != nil {
			t.Fatalf("Log on a canceled request context = %v; the entry must still be written", err)
		}
		if len(repo.entries) != 1 {
			t.Errorf("wrote %d entries, want 1", len(repo.entries))
		}
	})

	t.Run("critical event with the buffer full", func(t *testing.T) {
		repo := &ctxCheckingRepo{}
		l := NewLogger(repo, 1<<30) // batch mode, a flush that never comes
		defer l.Close(context.Background())
		l.bufferSize = 0 // every entry takes the buffer-full path
		_ = l.Log(canceled, RefreshTokenReplayed, "u", "", "", "", "", "", nil)
		if len(repo.entries) != 1 {
			t.Errorf("a critical event on a canceled context wrote %d entries, want 1", len(repo.entries))
		}
	})
}
