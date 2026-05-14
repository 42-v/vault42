package unit_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// Deterministic coverage for the `if !used { 409 backup_code_already_used }`
// branch — the race-flaky line that bounced 0..1 in CI. Mock MarkUsed to
// return (false, nil) and a real HMAC match against a known code.
func TestBackupCodeVerify_AlreadyUsed_Conflict(t *testing.T) {
	hmacKey := []byte("backup-code-hmac-test-key-32bytes")
	code := "ABCD-1234"
	codeHash := vaultcrypto.HMACSign([]byte(code), hmacKey)

	repo := &mocks.MockBackupCodeRepo{
		ListUnusedByUserFn: func(_ context.Context, _ string) ([]*model.BackupCode, error) {
			return []*model.BackupCode{{ID: "bc-1", UserID: testUserID, CodeHash: codeHash}}, nil
		},
		MarkUsedFn: func(_ context.Context, _ string) (bool, error) {
			return false, nil // already used — exercises the 409 branch
		},
	}
	h := handler.NewBackupCodeHandler(repo, hmacKey, nil, false)

	body, _ := json.Marshal(map[string]string{"code": code})
	req, w, keys := authedRequest(t, http.MethodPost, "/auth/2fa/backup-codes/verify", nil)
	req.Body = &readCloserImpl{Reader: strings.NewReader(string(body))}
	serveWithAuth(t, "POST /auth/2fa/backup-codes/verify", h.Verify, keys, w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 backup_code_already_used, got %d: %s", w.Code, w.Body.String())
	}
}
