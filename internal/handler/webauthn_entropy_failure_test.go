package handler

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

var errWanentEntropy = errors.New("handler test: entropy exhausted")

// wanentScriptedReader serves budget whole reads and then fails. Only code that
// reaches crypto/rand through io.ReadFull (RandomBytes and everything built on
// it) sees the error: crypto/rand.Read is process-fatal on a failing reader, so
// the budget must always cover the direct rand.Read calls a flow makes.
type wanentScriptedReader struct {
	left atomic.Int64
}

func (r *wanentScriptedReader) Read(p []byte) (int, error) {
	if r.left.Add(-1) < 0 {
		return 0, errWanentEntropy
	}
	for i := range p {
		p[i] = 0x42
	}
	return len(p), nil
}

var _ io.Reader = (*wanentScriptedReader)(nil)

// wanentStarveEntropy installs a reader that dies after budget reads and puts
// the real entropy source back when the test ends.
func wanentStarveEntropy(t *testing.T, budget int64) {
	t.Helper()
	r := &wanentScriptedReader{}
	r.left.Store(budget)
	handlerRandUse(t, r)
}

// The primary key of the credential row is minted from crypto/rand after the
// attestation has already verified. If the mint fails and the handler carried
// on, it would insert a credential keyed by the empty string: an authenticator
// the user can never list, name or revoke, and one that a later enrolment on the
// same empty key would silently collide with. The ceremony must fail closed with
// nothing written, even though the challenge is already spent.
func TestWebAuthnRegisterFinish_CredentialIDEntropyFailureStoresNothing(t *testing.T) {
	wan := newWanfidoWebAuthn(t)
	auth := newWanfidoAuthenticator(t, "starved-credential")
	sessions := newWanfidoSessionCache()
	challenge := wanfidoRegistrationSession(t, wan, sessions, "user-1")

	var created atomic.Bool
	credRepo := &mocks.MockWebAuthnRepo{
		ListByUserFn: func(context.Context, string) ([]*model.WebAuthnCredential, error) { return nil, nil },
		CreateFn: func(context.Context, *model.WebAuthnCredential) error {
			created.Store(true)
			return nil
		},
	}

	h := NewWebAuthnHandler(credRepo, newWanfidoUserRepo(), sessions, wan, nil, false)

	req := setAuthContext(auth.attestationRequest(t, challenge, 3), "user-1")
	rec := httptest.NewRecorder()

	wanentStarveEntropy(t, 0)

	h.RegisterFinish(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
	if created.Load() {
		t.Error("a credential row was written without a generated primary key")
	}

	var result map[string]string
	decodeResponse(t, rec, &result)
	if result["error"] != "internal_error" {
		t.Errorf("error = %q, want internal_error", result["error"])
	}
	if strings.Contains(rec.Body.String(), "webauthn_registered") {
		t.Error("enrolment reported as complete while no credential was stored")
	}
	if strings.Contains(rec.Body.String(), "entropy") || strings.Contains(rec.Body.String(), "crypto/rand") {
		t.Errorf("entropy failure detail leaked to the client: %s", rec.Body.String())
	}
}
