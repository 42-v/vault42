package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

// The behavioral half of tests/spec/erasure_write_guard_test.go.
//
// That gate reads the wiring and proves every create-or-update route under
// /user/ and /auth/2fa/ names a guarded wrapper. It cannot prove the wrapper
// refuses anything. This drives the handler the deployment actually serves --
// Chain(setupRoutes()), the same one chain_probe_test.go drives -- with a
// perfectly valid access token whose subject has since been erased, and asserts
// the request is refused before it reaches a handler.
//
// Both directions are asserted on purpose. A middleware that answered 401
// unconditionally would satisfy every erased case here while breaking the
// service, so each route is driven twice: erased, where the answer must be 401,
// and live, where it must not be. The repositories behind the guard stay nil, so
// a request that gets past every gate dereferences one and the deployed Recovery
// layer turns that panic into a 500 -- which is precisely the evidence the live
// case needs, and is the same convention chainProbeDeps documents.

// guardedWriteRoutes are the guarded create-or-update routes driven below.
// needConfirm marks the ones behind confirmMw, which runs in front of the guard
// and would otherwise stop the request at 403 before it reached the thing under
// test.
var guardedWriteRoutes = []struct {
	name        string
	method      string
	path        string
	needConfirm bool
}{
	{"password change", http.MethodPost, "/user/password", false},
	{"identity write", http.MethodPut, "/user/identity", false},
	{"blob upload", http.MethodPost, "/user/blobs", false},
	{"named blob upload", http.MethodPut, "/user/blobs/named/note", false},
	{"marketing unsubscribe", http.MethodPost, "/user/marketing/unsubscribe", false},
	{"TOTP enrollment", http.MethodPost, "/auth/2fa/totp/setup", true},
	{"backup-code generation", http.MethodPost, "/auth/2fa/backup-codes", true},
	{"WebAuthn enrollment", http.MethodPost, "/auth/2fa/webauthn/register/begin", true},
}

func TestAnErasedSubjectIsRefusedAtEveryGuardedWrite(t *testing.T) {
	for _, rt := range guardedWriteRoutes {
		t.Run(rt.name+"/erased is refused", func(t *testing.T) {
			status, body := driveGuardedRoute(t, rt.method, rt.path, rt.needConfirm, true)
			if status != http.StatusUnauthorized {
				t.Errorf("%s %s for an erased subject = %d (%s), want %d.\n"+
					"An access token minted before DELETE /user/account still writes, so the "+
					"Article 17 erasure does not stick.",
					rt.method, rt.path, status, strings.TrimSpace(body), http.StatusUnauthorized)
			}
		})

		t.Run(rt.name+"/live is admitted", func(t *testing.T) {
			status, body := driveGuardedRoute(t, rt.method, rt.path, rt.needConfirm, false)
			if status == http.StatusUnauthorized {
				t.Errorf("%s %s for a LIVE subject = 401 (%s). The guard refuses every caller, "+
					"so the erased case above proves nothing about erasure.",
					rt.method, rt.path, strings.TrimSpace(body))
			}
		})
	}
}

// driveGuardedRoute serves one request against the deployed chain for a subject
// that is either erased or live, and returns the status and body.
func driveGuardedRoute(t *testing.T, method, path string, needConfirm, erased bool) (int, string) {
	t.Helper()
	deps, key, memCache := chainProbeDeps(t)
	deps.Users = &mocks.MockUserRepo{
		GetByIDFn: func(_ context.Context, id string) (*model.User, error) {
			return &model.User{ID: id, Email: "probe@example.com", Deleted: erased}, nil
		},
	}
	// PUT /user/identity and the blob routes are only registered when these are
	// present, and the blob routes additionally need a quota above zero.
	deps.Identity = &mocks.MockIdentityRepo{}
	deps.Blobs = &mocks.MockBlobRepo{}
	deps.Config.BlobQuotaBytes = 1 << 20

	s := New(deps)
	h := s.Chain(s.setupRoutes())

	claims := chainProbeClaims()
	token := chainProbeSign(t, key, claims)

	if needConfirm {
		if err := memCache.Set(context.Background(), "confirm:"+claims.Subject, claims.ID, time.Minute); err != nil {
			t.Fatalf("seed confirm window: %v", err)
		}
	}

	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}
