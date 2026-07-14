package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/42-v/vault42/internal/keystore"
	"github.com/42-v/vault42/internal/kms"
	"github.com/42-v/vault42/tests/mocks"
)

// routeStatus asks the real mux what it would do with this request, with no auth and no
// body. The point is not the handler's answer but whether the route exists at all: 404
// means the endpoint was never wired, anything else means it was.
func routeStatus(t *testing.T, deps *Deps, method, path string) (int, string) {
	t.Helper()
	mux := New(deps).setupRoutes()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec.Code, rec.Body.String()
}

// Turning registration off in config has to actually stop registrations. If the flag only
// gated a banner somewhere and the route stayed live, an operator who closed signups
// would still be accepting them — and would have no reason to look.
//
// The route is deliberately still registered when disabled, answering 403
// registration_disabled rather than 404: a 404 would say "this server has no such
// endpoint", which is a different and less honest claim than "registration is off".
func TestWiring_RegistrationDisabledRefusesRegistration(t *testing.T) {
	deps := startTestDeps(t, "127.0.0.1:0")
	deps.Config.RegistrationEnabled = false

	code, body := routeStatus(t, deps, http.MethodPost, "/auth/register")

	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — registration is disabled but the endpoint still accepted the request", code)
	}
	if !strings.Contains(body, "registration_disabled") {
		t.Errorf("body = %s, want registration_disabled", body)
	}
}

func TestWiring_RegistrationEnabledServesRegistration(t *testing.T) {
	deps := startTestDeps(t, "127.0.0.1:0")
	deps.Config.RegistrationEnabled = true

	code, body := routeStatus(t, deps, http.MethodPost, "/auth/register")

	if code == http.StatusForbidden && strings.Contains(body, "registration_disabled") {
		t.Fatal("registration is enabled but the endpoint reports it as disabled")
	}
	if code == http.StatusNotFound {
		t.Fatal("registration is enabled but the endpoint is not wired at all")
	}
}

// Self-service erasure is wired only when a recovery escrow is configured. That is the
// fail-closed design made structural: erasure must not be reachable at all on a
// deployment that has nowhere to write the recoverable record, because the alternative
// is destroying an account with no way to restore it.
//
// If this route ever appeared without d.Recovery, the endpoint would exist with no
// escrow behind it — which is precisely the case the erasure service refuses to run in.
func TestWiring_ErasureEndpointRequiresRecoveryEscrow(t *testing.T) {
	t.Run("absent without a recovery store", func(t *testing.T) {
		deps := startTestDeps(t, "127.0.0.1:0")
		deps.Recovery = nil

		code, _ := routeStatus(t, deps, http.MethodDelete, "/user/account")

		if code != http.StatusNotFound {
			t.Errorf("status = %d, want 404 — erasure must not be reachable with no escrow to write to", code)
		}
	})

	t.Run("present with a recovery store", func(t *testing.T) {
		deps := startTestDeps(t, "127.0.0.1:0")
		deps.Recovery = &mocks.MockAccountRecoveryRepo{}

		code, _ := routeStatus(t, deps, http.MethodDelete, "/user/account")

		if code == http.StatusNotFound {
			t.Error("the erasure endpoint is not wired even though a recovery escrow is configured")
		}
		if code == http.StatusOK {
			t.Error("erasure answered 200 to an unauthenticated request")
		}
	})
}

// The KMS unwrap endpoint hands back plaintext key material to a caller holding the right
// scope. It must not exist on a deployment that has no KMS wired: an endpoint that is
// present but unbacked is a much larger surface than one that was never registered. And
// when it *is* wired it must still refuse an anonymous caller — an unwrap oracle that
// answered without auth would hand the data-root to anyone who asked.
func TestWiring_KMSUnwrapMountedOnlyWithKMS(t *testing.T) {
	t.Run("absent without a KMS", func(t *testing.T) {
		deps := startTestDeps(t, "127.0.0.1:0")
		deps.KMS = nil

		code, _ := routeStatus(t, deps, http.MethodPost, "/kms/unwrap")

		if code != http.StatusNotFound {
			t.Errorf("status = %d, want 404 — /kms/unwrap is reachable with no KMS behind it", code)
		}
	})

	t.Run("mounted and authenticated when a KMS is configured", func(t *testing.T) {
		svc, err := kms.New(bytes.Repeat([]byte{0x42}, 32))
		if err != nil {
			t.Fatalf("kms.New: %v", err)
		}
		deps := startTestDeps(t, "127.0.0.1:0")
		deps.KMS = svc

		code, _ := routeStatus(t, deps, http.MethodPost, "/kms/unwrap")

		if code == http.StatusNotFound {
			t.Fatal("a KMS is configured but /kms/unwrap was never wired")
		}
		if code == http.StatusOK {
			t.Error("the unwrap oracle answered an unauthenticated request — key material to anyone who asks")
		}
	})
}

// With key rotation on, the JWKS and the auth middleware are served from the keystore's
// live key provider rather than a static map. Both branches must produce a working
// surface: a deployment that rotates keys and one that does not are both supported, and
// the wiring picks between them on d.KeyStore alone.
func TestWiring_KeystoreBackedJWKS(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://vault:vault@127.0.0.1:1/vault?connect_timeout=1")
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	ks, err := keystore.New(pool, bytes.Repeat([]byte{0x42}, 32), time.Hour)
	if err != nil {
		t.Fatalf("keystore.New: %v", err)
	}

	deps := startTestDeps(t, "127.0.0.1:0")
	deps.KeyStore = ks

	code, _ := routeStatus(t, deps, http.MethodGet, "/.well-known/jwks.json")

	if code == http.StatusNotFound {
		t.Fatal("JWKS is not served when a keystore is wired")
	}
	if code != http.StatusOK {
		t.Errorf("JWKS status = %d, want 200 — relying parties cannot verify tokens without it", code)
	}
}

// Unauthenticated requests to the protected surface must not reach a handler, whichever
// key source is wired. This exercises the static-key branch (no keystore), which is the
// path a deployment without key rotation takes.
func TestWiring_ProtectedRoutesRejectAnonymous(t *testing.T) {
	deps := startTestDeps(t, "127.0.0.1:0")

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/user/profile"},
		{http.MethodGet, "/user/devices"},
	} {
		code, _ := routeStatus(t, deps, tc.method, tc.path)
		if code == http.StatusOK {
			t.Errorf("%s %s served an unauthenticated request", tc.method, tc.path)
		}
		if code == http.StatusNotFound {
			t.Errorf("%s %s is not wired at all", tc.method, tc.path)
		}
	}
}
