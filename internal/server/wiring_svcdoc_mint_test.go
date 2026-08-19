package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/metrics"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/internal/service"
)

// stubServiceDocRepo satisfies repository.ServiceDocumentRepository. setupRoutes
// only hands it to a service constructor, and every request these tests send is
// unauthenticated, so no method is reachable.
type stubServiceDocRepo struct{}

func (stubServiceDocRepo) Get(context.Context, string, string, string) (*repository.ServiceDocument, error) {
	return nil, nil
}

func (stubServiceDocRepo) ListSharedByKey(context.Context, string, string, string) ([]*repository.ServiceDocument, error) {
	return nil, nil
}

func (stubServiceDocRepo) Upsert(context.Context, *repository.ServiceDocument) (bool, error) {
	return false, nil
}

func (stubServiceDocRepo) Delete(context.Context, string, string, string) (bool, error) {
	return false, nil
}

func (stubServiceDocRepo) ListByOwner(context.Context, string, string) ([]*repository.ServiceDocument, error) {
	return nil, nil
}

func (stubServiceDocRepo) ListSharedForSubject(context.Context, string, string) ([]*repository.ServiceDocument, error) {
	return nil, nil
}

func (stubServiceDocRepo) ListAllForSubject(context.Context, string) ([]*repository.ServiceDocument, error) {
	return nil, nil
}

func (stubServiceDocRepo) CountForOwner(context.Context, string, string) (int, error) { return 0, nil }

func (stubServiceDocRepo) SumBytesForSubjectAndClient(context.Context, string, string) (int, error) {
	return 0, nil
}
func (stubServiceDocRepo) DeleteAllForSubject(context.Context, string) error { return nil }

var _ repository.ServiceDocumentRepository = stubServiceDocRepo{}

// svcDocRoutes is the complete surface the document store mounts. All four are
// asserted every time: a partial mount is the failure mode worth catching, since
// a store whose DELETE never registered leaves callers unable to withdraw what
// they wrote.
var svcDocRoutes = []struct{ method, path string }{
	{http.MethodPut, "/service/documents/user-1/profile"},
	{http.MethodGet, "/service/documents/user-1/profile"},
	{http.MethodDelete, "/service/documents/user-1/profile"},
	{http.MethodGet, "/service/documents/user-1"},
}

// The document store is new surface reachable by every existing
// client-credentials holder, so upgrading must not turn it on. Two independent
// conditions gate it and both have to hold: a repository to write to AND an
// operator who set VAULT_SVCDOC_ENABLED. Either one alone must leave the routes
// unregistered, not merely refusing.
func TestWiring_ServiceDocumentsMountedOnlyWhenEnabledAndBacked(t *testing.T) {
	t.Run("absent without a document repository", func(t *testing.T) {
		deps := startTestDeps(t, "127.0.0.1:0")
		deps.ServiceDocs = nil
		deps.Config.SvcDocEnabled = true

		for _, rt := range svcDocRoutes {
			code, _ := routeStatus(t, deps, rt.method, rt.path)
			if code != http.StatusNotFound {
				t.Errorf("%s %s = %d, want 404: the document store is reachable with no repository behind it", rt.method, rt.path, code)
			}
		}
	})

	t.Run("absent when the operator has not enabled it", func(t *testing.T) {
		deps := startTestDeps(t, "127.0.0.1:0")
		deps.ServiceDocs = stubServiceDocRepo{}
		deps.Config.SvcDocEnabled = false

		for _, rt := range svcDocRoutes {
			code, _ := routeStatus(t, deps, rt.method, rt.path)
			if code != http.StatusNotFound {
				t.Errorf("%s %s = %d, want 404: an upgrade enabled the document store without the operator asking", rt.method, rt.path, code)
			}
		}
	})

	t.Run("mounted and authenticated when backed and enabled", func(t *testing.T) {
		deps := startTestDeps(t, "127.0.0.1:0")
		deps.ServiceDocs = stubServiceDocRepo{}
		deps.Config.SvcDocEnabled = true
		deps.Config.SvcDocMaxSize = 64 * 1024
		deps.Config.SvcDocMaxPerSubject = 32
		deps.Config.SvcDocQuotaBytes = 1024 * 1024
		deps.Config.SvcDocSharedEnabled = true
		// A live collector takes the branch that hands the metrics interface to
		// the service, the one a metrics-enabled deployment runs.
		deps.Metrics = metrics.NewCollector(
			func() int64 { return 0 },
			func() int64 { return 0 },
			func() int { return 0 },
		)

		for _, rt := range svcDocRoutes {
			code, _ := routeStatus(t, deps, rt.method, rt.path)
			if code == http.StatusNotFound {
				t.Errorf("%s %s is not wired even though the store is backed and enabled", rt.method, rt.path)
			}
			if code == http.StatusOK {
				t.Errorf("%s %s served an unauthenticated request", rt.method, rt.path)
			}
		}
	})
}

// Metrics are optional. The store must mount and serve identically without a
// collector: the wiring converts an absent collector into a nil interface rather
// than a typed nil, and a typed nil would panic on the service's first use.
// Requests here stop at auth, so what this pins is that the metrics-off branch
// builds the same route set and answers rather than failing to register.
func TestWiring_ServiceDocumentsMountWithoutMetrics(t *testing.T) {
	deps := startTestDeps(t, "127.0.0.1:0")
	deps.ServiceDocs = stubServiceDocRepo{}
	deps.Config.SvcDocEnabled = true
	deps.Metrics = nil

	for _, rt := range svcDocRoutes {
		code, _ := routeStatus(t, deps, rt.method, rt.path)
		if code == http.StatusNotFound {
			t.Errorf("%s %s is not wired when metrics are disabled", rt.method, rt.path)
		}
		if code == http.StatusOK {
			t.Errorf("%s %s served an unauthenticated request", rt.method, rt.path)
		}
	}
}

// testMintService builds a MintService with a policy the constructor accepts:
// an audience distinct from the issuer and a TTL inside the hard ceiling.
func testMintService(t *testing.T) *service.MintService {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	svc, err := service.NewMintService(
		func() (*rsa.PrivateKey, string) { return key, "test-kid" },
		service.MintConfig{
			Issuer:     "https://vault.localhost",
			Audience:   "https://life42.localhost",
			DefaultTTL: time.Minute,
			MaxTTL:     5 * time.Minute,
		},
		nil,
	)
	if err != nil {
		t.Fatalf("service.NewMintService: %v", err)
	}
	return svc
}

// POST /mint signs assertions about subjects vault42 never authenticated. On a
// deployment that configured no mint the endpoint must not exist at all: a
// registered-but-unbacked signing oracle is a far larger surface than an absent
// one, and a vanilla vault42 has no reason to carry it. When it is configured it
// must still refuse an anonymous caller, or the oracle would sign for anyone.
func TestWiring_MintMountedOnlyWithAMintService(t *testing.T) {
	t.Run("absent without a mint service", func(t *testing.T) {
		deps := startTestDeps(t, "127.0.0.1:0")
		deps.Mint = nil

		code, _ := routeStatus(t, deps, http.MethodPost, "/mint")

		if code != http.StatusNotFound {
			t.Errorf("status = %d, want 404: POST /mint is reachable with no mint service behind it", code)
		}
	})

	t.Run("mounted and authenticated when a mint service is configured", func(t *testing.T) {
		deps := startTestDeps(t, "127.0.0.1:0")
		deps.Mint = testMintService(t)

		code, _ := routeStatus(t, deps, http.MethodPost, "/mint")

		if code == http.StatusNotFound {
			t.Fatal("a mint service is configured but POST /mint was never wired")
		}
		if code == http.StatusOK {
			t.Error("the mint oracle answered an unauthenticated request: a signed subject assertion to anyone who asks")
		}
	})

	// Mounting the mint must not mount anything else, and must not make the
	// document store appear: the two subsystems are independently gated.
	t.Run("the mint does not drag in the document store", func(t *testing.T) {
		deps := startTestDeps(t, "127.0.0.1:0")
		deps.Mint = testMintService(t)

		for _, rt := range svcDocRoutes {
			code, _ := routeStatus(t, deps, rt.method, rt.path)
			if code != http.StatusNotFound {
				t.Errorf("%s %s = %d, want 404: configuring the mint mounted the document store", rt.method, rt.path, code)
			}
		}
	})
}
