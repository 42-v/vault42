package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/config"
	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/metrics"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/oauth2"
	"github.com/42-v/vault42/internal/repository"
)

// stubIdentityRepo satisfies repository.IdentityRepository. setupRoutes only
// passes it to a service constructor — no methods are invoked during wiring.
type stubIdentityRepo struct{}

func (stubIdentityRepo) Upsert(context.Context, *model.IdentityProfile) error { return nil }
func (stubIdentityRepo) GetByPseudonym(context.Context, string) (*model.IdentityProfile, error) {
	return nil, nil
}
func (stubIdentityRepo) Delete(context.Context, string) error { return nil }

// stubBlobRepo satisfies repository.BlobRepository for route wiring only.
type stubBlobRepo struct{}

func (stubBlobRepo) Create(context.Context, *model.Blob) error { return nil }
func (stubBlobRepo) GetByIDAndPseudonym(context.Context, string, string) (*model.Blob, error) {
	return nil, nil
}
func (stubBlobRepo) GetByRefAndPseudonym(context.Context, string, string) (*model.Blob, error) {
	return nil, nil
}
func (stubBlobRepo) DeleteByRefAndPseudonym(context.Context, string, string) error { return nil }
func (stubBlobRepo) ListByPseudonym(context.Context, string) ([]*model.Blob, error) {
	return nil, nil
}
func (stubBlobRepo) GetQuota(context.Context, string) (*model.BlobQuota, error) { return nil, nil }
func (stubBlobRepo) Delete(context.Context, string, string) error              { return nil }

var (
	_ repository.IdentityRepository = stubIdentityRepo{}
	_ repository.BlobRepository     = stubBlobRepo{}
)

func newTestDeps(cfg *config.Config) (*Deps, *cache.MemoryCache) {
	mc := cache.NewMemoryCache()
	return &Deps{
		Config:    cfg,
		Cache:     mc,
		ReadyDeps: &handler.ReadyzDeps{},
	}, mc
}

// When all feature toggles are on, every conditional route block registers and
// the catch-all SPA route serves a request.
func TestSetupRoutesAllFeaturesEnabled(t *testing.T) {
	cfg := &config.Config{
		Origin:            "https://vault.localhost",
		AppName:           "Vault Test",
		PasswordMinLength: 15,
		ServeFrontend:     true,
		BlobQuotaBytes:    1024,
		BlobMaxSize:       512,
		BlobMaxPerUser:    5,
	}
	deps, mc := newTestDeps(cfg)
	defer mc.Close()

	deps.Metrics = metrics.NewCollector(
		func() int64 { return 0 },
		func() int64 { return 0 },
		func() int { return 0 },
	)
	deps.OAuthProviders = map[string]oauth2.Provider{
		"google": oauth2.NewGoogleProvider("id", "secret", "https://vault.localhost/cb"),
	}
	deps.Identity = stubIdentityRepo{}
	deps.Blobs = stubBlobRepo{}

	s := New(deps)
	mux := s.setupRoutes()
	if mux == nil {
		t.Fatal("setupRoutes returned nil")
	}

	// Metrics endpoint is wired.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GET /metrics = %d, want 200", rec.Code)
	}

	// Capabilities lists the registered OAuth provider.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/capabilities", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GET /auth/capabilities = %d, want 200", rec.Code)
	}

	// SPA catch-all responds (ServeFrontend on) rather than 404 from the mux.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/some/spa/path", nil))
	if rec.Code == http.StatusNotFound {
		t.Error("expected SPA catch-all to handle unknown path, got 404")
	}
}

// Metrics disabled => /metrics is not registered and returns 404.
func TestSetupRoutesMetricsDisabled(t *testing.T) {
	cfg := &config.Config{
		Origin:            "https://vault.localhost",
		AppName:           "Vault Test",
		PasswordMinLength: 15,
	}
	deps, mc := newTestDeps(cfg)
	defer mc.Close()

	mux := New(deps).setupRoutes()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /metrics with metrics disabled = %d, want 404", rec.Code)
	}
}

// RegistrationEnabled=false wires a stub handler that returns 403.
func TestSetupRoutesRegistrationDisabled(t *testing.T) {
	cfg := &config.Config{
		Origin:              "https://vault.localhost",
		AppName:             "Vault Test",
		PasswordMinLength:   15,
		RegistrationEnabled: false,
	}
	deps, mc := newTestDeps(cfg)
	defer mc.Close()

	mux := New(deps).setupRoutes()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/register", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST /auth/register disabled = %d, want 403", rec.Code)
	}
}

// Blob storage is gated on BlobQuotaBytes > 0; when zero the blob routes are
// not registered (405/404 rather than a wired handler).
func TestSetupRoutesBlobDisabledWhenQuotaZero(t *testing.T) {
	cfg := &config.Config{
		Origin:            "https://vault.localhost",
		AppName:           "Vault Test",
		PasswordMinLength: 15,
		BlobQuotaBytes:    0,
	}
	deps, mc := newTestDeps(cfg)
	defer mc.Close()
	deps.Blobs = stubBlobRepo{}

	mux := New(deps).setupRoutes()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/user/blobs", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /user/blobs with quota 0 = %d, want 404 (route unregistered)", rec.Code)
	}
}
