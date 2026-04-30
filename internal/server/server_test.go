package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/config"
	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/middleware"
)

func TestNew(t *testing.T) {
	deps := &Deps{Config: &config.Config{}}
	s := New(deps)
	if s == nil {
		t.Fatal("New() returned nil")
	}
	if s.deps != deps {
		t.Error("New() did not store deps")
	}
}

func TestSetupRoutes(t *testing.T) {
	// Verify that route registration succeeds and produces a non-nil mux.
	// This requires minimal deps — the route setup only reads config values
	// and calls handler constructors, it doesn't make network calls.
	memCache := cache.NewMemoryCache()
	defer memCache.Close()

	cfg := &config.Config{
		Origin:            "https://vault.localhost",
		AppName:           "Vault Test",
		PasswordMinLength: 15,
	}
	deps := &Deps{
		Config:    cfg,
		Cache:     memCache,
		ReadyDeps: &handler.ReadyzDeps{},
	}
	s := New(deps)
	mux := s.setupRoutes()
	if mux == nil {
		t.Fatal("setupRoutes() returned nil")
	}
}

func TestSetupRoutesDPoPEnabled(t *testing.T) {
	// Verify that route registration succeeds when DPoP is enabled.
	memCache := cache.NewMemoryCache()
	defer memCache.Close()

	cfg := &config.Config{
		Origin:            "https://vault.localhost",
		AppName:           "Vault Test",
		PasswordMinLength: 15,
		DPoPEnabled:       true,
	}
	deps := &Deps{
		Config:    cfg,
		Cache:     memCache,
		ReadyDeps: &handler.ReadyzDeps{},
	}
	s := New(deps)
	mux := s.setupRoutes()
	if mux == nil {
		t.Fatal("setupRoutes() returned nil with DPoP enabled")
	}
}

func TestDPoPMiddlewareWiredToLogin(t *testing.T) {
	// When DPoP is enabled and an invalid DPoP header is sent, the middleware
	// should reject the request before it reaches the login handler.
	memCache := cache.NewMemoryCache()
	defer memCache.Close()

	cfg := &config.Config{
		Origin:            "https://vault.localhost",
		AppName:           "Vault Test",
		PasswordMinLength: 15,
		DPoPEnabled:       true,
	}
	deps := &Deps{
		Config:    cfg,
		Cache:     memCache,
		ReadyDeps: &handler.ReadyzDeps{},
	}
	s := New(deps)
	mux := s.setupRoutes()

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"email":"test@test.com","password":"testpassword123"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DPoP", "invalid-dpop-proof")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	// DPoP middleware should reject the invalid proof with 401
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid DPoP proof on /auth/login, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "invalid_dpop_proof") {
		t.Errorf("expected invalid_dpop_proof error, got %q", rec.Body.String())
	}
}

func TestDPoPMiddlewareWiredToRefresh(t *testing.T) {
	// When DPoP is enabled and an invalid DPoP header is sent to /auth/refresh,
	// the middleware should reject it.
	memCache := cache.NewMemoryCache()
	defer memCache.Close()

	cfg := &config.Config{
		Origin:            "https://vault.localhost",
		AppName:           "Vault Test",
		PasswordMinLength: 15,
		DPoPEnabled:       true,
	}
	deps := &Deps{
		Config:    cfg,
		Cache:     memCache,
		ReadyDeps: &handler.ReadyzDeps{},
	}
	s := New(deps)
	mux := s.setupRoutes()

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", strings.NewReader(`{"refresh_token":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DPoP", "invalid-dpop-proof")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid DPoP proof on /auth/refresh, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "invalid_dpop_proof") {
		t.Errorf("expected invalid_dpop_proof error, got %q", rec.Body.String())
	}
}

func TestDPoPDisabledDoesNotIntercept(t *testing.T) {
	// When DPoP is disabled (default), sending a DPoP header should NOT trigger
	// DPoP validation — the request reaches the handler (which may panic on nil deps).
	// We wrap with recovery middleware to catch the panic gracefully.
	memCache := cache.NewMemoryCache()
	defer memCache.Close()

	cfg := &config.Config{
		Origin:            "https://vault.localhost",
		AppName:           "Vault Test",
		PasswordMinLength: 15,
		DPoPEnabled:       false,
	}
	deps := &Deps{
		Config:    cfg,
		Cache:     memCache,
		ReadyDeps: &handler.ReadyzDeps{},
	}
	s := New(deps)
	mux := s.setupRoutes()

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"email":"test@test.com","password":"testpassword123"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DPoP", "invalid-dpop-proof")
	rec := httptest.NewRecorder()

	// Wrap with recovery since the login handler will panic on nil AuthService
	// (which proves the request passed through without DPoP interception)
	recovered := middleware.Recovery(mux)
	recovered.ServeHTTP(rec, req)

	// When DPoP is disabled, the invalid DPoP header is ignored. The handler runs
	// and panics on nil service (caught by recovery as 500), NOT a DPoP 401 error.
	if rec.Code == http.StatusUnauthorized && strings.Contains(rec.Body.String(), "invalid_dpop_proof") {
		t.Error("DPoP middleware should NOT be active when DPoPEnabled is false")
	}
}

func TestDPoPNoDPoPHeaderPassesThrough(t *testing.T) {
	// When DPoP is enabled but no DPoP header is sent, the request should
	// pass through the DPoP middleware (since there are no cnf.jkt claims
	// on unauthenticated endpoints like /auth/login).
	memCache := cache.NewMemoryCache()
	defer memCache.Close()

	cfg := &config.Config{
		Origin:            "https://vault.localhost",
		AppName:           "Vault Test",
		PasswordMinLength: 15,
		DPoPEnabled:       true,
	}
	deps := &Deps{
		Config:    cfg,
		Cache:     memCache,
		ReadyDeps: &handler.ReadyzDeps{},
	}
	s := New(deps)
	mux := s.setupRoutes()

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"email":"test@test.com","password":"testpassword123"}`))
	req.Header.Set("Content-Type", "application/json")
	// No DPoP header
	rec := httptest.NewRecorder()

	// Wrap with recovery since the login handler will panic on nil AuthService
	// (which proves the request passed through the DPoP middleware)
	recovered := middleware.Recovery(mux)
	recovered.ServeHTTP(rec, req)

	// Should not get a DPoP error — request passes through to the handler
	if strings.Contains(rec.Body.String(), "dpop") {
		t.Errorf("no DPoP header should not produce DPoP error, got %q", rec.Body.String())
	}
}
