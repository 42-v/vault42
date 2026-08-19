package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// readyzProbe drives GET /readyz with the given dependencies and decodes the
// answer.
func readyzProbe(t *testing.T, deps *ReadyzDeps) (int, map[string]string) {
	t.Helper()

	w := httptest.NewRecorder()
	Readyz(deps)(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /readyz body %q: %v", w.Body.String(), err)
	}
	return w.Code, body
}

// TestReadyzDistinguishesAnUncheckedCacheFromAHealthyOne is the reason the
// wiring gate beside it exists.
//
// Readyz has always known how to report a failing cache: it sets
// "cache": "degraded" and, by a deliberate decision recorded in
// TestReadyzCacheDown, keeps answering 200, because a Redis blip taking every
// replica out of rotation at once is worse for an auth service than running
// degraded. That decision only works if the degraded state can actually be
// observed, and cmd/vault never populated PingCache, so the cache key was
// absent from every response the server ever served.
//
// Absent and healthy are different answers, and the operator watching this
// endpoint could not tell them apart: a vault whose cache had fallen back to
// per-process memory looked exactly like a vault whose cache was fine.
func TestReadyzDistinguishesAnUncheckedCacheFromAHealthyOne(t *testing.T) {
	_, unchecked := readyzProbe(t, &ReadyzDeps{PingDB: func() error { return nil }})
	if _, present := unchecked["cache"]; present {
		t.Errorf("a nil cache probe reported %q; absent has to mean not checked, or the wiring "+
			"gate below is measuring nothing", unchecked["cache"])
	}

	_, healthy := readyzProbe(t, &ReadyzDeps{
		PingDB:    func() error { return nil },
		PingCache: func() error { return nil },
	})
	if healthy["cache"] != "up" {
		t.Errorf("a healthy cache reported %q, want up", healthy["cache"])
	}

	code, degraded := readyzProbe(t, &ReadyzDeps{
		PingDB:    func() error { return nil },
		PingCache: func() error { return errors.New("cache fell back to per-process memory") },
	})
	if degraded["cache"] != "degraded" {
		t.Errorf("a failing cache reported %q, want degraded", degraded["cache"])
	}
	// 200 is deliberate and is pinned in TestReadyzCacheDown. Repeated here so
	// that changing it is a decision made in two places rather than a side
	// effect of editing one.
	if code != http.StatusOK {
		t.Errorf("status = %d, want 200. A degraded cache deliberately does not remove the pod "+
			"from rotation; if that trade-off is being revisited, both this and "+
			"TestReadyzCacheDown have to say so.", code)
	}
}
