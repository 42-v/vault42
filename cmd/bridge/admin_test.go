package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAdminAuth(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	ah := NewAdminHandler(fs, "secret-token")

	tests := []struct {
		name   string
		auth   string
		status int
	}{
		{"no auth", "", http.StatusUnauthorized},
		{"wrong token", "Bearer wrong", http.StatusUnauthorized},
		{"correct token", "Bearer secret-token", http.StatusMethodNotAllowed}, // GET on /bridge/flag = method not allowed
		{"no bearer prefix", "secret-token", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/bridge/flag", nil)
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}
			w := httptest.NewRecorder()
			ah.ServeFlag(w, req)

			if w.Code != tt.status {
				t.Errorf("status = %d, want %d", w.Code, tt.status)
			}
		})
	}
}

func TestAdminFlagUnflag(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	ah := NewAdminHandler(fs, "token123")

	// Flag an IP
	body, _ := json.Marshal(map[string]string{"ip": "10.0.0.1", "reason": "testing"})
	req := httptest.NewRequest(http.MethodPost, "/bridge/flag", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer token123")
	w := httptest.NewRecorder()
	ah.ServeFlag(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("flag status = %d, want %d", w.Code, http.StatusCreated)
	}

	if !fs.IsFlagged("10.0.0.1") {
		t.Error("IP should be flagged")
	}

	// List flags
	req = httptest.NewRequest(http.MethodGet, "/bridge/flags", nil)
	req.Header.Set("Authorization", "Bearer token123")
	w = httptest.NewRecorder()
	ah.ServeFlags(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("list status = %d, want %d", w.Code, http.StatusOK)
	}

	var listResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &listResp)
	if count, ok := listResp["count"].(float64); !ok || count != 1 {
		t.Errorf("list count = %v, want 1", listResp["count"])
	}

	// Unflag
	body, _ = json.Marshal(map[string]string{"ip": "10.0.0.1"})
	req = httptest.NewRequest(http.MethodDelete, "/bridge/flag", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer token123")
	w = httptest.NewRecorder()
	ah.ServeFlag(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("unflag status = %d, want %d", w.Code, http.StatusOK)
	}

	if fs.IsFlagged("10.0.0.1") {
		t.Error("IP should not be flagged after unflag")
	}
}

func TestAdminEmptyToken(t *testing.T) {
	fs := NewFlagStore(time.Hour, "")
	ah := NewAdminHandler(fs, "") // No token configured

	req := httptest.NewRequest(http.MethodGet, "/bridge/flags", nil)
	req.Header.Set("Authorization", "Bearer anything")
	w := httptest.NewRecorder()
	ah.ServeFlags(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("empty token: status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}
