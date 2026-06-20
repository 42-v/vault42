package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestID(t *testing.T) {
	var capturedID string
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = GetRequestID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	headerID := rec.Header().Get("X-Request-ID")
	if headerID == "" {
		t.Error("X-Request-ID header should be set")
	}
	if capturedID == "" {
		t.Error("request ID should be in context")
	}
	if headerID != capturedID {
		t.Error("header and context IDs should match")
	}
}

func TestGetRequestID(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{"background", context.Background(), ""},
		{"no key", context.WithValue(context.Background(), "other", "x"), ""},
		{"wrong type", context.WithValue(context.Background(), RequestIDKey, 123), ""},
		{"valid", func() context.Context {
			ctx := context.WithValue(context.Background(), RequestIDKey, "req-abc123")
			return ctx
		}(), "req-abc123"},
		{"empty string id", context.WithValue(context.Background(), RequestIDKey, ""), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetRequestID(tt.ctx)
			if got != tt.want {
				t.Errorf("GetRequestID() = %q, want %q", got, tt.want)
			}
		})
	}
}
