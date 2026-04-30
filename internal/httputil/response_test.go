package httputil

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	t.Run("writes status and content type", func(t *testing.T) {
		w := httptest.NewRecorder()
		WriteJSON(w, http.StatusOK, map[string]string{"msg": "hello"})

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want %q", ct, "application/json")
		}
	})

	t.Run("encodes body as JSON", func(t *testing.T) {
		w := httptest.NewRecorder()
		WriteJSON(w, http.StatusCreated, map[string]int{"count": 42})

		var got map[string]int
		if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got["count"] != 42 {
			t.Errorf("count = %d, want 42", got["count"])
		}
	})

	t.Run("handles nil data", func(t *testing.T) {
		w := httptest.NewRecorder()
		WriteJSON(w, http.StatusOK, nil)
		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("custom status codes", func(t *testing.T) {
		codes := []int{
			http.StatusBadRequest,
			http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusNotFound,
			http.StatusInternalServerError,
		}
		for _, code := range codes {
			w := httptest.NewRecorder()
			WriteJSON(w, code, map[string]string{"error": "test"})
			if w.Code != code {
				t.Errorf("status = %d, want %d", w.Code, code)
			}
		}
	})

	t.Run("encodes struct", func(t *testing.T) {
		type resp struct {
			Name  string `json:"name"`
			Count int    `json:"count"`
		}
		w := httptest.NewRecorder()
		WriteJSON(w, http.StatusOK, resp{Name: "test", Count: 5})

		var got resp
		if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Name != "test" || got.Count != 5 {
			t.Errorf("got %+v, want {Name:test Count:5}", got)
		}
	})
}

func TestWriteError(t *testing.T) {
	t.Run("writes error JSON", func(t *testing.T) {
		w := httptest.NewRecorder()
		WriteError(w, http.StatusBadRequest, "invalid input")

		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
		}

		var got map[string]string
		if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got["error"] != "invalid input" {
			t.Errorf("error = %q, want %q", got["error"], "invalid input")
		}
	})

	t.Run("content type is JSON", func(t *testing.T) {
		w := httptest.NewRecorder()
		WriteError(w, http.StatusInternalServerError, "boom")

		if ct := w.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want %q", ct, "application/json")
		}
	})

	t.Run("empty message", func(t *testing.T) {
		w := httptest.NewRecorder()
		WriteError(w, http.StatusForbidden, "")

		var got map[string]string
		if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got["error"] != "" {
			t.Errorf("error = %q, want empty", got["error"])
		}
	})
}
