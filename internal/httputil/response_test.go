package httputil

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteJSON_Table(t *testing.T) {
	tests := []struct {
		name   string
		status int
		data   interface{}
		wantCT string
	}{
		{"ok", http.StatusOK, map[string]string{"a": "b"}, "application/json"},
		{"created", http.StatusCreated, map[string]int{"c": 1}, "application/json"},
		{"nil data", http.StatusNoContent, nil, "application/json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			WriteJSON(w, tt.status, tt.data)
			if w.Code != tt.status {
				t.Errorf("status=%d want %d", w.Code, tt.status)
			}
			if ct := w.Header().Get("Content-Type"); ct != tt.wantCT {
				t.Errorf("ct=%q want %q", ct, tt.wantCT)
			}
		})
	}
}

func TestWriteJSON(t *testing.T) {
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

func TestWriteError_Table(t *testing.T) {
	tests := []struct {
		name    string
		code    int
		message string
	}{
		{"400", http.StatusBadRequest, "bad req"},
		{"401", http.StatusUnauthorized, "no auth"},
		{"empty msg 404", http.StatusNotFound, ""},
		{"500", http.StatusInternalServerError, "boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			WriteError(w, tt.code, tt.message)
			if w.Code != tt.code {
				t.Errorf("code %d", w.Code)
			}
		})
	}
}

// TestWriteJSON_EncodeError covers the error logging path (non-actionable).
func TestWriteJSON_EncodeError(t *testing.T) {
	w := httptest.NewRecorder()
	// func value cannot be JSON encoded; triggers err branch
	WriteJSON(w, http.StatusOK, func() {})
	// status already written before encode
	if w.Code != http.StatusOK {
		t.Errorf("status after bad encode = %d", w.Code)
	}
}
