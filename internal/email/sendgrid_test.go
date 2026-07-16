package email

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSendGridSender_Send(t *testing.T) {
	var receivedBody sendGridPayload
	var receivedAuth string
	var receivedContentType string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedContentType = r.Header.Get("Content-Type")

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if err := json.Unmarshal(body, &receivedBody); err != nil {
			t.Fatalf("unmarshal request body: %v", err)
		}

		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	// Override the API URL to point to our test server
	origURL := sendGridURL
	sendGridURL = srv.URL
	defer func() { sendGridURL = origURL }()

	sender := NewSendGridSender("test-api-key-123", "sender@example.com")
	err := sender.Send(
		context.Background(),
		Address{},
		"recipient@example.com",
		"Test Subject",
		"<h1>Hello</h1>",
		"Hello",
	)
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}

	// Verify Authorization header
	if receivedAuth != "Bearer test-api-key-123" {
		t.Errorf("Authorization header = %q, want %q", receivedAuth, "Bearer test-api-key-123")
	}

	// Verify Content-Type header
	if receivedContentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", receivedContentType, "application/json")
	}

	// Verify From
	if receivedBody.From.Email != "sender@example.com" {
		t.Errorf("From = %q, want %q", receivedBody.From.Email, "sender@example.com")
	}

	// Verify Subject
	if receivedBody.Subject != "Test Subject" {
		t.Errorf("Subject = %q, want %q", receivedBody.Subject, "Test Subject")
	}

	// Verify Personalizations (To)
	if len(receivedBody.Personalizations) != 1 {
		t.Fatalf("Personalizations count = %d, want 1", len(receivedBody.Personalizations))
	}
	if len(receivedBody.Personalizations[0].To) != 1 {
		t.Fatalf("To count = %d, want 1", len(receivedBody.Personalizations[0].To))
	}
	if receivedBody.Personalizations[0].To[0].Email != "recipient@example.com" {
		t.Errorf("To = %q, want %q", receivedBody.Personalizations[0].To[0].Email, "recipient@example.com")
	}

	// Verify Content (plain text first, then HTML — SendGrid v3 spec order)
	if len(receivedBody.Content) != 2 {
		t.Fatalf("Content count = %d, want 2", len(receivedBody.Content))
	}
	if receivedBody.Content[0].Type != "text/plain" {
		t.Errorf("Content[0].Type = %q, want %q", receivedBody.Content[0].Type, "text/plain")
	}
	if receivedBody.Content[0].Value != "Hello" {
		t.Errorf("Content[0].Value = %q, want %q", receivedBody.Content[0].Value, "Hello")
	}
	if receivedBody.Content[1].Type != "text/html" {
		t.Errorf("Content[1].Type = %q, want %q", receivedBody.Content[1].Type, "text/html")
	}
	if receivedBody.Content[1].Value != "<h1>Hello</h1>" {
		t.Errorf("Content[1].Value = %q, want %q", receivedBody.Content[1].Value, "<h1>Hello</h1>")
	}
}

func TestSendGridSender_FromOverride(t *testing.T) {
	var receivedBody sendGridPayload

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		if err := json.Unmarshal(body, &receivedBody); err != nil {
			t.Fatalf("unmarshal request body: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	origURL := sendGridURL
	sendGridURL = srv.URL
	defer func() { sendGridURL = origURL }()

	sender := NewSendGridSender("key", "default@example.com")
	err := sender.Send(
		context.Background(),
		Address{Email: "tenant@acme.test", Name: "Acme\r\nSupport"},
		"to@example.com",
		"Subj",
		"<p>body</p>",
		"body",
	)
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}

	if receivedBody.From.Email != "tenant@acme.test" {
		t.Errorf("From.Email = %q, want the per-app override %q", receivedBody.From.Email, "tenant@acme.test")
	}
	// The display name passes through sanitizeHeader, so the CRLF is stripped.
	if receivedBody.From.Name != "AcmeSupport" {
		t.Errorf("From.Name = %q, want %q", receivedBody.From.Name, "AcmeSupport")
	}
}

func TestSendGridSender_InvalidURL(t *testing.T) {
	origURL := sendGridURL
	sendGridURL = "://missing-scheme"
	defer func() { sendGridURL = origURL }()

	sender := NewSendGridSender("key", "sender@example.com")
	err := sender.Send(context.Background(), Address{}, "to@example.com", "Subj", "<p>body</p>", "body")

	if err == nil {
		t.Fatal("expected error for unparseable URL, got nil")
	}
	if want := "create request"; !contains(err.Error(), want) {
		t.Errorf("error %q should contain %q", err.Error(), want)
	}
}

func TestSendGridSender_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"errors":[{"message":"The provided authorization grant is invalid"}]}`))
	}))
	defer srv.Close()

	origURL := sendGridURL
	sendGridURL = srv.URL
	defer func() { sendGridURL = origURL }()

	sender := NewSendGridSender("bad-key", "sender@example.com")
	err := sender.Send(context.Background(), Address{}, "to@example.com", "Subj", "<p>body</p>", "body")

	if err == nil {
		t.Fatal("expected error for 401 response, got nil")
	}

	// Should contain status code
	if want := "401"; !contains(err.Error(), want) {
		t.Errorf("error %q should contain status %q", err.Error(), want)
	}

	// Should contain response body for debugging
	if want := "invalid"; !contains(err.Error(), want) {
		t.Errorf("error %q should contain response body hint %q", err.Error(), want)
	}
}

func TestSendGridSender_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"errors":[{"message":"Internal server error"}]}`))
	}))
	defer srv.Close()

	origURL := sendGridURL
	sendGridURL = srv.URL
	defer func() { sendGridURL = origURL }()

	sender := NewSendGridSender("valid-key", "sender@example.com")
	err := sender.Send(context.Background(), Address{}, "to@example.com", "Subj", "<p>body</p>", "body")

	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
	if want := "500"; !contains(err.Error(), want) {
		t.Errorf("error %q should contain status %q", err.Error(), want)
	}
}

func TestSendGridSender_MissingAPIKey(t *testing.T) {
	sender := NewSendGridSender("", "sender@example.com")
	err := sender.Send(context.Background(), Address{}, "to@example.com", "Subj", "<p>body</p>", "body")

	if err == nil {
		t.Fatal("expected error for missing API key, got nil")
	}
	if want := "API key is not configured"; !contains(err.Error(), want) {
		t.Errorf("error %q should contain %q", err.Error(), want)
	}
}

func TestSendGridSender_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never respond — simulate a slow server
		<-r.Context().Done()
	}))
	defer srv.Close()

	origURL := sendGridURL
	sendGridURL = srv.URL
	defer func() { sendGridURL = origURL }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	sender := NewSendGridSender("key", "sender@example.com")
	err := sender.Send(ctx, Address{}, "to@example.com", "Subj", "<p>body</p>", "body")

	if err == nil {
		t.Fatal("expected error for canceled context, got nil")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
