package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// sendGridURL is the SendGrid v3 Mail Send API endpoint.
// Exported as a variable so tests can override it.
var sendGridURL = "https://api.sendgrid.com/v3/mail/send"

// SendGridSender sends emails via the SendGrid v3 Mail Send API.
// It implements the [Sender] interface using only net/http (no external SDK).
type SendGridSender struct {
	apiKey string
	from   string
}

// NewSendGridSender creates a new SendGrid email sender.
// apiKey is the SendGrid API key, fromAddr is the sender email address.
func NewSendGridSender(apiKey, fromAddr string) *SendGridSender {
	return &SendGridSender{
		apiKey: apiKey,
		from:   fromAddr,
	}
}

// sendGridPayload mirrors the SendGrid v3 Mail Send JSON structure.
type sendGridPayload struct {
	Personalizations []sendGridPersonalization `json:"personalizations"`
	From             sendGridEmail             `json:"from"`
	Subject          string                    `json:"subject"`
	Content          []sendGridContent         `json:"content"`
}

type sendGridPersonalization struct {
	To []sendGridEmail `json:"to"`
}

type sendGridEmail struct {
	Email string `json:"email"`
}

type sendGridContent struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Send sends an email via the SendGrid v3 API. Both HTML and plain-text bodies
// are included as content entries, matching the multipart/alternative behavior
// of the SMTP sender. The SendGrid API returns 202 Accepted on success.
func (s *SendGridSender) Send(ctx context.Context, to, subject, htmlBody, textBody string) error {
	if s.apiKey == "" {
		return fmt.Errorf("sendgrid: API key is not configured")
	}

	payload := sendGridPayload{
		Personalizations: []sendGridPersonalization{
			{To: []sendGridEmail{{Email: to}}},
		},
		From:    sendGridEmail{Email: s.from},
		Subject: subject,
		Content: []sendGridContent{
			{Type: "text/plain", Value: textBody},
			{Type: "text/html", Value: htmlBody},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("sendgrid: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sendGridURL, bytes.NewReader(body)) // #nosec G107 -- sendGridURL defaults to hardcoded SendGrid API constant; only overridden in tests
	if err != nil {
		return fmt.Errorf("sendgrid: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req) // #nosec G107 -- see above
	if err != nil {
		return fmt.Errorf("sendgrid: send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("sendgrid: unexpected status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
