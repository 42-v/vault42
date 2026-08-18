package audit

import (
	"context"
	"testing"
)

func TestScrubMetadataNestedMaps(t *testing.T) {
	repo := &mockAuditRepo{}
	logger := NewLogger(repo, 0)
	ctx := context.Background()

	logger.Log(ctx, LoginSuccess, "u1", "", "1.1.1.1", "", "", "",
		map[string]interface{}{
			"action": "login",
			"nested": map[string]interface{}{
				"password": "should-be-scrubbed",
				"token":    "also-scrubbed",
				"safe_key": "preserved",
			},
		})

	e := repo.entries[0]

	nested, ok := e.Metadata["nested"].(map[string]interface{})
	if !ok {
		t.Fatal("nested map should be preserved")
	}

	if _, exists := nested["password"]; exists {
		t.Error("nested password should be scrubbed")
	}
	if _, exists := nested["token"]; exists {
		t.Error("nested token should be scrubbed")
	}
	if nested["safe_key"] != "preserved" {
		t.Error("nested safe_key should be preserved")
	}
}

func TestScrubMetadataDeeplyNested(t *testing.T) {
	result := scrubMetadata(map[string]interface{}{
		"level1": map[string]interface{}{
			"level2": map[string]interface{}{
				"secret":  "deep-secret",
				"visible": "ok",
			},
		},
	})

	l1, ok := result["level1"].(map[string]interface{})
	if !ok {
		t.Fatal("level1 should exist")
	}
	l2, ok := l1["level2"].(map[string]interface{})
	if !ok {
		t.Fatal("level2 should exist")
	}
	if _, exists := l2["secret"]; exists {
		t.Error("deeply nested 'secret' key should be scrubbed")
	}
	if l2["visible"] != "ok" {
		t.Error("non-sensitive key should survive")
	}
}

func TestScrubMetadataCaseInsensitive(t *testing.T) {
	result := scrubMetadata(map[string]interface{}{
		"PASSWORD":     "secret1",
		"Token":        "secret2",
		"Access_Token": "secret3",
		"action":       "login",
	})

	if _, exists := result["PASSWORD"]; exists {
		t.Error("uppercase PASSWORD should be scrubbed")
	}
	if _, exists := result["Token"]; exists {
		t.Error("mixed-case Token should be scrubbed")
	}
	if _, exists := result["Access_Token"]; exists {
		t.Error("mixed-case Access_Token should be scrubbed")
	}
	if result["action"] != "login" {
		t.Error("non-sensitive key should survive")
	}
}

func TestScrubMetadataAllSensitiveKeys(t *testing.T) {
	// Verify all known sensitive keys are scrubbed
	keys := []string{
		"password", "secret", "token",
		"access_token", "refresh_token", "code",
		"totp_secret", "backup_code", "master_key",
		"client_secret", "api_key",
	}

	metadata := make(map[string]interface{})
	for _, k := range keys {
		metadata[k] = "sensitive-value"
	}
	metadata["safe_key"] = "ok"

	result := scrubMetadata(metadata)

	for _, k := range keys {
		if _, exists := result[k]; exists {
			t.Errorf("key %q should be scrubbed", k)
		}
	}
	if result["safe_key"] != "ok" {
		t.Error("safe_key should survive")
	}
}

func TestScrubMetadataEmptyMap(t *testing.T) {
	result := scrubMetadata(map[string]interface{}{})
	if result == nil {
		t.Error("empty map should return non-nil empty map")
	}
	if len(result) != 0 {
		t.Error("empty map should return empty map")
	}
}
