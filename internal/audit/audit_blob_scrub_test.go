package audit

import (
	"context"
	"testing"
)

func TestScrubEventMetadataBlobKeys(t *testing.T) {
	tests := []struct {
		name      string
		eventType string
		metadata  map[string]interface{}
		dropped   []string
		kept      []string
	}{
		{
			name:      "named upload drops reference name",
			eventType: "blob_upload_named",
			metadata:  map[string]interface{}{"name": "tax-return", "blob_id": "b-1", "named": true},
			dropped:   []string{"name"},
			kept:      []string{"blob_id", "named"},
		},
		{
			name:      "all blob key aliases dropped",
			eventType: "blob_download_named",
			metadata: map[string]interface{}{
				"Name": "a", "blob_name": "b", "ref_name": "c", "label": "d", "blob_id": "b-2",
			},
			dropped: []string{"Name", "blob_name", "ref_name", "label"},
			kept:    []string{"blob_id"},
		},
		{
			name:      "admin role name survives",
			eventType: "admin:role_create",
			metadata:  map[string]interface{}{"name": "editor", "namespace": "app"},
			kept:      []string{"name", "namespace"},
		},
		{
			name:      "global scrub still applies to blob events",
			eventType: "blob_upload",
			metadata:  map[string]interface{}{"token": "t", "blob_id": "b-3"},
			dropped:   []string{"token"},
			kept:      []string{"blob_id"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scrubEventMetadata(tt.eventType, tt.metadata)
			for _, k := range tt.dropped {
				if _, exists := got[k]; exists {
					t.Errorf("key %q should be dropped for %s", k, tt.eventType)
				}
			}
			for _, k := range tt.kept {
				if _, exists := got[k]; !exists {
					t.Errorf("key %q should survive for %s", k, tt.eventType)
				}
			}
		})
	}
}

func TestScrubEventMetadataNestedBlobName(t *testing.T) {
	got := scrubEventMetadata("blob_download_named", map[string]interface{}{
		"ref": map[string]interface{}{"name": "secret-ref", "count": 2},
	})

	nested, ok := got["ref"].(map[string]interface{})
	if !ok {
		t.Fatal("nested ref map should survive")
	}
	if _, exists := nested["name"]; exists {
		t.Error("nested blob name should be dropped")
	}
	if nested["count"] != 2 {
		t.Error("nested non-sensitive key should survive")
	}
}

func TestScrubEventMetadataNil(t *testing.T) {
	if got := scrubEventMetadata("blob_upload_named", nil); got != nil {
		t.Errorf("nil metadata should stay nil, got %v", got)
	}
}

func TestLoggerDropsBlobNameOnInsert(t *testing.T) {
	repo := &mockAuditRepo{}
	l := NewLogger(repo, 0)

	if err := l.Log(context.Background(), "blob_upload_named", "u-1", "", "", "", "", "",
		map[string]interface{}{"name": "private-ref", "blob_id": "b-1"}); err != nil {
		t.Fatalf("log: %v", err)
	}

	if len(repo.entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(repo.entries))
	}
	if _, exists := repo.entries[0].Metadata["name"]; exists {
		t.Error("blob name reached the repository layer")
	}
	if repo.entries[0].Metadata["blob_id"] != "b-1" {
		t.Error("blob_id should survive")
	}
}
