package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/tests/mocks"
)

// GetConfig answers with an object, not a list, so an empty store has to
// serialize as {} rather than null. AdminConfigRepository is an interface and
// nothing in it forbids a nil map on success, which is what a Go map-returning
// implementation produces when it never allocates. Handing that straight to the
// encoder writes "entries": null, and the dashboard reads a null where it
// expects an object: config editing breaks on a store that is merely empty.
func TestGetConfig_EmptyStoreIsAnEmptyObjectNotNull(t *testing.T) {
	for name, list := range map[string]func(context.Context) (map[string]string, error){
		"the store returns a nil map": func(context.Context) (map[string]string, error) { return nil, nil },
		"the store returns an empty map": func(context.Context) (map[string]string, error) {
			return map[string]string{}, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHandler(nil, nil, nil, nil)
			h.adminConfig = &mocks.MockAdminConfigRepo{ListFn: list}

			rec := httptest.NewRecorder()
			h.GetConfig(rec, withActor(httptest.NewRequest(http.MethodGet, "/admin/config", nil)))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}

			var body struct {
				Entries *map[string]string `json:"entries"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if body.Entries == nil {
				t.Fatalf("entries serialized as null: %s", rec.Body.String())
			}
			if len(*body.Entries) != 0 {
				t.Errorf("entries = %v, want empty", *body.Entries)
			}
		})
	}
}
