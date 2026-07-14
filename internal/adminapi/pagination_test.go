package adminapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// The admin-user list must enforce the pagination cap: a request asking for
// more rows than maxListLimit is clamped, so the response can never return an
// unbounded set even when far more rows exist (OWASP API4/M06).
func TestListAdmins_EnforcesPaginationCap(t *testing.T) {
	repo := newFakeAdminRepo()
	for i := 0; i < maxListLimit+50; i++ {
		id := fmt.Sprintf("admin-%03d", i)
		repo.users[id] = &model.AdminUser{ID: id, Username: id, Role: "viewer"}
	}

	h := newTestHandler(repo, nil, nil, nil)
	rec := httptest.NewRecorder()
	h.ListAdmins(rec, httptest.NewRequest(http.MethodGet, "/admin/admins?limit=10000", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var resp struct {
		Admins []map[string]any `json:"admins"`
		Total  int              `json:"total"`
		Limit  int              `json:"limit"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Limit != maxListLimit {
		t.Errorf("limit = %d, want clamped to %d", resp.Limit, maxListLimit)
	}
	if len(resp.Admins) != maxListLimit {
		t.Errorf("returned %d admins, want capped at %d", len(resp.Admins), maxListLimit)
	}
	if resp.Total != maxListLimit+50 {
		t.Errorf("total = %d, want full count %d", resp.Total, maxListLimit+50)
	}
}

// parsePagination is the bound on result-set size: an unbounded list of every
// user or every audit entry is a denial-of-service against the admin gateway, and
// the limit is caller-controlled. These are the cases where trusting the caller
// would remove the bound.
func TestParsePagination_ClampsCallerControlledLimits(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantLimit  int
		wantOffset int
	}{
		{"absent falls back to the default", "", defaultListLimit, 0},
		{"explicit values are honoured", "?limit=10&offset=5", 10, 5},
		{"an oversized limit is clamped, not trusted", "?limit=100000", maxListLimit, 0},
		{"zero falls back rather than returning an empty page", "?limit=0", defaultListLimit, 0},
		{"a negative limit falls back", "?limit=-1", defaultListLimit, 0},
		{"a non-numeric limit falls back", "?limit=all", defaultListLimit, 0},
		{"a negative offset is ignored", "?offset=-5", defaultListLimit, 0},
		{"a non-numeric offset is ignored", "?offset=abc", defaultListLimit, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/admin/users"+tc.query, nil)
			limit, offset := parsePagination(r)

			if limit != tc.wantLimit {
				t.Errorf("limit = %d, want %d", limit, tc.wantLimit)
			}
			if offset != tc.wantOffset {
				t.Errorf("offset = %d, want %d", offset, tc.wantOffset)
			}
			if limit > maxListLimit {
				t.Errorf("limit %d exceeds the hard cap %d — the result-set bound is gone", limit, maxListLimit)
			}
		})
	}
}

// paginate applies the window. An off-by-one drops records from an admin's view;
// an unguarded slice panics on an offset past the end.
func TestPaginate_Windowing(t *testing.T) {
	items := []int{0, 1, 2, 3, 4}

	tests := []struct {
		name   string
		limit  int
		offset int
		want   []int
	}{
		{"a window inside the slice", 2, 1, []int{1, 2}},
		{"a limit past the end truncates", 10, 3, []int{3, 4}},
		{"an offset past the end yields nothing, not a panic", 5, 99, []int{}},
		{"an offset exactly at the end yields nothing", 5, 5, []int{}},
		{"the whole slice", 5, 0, []int{0, 1, 2, 3, 4}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := paginate(items, tc.limit, tc.offset)
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d, want %d (got %v)", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("item %d = %d, want %d", i, got[i], tc.want[i])
				}
			}
		})
	}
}
