package adminapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/rbac"
	"github.com/42-v/vault42/internal/repository"
)

// The audit trail is the admin roster in historical form, and GET /admin/audit
// used to hand all of it to whoever held audit:read.
//
// GET /admin/sessions was raised to admins:manage because the roster of who
// administers the deployment, with each one's source address, is reconnaissance
// for an attacker holding a lower-tier admin session, which is what
// TestListSessionsIsNotAViewerCapability pins. The audit route sits a few lines
// below it on audit:read, which viewer holds, and event_type=admin_login returned
// the same roster for every admin that had ever logged in -- their id, address
// and user agent, plus the username and role that internal/adminapi/auth.go
// writes into the metadata. That is a superset of what the sibling route
// denies: historical rather than live, and with the role attached.
//
// The route keeps audit:read, because a viewer-tier auditor is who the audit
// trail is for. The admin-plane rows come out of it per caller instead.

// rosterAuditRepo is a store that honors AuditFilter the way the postgres one
// does: it applies the exclusion and the event-type predicate first and the
// limit last, which is the ordering the whole fix rests on. It records the
// filter it was handed so a test can assert the exclusion was asked of the
// store rather than applied to its answer.
type rosterAuditRepo struct {
	repository.AuditRepository
	entries  []*model.AuditEntry
	captured repository.AuditFilter
}

func (r *rosterAuditRepo) Query(_ context.Context, filter repository.AuditFilter) ([]*model.AuditEntry, error) {
	r.captured = filter

	kept := make([]*model.AuditEntry, 0, len(r.entries))
	for _, e := range r.entries {
		if filter.EventType != "" && e.EventType != filter.EventType {
			continue
		}
		excluded := false
		for _, prefix := range filter.ExcludeEventTypePrefixes {
			if strings.HasPrefix(e.EventType, prefix) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		kept = append(kept, e)
	}
	if filter.Limit > 0 && len(kept) > filter.Limit {
		kept = kept[:filter.Limit]
	}
	return kept, nil
}

// rosterTrail is a trail holding both planes, with the admin-plane rows written
// the way the product writes them: the acting admin's id and address in the
// columns, the username and role in the metadata.
func rosterTrail() []*model.AuditEntry {
	return []*model.AuditEntry{
		{
			ID: "a-1", EventType: audit.AdminLogin, UserID: "admin-uuid-1",
			IP: "198.51.100.7", UserAgent: "curl/8",
			Metadata: map[string]interface{}{"username": "rootish", "role": "super_admin"},
		},
		{
			ID: "a-2", EventType: "admin:role_create", UserID: "admin-uuid-1",
			IP:       "198.51.100.7",
			Metadata: map[string]interface{}{"name": "auditors"},
		},
		{
			ID: "a-3", EventType: audit.AdminTwoFASetup, UserID: "admin-uuid-2",
			IP: "198.51.100.9",
		},
		{ID: "u-1", EventType: audit.LoginSuccess, UserID: "user-uuid-1", IP: "203.0.113.4"},
		{ID: "u-2", EventType: audit.PasswordChange, UserID: "user-uuid-2", IP: "203.0.113.5"},
	}
}

// routerWithSessionAndAudit is routerWithSession with an audit repository the
// trail route can actually read through, so the gate below runs against a
// response body rather than an empty page.
func routerWithSessionAndAudit(t *testing.T, role rbac.Role) (http.Handler, string, *rosterAuditRepo) {
	t.Helper()

	admins := newFakeAdminRepo()
	admin := &model.AdminUser{
		ID:           "00000000-0000-0000-0000-0000000000ac",
		Username:     "someone",
		Role:         string(role),
		TOTPVerified: true,
	}
	admins.users[admin.ID] = admin

	const token = "session-token-for-the-audit-roster-gate"
	sessions := newFakeSessionRepo()
	sessions.sessions["s1"] = &model.AdminSession{
		ID:        "s1",
		AdminID:   admin.ID,
		TokenHash: hashSessionToken(token),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	auditRepo := &rosterAuditRepo{entries: rosterTrail()}
	api := newTestHandler(admins, nil, nil, auditRepo)
	api.sessions = sessions

	return NewRouter(newTestAuth(admins, sessions), api, RouterOpts{DevMode: true}), token, auditRepo
}

// queryTrail drives the real router and returns the decoded entries.
func queryTrail(t *testing.T, router http.Handler, token, target string) ([]map[string]interface{}, string) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Entries []map[string]interface{} `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding the trail: %v; body %s", err, rec.Body.String())
	}
	return body.Entries, rec.Body.String()
}

// TestQueryAuditIsNotAnAdminRosterForTheViewerTier is the gate.
func TestQueryAuditIsNotAnAdminRosterForTheViewerTier(t *testing.T) {
	router, token, repo := routerWithSessionAndAudit(t, rbac.RoleViewer)

	entries, raw := queryTrail(t, router, token, "/admin/audit?event_type="+audit.AdminLogin)

	if len(entries) != 0 {
		t.Fatalf("a viewer-tier session asked for %s and was handed %d rows. That is the roster of "+
			"every admin that has ever logged in, with their source addresses, usernames and roles -- "+
			"the reconnaissance the admins:manage tier exists to deny, served from the trail instead "+
			"of from GET /admin/sessions. Body: %s", audit.AdminLogin, len(entries), raw)
	}
	for _, leak := range []string{"rootish", "super_admin", "admin-uuid-1", "198.51.100.7"} {
		if strings.Contains(raw, leak) {
			t.Errorf("the response carries %q, which belongs to an admin account: %s", leak, raw)
		}
	}

	// The exclusion has to be asked of the store, not applied to its answer.
	// The limit is counted where the rows are read, so a filter applied after
	// the query returns short pages and an offset that skips rows the caller
	// never saw.
	if len(repo.captured.ExcludeEventTypePrefixes) == 0 {
		t.Fatal("the repository was queried without an event-type exclusion, so any withholding " +
			"happened after the store had already counted the limit. Pages would come back short " +
			"and consecutive pages would skip rows.")
	}
	for _, prefix := range audit.AdminPlaneEventPrefixes() {
		if !slices.Contains(repo.captured.ExcludeEventTypePrefixes, prefix) {
			t.Errorf("the filter excludes %v and not %q. Both namespaces are in the store: the "+
				"vocabulary spells the admin plane admin_something and the role, import and email "+
				"routes spell it admin:something.", repo.captured.ExcludeEventTypePrefixes, prefix)
		}
	}
}

// TestQueryAuditWithholdsEveryAdminNamespaceFromTheViewerTier walks the whole
// trail rather than one event type, because an unfiltered request returns the
// same rows mixed into the page and is the shape a gate on event_type alone
// would have missed.
func TestQueryAuditWithholdsEveryAdminNamespaceFromTheViewerTier(t *testing.T) {
	router, token, _ := routerWithSessionAndAudit(t, rbac.RoleViewer)

	entries, raw := queryTrail(t, router, token, "/admin/audit")

	if len(entries) != 2 {
		t.Fatalf("got %d rows, want the 2 user-plane rows: %s", len(entries), raw)
	}
	for _, e := range entries {
		eventType, _ := e["event_type"].(string)
		if audit.IsAdminPlaneEvent(eventType) {
			t.Errorf("the unfiltered trail returned %q to a viewer", eventType)
		}
	}
}

// TestQueryAuditStaysWholeForTheAdminTier is the other direction, so the gate
// above cannot pass by withholding the admin plane from everyone. An operator
// investigating an incident on the admin plane is exactly who admins:manage is
// held by.
func TestQueryAuditStaysWholeForTheAdminTier(t *testing.T) {
	router, token, repo := routerWithSessionAndAudit(t, rbac.RoleSuperAdmin)

	entries, raw := queryTrail(t, router, token, "/admin/audit?event_type="+audit.AdminLogin)

	if len(entries) != 1 {
		t.Fatalf("a super_admin asked for %s and got %d rows, want 1: %s", audit.AdminLogin, len(entries), raw)
	}
	if !strings.Contains(raw, "rootish") || !strings.Contains(raw, "super_admin") {
		t.Errorf("the admin tier lost the username and role the row is investigated through: %s", raw)
	}
	if repo.captured.ExcludeEventTypePrefixes != nil {
		t.Errorf("a caller holding admins:manage was still handed an exclusion: %v",
			repo.captured.ExcludeEventTypePrefixes)
	}
}

// TestQueryAuditPagesAreNotShortenedByTheExclusion is the pagination half.
//
// The store applies the exclusion and then the limit, so a viewer asking for
// two rows gets two rows. Had the handler filtered the returned slice instead,
// this page would have come back holding whatever survived out of the first two
// rows read, which for this trail is none of them.
func TestQueryAuditPagesAreNotShortenedByTheExclusion(t *testing.T) {
	router, token, _ := routerWithSessionAndAudit(t, rbac.RoleViewer)

	entries, raw := queryTrail(t, router, token, "/admin/audit?limit=2")

	if len(entries) != 2 {
		t.Fatalf("a page of 2 came back holding %d. The admin-plane rows were counted against the "+
			"limit and then dropped, so the caller pages through a trail whose pages shrink and "+
			"whose offsets skip rows they were never shown: %s", len(entries), raw)
	}
}

// TestQueryAuditWithholdsTheAdminPlaneWithoutACaller pins the direction the
// permission check fails in.
//
// A request that reaches the handler with no admin on its context has no caller
// to check, which happens when the session middleware is not in front of the
// route and when a test drives the handler directly. Neither is an argument for
// handing over the roster, so the absence of a caller reads as "not permitted"
// rather than as "no restriction applies".
func TestQueryAuditWithholdsTheAdminPlaneWithoutACaller(t *testing.T) {
	auditRepo := &rosterAuditRepo{entries: rosterTrail()}
	h := newTestHandler(nil, nil, nil, auditRepo)

	rec := httptest.NewRecorder()
	h.QueryAudit(rec, httptest.NewRequest(http.MethodGet, "/admin/audit", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if len(auditRepo.captured.ExcludeEventTypePrefixes) == 0 {
		t.Error("an unauthenticated call was served the admin plane. The permission check has to " +
			"fail closed on a missing caller: the two ways a request arrives without one are a " +
			"wiring mistake and a test, and neither should widen what the endpoint returns.")
	}
}
