package adminapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/model"
)

// Revoking an admin who opened other accounts nulls their created_by, so the
// answer to "who authorized this account" leaves the row. It has to land
// somewhere, and the audit trail is the only place left.
func TestRevokeAdmin_RecordsTheProvenanceItIsAboutToErase(t *testing.T) {
	const target = "00000000-0000-0000-0000-0000000000aa"

	repo := newFakeAdminRepo()
	repo.users[target] = &model.AdminUser{
		ID: target, Username: "doomed", Role: "viewer", CreatedBy: "root",
	}

	var captured []*model.AuditEntry
	h := &Handler{admins: repo, auditLog: captureAudit(&captured)}

	rec := httptest.NewRecorder()
	r := withActor(httptest.NewRequest(http.MethodPost, "/admin/admins/"+target+"/revoke", nil))
	r.SetPathValue("id", target)
	h.RevokeAdmin(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if len(captured) == 0 {
		t.Fatal("no audit entry for a successful revoke")
	}
	last := captured[len(captured)-1]
	if got := last.Metadata["revoked_admin_created_by"]; got != "root" {
		t.Errorf("revoked_admin_created_by = %v, want \"root\". Migration 042 nulls that "+
			"column on the accounts the revoked admin opened, so this row is where the "+
			"provenance survives.", got)
	}
	if got := last.Metadata["outcome"]; got != "revoked" {
		t.Errorf("outcome = %v, want \"revoked\"", got)
	}
}

// A revoke that fails is the event an operator most needs to see: this route is
// the only containment lever there is, so a 500 means a compromised account is
// still live and nothing else can stop it. It used to return before the audit
// call and leave no trace at all.
func TestRevokeAdmin_AuditsAFailedContainmentAttempt(t *testing.T) {
	const target = "00000000-0000-0000-0000-0000000000bb"

	repo := newFakeAdminRepo()
	repo.users[target] = &model.AdminUser{ID: target, Username: "doomed", Role: "viewer"}
	repo.errRevoke = errors.New("violates foreign key constraint")

	var captured []*model.AuditEntry
	h := &Handler{admins: repo, auditLog: captureAudit(&captured)}

	rec := httptest.NewRecorder()
	r := withActor(httptest.NewRequest(http.MethodPost, "/admin/admins/"+target+"/revoke", nil))
	r.SetPathValue("id", target)
	h.RevokeAdmin(rec, r)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if len(captured) == 0 {
		t.Fatal("a failed revoke wrote no audit row at all. The operator is told the request " +
			"failed and the trail says the attempt never happened.")
	}
	last := captured[len(captured)-1]
	if got := last.Metadata["outcome"]; got != "failed" {
		t.Errorf("outcome = %v, want \"failed\"", got)
	}
	if got, _ := last.Metadata["error"].(string); got == "" {
		t.Error("the audit row carries no reason, so it cannot distinguish a constraint " +
			"violation from the database being down")
	}
}
