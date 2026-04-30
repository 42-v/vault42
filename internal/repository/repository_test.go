package repository

import "testing"

func TestAuditFilterDefaults(t *testing.T) {
	// Verify zero-value AuditFilter is usable (no required fields).
	f := AuditFilter{}
	if f.Limit != 0 {
		t.Error("expected zero Limit default")
	}
	if f.UserID != "" {
		t.Error("expected empty UserID default")
	}
	if f.Since != nil {
		t.Error("expected nil Since default")
	}
}
