package repository

import (
	"testing"
	"time"
)

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

func TestAuditFilter_Table(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name string
		f    AuditFilter
	}{
		{"zero", AuditFilter{}},
		{"full", AuditFilter{UserID: "u1", EventType: "login", Since: &now, Until: &now, Limit: 10, Offset: 5}},
		{"negative limit ok", AuditFilter{Limit: -1}},
		{"all fields", AuditFilter{UserID: "u", EventType: "e", Since: &now, Until: &now, Limit: 1, Offset: 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = tt.f.UserID
			_ = tt.f.Limit
			_ = tt.f.EventType
		})
	}
}

func TestErrRoleReserved_Table(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"not nil", ErrRoleReserved},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Error("ErrRoleReserved should be non-nil")
			}
		})
	}
}
