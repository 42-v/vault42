package repository

import (
	"testing"
)

// The zero value is the "no filtering" filter, and every field has to mean
// absent at zero for that to hold. MinRiskScore is the one that says so out
// loud: a floor of zero selects everything, so reading the zero as a floor would
// make an unset filter look set. A field that acquired a non-zero default would
// silently narrow every query built from an unset filter, which from the outside
// looks like an audit review that shows fewer rows than exist.
//
// A table test stood here and read three fields into the blank identifier
// across four cases. AuditFilter carries no methods, so there was nothing for
// it to exercise and no outcome it could report. It is not named here, because
// a comment naming a test that does not exist is the thing the gate-liveness
// check refuses, and history is worth keeping without spending an exemption on
// it.
func TestAuditFilterDefaults(t *testing.T) {
	f := AuditFilter{}
	if f.UserID != "" {
		t.Errorf("UserID default = %q, want empty", f.UserID)
	}
	if f.EventType != "" {
		t.Errorf("EventType default = %q, want empty", f.EventType)
	}
	if f.Since != nil || f.Until != nil {
		t.Errorf("time bounds default to %v/%v, want nil/nil", f.Since, f.Until)
	}
	if f.MinRiskScore != 0 {
		t.Errorf("MinRiskScore default = %d, want 0 meaning no floor at all", f.MinRiskScore)
	}
	if f.Limit != 0 {
		t.Errorf("Limit default = %d, want 0", f.Limit)
	}
	if f.Offset != 0 {
		t.Errorf("Offset default = %d, want 0", f.Offset)
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
