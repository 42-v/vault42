package audit

import (
	"testing"
	"time"
)

func TestLoggerDroppedTotalStartsZero(t *testing.T) {
	l := NewLogger(&mockAuditRepo{}, time.Hour)
	if got := l.DroppedTotal(); got != 0 {
		t.Fatalf("DroppedTotal = %d on fresh logger, want 0", got)
	}
}

func TestIsCriticalEvent(t *testing.T) {
	if !isCriticalEvent(LoginFailure) {
		t.Error("LoginFailure should be critical")
	}
	if !isCriticalEvent(PasswordChange) {
		t.Error("PasswordChange should be critical")
	}
	if isCriticalEvent("something:noncritical") {
		t.Error("arbitrary event should not be critical")
	}
}
