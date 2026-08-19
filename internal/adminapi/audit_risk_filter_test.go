package adminapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/42-v/vault42/internal/audit"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/tests/mocks"
)

// capturingAuditRepo records the filter QueryAudit assembled.
func capturingAuditRepo(into *repository.AuditFilter) *mocks.MockAuditRepo {
	return &mocks.MockAuditRepo{QueryFn: func(_ context.Context, f repository.AuditFilter) ([]*model.AuditEntry, error) {
		*into = f
		return nil, nil
	}}
}

// AU-6's review half is the admin audit view, and until now it could filter by
// user, event type and time window only. There was no query an operator could
// write that meant "show me everything that mattered", so the one severity
// signal in the store was unreviewable. This is the query-string end of that.
func TestQueryAudit_MinRiskScoreReachesTheRepositoryFilter(t *testing.T) {
	var captured repository.AuditFilter
	h := newTestHandler(nil, nil, nil, capturingAuditRepo(&captured))

	rec := httptest.NewRecorder()
	h.QueryAudit(rec, httptest.NewRequest(http.MethodGet, "/admin/audit?min_risk_score=75", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if captured.MinRiskScore != 75 {
		t.Errorf("MinRiskScore = %d, want 75; the severity predicate never reaches the store",
			captured.MinRiskScore)
	}
}

// The scale the number lives on is internal/audit's, so a query written against
// a band name has to select the same rows as the number behind it. This is what
// stops the two from drifting into two scales.
func TestQueryAudit_TheThresholdIsOnTheSeverityScale(t *testing.T) {
	var captured repository.AuditFilter
	h := newTestHandler(nil, nil, nil, capturingAuditRepo(&captured))

	rec := httptest.NewRecorder()
	h.QueryAudit(rec, httptest.NewRequest(http.MethodGet, "/admin/audit?min_risk_score=100", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if captured.MinRiskScore != audit.SeverityCritical {
		t.Errorf("MinRiskScore = %d, want SeverityCritical = %d", captured.MinRiskScore, audit.SeverityCritical)
	}
}

// A filter an operator cannot express is a filter, but a filter that silently
// becomes a different filter is a wrong answer. An unparseable or negative
// value has to leave the predicate off rather than land on some other threshold.
func TestQueryAudit_AnUnusableMinRiskScoreLeavesThePredicateOff(t *testing.T) {
	for _, q := range []string{
		"min_risk_score=",
		"min_risk_score=high",
		"min_risk_score=-1",
		"min_risk_score=7.5",
		"", // absent entirely
	} {
		var captured repository.AuditFilter
		h := newTestHandler(nil, nil, nil, capturingAuditRepo(&captured))
		rec := httptest.NewRecorder()
		h.QueryAudit(rec, httptest.NewRequest(http.MethodGet, "/admin/audit?"+q, nil))

		if rec.Code != http.StatusOK {
			t.Errorf("%q: status = %d, want 200", q, rec.Code)
		}
		if captured.MinRiskScore != 0 {
			t.Errorf("%q: MinRiskScore = %d, want 0 (predicate off)", q, captured.MinRiskScore)
		}
	}
}
