package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

func testIdentitySvc(repo *mocks.MockIdentityRepo) *IdentityService {
	return NewIdentityService(repo, make([]byte, 32), testHMAC)
}

// MarketingAllowed is the only gate a campaign sender consults. Every path that
// is not a demonstrable opt-in must return false — a bug here mails people who
// never agreed to be mailed.
func TestMarketingAllowed_FailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		profile *IdentityData
		want    bool
	}{
		{"no profile at all", nil, false},
		{"registration opt-in", stamped(true, ConsentSourceRegistration), true},
		{"profile opt-in", stamped(true, ConsentSourceProfile), true},
		{"imported opt-in is not consent", stamped(true, ConsentSourceImport), false},
		{"legacy opt-in is not consent", stamped(true, ConsentSourceLegacy), false},
		{"withdrawn", stamped(false, ConsentSourceUnsubscribe), false},
		{"profile with no consent at all", &IdentityData{GivenName: "Ada"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := &mocks.MockIdentityRepo{}
			svc := testIdentitySvc(repo)

			if tc.profile == nil {
				repo.GetByPseudonymFn = func(context.Context, string) (*model.IdentityProfile, error) {
					return nil, nil
				}
			} else {
				// Round-trip through Upsert so the test reads back real ciphertext
				// rather than a hand-built struct.
				var stored *model.IdentityProfile
				repo.UpsertFn = func(_ context.Context, p *model.IdentityProfile) error {
					stored = p
					return nil
				}
				if err := svc.Upsert(context.Background(), "user-1", tc.profile); err != nil {
					t.Fatalf("Upsert: %v", err)
				}
				repo.GetByPseudonymFn = func(context.Context, string) (*model.IdentityProfile, error) {
					return stored, nil
				}
			}

			got, err := svc.MarketingAllowed(context.Background(), "user-1")
			if err != nil {
				t.Fatalf("MarketingAllowed: %v", err)
			}
			if got != tc.want {
				t.Errorf("MarketingAllowed = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMarketingAllowed_RepoErrorFailsClosed(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		GetByPseudonymFn: func(context.Context, string) (*model.IdentityProfile, error) {
			return nil, errors.New("db down")
		},
	}
	allowed, err := testIdentitySvc(repo).MarketingAllowed(context.Background(), "user-1")
	if err == nil {
		t.Error("expected the repo error to surface")
	}
	if allowed {
		t.Error("a failed lookup must not authorise sending")
	}
}

// A consent record must survive the encrypt/decrypt round-trip intact: the
// source is what makes it demonstrable, so losing it silently downgrades a real
// opt-in to an unusable one (or worse, an import to a real one).
func TestConsentSurvivesRoundTrip(t *testing.T) {
	repo := &mocks.MockIdentityRepo{}
	svc := testIdentitySvc(repo)

	var stored *model.IdentityProfile
	repo.UpsertFn = func(_ context.Context, p *model.IdentityProfile) error {
		stored = p
		return nil
	}
	repo.GetByPseudonymFn = func(context.Context, string) (*model.IdentityProfile, error) {
		return stored, nil
	}

	in := &IdentityData{GivenName: "Ada"}
	in.StampMarketingConsent(true, ConsentSourceRegistration, "")
	if err := svc.Upsert(context.Background(), "user-1", in); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	out, _, err := svc.Get(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if out.MarketingConsent == nil {
		t.Fatal("consent record lost in round-trip")
	}
	if out.MarketingConsent.Source != ConsentSourceRegistration {
		t.Errorf("source = %q, want %q", out.MarketingConsent.Source, ConsentSourceRegistration)
	}
	if out.MarketingConsent.At.IsZero() {
		t.Error("consent timestamp lost in round-trip")
	}
	if !out.MarketingConsent.Affirmative() {
		t.Error("a registration opt-in must still be affirmative after a round-trip")
	}
}

func stamped(granted bool, source string) *IdentityData {
	d := &IdentityData{}
	d.StampMarketingConsent(granted, source, "")
	return d
}

// The CAS is the whole protection against a concurrent write dropping a
// withdrawal, and the default mocks return "won the race" unconditionally — so a
// test that only stubs UpsertFn would pass even if the CAS semantics were
// inverted. This mock lies: it loses the race a fixed number of times, and the
// profile it hands back changes underneath, exactly as a competing writer would.
type racingIdentityRepo struct {
	mocks.MockIdentityRepo
	losses  int
	commits int
	stored  *model.IdentityProfile
}

func (r *racingIdentityRepo) GetByPseudonym(context.Context, string) (*model.IdentityProfile, error) {
	return r.stored, nil
}

func (r *racingIdentityRepo) UpsertCAS(_ context.Context, p *model.IdentityProfile, expected time.Time) (bool, error) {
	if r.losses > 0 {
		r.losses--
		// Someone else committed: the stored row moves on, so the caller's
		// expectation is now stale and must be re-read.
		if r.stored != nil {
			r.stored.UpdatedAt = r.stored.UpdatedAt.Add(time.Second)
		}
		return false, nil
	}
	if r.stored != nil && !expected.Equal(r.stored.UpdatedAt) {
		return false, nil // stale expectation — a correct caller retries
	}
	r.commits++
	r.stored = p
	return true, nil
}

func TestUpdateMarketingConsent_RetriesUntilItWins(t *testing.T) {
	repo := &racingIdentityRepo{losses: 2}
	svc := NewIdentityService(repo, make([]byte, 32), testHMAC)

	if err := svc.UpdateMarketingConsent(context.Background(), "user-1", false, ConsentSourceUnsubscribe, ""); err != nil {
		t.Fatalf("UpdateMarketingConsent: %v", err)
	}
	if repo.commits != 1 {
		t.Errorf("commits = %d, want exactly 1", repo.commits)
	}
	if repo.losses != 0 {
		t.Errorf("retries did not consume the lost races: %d left", repo.losses)
	}
}

// If the profile keeps moving, the withdrawal must fail loudly rather than be
// silently dropped or written over someone else's change.
func TestUpdateMarketingConsent_GivesUpRatherThanClobber(t *testing.T) {
	repo := &racingIdentityRepo{losses: 99}
	svc := NewIdentityService(repo, make([]byte, 32), testHMAC)

	err := svc.UpdateMarketingConsent(context.Background(), "user-1", false, ConsentSourceUnsubscribe, "")
	if !errors.Is(err, ErrConcurrentUpdate) {
		t.Fatalf("err = %v, want ErrConcurrentUpdate", err)
	}
	if repo.commits != 0 {
		t.Error("a losing CAS must never commit")
	}
}
