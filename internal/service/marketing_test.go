package service

import (
	"bytes"
	"context"
	"errors"
	"strings"
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

func (r *racingIdentityRepo) Upsert(_ context.Context, p *model.IdentityProfile) error {
	r.stored = p
	return nil
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

// The CAS loop retries only on losing the race. A hard read error must surface
// immediately, not be retried into ErrConcurrentUpdate.
func TestUpdateMarketingConsent_GetErrorAborts(t *testing.T) {
	boom := errors.New("db down")
	repo := &mocks.MockIdentityRepo{
		GetByPseudonymFn: func(context.Context, string) (*model.IdentityProfile, error) {
			return nil, boom
		},
	}

	err := testIdentitySvc(repo).UpdateMarketingConsent(context.Background(), "user-1", false, ConsentSourceUnsubscribe, "")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the read error", err)
	}
}

// Same for a hard write error: it is not contention and must not be masked as it.
func TestUpdateMarketingConsent_UpsertHardErrorAborts(t *testing.T) {
	boom := errors.New("db down")
	repo := &mocks.MockIdentityRepo{
		UpsertCASFn: func(context.Context, *model.IdentityProfile, time.Time) (bool, error) {
			return false, boom
		},
	}

	err := testIdentitySvc(repo).UpdateMarketingConsent(context.Background(), "user-1", false, ConsentSourceUnsubscribe, "")
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the write error", err)
	}
	if errors.Is(err, ErrConcurrentUpdate) {
		t.Error("a hard write error must not be reported as contention")
	}
}

func TestPutProfile_UpsertHardErrorAborts(t *testing.T) {
	boom := errors.New("db down")
	repo := &mocks.MockIdentityRepo{
		UpsertCASFn: func(context.Context, *model.IdentityProfile, time.Time) (bool, error) {
			return false, boom
		},
	}

	yes := true
	stored, changed, err := testIdentitySvc(repo).PutProfile(context.Background(), "user-1", &IdentityData{}, &yes)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the write error", err)
	}
	if stored != nil || changed {
		t.Errorf("a failed write must not report a persisted consent: stored=%+v changed=%v", stored, changed)
	}
}

// The CAS write path encrypts before it writes; with an unusable master key the
// write must be refused entirely (the same invariant identity_encrypt_test.go
// pins for the plain Upsert path).
func TestUpdateMarketingConsent_EncryptFailureNeverWrites(t *testing.T) {
	wrote := false
	repo := &mocks.MockIdentityRepo{
		UpsertCASFn: func(context.Context, *model.IdentityProfile, time.Time) (bool, error) {
			wrote = true
			return true, nil
		},
	}
	svc := NewIdentityService(repo, bytes.Repeat([]byte{0x42}, 7), testHMAC)

	err := svc.UpdateMarketingConsent(context.Background(), "user-1", true, ConsentSourceProfile, "")
	if err == nil || !strings.Contains(err.Error(), "identity encrypt") {
		t.Fatalf("err = %v, want an identity encrypt failure", err)
	}
	if wrote {
		t.Error("the repository was written despite the encryption failing")
	}
}

// PutProfile is the full-replace write behind PUT /user/identity. Its whole job
// is to reconcile consent inside the same compare-and-set as the write, so these
// cover the cases that a blind read-then-write got wrong.
func TestPutProfile_UnchangedValueKeepsImportProvenance(t *testing.T) {
	repo := &racingIdentityRepo{}
	svc := NewIdentityService(repo, make([]byte, 32), testHMAC)
	ctx := context.Background()

	// Seed an imported (pre-ticked, never affirmed) opt-in, the way the import
	// endpoint does — PutProfile reconciles against the prior record, so it is the
	// wrong tool for establishing a starting state.
	seed := &IdentityData{GivenName: "Ada"}
	seed.StampMarketingConsent(true, ConsentSourceImport, "beon3")
	if err := svc.Upsert(ctx, "user-1", seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// The user edits their country and the client re-submits the ticked box.
	yes := true
	incoming := &IdentityData{GivenName: "Ada", Country: "GB"}
	stored, changed, err := svc.PutProfile(ctx, "user-1", incoming, &yes)
	if err != nil {
		t.Fatalf("PutProfile: %v", err)
	}
	if changed {
		t.Error("re-submitting an unchanged value is not an act of consent")
	}
	if stored.Source != ConsentSourceImport {
		t.Errorf("source = %q, want %q — imported consent was laundered", stored.Source, ConsentSourceImport)
	}
	if stored.Affirmative() {
		t.Error("an imported flag must not become affirmative by being echoed back")
	}
}

func TestPutProfile_OmittedFieldPreservesWithdrawal(t *testing.T) {
	repo := &racingIdentityRepo{}
	svc := NewIdentityService(repo, make([]byte, 32), testHMAC)
	ctx := context.Background()

	if err := svc.UpdateMarketingConsent(ctx, "user-1", false, ConsentSourceUnsubscribe, ""); err != nil {
		t.Fatalf("unsubscribe: %v", err)
	}

	// A client with no checkbox saves the profile.
	stored, changed, err := svc.PutProfile(ctx, "user-1", &IdentityData{GivenName: "Ada"}, nil)
	if err != nil {
		t.Fatalf("PutProfile: %v", err)
	}
	if changed {
		t.Error("omitting the field is not a consent change")
	}
	if stored == nil || stored.Granted || stored.Source != ConsentSourceUnsubscribe {
		t.Errorf("withdrawal destroyed by a save that never mentioned it: %+v", stored)
	}
}

func TestPutProfile_RealChangeIsAffirmative(t *testing.T) {
	repo := &racingIdentityRepo{}
	svc := NewIdentityService(repo, make([]byte, 32), testHMAC)
	ctx := context.Background()

	yes := true
	stored, changed, err := svc.PutProfile(ctx, "user-1", &IdentityData{}, &yes)
	if err != nil {
		t.Fatalf("PutProfile: %v", err)
	}
	if !changed || !stored.Affirmative() {
		t.Errorf("a user ticking the box is affirmative consent: changed=%v stored=%+v", changed, stored)
	}
}

// A failed read of the prior consent must abort. Treating it as "no prior
// consent" is what silently blanked withdrawals and laundered imported flags.
func TestPutProfile_ReadFailureAborts(t *testing.T) {
	repo := &mocks.MockIdentityRepo{
		GetByPseudonymFn: func(context.Context, string) (*model.IdentityProfile, error) {
			return nil, errors.New("db down")
		},
	}
	svc := NewIdentityService(repo, make([]byte, 32), testHMAC)

	yes := true
	if _, _, err := svc.PutProfile(context.Background(), "user-1", &IdentityData{}, &yes); err == nil {
		t.Fatal("a failed consent read must fail the request, not guess")
	}
}

// A profile that keeps moving must 409 rather than overwrite someone else's write.
func TestPutProfile_GivesUpUnderPermanentContention(t *testing.T) {
	repo := &racingIdentityRepo{losses: 99}
	svc := NewIdentityService(repo, make([]byte, 32), testHMAC)

	yes := true
	_, _, err := svc.PutProfile(context.Background(), "user-1", &IdentityData{}, &yes)
	if !errors.Is(err, ErrConcurrentUpdate) {
		t.Fatalf("err = %v, want ErrConcurrentUpdate", err)
	}
	if repo.commits != 0 {
		t.Error("a losing CAS must never commit")
	}
}
