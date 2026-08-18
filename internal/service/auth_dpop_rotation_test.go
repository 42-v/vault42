package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/dpop"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/internal/repository"
	"github.com/42-v/vault42/tests/mocks"
)

// DPoP exists so that stealing a token is not enough: the token names a key
// (cnf.jkt, RFC 9449 §6.1) and every use of it has to be signed by that key. In
// a browser the key is a non-extractable WebCrypto keypair, so the whole point
// is that script which reads a token cannot read the key, and the credential it
// steals stops working the moment the page is gone.
//
// Rotation was where that promise was paid out. The access token's cnf.jkt came
// from dpop.Thumbprint(ctx) — the CURRENT request's proof — at both mint sites,
// and no binding was stored for a rotation to be checked against: model
// .RefreshToken had no jkt field and no migration created a column for one.
// POST /auth/refresh is mounted under dpopWrap without authMw, so claims is nil,
// tokenRequiresDPoP is false and the middleware's own comparison never fires.
//
// So the attack is: script steals nothing but the opaque refresh cookie, which
// rides on the request automatically. It generates its OWN keypair — extractable
// this time, because it chose the parameters — presents a proof over it to
// /auth/refresh, and receives an access token validly bound to a key it can
// serialize and carry off the machine. A non-extractable-key credential has been
// laundered into a portable one. The device fingerprint at auth.go's
// CompareFingerprints is the only obstacle, and it is IP plus User-Agent plus
// Accept-Language — everything the same script already matches by construction.
//
// The three tests below are the three ways the binding can be lost, and each one
// is stated as what the ROTATED token must carry.

const (
	// Two distinct RFC 7638 thumbprints. The values only have to be unequal and
	// shaped like the real thing; nothing here recomputes them from a key.
	victimJKT   = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
	attackerJKT = "hVQ8s3rTPWlnBiSA7XvBGb0EN4uCfLcXqXzJnAy5T2M"
)

// bindingTokenRepo round-trips rows the way PostgreSQL does: what Create writes
// is what GetByTokenHash reads back. The function-hook MockRefreshTokenRepo
// cannot express that, and it is exactly the property under test — a binding is
// only enforceable at rotation if the store carried it there.
type bindingTokenRepo struct {
	*mocks.MockRefreshTokenRepo

	mu      sync.Mutex
	rows    map[string]*model.RefreshToken // token hash -> row
	origins map[string]time.Time           // family id -> birth date
	revoked map[string]bool                // family id -> revoked
}

func newBindingTokenRepo(base *mocks.MockRefreshTokenRepo) *bindingTokenRepo {
	return &bindingTokenRepo{
		MockRefreshTokenRepo: base,
		rows:                 map[string]*model.RefreshToken{},
		origins:              map[string]time.Time{},
		revoked:              map[string]bool{},
	}
}

func (r *bindingTokenRepo) Create(_ context.Context, token *model.RefreshToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revoked[token.FamilyID] {
		return repository.ErrFamilyRevoked
	}
	if _, ok := r.origins[token.FamilyID]; !ok {
		r.origins[token.FamilyID] = token.CreatedAt
	}
	row := *token
	r.rows[token.TokenHash] = &row
	return nil
}

func (r *bindingTokenRepo) CreateWithinCap(ctx context.Context, token *model.RefreshToken, _ int) error {
	return r.Create(ctx, token)
}

func (r *bindingTokenRepo) GetByTokenHash(_ context.Context, hash string) (*model.RefreshToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[hash]
	if !ok {
		return nil, nil
	}
	out := *row
	return &out, nil
}

func (r *bindingTokenRepo) MarkUsed(_ context.Context, id string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		if row.ID == id {
			if row.Used || row.Revoked {
				return false, nil
			}
			row.Used = true
			return true, nil
		}
	}
	return false, nil
}

func (r *bindingTokenRepo) RevokeFamily(_ context.Context, familyID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[familyID] = true
	for _, row := range r.rows {
		if row.FamilyID == familyID {
			row.Revoked = true
		}
	}
	return nil
}

func (r *bindingTokenRepo) FamilyOrigin(_ context.Context, familyID string) (time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.origins[familyID], nil
}

func (r *bindingTokenRepo) familyRevoked(familyID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.revoked[familyID]
}

// rotationFixture wires a service over a store that really persists rows.
func rotationFixture(t *testing.T) (*AuthService, *bindingTokenRepo) {
	t.Helper()
	svc, o := newMockAuthService(t)
	repo := newBindingTokenRepo(o.tokenRepo)
	svc.tokens = repo
	return svc, repo
}

// loginBoundTo performs the issuance half of a login: a pair minted under a
// validated proof (or under none, when jkt is empty) and stored as the family's
// first row. It returns the opaque refresh token — the only thing the attacker
// in these tests is assumed to hold.
func loginBoundTo(t *testing.T, svc *AuthService, jkt string) string {
	t.Helper()
	ctx := context.Background()
	if jkt != "" {
		ctx = dpop.WithThumbprint(ctx, jkt)
	}
	pair, err := svc.tokenSvc.IssueTokenPairWithAuth(ctx, "u-1", []string{"user"},
		[]string{"read", "write"}, "", "", "", false, AuthContext{AuthTime: time.Now()})
	if err != nil {
		t.Fatalf("issue the login pair: %v", err)
	}
	if err := svc.storeRefreshToken(ctx, "u-1", "", "", "", pair); err != nil {
		t.Fatalf("store the login refresh token: %v", err)
	}
	return pair.RefreshToken
}

// rotateWith runs one refresh under the given proof thumbprint ("" = no proof).
func rotateWith(t *testing.T, svc *AuthService, refreshToken, jkt string) (*RefreshResult, error) {
	t.Helper()
	ctx := context.Background()
	if jkt != "" {
		ctx = dpop.WithThumbprint(ctx, jkt)
	}
	return svc.Refresh(ctx, refreshToken, "1.2.3.4", "UA", vaultcrypto.FingerprintInput{})
}

// accessClaimsOf parses an issued access token.
func accessClaimsOf(t *testing.T, svc *AuthService, accessToken string) *vaultcrypto.VaultClaims {
	t.Helper()
	claims, err := vaultcrypto.ParseAndValidate(accessToken, func(_ *vjwt.Token) (any, error) {
		return &svc.tokenSvc.privateKey.PublicKey, nil
	}, svc.tokenSvc.issuer, svc.tokenSvc.audience)
	if err != nil {
		t.Fatalf("parse the rotated access token: %v", err)
	}
	return claims
}

// confirmationJKT is the rotated token's binding, or "" when it carries none.
func confirmationJKT(c *vaultcrypto.VaultClaims) string {
	if c.Confirmation == nil {
		return ""
	}
	return c.Confirmation.JKT
}

// THE ATTACK. The family was bound to the victim's non-extractable key at login.
// The attacker holds the refresh cookie and no private key at all, so it brings
// its own — and a rotation that mints cnf.jkt from the request re-binds the
// session to it. The rotated token is then a valid, sender-constrained
// credential whose key the attacker can export.
func TestRotationWithAForeignProofMustNotRebindTheFamily(t *testing.T) {
	svc, _ := rotationFixture(t)
	refresh := loginBoundTo(t, svc, victimJKT)

	res, err := rotateWith(t, svc, refresh, attackerJKT)
	if err == nil {
		got := confirmationJKT(accessClaimsOf(t, svc, res.AccessToken))
		if got == attackerJKT {
			t.Fatalf("the rotated access token is bound to the ATTACKER's key %q; the family was "+
				"bound to %q. Whoever holds the refresh cookie can re-bind the session to a key "+
				"they generated and export, which is the entire benefit DPoP claims to provide",
				got, victimJKT)
		}
		t.Fatalf("the rotation succeeded with cnf.jkt %q; a caller who cannot prove possession of "+
			"the family's key must be refused, not served a differently-bound token", got)
	}
	// Refusing is the chosen answer. It must be the SAME refusal an unknown or
	// expired cookie gets, or the response tells a prober that the cookie is
	// real and that this family is DPoP-bound.
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("err = %v, want ErrTokenInvalid", err)
	}
	if errors.Is(err, ErrReplayDetected) {
		t.Error("a binding mismatch reported as replay tells the caller which check refused it")
	}
}

// The same hole with the proof simply omitted. Nothing enforces DPoP on
// /auth/refresh, so a bare cookie POST rotated and the successor carried no cnf
// at all — the session silently downgraded to bearer, and the stolen cookie was
// once again a complete credential.
func TestRotationWithNoProofMustNotDropTheBinding(t *testing.T) {
	svc, _ := rotationFixture(t)
	refresh := loginBoundTo(t, svc, victimJKT)

	res, err := rotateWith(t, svc, refresh, "")
	if err == nil {
		t.Fatalf("a rotation carrying no proof was served, with cnf.jkt %q; the sender constraint "+
			"was dropped by whoever held the cookie",
			confirmationJKT(accessClaimsOf(t, svc, res.AccessToken)))
	}
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("err = %v, want ErrTokenInvalid", err)
	}
}

// The two refusals must be indistinguishable to the caller. An attacker probing
// with no proof and then with a wrong key learns nothing from the difference,
// which is the same anti-enumeration argument recordLoginFailure makes.
func TestBothBindingFailuresLookIdenticalToTheCaller(t *testing.T) {
	svcA, _ := rotationFixture(t)
	_, noProof := rotateWith(t, svcA, loginBoundTo(t, svcA, victimJKT), "")

	svcB, _ := rotationFixture(t)
	_, wrongKey := rotateWith(t, svcB, loginBoundTo(t, svcB, victimJKT), attackerJKT)

	if noProof == nil || wrongKey == nil {
		t.Fatal("both rotations must be refused")
	}
	if noProof.Error() != wrongKey.Error() {
		t.Errorf("absent proof gives %q and a wrong key gives %q; the difference tells a prober "+
			"whether the family is bound", noProof, wrongKey)
	}
}

// The refusal must leave the session exactly as it found it. This is the reason
// the check runs BEFORE MarkUsed rather than inside issueRotatedPair: spending
// the presented token first would mean the victim's own next refresh presents a
// row already marked used, which is replay, which burns the family. The refusal
// would then destroy the session it exists to defend, and an attacker holding
// only the cookie would gain a one-request session kill they do not otherwise
// have.
func TestARefusedRotationNeitherSpendsTheTokenNorBurnsTheFamily(t *testing.T) {
	svc, repo := rotationFixture(t)
	refresh := loginBoundTo(t, svc, victimJKT)

	if _, err := rotateWith(t, svc, refresh, attackerJKT); err == nil {
		t.Fatal("the attacker's rotation must be refused")
	}

	stored, err := repo.GetByTokenHash(context.Background(), vaultcrypto.SHA256Hex(refresh))
	if err != nil || stored == nil {
		t.Fatalf("the presented row vanished: %v", err)
	}
	if stored.Used {
		t.Error("the refused rotation consumed the victim's refresh token; their next refresh " +
			"will look like a replay and burn the family")
	}
	if repo.familyRevoked(stored.FamilyID) {
		t.Error("the refused rotation burned the family; an attacker holding only the cookie can " +
			"now end the session on demand, which they could not do before")
	}

	// The proof of the point: the victim rotates afterwards, unaffected.
	res, err := rotateWith(t, svc, refresh, victimJKT)
	if err != nil {
		t.Fatalf("the victim could not rotate after the attacker's attempt: %v", err)
	}
	if got := confirmationJKT(accessClaimsOf(t, svc, res.AccessToken)); got != victimJKT {
		t.Errorf("cnf.jkt = %q, want %q", got, victimJKT)
	}
}

// The binding has to survive more than one hop, because the successor row is
// written by a different code path (issueRotatedPair) than the first row
// (storeRefreshToken). A binding that is enforced on hop one and dropped on hop
// two is the same hole one rotation later.
func TestTheBindingSurvivesRepeatedRotation(t *testing.T) {
	svc, _ := rotationFixture(t)
	refresh := loginBoundTo(t, svc, victimJKT)

	for hop := 1; hop <= 4; hop++ {
		res, err := rotateWith(t, svc, refresh, victimJKT)
		if err != nil {
			t.Fatalf("hop %d: %v", hop, err)
		}
		if got := confirmationJKT(accessClaimsOf(t, svc, res.AccessToken)); got != victimJKT {
			t.Fatalf("hop %d: cnf.jkt = %q, want %q", hop, got, victimJKT)
		}
		refresh = res.RefreshToken

		// And the successor must still refuse a foreign key.
		if _, err := rotateWith(t, svc, refresh, attackerJKT); err == nil {
			t.Fatalf("hop %d: the successor row rotated for the attacker's key", hop)
		}
	}
}

// The laundering path in its second form. An unbound family — every non-DPoP
// client — must not be upgradable by whoever presents a proof, because "bound"
// would then mean "bound to the last caller", which is not a constraint at all.
func TestAnUnboundFamilyMustNotBeUpgradedByAPresentedProof(t *testing.T) {
	svc, _ := rotationFixture(t)
	refresh := loginBoundTo(t, svc, "")

	res, err := rotateWith(t, svc, refresh, attackerJKT)
	if err != nil {
		t.Fatalf("an unbound family must keep rotating exactly as it does today: %v", err)
	}
	if got := confirmationJKT(accessClaimsOf(t, svc, res.AccessToken)); got != "" {
		t.Fatalf("an unbound family was upgraded to cnf.jkt %q by a proof the caller chose; a "+
			"binding nobody established is a binding the attacker establishes", got)
	}
}

// The regression guard the fix must not break: a bound family rotating under its
// OWN key keeps working, and keeps its binding.
func TestABoundFamilyRotatesUnderItsOwnKey(t *testing.T) {
	svc, _ := rotationFixture(t)
	refresh := loginBoundTo(t, svc, victimJKT)

	res, err := rotateWith(t, svc, refresh, victimJKT)
	if err != nil {
		t.Fatalf("the legitimate holder of the bound key was refused: %v", err)
	}
	if got := confirmationJKT(accessClaimsOf(t, svc, res.AccessToken)); got != victimJKT {
		t.Fatalf("cnf.jkt = %q, want %q", got, victimJKT)
	}
}

// A non-DPoP client is the majority of deployments and must be untouched.
func TestAnUnboundFamilyRotatesWithNoProofAsBefore(t *testing.T) {
	svc, _ := rotationFixture(t)
	refresh := loginBoundTo(t, svc, "")

	res, err := rotateWith(t, svc, refresh, "")
	if err != nil {
		t.Fatalf("an unbound family failed to rotate: %v", err)
	}
	if got := confirmationJKT(accessClaimsOf(t, svc, res.AccessToken)); got != "" {
		t.Fatalf("an unbound rotation produced cnf.jkt %q", got)
	}
}
