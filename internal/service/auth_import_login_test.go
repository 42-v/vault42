package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/model"
)

// An unclaimed imported account used to answer its first login with a distinct
// success-shaped result carrying import_claim_required, which the transport
// turned into 202. That is two oracles in one response: the address is
// registered, and the account is an unclaimed import. It also mailed the account
// holder on every attempt, from an unauthenticated endpoint, invalidating any
// claim link they were part-way through using.
//
// The whole point of the fix is that nothing about the response distinguishes
// this account from any other failed login, so that is what these tests pin.

func importPendingService(t *testing.T) (*AuthService, *mockAuthOpts) {
	t.Helper()
	svc, o := newMockAuthService(t)
	o.userRepo.GetByEmailFn = func(_ context.Context, _ string) (*model.User, error) {
		return &model.User{
			ID: "u-imp", Email: "rider@legacy.test", EmailVerified: true,
			ImportPending: true, ImportedFrom: "legacy", // no password hash
		}, nil
	}
	return svc, o
}

func TestLogin_ImportPendingIsIndistinguishableFromWrongPassword(t *testing.T) {
	svc, _ := importPendingService(t)

	res, err := svc.Login(context.Background(), LoginInput{
		Email: "rider@legacy.test", Password: "anything",
	}, "1.2.3.4", "UA")

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("import-pending login must answer ErrInvalidCredentials, got %v", err)
	}
	if res != nil {
		t.Fatalf("no result may be returned: an import-pending login is a failed login, got %+v", res)
	}
}

// The oracle would come back the moment the failure bookkeeping diverged: an
// account that never increments its lockout counter stays answerable forever
// while every other account locks after lockoutThreshold, which is the same
// oracle one step removed.
func TestLogin_ImportPendingFeedsTheSameLockoutCounters(t *testing.T) {
	svc, o := importPendingService(t)

	var failedLoginUser string
	o.userRepo.IncrementFailedLoginFn = func(_ context.Context, id string) error {
		failedLoginUser = id
		return nil
	}

	var mu sync.Mutex
	counters := map[string]int{}
	o.cache.IncrementFn = func(_ context.Context, key string, _ time.Duration) (int64, error) {
		mu.Lock()
		defer mu.Unlock()
		counters[key]++
		return int64(counters[key]), nil
	}

	if _, err := svc.Login(context.Background(), LoginInput{
		Email: "rider@legacy.test", Password: "anything",
	}, "1.2.3.4", "UA"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	if failedLoginUser != "u-imp" {
		t.Error("the DB failed-login counter must advance exactly as it does for a wrong password")
	}
	mu.Lock()
	defer mu.Unlock()
	if counters["lockout:u-imp"] != 1 {
		t.Errorf("per-account lockout counter = %d, want 1", counters["lockout:u-imp"])
	}
	if counters["lockout_ip:1.2.3.4"] != 1 {
		t.Errorf("per-IP lockout counter = %d, want 1", counters["lockout_ip:1.2.3.4"])
	}
}

// The claim link is the only way an imported user reaches their account, so it
// must still be sent; it just travels out of band instead of being announced in
// the response.
func TestLogin_ImportPendingStillMailsTheClaimLink(t *testing.T) {
	svc, o := importPendingService(t)

	sent := make(chan string, 4)
	o.emailSender.SendFn = func(_ context.Context, to, _, _, text string) error {
		sent <- to + "|" + text
		return nil
	}

	if _, err := svc.Login(context.Background(), LoginInput{
		Email: "rider@legacy.test", Password: "anything",
	}, "1.2.3.4", "UA"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	select {
	case got := <-sent:
		if !strings.Contains(got, "rider@legacy.test") || !strings.Contains(got, "import=1") {
			t.Errorf("claim mail did not carry the import claim link: %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no claim link was mailed; an imported user could never claim the account")
	}
}

// Unauthenticated mail-trigger and claim-link denial: without the reservation,
// every login attempt mints a token, deletes the previous one and sends a mail.
func TestSendImportClaimLink_ThrottledPerAccount(t *testing.T) {
	svc, o := importPendingService(t)

	var mu sync.Mutex
	reserved := map[string]bool{}
	o.cache.SetIfNotExistsFn = func(_ context.Context, key, _ string, _ time.Duration) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		if reserved[key] {
			return false, nil
		}
		reserved[key] = true
		return true, nil
	}

	var invalidations int
	o.cache.GetAndDeleteFn = func(_ context.Context, _ string) (string, error) {
		mu.Lock()
		invalidations++
		mu.Unlock()
		return "old-hash", nil
	}

	sends := make(chan struct{}, 8)
	o.emailSender.SendFn = func(_ context.Context, _, _, _, _ string) error {
		sends <- struct{}{}
		return nil
	}

	for i := 0; i < 5; i++ {
		svc.sendImportClaimLink("u-imp", "rider@legacy.test", "")
	}
	// One send is expected; wait for it, then give the losers time to be wrong.
	select {
	case <-sends:
	case <-time.After(2 * time.Second):
		t.Fatal("the first claim link was never sent")
	}
	time.Sleep(200 * time.Millisecond)

	if extra := len(sends); extra != 0 {
		t.Errorf("%d extra claim mails sent; the endpoint is an unauthenticated mail trigger", extra)
	}
	mu.Lock()
	defer mu.Unlock()
	if invalidations != 1 {
		t.Errorf("outstanding claim link invalidated %d times, want 1: repeated logins must not revoke a link the user is using", invalidations)
	}
}

// A cache that cannot hold the reservation cannot hold the claim token either,
// so failing closed costs nothing and closes the unthrottled path.
func TestSendImportClaimLink_FailsClosedWhenReservationErrors(t *testing.T) {
	svc, o := importPendingService(t)

	o.cache.SetIfNotExistsFn = func(_ context.Context, _, _ string, _ time.Duration) (bool, error) {
		return false, errors.New("cache down")
	}
	sends := make(chan struct{}, 4)
	o.emailSender.SendFn = func(_ context.Context, _, _, _, _ string) error {
		sends <- struct{}{}
		return nil
	}

	svc.sendImportClaimLink("u-imp", "rider@legacy.test", "")
	time.Sleep(200 * time.Millisecond)

	if len(sends) != 0 {
		t.Error("a cache failure must not open an unthrottled mail path")
	}
}
