package service

import (
	"context"
	"crypto/sha1" // #nosec G505 -- mirrors the HIBP k-anonymity protocol under test
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/audit"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/model"
	"github.com/42-v/vault42/tests/mocks"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// hibpReturning builds an HIBP client whose upstream is stubbed, and records the URL
// that was actually requested so a test can check what left the process.
func hibpReturning(status int, body string, gotURL *string) *HIBPClient {
	return &HIBPClient{client: &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if gotURL != nil {
				*gotURL = r.URL.String()
			}
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}),
	}}
}

// authServiceWith builds an AuthService over the given user repo and HIBP client.
func authServiceWith(t *testing.T, users *mocks.MockUserRepo, hibp *HIBPClient, hibpEnabled bool) *AuthService {
	t.Helper()
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	tokenSvc := NewTokenService(key, kid, "https://vault.test", "https://vault.test",
		15*time.Minute, 24*time.Hour, 30*24*time.Hour)

	return NewAuthService(
		users, &mocks.MockRefreshTokenRepo{},
		&mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, audit.NewLogger(&mocks.MockAuditRepo{}, 0), hibp,
		&mocks.MockCache{}, &mocks.MockEmailSender{}, "https://vault.test", "TestVault",
		"", 12, hibpEnabled, nil,
	)
}

// hibpRangeFor returns the (prefix, canned-response) pair that makes HIBP report the
// given password as breached, in the wire format the real API uses.
func hibpRangeFor(password string) (prefix, body string) {
	sum := fmt.Sprintf("%X", sha1.Sum([]byte(password))) // #nosec G401 -- protocol-mandated
	// The API answers with the *suffixes* of every hash sharing the 5-char prefix,
	// each with a breach count. Include an unrelated one so the match has to be found
	// rather than assumed.
	return sum[:5], "00000000000000000000000000000000000:3\r\n" + sum[5:] + ":42"
}

// Email OTP is stored in the cache and consumed atomically with GetAndDelete — the
// cache IS the single-use guarantee. With no cache wired there is nothing to verify a
// code against, and the only safe answer is to refuse.
//
// This must fail closed. A fall-through here would mean an OTP check with no store
// behind it, and the branch is invisible in a deployment that has Redis configured —
// it only opens up when the cache is absent, which is exactly when nobody is looking.
func TestVerifyEmailOTP_WithoutCacheFailsClosed(t *testing.T) {
	key, _ := vaultcrypto.GenerateRSAKeyPair()
	kid, _ := vaultcrypto.RandomUUID()
	tokenSvc := NewTokenService(key, kid, "https://vault.test", "https://vault.test",
		15*time.Minute, 24*time.Hour, 30*24*time.Hour)

	svc := NewAuthService(
		&mocks.MockUserRepo{}, &mocks.MockRefreshTokenRepo{},
		&mocks.MockDeviceRepo{}, &mocks.MockPasswordHistoryRepo{},
		tokenSvc, nil, audit.NewLogger(&mocks.MockAuditRepo{}, 0), NewHIBPClient(),
		nil, &mocks.MockEmailSender{}, "https://vault.test", "TestVault",
		"", 12, false, nil,
	)

	if err := svc.VerifyEmailOTP(context.Background(), "user-1", "123456"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("err = %v, want ErrInvalidCredentials — an OTP was checked with no store behind it", err)
	}
}

// A password known to be breached must be refused at registration. This is the one
// check that stops a user re-using a credential that is already in an attacker's
// wordlist, and it is off by default — so if the flag is honored incorrectly, the
// failure is silent.
func TestRegister_BreachedPasswordIsRejected(t *testing.T) {
	const breached = "correct horse battery staple"
	prefix, body := hibpRangeFor(breached)

	var requested string
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(context.Context, string) (*model.User, error) { return nil, nil },
	}
	svc := authServiceWith(t, users, hibpReturning(http.StatusOK, body, &requested), true)

	_, err := svc.Register(context.Background(), RegisterInput{
		Email:    "new@example.com",
		Password: breached,
	}, "203.0.113.10")

	if !errors.Is(err, ErrPasswordBreached) {
		t.Fatalf("err = %v, want ErrPasswordBreached — a known-breached password was accepted", err)
	}

	// k-anonymity is the whole reason this check is safe to run against a third party:
	// only the first five characters of the SHA-1 may leave the process. If the full
	// hash (or the password) were ever sent, every registration would be handing a
	// crackable credential to an outside service.
	sum := fmt.Sprintf("%X", sha1.Sum([]byte(breached))) // #nosec G401 -- protocol-mandated
	if !strings.HasSuffix(requested, "/range/"+prefix) {
		t.Errorf("requested %q, want the k-anonymity range endpoint for prefix %s", requested, prefix)
	}
	if strings.Contains(requested, sum[5:]) {
		t.Error("the hash suffix was sent upstream — k-anonymity is broken and the full hash left the process")
	}
	if strings.Contains(requested, breached) {
		t.Error("the plaintext password was sent to the HIBP API")
	}
}

// HIBP being down must not block registration. This is a deliberate trade (documented
// on IsBreached): an outage at a third party is not a reason to refuse every new user.
// It is only defensible if it is actually what happens, rather than an unhandled error.
func TestRegister_HIBPOutageFailsOpen(t *testing.T) {
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(context.Context, string) (*model.User, error) { return nil, nil },
		CreateFn:     func(context.Context, *model.User) error { return nil },
	}
	svc := authServiceWith(t, users, hibpReturning(http.StatusServiceUnavailable, "", nil), true)

	_, err := svc.Register(context.Background(), RegisterInput{
		Email:    "new@example.com",
		Password: "a-perfectly-fine-password",
	}, "203.0.113.10")

	if errors.Is(err, ErrPasswordBreached) {
		t.Fatal("an HIBP outage was reported as a breached password — registration would be blocked whenever HIBP is down")
	}
}

// When the check is disabled, HIBP must not be consulted at all: an operator who
// turned it off should not still be leaking password prefixes to a third party.
func TestRegister_HIBPDisabledDoesNotCallUpstream(t *testing.T) {
	_, body := hibpRangeFor("correct horse battery staple")

	var requested string
	users := &mocks.MockUserRepo{
		GetByEmailFn: func(context.Context, string) (*model.User, error) { return nil, nil },
		CreateFn:     func(context.Context, *model.User) error { return nil },
	}
	svc := authServiceWith(t, users, hibpReturning(http.StatusOK, body, &requested), false)

	_, err := svc.Register(context.Background(), RegisterInput{
		Email:    "new@example.com",
		Password: "correct horse battery staple",
	}, "203.0.113.10")

	if errors.Is(err, ErrPasswordBreached) {
		t.Error("the breach check ran while disabled")
	}
	if requested != "" {
		t.Errorf("HIBP was called while disabled — password prefixes are leaving the process: %s", requested)
	}
}
