package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/cache"
	"github.com/42-v/vault42/internal/config"
	vaultcrypto "github.com/42-v/vault42/internal/crypto"
	"github.com/42-v/vault42/internal/handler"
	"github.com/42-v/vault42/internal/httputil"
	vjwt "github.com/42-v/vault42/internal/jwt"
	"github.com/42-v/vault42/internal/kms"
	"github.com/42-v/vault42/internal/middleware"
	"github.com/42-v/vault42/tests/mocks"
)

// The behavioral half of the deployment-chain gate.
//
// Every control in this repository is a middleware, and a middleware is a
// control only on the routes it is mounted on. Nothing drove the mounting: three
// files in the tree import this package, one of them added the day the finding
// was written and one container-gated, so 986 tests in tests/attack,
// tests/compliance and internal/middleware construct middleware in isolation and
// certify it there. A deployment-level mutation sweep neutered eight of the ten
// layers Chain installs and three of the four guard closures setupRoutes builds,
// with every suite green.
//
// So these tests do the one thing none of those could: they send a request that
// must be refused through the handler the deployment actually serves —
// Chain(setupRoutes()) — and assert the refusal, by status and by reason.
//
// The reason matters as much as the status. Every authenticated handler
// independently answers 401 to a request with no claims, which is real defense
// in depth and also the thing that makes a bare status assertion useless: with
// the authentication middleware removed the routes still answer 401, from a
// handler rather than from the chain. The two are told apart by which refusal
// was written — the chain says missing_authorization, the handler says
// unauthorized — so every assertion below names the code it expects.
//
// Completeness is the structural gate's job, not this file's:
// tests/spec/chain_wiring_test.go names every route and the exact guard set it
// is entitled to, so a route added without a probe here still cannot be added
// without a guard. What this file adds is that the guards enforce, which no
// amount of parsing can show.
//
// These tests do not run in parallel. Three of them touch process-wide
// middleware state (the IP access lists) or the standard logger, and both are
// restored on cleanup.

const chainProbeKID = "beefcafe-0000-0001"

// chainProbeDeps builds the dependency set the probes run against: a real
// in-memory cache, a real signing key, the KMS and mint services so the two
// credential-release oracles are mounted, and a recovery escrow so self-service
// erasure is. Every repository stays nil, which is deliberate — a request that
// reaches a handler dereferences one and panics, and that panic, surfaced by the
// deployed Recovery layer as a 500, is the signal that the request got past
// every gate in front of it. A refused request never reaches a handler at all.
func chainProbeDeps(t *testing.T) (*Deps, *rsa.PrivateKey, cache.Cache) {
	t.Helper()
	memCache := cache.NewMemoryCache()
	t.Cleanup(func() { _ = memCache.Close() })

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	kmsSvc, err := kms.New(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatalf("kms.New: %v", err)
	}

	return &Deps{
		Config: &config.Config{
			Origin:            "https://vault.localhost",
			AppName:           "Vault Test",
			PasswordMinLength: 15,
			Profile:           config.ProfileDev,
			RateLimitEnabled:  true,
		},
		Cache:     memCache,
		Keys:      map[string]*rsa.PublicKey{chainProbeKID: &key.PublicKey},
		ReadyDeps: &handler.ReadyzDeps{},
		KMS:       kmsSvc,
		Mint:      testMintService(t),
		Recovery:  &mocks.MockAccountRecoveryRepo{},
	}, key, memCache
}

// chainProbeHandler returns the handler the deployment serves: the wired mux
// inside the assembled chain. Nothing here reconstructs either.
func chainProbeHandler(t *testing.T) (http.Handler, *rsa.PrivateKey, cache.Cache) {
	t.Helper()
	deps, key, memCache := chainProbeDeps(t)
	s := New(deps)
	return s.Chain(s.setupRoutes()), key, memCache
}

// chainProbeClaims is a valid access token for user-1 on the probe server.
func chainProbeClaims() vaultcrypto.VaultClaims {
	now := time.Now()
	return vaultcrypto.VaultClaims{
		RegisteredClaims: vjwt.RegisteredClaims{
			Issuer:    "https://vault.localhost",
			Audience:  vjwt.ClaimStrings{"https://vault.localhost"},
			Subject:   "user-1",
			ExpiresAt: vjwt.NewNumericDate(now.Add(15 * time.Minute)),
			NotBefore: vjwt.NewNumericDate(now),
			IssuedAt:  vjwt.NewNumericDate(now),
			ID:        "jti-chain-probe",
		},
		TokenType: "Bearer",
	}
}

// chainProbeSign signs a claim set with the probe server's key.
func chainProbeSign(t *testing.T, key *rsa.PrivateKey, claims vaultcrypto.VaultClaims) string {
	t.Helper()
	token, err := vaultcrypto.SignToken(claims, key, chainProbeKID)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}

// chainProbeSend drives one request through the deployed handler.
func chainProbeSend(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// chainProbeRequest builds a request with the probe's device identity: the
// User-Agent and Accept-Language the fingerprint is computed over, and a JSON
// body so the confirm-gated POSTs are well formed.
func chainProbeRequest(method, target, token string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "chain-probe/1.0")
	req.Header.Set("Accept-Language", "en-GB")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// chainProbeAccessRoutes are routes that take an access token and nothing else.
// The set spans the three things a challenge token must not reach: the profile,
// the session and device roster, and the GDPR export.
var chainProbeAccessRoutes = []struct{ method, target string }{
	{http.MethodGet, "/user/profile"},
	{http.MethodGet, "/user/sessions"},
	{http.MethodGet, "/user/devices"},
	{http.MethodGet, "/user/social"},
	{http.MethodGet, "/user/data-export"},
	{http.MethodGet, "/auth/2fa/status"},
	{http.MethodPost, "/auth/logout"},
}

// chainProbeConfirmRoutes are the second-factor management routes. All six take
// an access token plus a password re-entry inside the confirmation window.
var chainProbeConfirmRoutes = []struct{ method, target string }{
	{http.MethodPost, "/auth/2fa/totp/setup"},
	{http.MethodDelete, "/auth/2fa/totp"},
	{http.MethodPost, "/auth/2fa/webauthn/register/begin"},
	{http.MethodPost, "/auth/2fa/webauthn/register/finish"},
	{http.MethodDelete, "/auth/2fa/webauthn/credentials/cred-1"},
	{http.MethodPost, "/auth/2fa/backup-codes"},
}

// A 2fa_challenge token is minted by TokenService.IssueChallengeToken after the
// password succeeds and before the second factor, with the user's id as its
// subject and a five-minute lifetime. Its whole purpose is to be worth nothing
// on its own.
//
// Repointing the authed closure from authMw to challengeMw is one identifier,
// and it hands every route below to a caller holding the victim's password
// alone — decrypted identity, the session and device roster, and the full GDPR
// export. No handler reads TokenType, so the defense in depth that makes plain
// authentication removal survivable does not apply here. Both source-reading
// gates accepted the two middleware as interchangeable.
func TestAChallengeTokenIsRefusedOnEveryRouteThatRequiresAFullSession(t *testing.T) {
	h, key, _ := chainProbeHandler(t)
	claims := chainProbeClaims()
	claims.TokenType = "2fa_challenge"
	token := chainProbeSign(t, key, claims)

	for _, rt := range chainProbeAccessRoutes {
		t.Run(rt.method+" "+rt.target, func(t *testing.T) {
			rec := chainProbeSend(h, chainProbeRequest(rt.method, rt.target, token))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s with a 2fa_challenge token = %d, want 401. This route accepts the "+
					"token minted between the first and second factor, so the victim's password "+
					"alone reaches it: body=%s", rt.method, rt.target, rec.Code, rec.Body.String())
			}
			if body := rec.Body.String(); !strings.Contains(body, "invalid_token_type") {
				t.Errorf("%s %s refused with %s, want invalid_token_type. A refusal from the "+
					"handler rather than from the chain means the token type is not being checked "+
					"where it has to be.", rt.method, rt.target, strings.TrimSpace(body))
			}
		})
	}
}

// The converse, so the test above cannot be satisfied by a chain that refuses
// everything. The four verify routes exist to be reachable with exactly this
// token, and swapping their middleware the other way would make the second
// factor uncompletable.
func TestAChallengeTokenIsAcceptedOnTheSecondFactorVerifyRoutes(t *testing.T) {
	h, key, _ := chainProbeHandler(t)
	claims := chainProbeClaims()
	claims.TokenType = "2fa_challenge"
	token := chainProbeSign(t, key, claims)

	for _, target := range []string{
		"/auth/2fa/totp/verify",
		"/auth/2fa/webauthn/verify/begin",
		"/auth/2fa/backup-code/verify",
		"/auth/2fa/email-otp/verify",
	} {
		t.Run(target, func(t *testing.T) {
			rec := chainProbeSend(h, chainProbeRequest(http.MethodPost, target, token))
			if rec.Code == http.StatusUnauthorized {
				t.Fatalf("POST %s refused the challenge token (%s); the second factor cannot be "+
					"completed and the login is a dead end", target, strings.TrimSpace(rec.Body.String()))
			}
		})
	}
}

// The vault twin of TestAdminAuth_EveryGuardedRouteRefusesAnAnonymousCaller.
//
// It asserts the refusal reason rather than the status, because the status alone
// proves nothing: every authenticated handler independently refuses nil claims
// with unauthorized, so removing the authentication middleware entirely leaves
// all of these answering 401 from one layer further in. missing_authorization is
// written only by middleware.Auth, so it is the observable that separates a
// chain that authenticates from a chain that has stopped.
func TestEveryGuardedRouteRefusesAnAnonymousCallerAtTheChain(t *testing.T) {
	deps, _, _ := chainProbeDeps(t)
	s := New(deps)
	mux := s.setupRoutes()
	h := s.Chain(mux)

	routes := append([]struct{ method, target string }{}, chainProbeAccessRoutes...)
	routes = append(routes, chainProbeConfirmRoutes...)
	routes = append(routes,
		struct{ method, target string }{http.MethodPost, "/auth/confirm"},
		struct{ method, target string }{http.MethodPost, "/user/password"},
		struct{ method, target string }{http.MethodDelete, "/user/account"},
		struct{ method, target string }{http.MethodPost, "/kms/unwrap"},
		struct{ method, target string }{http.MethodPost, "/mint"},
	)

	for _, rt := range routes {
		t.Run(rt.method+" "+rt.target, func(t *testing.T) {
			req := chainProbeRequest(rt.method, rt.target, "")

			// A typo in the table above would 404 and pass every assertion
			// below, so the pattern the mux matched is checked first.
			if _, pattern := mux.Handler(req); pattern == "" {
				t.Fatalf("%s %s matches no registered pattern; the probe is aimed at a route that "+
					"does not exist", rt.method, rt.target)
			}

			rec := chainProbeSend(h, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s with no Authorization header = %d, want 401: body=%s",
					rt.method, rt.target, rec.Code, rec.Body.String())
			}
			if body := rec.Body.String(); !strings.Contains(body, "missing_authorization") {
				t.Errorf("%s %s refused with %s, want missing_authorization. That code is written "+
					"only by the authentication middleware; anything else means the refusal came "+
					"from the handler and the chain no longer authenticates.",
					rt.method, rt.target, strings.TrimSpace(body))
			}
		})
	}
}

// middleware.Confirmed is the only password re-entry gate on the six routes that
// enroll, remove or regenerate a second factor. Dropping it from the confirmed
// closure leaves the whole suite green: the gate that counts confirmMw call
// sites has a floor of three and the clean tree has four, so deleting the one
// that guards all six routes lands exactly on the floor.
//
// In the mutated state a stolen access token disables TOTP and enrolls the
// attacker's own authenticator. Nothing else stops it — TOTPHandler.Disable,
// BackupCodeHandler.Generate and WebAuthnHandler.RegisterBegin perform no
// password check of their own — and the post-change revocation retires refresh
// families only, so the attacker's stateless access token outlives the owner
// being signed out.
func TestSecondFactorManagementRefusesATokenThatHasNotConfirmedItsPassword(t *testing.T) {
	h, key, _ := chainProbeHandler(t)
	token := chainProbeSign(t, key, chainProbeClaims())

	for _, rt := range chainProbeConfirmRoutes {
		t.Run(rt.method+" "+rt.target, func(t *testing.T) {
			rec := chainProbeSend(h, chainProbeRequest(rt.method, rt.target, token))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s %s with a valid but unconfirmed access token = %d, want 403. A stolen "+
					"access token now reaches second-factor management: body=%s",
					rt.method, rt.target, rec.Code, rec.Body.String())
			}
			if body := rec.Body.String(); !strings.Contains(body, "requires_confirmation") {
				t.Errorf("%s %s refused with %s, want requires_confirmation",
					rt.method, rt.target, strings.TrimSpace(body))
			}
		})
	}
}

// The confirmation gate has to be a gate rather than a wall: a token that did
// confirm, inside the window, must get through. Without this the test above
// would be satisfied by a route that refuses everyone.
func TestSecondFactorManagementAdmitsATokenThatDidConfirmItsPassword(t *testing.T) {
	h, key, memCache := chainProbeHandler(t)
	claims := chainProbeClaims()
	token := chainProbeSign(t, key, claims)

	// The confirmation is bound to the presented token's jti, not merely to the
	// user, so the cache entry carries the id of the token that confirmed.
	if err := memCache.Set(context.Background(), "confirm:"+claims.Subject, claims.ID, 5*time.Minute); err != nil {
		t.Fatalf("seed confirmation: %v", err)
	}

	rec := chainProbeSend(h, chainProbeRequest(http.MethodPost, "/auth/2fa/totp/setup", token))
	if rec.Code == http.StatusForbidden {
		t.Fatalf("a confirmed token was still refused with %s; the confirmation window cannot be "+
			"entered and second-factor enrollment is unreachable", strings.TrimSpace(rec.Body.String()))
	}
}

// middleware.Fingerprint is the only thing on an authenticated route that
// compares the access token's device claim against the request. It is deployed
// as Fingerprint(false) — enforcing — and Fingerprint(true) is soft mode, where
// a mismatch is logged and the request proceeds. Both the flip and the outright
// removal leave the text fingerprintMw( at every call site, which is all the
// source-reading gates ever checked.
func TestAStolenTokenIsRefusedWhenReplayedFromAnotherDevice(t *testing.T) {
	h, key, _ := chainProbeHandler(t)

	claims := chainProbeClaims()
	claims.Fingerprint = vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
		IP:             "192.0.2.1",
		UserAgent:      "chain-probe/1.0",
		AcceptLanguage: "en-GB",
	})
	token := chainProbeSign(t, key, claims)

	t.Run("the device the token was issued to", func(t *testing.T) {
		rec := chainProbeSend(h, chainProbeRequest(http.MethodGet, "/user/profile", token))
		if rec.Code == http.StatusUnauthorized {
			t.Fatalf("the binding refused the device the token was issued to (%s); every "+
				"legitimate session would be broken", strings.TrimSpace(rec.Body.String()))
		}
	})

	t.Run("another device", func(t *testing.T) {
		req := chainProbeRequest(http.MethodGet, "/user/profile", token)
		req.Header.Set("User-Agent", "attacker/9.9")
		req.Header.Set("Accept-Language", "ru-RU")
		req.RemoteAddr = "203.0.113.9:44444"

		rec := chainProbeSend(h, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("a token carrying another device's fingerprint = %d, want 401. The binding is "+
				"either removed or in soft mode, and a stolen token replays from anywhere: body=%s",
				rec.Code, rec.Body.String())
		}
		if body := rec.Body.String(); !strings.Contains(body, "invalid_token") {
			t.Errorf("refused with %s, want invalid_token", strings.TrimSpace(body))
		}
	})
}

// The two credential-release oracles are authorized by a scope literal in the
// route and nothing else. Every user-token issuance site in the tree hardcodes
// read and write, so widening either literal to one of those hands the oracle to
// every logged-in user — and KMSHandler.Unwrap, unlike MintHandler.Mint, has no
// check of its own to fall back on.
func TestTheCredentialReleaseOraclesRefuseATokenWithoutTheirOwnScope(t *testing.T) {
	h, key, _ := chainProbeHandler(t)

	claims := chainProbeClaims()
	claims.ClientID = "svc-probe" // a real service client, so only the scope is missing
	claims.Scopes = []string{"read", "write"}
	token := chainProbeSign(t, key, claims)

	for _, target := range []string{"/kms/unwrap", "/mint"} {
		t.Run(target, func(t *testing.T) {
			rec := chainProbeSend(h, chainProbeRequest(http.MethodPost, target, token))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("POST %s with the scopes every user token carries = %d, want 403: body=%s",
					target, rec.Code, rec.Body.String())
			}
			if body := rec.Body.String(); !strings.Contains(body, "insufficient_scope") {
				t.Errorf("POST %s refused with %s, want insufficient_scope. Any other refusal means "+
					"the scope gate let the request through and something further in stopped it, "+
					"which is not the same control and does not hold for both oracles.",
					target, strings.TrimSpace(body))
			}
		})
	}
}

// The converse: a token holding the right scope must get past the gate. A route
// that refuses every scope would satisfy the test above and release nothing.
func TestTheCredentialReleaseOraclesAdmitTheirOwnScope(t *testing.T) {
	h, key, _ := chainProbeHandler(t)

	for _, tc := range []struct{ target, scope string }{
		{"/kms/unwrap", "kms:unwrap"},
		{"/mint", handler.MintScope},
	} {
		t.Run(tc.target, func(t *testing.T) {
			claims := chainProbeClaims()
			claims.ClientID = "svc-probe"
			claims.Scopes = []string{tc.scope}
			token := chainProbeSign(t, key, claims)

			rec := chainProbeSend(h, chainProbeRequest(http.MethodPost, tc.target, token))
			if body := rec.Body.String(); strings.Contains(body, "insufficient_scope") {
				t.Fatalf("POST %s refused a token carrying %q as insufficient; the oracle is "+
					"unreachable by the credential it is meant to serve", tc.target, tc.scope)
			}
		})
	}
}

// The audience and issuer arguments to the authentication middleware are the
// whole of RFC 8725 §3.9 here. internal/jwt gates the audience comparison on the
// expected value being non-empty, so emptying the argument does not fail — it
// silently means "do not check", and the deployed argument is read by nothing
// else in the tree.
func TestATokenMintedForAnotherAudienceOrIssuerIsRefused(t *testing.T) {
	h, key, _ := chainProbeHandler(t)

	for _, tc := range []struct {
		name  string
		claim func(*vaultcrypto.VaultClaims)
	}{
		{"another audience", func(c *vaultcrypto.VaultClaims) {
			c.Audience = vjwt.ClaimStrings{"https://evil.example"}
		}},
		{"another issuer", func(c *vaultcrypto.VaultClaims) {
			c.Issuer = "https://evil.example"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := chainProbeClaims()
			tc.claim(&claims)
			token := chainProbeSign(t, key, claims)

			rec := chainProbeSend(h, chainProbeRequest(http.MethodGet, "/user/profile", token))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("a token minted for %s = %d, want 401. The check is gated on the expected "+
					"value being non-empty, so an emptied argument disables it silently: body=%s",
					tc.name, rec.Code, rec.Body.String())
			}
			if body := rec.Body.String(); !strings.Contains(body, "invalid_token") {
				t.Errorf("refused with %s, want invalid_token", strings.TrimSpace(body))
			}
		})
	}
}

// totpRL caps TOTP verify, backup-code verify and both email-OTP routes, which
// together are the entire guessing surface of a six-digit second factor inside
// its five-minute window. Only two of the eleven limiters the vault deploys had
// any behavioral cover, and this was not one of them: raising its limit to a
// billion left every suite green.
func TestTheSecondFactorGuessingBudgetIsEnforcedOnTheDeployedRoute(t *testing.T) {
	h, _, _ := chainProbeHandler(t)

	const budget = 5
	for i := 1; i <= budget; i++ {
		rec := chainProbeSend(h, chainProbeRequest(http.MethodPost, "/auth/2fa/totp/verify", ""))
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d of %d was rate limited; the deployed budget is smaller than the "+
				"one the register pins, and a legitimate user gets fewer tries than intended", i, budget)
		}
	}

	rec := chainProbeSend(h, chainProbeRequest(http.MethodPost, "/auth/2fa/totp/verify", ""))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d = %d, want 429. The budget on the second-factor verify routes is not "+
			"enforced on the deployed route, so a six-digit code is guessable inside the challenge "+
			"window: body=%s", budget+1, rec.Code, rec.Body.String())
	}
}

// middleware.IPAccess is the sole enforcement point for all four operator IP and
// geo lists, and before this test no test anywhere under tests/ referenced it at
// all. Removing it from Chain — by deletion or by leaving the call unassigned —
// left every suite green with all four lists inert.
func TestTheOperatorIPBlocklistIsEnforcedByTheDeployedChain(t *testing.T) {
	chainProbeWithIPLists(t, nil, []string{"192.0.2.0/24"})
	h, _, _ := chainProbeHandler(t)

	t.Run("a blocked address is refused before authentication", func(t *testing.T) {
		rec := chainProbeSend(h, chainProbeRequest(http.MethodGet, "/user/profile", ""))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("a request from a blocklisted address = %d, want 403. The operator's IP "+
				"blocklist is not installed on the deployed chain, so all four IP and geo lists "+
				"are inert: body=%s", rec.Code, rec.Body.String())
		}
		if body := rec.Body.String(); !strings.Contains(body, "access_denied") {
			t.Errorf("refused with %s, want access_denied", strings.TrimSpace(body))
		}
	})

	// The documented exception. Blocking the liveness probe would make a
	// deployment that sets a blocklist fail its own health checks and roll back.
	t.Run("the health probes are exempt", func(t *testing.T) {
		rec := chainProbeSend(h, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if rec.Code != http.StatusOK {
			t.Errorf("/healthz from a blocklisted address = %d, want 200; the liveness probe is "+
				"deliberately exempt and a deployment that sets a blocklist would roll itself back",
				rec.Code)
		}
	})
}

// chainProbeWithIPLists installs process-wide IP access lists for one test and
// clears them afterwards. The lists are package-level state in
// internal/middleware, so leaving them set would silently 403 every later test
// in this package.
func chainProbeWithIPLists(t *testing.T, allow, block []string) {
	t.Helper()
	middleware.SetIPAccessLists(allow, block, nil, nil, "")
	t.Cleanup(func() { middleware.SetIPAccessLists(nil, nil, nil, nil, "") })
}

// ClientIPContext resolves the caller's address once and puts it on the context,
// which is where the account lockout reads it. Without it the lockout key
// collapses to one bucket per user across every source, and five failed logins
// from anywhere lock any account whose email the caller knows — the exact
// regression the per-source key was introduced to end.
//
// Chain takes any handler, so the observable is read directly out of the context
// the chain built rather than inferred from a lockout that needs a database.
func TestTheChainResolvesTheClientAddressOntoTheRequestContext(t *testing.T) {
	deps, _, _ := chainProbeDeps(t)
	s := New(deps)

	var got string
	h := s.Chain(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = httputil.ClientIPFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/user/profile", nil)
	req.RemoteAddr = "198.51.100.7:33333"
	chainProbeSend(h, req)

	if got != "198.51.100.7" {
		t.Fatalf("the chain put %q on the context, want 198.51.100.7. The account lockout keys on "+
			"this value, so an empty one collapses every source into a single per-user bucket and "+
			"five failures from anywhere lock any known account.", got)
	}
}

// An untrusted caller's X-Forwarded-For must not be believed. Start configures
// the trusted-proxy set from cfg.TrustedProxies, and widening it to 0.0.0.0/0
// makes every client's header authoritative at once — defeating every per-IP
// limiter, the per-source lockout, both IP access lists, the tenant gate and the
// address on every audit row.
//
// The observable is the IP access list, which is the one control that answers
// visibly on the resolved address.
func TestAnUntrustedCallersForwardedForIsNotBelieved(t *testing.T) {
	chainProbeWithIPLists(t, nil, []string{"203.0.113.9/32"})
	h, _, _ := chainProbeHandler(t)

	req := chainProbeRequest(http.MethodGet, "/user/profile", "")
	req.RemoteAddr = "198.51.100.7:33333"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")

	rec := chainProbeSend(h, req)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("a client-supplied X-Forwarded-For decided the address the access lists were "+
			"applied to. Every caller can now choose their own source address, which defeats the "+
			"per-IP limiters, the per-source lockout and the audit attribution at the same time: "+
			"body=%s", rec.Body.String())
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: the request should reach authentication and be refused "+
			"there, not anywhere earlier", rec.Code)
	}
}

// Recovery is the outermost layer, and it is the only thing between a handler
// panic and a dropped connection. Removing it left every suite green because
// nothing drove a panicking handler through the assembled chain.
func TestAPanickingHandlerBecomesAJSONErrorRatherThanADroppedConnection(t *testing.T) {
	deps, _, _ := chainProbeDeps(t)
	s := New(deps)
	h := s.Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("chain probe: a handler panicked")
	}))

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the panic escaped the chain (%v). Without the recovery layer the connection "+
				"is dropped mid-response, and on a real listener that is one killed request per "+
				"panic with nothing written to the client.", r)
		}
	}()

	rec := chainProbeSend(h, httptest.NewRequest(http.MethodGet, "/user/profile", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("a panicking handler = %d, want 500", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "error") {
		t.Errorf("body = %q, want the standard JSON error envelope", body)
	}
}

// RequestID stamps the correlation id that the IP-access deny logging and every
// access-log line carry, and it answers with it. Losing it empties
// GetRequestID everywhere, which makes a refusal untraceable to the request that
// caused it.
func TestTheChainStampsACorrelationIDOnEveryResponse(t *testing.T) {
	h, _, _ := chainProbeHandler(t)
	rec := chainProbeSend(h, chainProbeRequest(http.MethodGet, "/user/profile", ""))

	id := rec.Header().Get("X-Request-ID")
	if id == "" {
		t.Fatal("the response carries no X-Request-ID; the correlation id every log line and every " +
			"IP-access denial quotes is empty, so a refusal cannot be traced to the request that caused it")
	}
	if len(id) < 16 {
		t.Errorf("X-Request-ID = %q, which is shorter than the 32 hex characters the generator "+
			"produces; something other than the request-id layer set it", id)
	}
}

// Logger writes the access line every forensic and audit claim in the register
// reads back. It is the one layer with no response-visible effect, so the
// observable is the standard logger the deployment writes to.
func TestTheChainWritesAnAccessLogLineForEveryRequest(t *testing.T) {
	var buf bytes.Buffer
	out := log.Writer()
	flags := log.Flags()
	log.SetOutput(&buf)
	t.Cleanup(func() {
		log.SetOutput(out)
		log.SetFlags(flags)
	})

	h, _, _ := chainProbeHandler(t)
	chainProbeSend(h, chainProbeRequest(http.MethodGet, "/user/data-export", ""))

	if got := buf.String(); !strings.Contains(got, "/user/data-export") {
		t.Fatalf("the access log records no line for the request. Output was:\n%s\nWithout the "+
			"logging layer there is no access record at all, and every claim in the register that "+
			"reads one back is describing a log nobody writes.", got)
	}
}
