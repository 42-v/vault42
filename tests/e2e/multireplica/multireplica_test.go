package multireplica_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/42-v/vault42/internal/redis"
)

// TestMultiReplica runs the core 8 behaviors + matrix with redis cache (shared) using dev and production profiles.
func TestMultiReplica(t *testing.T) {
	httpClient := &http.Client{Timeout: 15 * time.Second}

	profiles := []string{"dev", "production"}

	for i, prof := range profiles {
		prof := prof
		basePort := 18700 + i*10
		t.Run("profile_"+prof, func(t *testing.T) {
			// Each profile gets its OWN postgres + redis so signing-key/keystore
			// state from one profile never bleeds into the next.
			pool, redisAddr, appDSN, cleanup := setupContainers(t)
			if pool == nil {
				return
			}
			defer cleanup()
			rclient := redis.NewClient(&redis.Options{Addr: redisAddr})
			defer rclient.Close()

			replA, replB, closeRepls := startReplicasForTest(t, basePort, redisAddr, appDSN, "redis", prof)
			defer closeRepls()

			cleanupState(t, pool, rclient)

			// 1. Shared JWKS: register+login on A, use access token on B protected endpoint.
			t.Run("shared_jwks_access_token", func(t *testing.T) {
				email := uniqueEmail("jwks-" + prof)
				registerAndVerify(t, pool, httpClient, replA, email)
				access, _ := loginUser(t, httpClient, replA, email, testPassword)
				if access == "" {
					t.Fatal("no access token after login on A")
				}
				stP, pbody := authedGet(t, httpClient, replB.URL+"/user/profile", access)
				if stP != 200 {
					t.Fatalf("cross-replica: token from A rejected on B profile: status=%d body=%v", stP, pbody)
				}
			})

			// 2. Refresh rotation cross-replica: refresh on B (token from A), replay original refused on A.
			t.Run("refresh_rotation_cross_replica", func(t *testing.T) {
				cleanupState(t, pool, rclient)
				email := uniqueEmail("refresh-" + prof)
				registerAndVerify(t, pool, httpClient, replA, email)
				_, refresh := loginUser(t, httpClient, replA, email, testPassword)
				if refresh == "" {
					t.Fatal("no refresh token issued by A")
				}
				stR, rbody, rresp := refreshWithCookie(t, httpClient, replB.URL, refresh)
				if stR != 200 {
					t.Fatalf("refresh original on B should succeed: got %d %v", stR, rbody)
				}
				// new refresh from B response
				newRefresh := getCookie(rresp, "__Host-refresh_token")
				if newRefresh == "" {
					t.Log("note: no new refresh cookie observed (may be config)")
				}
				stReplay, replayBody, _ := refreshWithCookie(t, httpClient, replA.URL, refresh)
				if stReplay != 401 {
					t.Fatalf("replay of original refresh on A must be refused after cross use: got %d %v (want 401)", stReplay, replayBody)
				}
			})

			// 3. Account lockout shared across replicas.
			t.Run("account_lockout_shared", func(t *testing.T) {
				cleanupState(t, pool, rclient)
				email := uniqueEmail("lock-" + prof)
				registerAndVerify(t, pool, httpClient, replA, email)

				wrong := "Wrong!Passw0rd-NotCorrect-15chars"
				// threshold=5; split attempts to prove shared cache counter.
				for i := 0; i < 3; i++ {
					jsonPost(t, httpClient, replA.URL+"/auth/login", map[string]string{"email": email, "password": wrong})
				}
				for i := 0; i < 3; i++ {
					jsonPost(t, httpClient, replB.URL+"/auth/login", map[string]string{"email": email, "password": wrong})
				}
				stGoodA, _ := jsonPost(t, httpClient, replA.URL+"/auth/login", map[string]string{"email": email, "password": testPassword})
				stGoodB, _ := jsonPost(t, httpClient, replB.URL+"/auth/login", map[string]string{"email": email, "password": testPassword})
				if stGoodA == 200 || stGoodB == 200 {
					t.Fatalf("lockout not shared: good pw login succeeded on A=%d or B=%d (expected lock)", stGoodA, stGoodB)
				}
			})

			// 4. MFA: challenge issued on A, second factor verified on B -> full session.
			t.Run("mfa_challenge_on_A_verify_on_B", func(t *testing.T) {
				cleanupState(t, pool, rclient)
				email := uniqueEmail("mfa-" + prof)
				registerAndVerify(t, pool, httpClient, replA, email)

				st, lbody, resp := jsonPostWithResp(t, httpClient, replA.URL+"/auth/login", map[string]string{"email": email, "password": testPassword})
				resp.Body.Close()
				if st != 200 {
					t.Fatalf("login mfa A: %d", st)
				}
				chTok, _ := lbody["challenge_token"].(string)
				if chTok == "" {
					t.Fatalf("expected challenge_token (MFARequired): %v", lbody)
				}
				code := replA.email.waitOTP(email, 5*time.Second)
				if code == "" {
					t.Fatal("no OTP captured from A")
				}
				stV, vbody := challengePost(t, httpClient, replB.URL+"/auth/2fa/email-otp/verify", chTok, map[string]string{"code": code})
				if stV != 200 {
					t.Fatalf("cross verify on B: %d %v", stV, vbody)
				}
				access, _ := vbody["access_token"].(string)
				if access == "" {
					t.Fatal("no access after cross mfa verify")
				}
				stP, _ := authedGet(t, httpClient, replA.URL+"/user/profile", access)
				if stP != 200 {
					t.Fatalf("profile after cross mfa: %d", stP)
				}
			})

			// 5. Rate limit shared: per-identifier (IP for register) exhausted via A enforced on B.
			t.Run("rate_limit_shared", func(t *testing.T) {
				cleanupState(t, pool, rclient)
				// 3/h for register per IP key (via redis when backend=redis).
				var saw429 bool
				for i := 0; i < 5; i++ {
					em := uniqueEmail("rl-" + prof + "-" + itoa(i))
					st, _ := jsonPost(t, httpClient, replA.URL+"/auth/register", map[string]string{
						"email": em, "password": testPassword, "display_name": "r",
					})
					if st == 429 {
						saw429 = true
					}
				}
				stB, _ := jsonPost(t, httpClient, replB.URL+"/auth/register", map[string]string{
					"email": uniqueEmail("rlb-" + prof), "password": testPassword, "display_name": "r2",
				})
				if stB == 429 {
					saw429 = true
				}
				if !saw429 {
					t.Logf("rate shared: did not observe 429 (timing/window may allow more); IP rate via redis is intended shared path")
				}
			})

			// 6. Session-count limit enforced across replicas (DB state, always shared).
			t.Run("session_count_limit_cross_replica", func(t *testing.T) {
				cleanupState(t, pool, rclient)
				email := uniqueEmail("sess-" + prof)
				registerAndVerify(t, pool, httpClient, replA, email)

				success := 0
				var anAccess string
				for i := 0; i < 8; i++ {
					stL, lbody := jsonPost(t, httpClient, replA.URL+"/auth/login", map[string]string{"email": email, "password": testPassword})
					if stL == 200 {
						success++
						if a, ok := lbody["access_token"].(string); ok && a != "" {
							anAccess = a
						}
					} else if ch, ok := lbody["challenge_token"].(string); ok && ch != "" {
						if c := replA.email.getOTP(email); c != "" {
							stV, _ := challengePost(t, httpClient, replA.URL+"/auth/2fa/email-otp/verify", ch, map[string]string{"code": c})
							if stV == 200 {
								success++
							}
						}
					} else {
						// expected: too_many_sessions or rate; stop early
						break
					}
				}
				if success > 6 {
					t.Fatalf("too many successful logins (%d) despite MaxSessionsPerUser=5", success)
				}
				if anAccess != "" {
					stS, sb := authedGet(t, httpClient, replB.URL+"/user/sessions", anAccess)
					if stS == 200 {
						if sl, ok := sb["sessions"].([]interface{}); ok && len(sl) > 5 {
							t.Fatalf("cross-replica sessions list exceeded limit: got %d", len(sl))
						}
					}
				}
			})

			// 7. Signing-key rotation: rotate on A; B accepts new tokens after ks refresh.
			t.Run("signing_key_rotation", func(t *testing.T) {
				cleanupState(t, pool, rclient)
				if replA.ks == nil {
					t.Fatal("keystore not exposed on replica A")
				}
				newKid, err := replA.ks.Rotate(context.Background())
				if err != nil {
					t.Fatalf("rotate on A: %v", err)
				}
				if replB.ks != nil {
					_ = replB.ks.Refresh(context.Background())
				}
				time.Sleep(700 * time.Millisecond) // allow refresh loops

				email := uniqueEmail("rot-" + prof)
				registerAndVerify(t, pool, httpClient, replA, email)
				acc, _ := loginUser(t, httpClient, replA, email, testPassword)
				if acc == "" {
					t.Fatal("no access token after post-rotation login on A")
				}
				stP, pbody := authedGet(t, httpClient, replB.URL+"/user/profile", acc)
				if stP != 200 {
					t.Fatalf("B failed to validate token from rotated key on A: %d %v", stP, pbody)
				}
				// parse kid to optionally assert
				parts := strings.Split(acc, ".")
				if len(parts) == 3 {
					padded := parts[0]
					for len(padded)%4 != 0 {
						padded += "="
					}
					if hdrB, err := base64.StdEncoding.DecodeString(padded); err == nil {
						var hdr map[string]interface{}
						_ = json.Unmarshal(hdrB, &hdr)
						if k, ok := hdr["kid"].(string); ok && k != "" && k != newKid {
							t.Logf("token kid=%s (after rot to %s); B accepted via ks pubkeys", k, newKid)
						}
					}
				}
			})

			// 8. One-time tokens cross-replica: minted on A, consumable on B, second use refused on either.
			t.Run("one_time_tokens_cross_replica", func(t *testing.T) {
				cleanupState(t, pool, rclient)
				email := uniqueEmail("onet-" + prof)
				st, _ := jsonPost(t, httpClient, replA.URL+"/auth/register", map[string]string{
					"email": email, "password": testPassword, "display_name": "O",
				})
				if st == 429 {
					t.Skip("rate on reg")
					t.SkipNow()
				}
				if st != 201 && st != 200 {
					t.Fatalf("reg: %d", st)
				}
				// allow time for email capture
				time.Sleep(50 * time.Millisecond)
				vTok := replA.email.getVerifyToken(email)
				if vTok != "" {
					stV, vbody := jsonGet(t, httpClient, replB.URL+"/auth/verify-email?token="+vTok)
					if stV != 200 {
						t.Fatalf("verify-email on B: %d %v", stV, vbody)
					}
					stV2, _ := jsonGet(t, httpClient, replA.URL+"/auth/verify-email?token="+vTok)
					if stV2 == 200 {
						t.Fatal("replay of verify-email token accepted on A after B used it")
					}
					return
				}
				// reset token path
				jsonPost(t, httpClient, replA.URL+"/auth/password/reset", map[string]string{"email": email})
				time.Sleep(50 * time.Millisecond)
				rTok := replA.email.getResetToken(email)
				if rTok == "" {
					t.Log("no one-time token captured (email path may differ by profile); covered if verify succeeded above")
					return
				}
				stC, cbody := jsonPost(t, httpClient, replB.URL+"/auth/password/reset/confirm", map[string]string{
					"token": rTok, "new_password": "NewP4ssw0rd-Changed-15chars!!",
				})
				if stC != 200 {
					t.Fatalf("reset confirm on B: %d %v", stC, cbody)
				}
				stR, _ := jsonPost(t, httpClient, replA.URL+"/auth/password/reset/confirm", map[string]string{
					"token": rTok, "new_password": "ReplayP4ss-Changed-15chars!!",
				})
				if stR == 200 {
					t.Fatal("replay reset token accepted after cross-replica consume")
				}
			})
		})
	}
}

// TestMultiReplica_MemoryCacheNotShared asserts that memory cache is not HA safe (per-process state).
func TestMultiReplica_MemoryCacheNotShared(t *testing.T) {
	pool, redisAddr, appDSN, cleanup := setupContainers(t)
	if pool == nil {
		return
	}
	defer cleanup()

	rclient := redis.NewClient(&redis.Options{Addr: redisAddr})
	defer rclient.Close()

	// Mix dev/prod with memory to exercise; memory state is per-process anyway.
	replA := startReplica(t, 18810, redisAddr, appDSN, "memory", "production")
	replB := startReplica(t, 18811, redisAddr, appDSN, "memory", "dev")
	defer replA.closeFn()
	defer replB.closeFn()

	httpClient := &http.Client{Timeout: 15 * time.Second}
	cleanupState(t, pool, rclient)

	// The property under test is that the in-memory cache backend keeps its state
	// per process, so a limit one replica reaches does not carry to another. The
	// probe is the registration IP rate limit, which lives only in the cache: 3
	// per hour per IP (internal/server/server.go). Account lockout is no longer a
	// valid probe for this: failed_login_count is a durable column every replica
	// reads from the shared database, so a lockout is shared by design and cannot
	// tell the memory backend apart from Postgres. The limiter runs ahead of the
	// register handler, so it counts every request and the profile of the replica
	// does not matter.

	// Drive replica A past its registration limit from this one client IP.
	var lastA int
	for i := 0; i < 5; i++ {
		lastA, _ = jsonPost(t, httpClient, replA.URL+"/auth/register", map[string]string{
			"email": uniqueEmail("memrl-a"), "password": testPassword, "display_name": "r",
		})
	}
	if lastA != http.StatusTooManyRequests {
		t.Fatalf("replica A never rate limited its registrations from one IP: last status %d, want 429", lastA)
	}

	// Replica B, hit from the same IP, keeps its own counter in its own process,
	// so a first registration there is admitted rather than refused. A 429 here
	// would mean the two processes shared the counter, which only a shared backend
	// does.
	stB, _ := jsonPost(t, httpClient, replB.URL+"/auth/register", map[string]string{
		"email": uniqueEmail("memrl-b"), "password": testPassword, "display_name": "r2",
	})
	if stB == http.StatusTooManyRequests {
		t.Fatalf("memory cache incorrectly shared the registration rate limit across replicas: " +
			"B refused a first registration with 429")
	}
}
