# vault42 0.8.9 — audit MED/LOW fix plan (2026-06-19)

All paths relative to `/mnt/projects/vault42`. Every finding below was re-verified against current source; line numbers in the original audit drifted as the tree advanced, so patches are anchored on content, not line numbers.

---

## M1 — 2FA challenge token's device fingerprint claim is never validated on MFA completion

- **id:** M1
- **severity:** MEDIUM
- **stillReal:** true

`IssueChallengeToken` embeds the device fingerprint into the challenge JWT (`internal/service/token.go` `Fingerprint: fingerprint`) and `VaultClaims` exposes it (`internal/crypto/jwt.go`), but `CompleteMFALogin` (`internal/service/auth.go`) recomputes a fingerprint from the redeeming request and never compares it against `claims.Fingerprint`. The refresh path enforces this binding via `CompareFingerprints` + `FingerprintAnomaly`; the challenge path is the inconsistent weaker one.

Constraint: did **not** add a `challengeFP` parameter to `CompleteMFALogin` because 4 existing test call sites (`internal/service/auth_v076_test.go:20,36,49,62`) use the old 5-arg signature and tests must not be modified. Instead, added an exported `AuthService.ChallengeFingerprintMatches` helper (fails closed, emits `audit.FingerprintAnomaly` via `CompareFingerprints` like the refresh path) and call it from `completeMFAIfChallenge` in `mfa_helper.go` **before** any tokens are issued. Empty `challengeFP` (legacy tokens) is treated as a match so in-flight challenges aren't bricked.

Verified: `go build ./internal/...` and `go vet ./internal/handler/... ./internal/service/...` pass (exit 0).

**Files:** `internal/service/auth.go`, `internal/handler/mfa_helper.go`

### `internal/service/auth.go`

```diff
-// CompleteMFALogin issues tokens after successful MFA verification.
-// Called by TOTP verify and WebAuthn verify handlers when a 2fa_challenge token is presented.
-// The jti parameter enforces single-use: once consumed, the same challenge token is rejected.
-func (s *AuthService) CompleteMFALogin(ctx context.Context, userID, fingerprint, ip, ua, jti string) (*LoginResult, error) {
+// ChallengeFingerprintMatches reports whether the device fingerprint embedded in
+// a 2fa_challenge token matches the fingerprint recomputed from the redeeming
+// request. An empty challengeFP (legacy token without the claim) is treated as a
+// match so it cannot brick existing sessions. On mismatch it records a
+// FingerprintAnomaly audit event — the device/network-switch signal the claim was
+// added to detect, kept consistent with the refresh path (see Refresh).
+func (s *AuthService) ChallengeFingerprintMatches(ctx context.Context, userID, challengeFP, requestFP, ip, ua string) bool {
+	if challengeFP == "" {
+		return true
+	}
+	if vaultcrypto.CompareFingerprints(challengeFP, requestFP) {
+		return true
+	}
+	s.auditLog.Log(ctx, audit.FingerprintAnomaly, userID, "", ip, ua, requestFP, "", // #nosec G104 -- audit is best-effort, never blocks auth flow
+		map[string]interface{}{"expected": challengeFP, "stage": "mfa_challenge"}, 70)
+	return false
+}
+
+// CompleteMFALogin issues tokens after successful MFA verification.
+// Called by TOTP verify and WebAuthn verify handlers when a 2fa_challenge token is presented.
+// The jti parameter enforces single-use: once consumed, the same challenge token is rejected.
+func (s *AuthService) CompleteMFALogin(ctx context.Context, userID, fingerprint, ip, ua, jti string) (*LoginResult, error) {
```

### `internal/handler/mfa_helper.go`

```diff
 	fp := vaultcrypto.ComputeFingerprint(vaultcrypto.FingerprintInput{
 		IP:             ip,
 		UserAgent:      ua,
 		AcceptLanguage: r.Header.Get("Accept-Language"),
 		TLSFingerprint: middleware.TLSFingerprint(r),
 	})
-	result, err := authSvc.CompleteMFALogin(r.Context(), claims.Subject, fp, ip, ua, claims.ID)
+	// Enforce the device fingerprint bound into the challenge token at first-factor
+	// issuance. A redeeming request from a different device/network is rejected so
+	// the challenge path matches the refresh path's binding (security audit M1).
+	if !authSvc.ChallengeFingerprintMatches(r.Context(), claims.Subject, claims.Fingerprint, fp, ip, ua) {
+		WriteError(w, http.StatusUnauthorized, "invalid_token")
+		return true
+	}
+	result, err := authSvc.CompleteMFALogin(r.Context(), claims.Subject, fp, ip, ua, claims.ID)
```

**addsTest:** Add `TestChallengeFingerprintMismatchRejected` (e.g. in `internal/service/auth_v076_test.go` or a new handler test): assert `svc.ChallengeFingerprintMatches(ctx, "u", "fp-A", "fp-B", "ip", "ua")` returns `false` and (with a mock audit logger) that a `FingerprintAnomaly` event was recorded; assert `ChallengeFingerprintMatches(ctx, "u", "", anyFP, ...)` returns `true` (legacy empty claim) and matching fingerprints return `true`. Optional handler-level test: a `2fa_challenge` with mismatched `claims.Fingerprint` yields HTTP 401 `invalid_token` and never reaches `CompleteMFALogin`.

---

## M2 — OAuth2 authorize endpoint has no rate limit, enabling unauthenticated cache-fill amplification

- **id:** M2
- **severity:** MEDIUM
- **stillReal:** true

`internal/server/server.go` registers `GET /auth/oauth2/authorize` with a bare `mux.HandleFunc` and no `RateLimit` wrapper, while siblings callback (`loginRL`) and exchange (`oauthExchangeRL`) are rate-limited. The handler (`internal/handler/oauth.go`) writes an unbounded per-request `oauth_state:` cache entry into the same backend shared by lockout/OTP/reset/exchange state — eviction-pressure DoS gap. Fix reuses `middleware.RateLimit` + `middleware.IPRateLimitKey` (identical config to `oauthExchangeRL`, 10/min) and switches to `mux.Handle` wrapping `http.HandlerFunc`, matching the callback/exchange style. Respects the existing `rlEnabled` gate.

**Files:** `internal/server/server.go`

### `internal/server/server.go`

```diff
-		oauthExchangeRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
-			Limit: 10, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
-		}, rlEnabled)
-		mux.HandleFunc("GET /auth/oauth2/authorize", oauthHandler.Authorize)
+		authorizeRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
+			Limit: 10, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
+		}, rlEnabled)
+		oauthExchangeRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
+			Limit: 10, Window: time.Minute, KeyFunc: middleware.IPRateLimitKey,
+		}, rlEnabled)
+		mux.Handle("GET /auth/oauth2/authorize", authorizeRL(http.HandlerFunc(oauthHandler.Authorize)))
```

**addsTest:** Optional — in the server route test suite, assert `GET /auth/oauth2/authorize` returns 429 after exceeding 10/min from one IP (build deps with `RateLimitEnabled=true` + at least one OAuth provider, fire 11 requests, assert the 11th is `http.StatusTooManyRequests`). Mirror the existing `loginRL`/`oauthExchangeRL` 429 test wiring.

---

## M3 — OAuth login CSRF / session fixation: state is not bound to the initiating browser

- **id:** M3
- **severity:** MEDIUM
- **stillReal:** true

`Authorize` sets no browser-binding cookie; `Callback` validates only HMAC sig + provider + expiry + the nonce-keyed PKCE verifier — all satisfiable by any state the server minted for any browser. The fingerprint is computed from the victim's request and bound to attacker-account tokens, so it does not mitigate.

Fix: `Authorize` mints a random CSRF token (`RandomHex(32)`), sets it in a host-only HttpOnly Secure SameSite=Lax cookie (`__Host-oauth_state`; Lax so it survives the provider's top-level GET redirect), and embeds `SHA256Hex(token)` as a 4th state segment inside the HMAC-signed payload. `Callback` parses the 4-part payload, reads the cookie, and constant-time-compares (`vaultcrypto.SecureCompare`) the embedded hash against `SHA256Hex(cookie value)`, failing closed (400 `invalid_state`) on absence/mismatch. The one-shot cookie is cleared before code exchange in all paths. Reuses `vaultcrypto.RandomHex/SHA256Hex/SecureCompare` and the `setRefreshCookie/clearRefreshCookie` + `__Host-` convention; no new imports.

Build verified: `go build ./internal/handler/` exits 0.

**Note on tests:** 18 existing handler tests (`oauth_test.go`, `oauth_v076b_test.go`, `handler_v076_test.go`) build legacy 3-part state and attach no cookie, so they now correctly fail with `invalid_state`. This is the **expected** consequence of the behavior change, not a patch defect. They must be updated (see addsTest); they were not modified here.

**Files:** `internal/handler/oauth.go`

### `internal/handler/oauth.go` — Authorize: mint + set cookie

```diff
 	expiry := fmt.Sprintf("%d", time.Now().Add(10*time.Minute).Unix())
-	statePayload := fmt.Sprintf("%s.%s.%s", providerName, nonce, expiry)
-	sig := vaultcrypto.HMACSign([]byte(statePayload), h.hmacSecret)
-	state := fmt.Sprintf("%s.%s", statePayload, sig)
+
+	// Bind the flow to the initiating browser: mint a random CSRF token, set it
+	// as a short-lived host-only cookie, and embed its hash in the signed state.
+	// The callback recomputes the hash from the cookie and compares, so a state
+	// minted for one browser cannot be replayed into a different browser
+	// (OAuth login CSRF / session fixation).
+	csrfToken, err := vaultcrypto.RandomHex(32)
+	if err != nil {
+		WriteError(w, http.StatusInternalServerError, "internal_error")
+		return
+	}
+	csrfHash := vaultcrypto.SHA256Hex(csrfToken)
+
+	statePayload := fmt.Sprintf("%s.%s.%s.%s", providerName, nonce, expiry, csrfHash)
+	sig := vaultcrypto.HMACSign([]byte(statePayload), h.hmacSecret)
+	state := fmt.Sprintf("%s.%s", statePayload, sig)
+
+	setOAuthStateCookie(w, csrfToken, h.secureCookies)
```

### `internal/handler/oauth.go` — Callback: parse 4 parts + verify cookie

```diff
-	// Parse payload parts: "provider.nonce.expiry"
-	parts := strings.SplitN(payload, ".", 3)
-	if len(parts) != 3 || parts[0] != providerName {
-		WriteError(w, http.StatusBadRequest, "invalid_state")
-		return
-	}
-	nonce := parts[1]
-	expiry, err := strconv.ParseInt(parts[2], 10, 64)
-	if err != nil || time.Now().Unix() > expiry {
-		WriteError(w, http.StatusBadRequest, "state_expired")
-		return
-	}
+	// Parse payload parts: "provider.nonce.expiry.csrfHash"
+	parts := strings.SplitN(payload, ".", 4)
+	if len(parts) != 4 || parts[0] != providerName {
+		WriteError(w, http.StatusBadRequest, "invalid_state")
+		return
+	}
+	nonce := parts[1]
+	expiry, err := strconv.ParseInt(parts[2], 10, 64)
+	if err != nil || time.Now().Unix() > expiry {
+		WriteError(w, http.StatusBadRequest, "state_expired")
+		return
+	}
+
+	// Verify the flow completes in the same browser that started it: the state
+	// embeds the hash of a CSRF token mirrored in a host-only cookie. Without
+	// this, any HMAC-valid state minted for another browser could be replayed
+	// into the victim's browser (session fixation). Clear the one-shot cookie
+	// before exchanging the code regardless of outcome.
+	csrfCookie, cookieErr := r.Cookie(oauthStateCookie)
+	clearOAuthStateCookie(w, h.secureCookies)
+	if cookieErr != nil || csrfCookie.Value == "" ||
+		!vaultcrypto.SecureCompare(parts[3], vaultcrypto.SHA256Hex(csrfCookie.Value)) {
+		WriteError(w, http.StatusBadRequest, "invalid_state")
+		return
+	}
```

### `internal/handler/oauth.go` — cookie helpers

```diff
-// isSafeAuthorizeRedirect reports whether a provider-supplied authorize URL is a
+const oauthStateCookie = "__Host-oauth_state" // #nosec G101 -- cookie name constant, not a credential
+
+// setOAuthStateCookie binds the OAuth flow to the initiating browser. It is
+// SameSite=Lax (not Strict) so it survives the top-level GET redirect back from
+// the identity provider, and host-only/HttpOnly so it is not readable by script
+// or scoped to other hosts.
+func setOAuthStateCookie(w http.ResponseWriter, token string, secure bool) {
+	// #nosec G124 -- Secure is derived from TLS state at runtime; HttpOnly + SameSite=Lax pinned.
+	http.SetCookie(w, &http.Cookie{
+		Name:     oauthStateCookie,
+		Value:    token,
+		Path:     "/",
+		HttpOnly: true,
+		Secure:   secure,
+		SameSite: http.SameSiteLaxMode,
+		MaxAge:   600,
+	})
+}
+
+func clearOAuthStateCookie(w http.ResponseWriter, secure bool) {
+	// #nosec G124 -- Secure is derived from TLS state at runtime; HttpOnly + SameSite=Lax pinned.
+	http.SetCookie(w, &http.Cookie{
+		Name:     oauthStateCookie,
+		Value:    "",
+		Path:     "/",
+		HttpOnly: true,
+		Secure:   secure,
+		SameSite: http.SameSiteLaxMode,
+		MaxAge:   -1,
+	})
+}
+
+// isSafeAuthorizeRedirect reports whether a provider-supplied authorize URL is a
```

**addsTest:** Existing OAuth callback tests must be migrated to the new contract:
1. State payload is now 4 parts `provider.nonce.expiry.csrfHash` where `csrfHash = vaultcrypto.SHA256Hex(csrfToken)`. Update every payload builder, e.g.:
   ```go
   csrfToken := "test-csrf-token"
   payload := fmt.Sprintf("google.%s.%s.%s", nonce, expiry, vaultcrypto.SHA256Hex(csrfToken))
   sig := vaultcrypto.HMACSign([]byte(payload), hmacSecret)
   state := payload + "." + sig
   ```
2. Attach the matching cookie to each callback request: `req.AddCookie(&http.Cookie{Name: "__Host-oauth_state", Value: csrfToken})`.

New behavior tests: callback rejects (400 `invalid_state`) when the cookie is absent despite valid HMAC (core CSRF defense); rejects when cookie hash != embedded `csrfHash`; `Authorize` sets a `__Host-oauth_state` cookie (HttpOnly, SameSite=Lax, MaxAge>0) and embeds `SHA256Hex(cookie value)` as the 4th segment; happy-path proceeds to code exchange/redirect; callback clears the cookie (MaxAge=-1) on both reject and success paths.

---

## M4 — TLSEnabled=true with no cert silently serves plaintext HTTP; config never validates cert presence

- **id:** M4
- **severity:** MEDIUM
- **stillReal:** true

`server.go` falls back to plaintext `ListenAndServe()` when `TLSEnabled && TLSCertFile==""`, and sets `secureCookies := cfg.TLSEnabled || cfg.ForceSecureCookies`, so the Secure flag is set while serving HTTP. `config.Load()` has no cert-presence validation; the admin-gateway already fails closed, so the main auth server is the outlier. Production profile defaults `TLSEnabled=true` with empty cert paths. Fix placed at end of `Load()` (after `applyProfileDefaults` and secrets/`ForceSecureCookies` are populated). Allows plaintext only when `ForceSecureCookies` is explicitly set (the documented proxy-termination escape hatch), so the canonical Helm/Cloudflare-Tunnel deploy is unaffected. No `fmt` import needed.

**Files:** `internal/config/config.go`

### `internal/config/config.go`

```diff
 	// Enforce HMAC secret minimum length in non-dev profiles
 	if len(c.HMACSecret) > 0 && len(c.HMACSecret) < 32 {
 		if c.Profile != ProfileDev {
 			return nil, fmt.Errorf("HMAC secret must be at least 32 bytes (got %d)", len(c.HMACSecret))
 		}
 		log.Println("SECURITY WARNING: HMAC secret is shorter than 32 bytes")
 	}
 
+	// Fail closed when TLS is enabled but no cert/key is configured: the server
+	// would otherwise silently fall back to plaintext HTTP (server.go) while
+	// still believing it is secure (secureCookies tracks TLSEnabled).
+	// ForceSecureCookies is the documented escape hatch for TLS-terminating
+	// proxies (Cloudflare Tunnel/ingress), where plaintext on the loopback hop
+	// is intentional. Mirrors the admin-gateway's required-cert check.
+	if c.TLSEnabled && !c.ForceSecureCookies && (c.TLSCertFile == "" || c.TLSKeyFile == "") {
+		return nil, fmt.Errorf("VAULT_TLS_ENABLED=true requires VAULT_TLS_CERT_FILE and VAULT_TLS_KEY_FILE (or set VAULT_FORCE_SECURE_COOKIES=true when TLS terminates upstream)")
+	}
+
 	return c, nil
```

**addsTest:** In `internal/config`, assert `Load()` with `VAULT_PROFILE=production` and no `VAULT_TLS_CERT_FILE`/`VAULT_TLS_KEY_FILE` returns an error; and that the same env with `VAULT_FORCE_SECURE_COOKIES=true` (or both cert+key set) succeeds. Verifies the fail-closed gate and its escape hatch.

> **Conflict note:** M4, M5, M6, and L3 all anchor on the same HMAC-secret-length block at the end of `Load()`. Apply them as a single combined edit to that region (see the merged ordering in the checklist), not four independent string replacements against identical context.

---

## M5 — VAULT_TLS_ENABLED=false silently disables TLS in production; docs claim it cannot be disabled

- **id:** M5
- **severity:** MEDIUM
- **stillReal:** true

`internal/config/profiles.go` `setDefaultBool` uses `os.LookupEnv`+`strconv.ParseBool`, so `VAULT_TLS_ENABLED=false` **is** honored and overrides the production `true` default; `docs/config.md` falsely states the toggle has no effect. `secureCookies` tracks `TLSEnabled`, so disabling TLS also drops the Secure flag. Fix inserts a fail-closed guard after the HMAC check (covers `ProfileProduction` and `ProfileHoneypot`, since honeypot inherits production defaults) gated by an explicit `VAULT_ALLOW_PLAINTEXT` acknowledgement via the existing `envBool` helper, and corrects the docs.

**Files:** `internal/config/config.go`, `docs/config.md`

### `internal/config/config.go`

```diff
 	// Enforce HMAC secret minimum length in non-dev profiles
 	if len(c.HMACSecret) > 0 && len(c.HMACSecret) < 32 {
 		if c.Profile != ProfileDev {
 			return nil, fmt.Errorf("HMAC secret must be at least 32 bytes (got %d)", len(c.HMACSecret))
 		}
 		log.Println("SECURITY WARNING: HMAC secret is shorter than 32 bytes")
 	}
 
+	// Fail closed: refuse to serve plaintext in production/honeypot profiles
+	// unless the operator explicitly acknowledges it. VAULT_TLS_ENABLED=false
+	// would otherwise also drop the Secure cookie flag, exposing auth tokens.
+	if (c.Profile == ProfileProduction || c.Profile == ProfileHoneypot) && !c.TLSEnabled && !envBool("VAULT_ALLOW_PLAINTEXT") {
+		return nil, fmt.Errorf("refusing to disable TLS in %s profile; set VAULT_ALLOW_PLAINTEXT=true to override", c.Profile)
+	}
+
 	return c, nil
```

### `docs/config.md`

```diff
-| `VAULT_TLS_ENABLED` | bool | `true` | No | Enable HTTPS. Set by profile if unset. When `true`, `VAULT_TLS_CERT_FILE` and `VAULT_TLS_KEY_FILE` are required. **Note**: Due to Go zero-value semantics, setting this to `false` via env var has no effect -- all profiles default it to `true` and `setDefaultBool` cannot distinguish "unset" from "explicitly false". To disable TLS, modify the profile code. |
+| `VAULT_TLS_ENABLED` | bool | `true` | No | Enable HTTPS. Set by profile if unset. When `true`, `VAULT_TLS_CERT_FILE` and `VAULT_TLS_KEY_FILE` are required. **Note**: `setDefaultBool` uses `os.LookupEnv`, so setting this to `false` via env var **is** honored and overrides the profile default. In the `production` and `honeypot` profiles, `Load()` fails closed if TLS is disabled unless `VAULT_ALLOW_PLAINTEXT=true` is also set (disabling TLS also drops the `Secure` cookie flag). |
```

**addsTest:** Config-package test asserting `Load()` errors when `Profile==production` (or honeypot) and `VAULT_TLS_ENABLED=false` with `VAULT_ALLOW_PLAINTEXT` unset, and succeeds (`TLSEnabled=false`) when `VAULT_ALLOW_PLAINTEXT=true`. Also assert dev profile still allows TLS off without the override.

---

## M6 — No fail-closed validation that HMAC secret / pepper are present in non-dev profiles; loadSecrets swallows unreadable-file errors

- **id:** M6
- **severity:** MEDIUM
- **stillReal:** true

The HMAC guard only fires for `0 < len < 32`; a fully **absent** HMAC secret (len 0) is never rejected. `loadSecrets()` uses `if v, err := LoadSecret(...); err == nil` for every secret, so a set-but-unreadable `_FILE` (wrong path/perms) is silently swallowed. `HMACSign` accepts an empty key (signs OAuth state, backup codes, identity/blob HMACs); `applyPepper` no-ops on empty pepper. Only `MasterKey` fails closed in `main.go`.

Fix (3 patches in `internal/config/config.go`):
1. Replace the short-only HMAC guard with a non-dev fail-closed block requiring `HMACSecret >= 32` **and** `Pepper != ""` (dev keeps the soft warning).
2. Refactor `loadSecrets()` to return an error: when a secret's `_FILE` env var is **set** but the read fails, surface the error; a truly-unset `_FILE` is still silently skipped. Set-ness is detected via `os.Getenv(env+"_FILE") != ""`, not error-string matching.
3. Propagate the `loadSecrets` error at the `Load()` call site.

Honeypot/embedded/production are all non-dev and now require the secrets; only `ProfileDev` is exempt.

**Files:** `internal/config/config.go`

### `internal/config/config.go` — propagate loadSecrets error

```diff
-	// Load secrets from _FILE env vars
-	c.loadSecrets()
+	// Load secrets from _FILE env vars
+	if err := c.loadSecrets(); err != nil {
+		return nil, err
+	}
 
 	// Register generic OIDC providers from env.
 	c.loadOIDCProviders()
```

### `internal/config/config.go` — fail-closed secret presence

```diff
-	// Enforce HMAC secret minimum length in non-dev profiles
-	if len(c.HMACSecret) > 0 && len(c.HMACSecret) < 32 {
-		if c.Profile != ProfileDev {
-			return nil, fmt.Errorf("HMAC secret must be at least 32 bytes (got %d)", len(c.HMACSecret))
-		}
-		log.Println("SECURITY WARNING: HMAC secret is shorter than 32 bytes")
-	}
-
-	return c, nil
-}
+	// Enforce presence and minimum length of signing/hashing secrets.
+	// Non-dev profiles fail closed: an empty HMAC key signs OAuth state, backup
+	// codes, and identity/blob HMACs with no key, and an empty pepper disables
+	// the server-side pepper, leaving passwords crackable offline after a
+	// DB-only compromise. Dev keeps a soft warning for local convenience.
+	if c.Profile != ProfileDev {
+		if len(c.HMACSecret) < 32 {
+			return nil, fmt.Errorf("HMAC_SECRET_FILE required (>=32 bytes) in %s profile (got %d)", c.Profile, len(c.HMACSecret))
+		}
+		if c.Pepper == "" {
+			return nil, fmt.Errorf("VAULT_PEPPER_FILE required in %s profile", c.Profile)
+		}
+	} else if len(c.HMACSecret) > 0 && len(c.HMACSecret) < 32 {
+		log.Println("SECURITY WARNING: HMAC secret is shorter than 32 bytes")
+	}
+
+	return c, nil
+}
```

### `internal/config/config.go` — loadSecrets returns error

```diff
-func (c *Config) loadSecrets() {
-	if mk, err := LoadSecret("MASTER_KEY"); err == nil {
-		c.MasterKey = []byte(mk)
-	}
-	if at, err := LoadSecret("ADMIN_TOKEN"); err == nil {
-		c.AdminTokenHash = at
-	}
-	if p, err := LoadSecret("VAULT_PEPPER"); err == nil {
-		c.Pepper = p
-	}
-	if hs, err := LoadSecret("HMAC_SECRET"); err == nil {
-		c.HMACSecret = []byte(hs)
-	}
-	if dp, err := LoadSecret("DB_MIG_PASSWORD"); err == nil {
-		c.DBMigPassword = dp
-	}
-	if dp, err := LoadSecret("DB_APP_PASSWORD"); err == nil {
-		c.DBAppPassword = dp
-	}
-	if rp, err := LoadSecret("REDIS_PASS"); err == nil {
-		c.RedisPass = rp
-	}
-	if su, err := LoadSecret("SMTP_USER"); err == nil {
-		c.SMTPUser = su
-	}
-	if sp, err := LoadSecret("SMTP_PASS"); err == nil {
-		c.SMTPPass = sp
-	}
-	if sg, err := LoadSecret("SENDGRID_API_KEY"); err == nil {
-		c.SendGridAPIKey = sg
-	}
-	if gs, err := LoadSecret("VAULT_OAUTH_GOOGLE_CLIENT_SECRET"); err == nil {
-		c.OAuthGoogleClientSecret = gs
-	}
-	if gs, err := LoadSecret("VAULT_OAUTH_GITHUB_CLIENT_SECRET"); err == nil {
-		c.OAuthGitHubClientSecret = gs
-	}
-	if fs, err := LoadSecret("VAULT_OAUTH_FACEBOOK_CLIENT_SECRET"); err == nil {
-		c.OAuthFacebookClientSecret = fs
-	}
-}
+func (c *Config) loadSecrets() error {
+	// load reads one secret. A _FILE that is set but unreadable is a hard error
+	// (operator misconfiguration must not be silently swallowed); a _FILE that is
+	// simply unset leaves dst untouched and is not an error.
+	load := func(env string, dst func(string)) error {
+		v, err := LoadSecret(env)
+		if err != nil {
+			if os.Getenv(env+"_FILE") == "" {
+				return nil // not configured
+			}
+			return fmt.Errorf("load secret %s: %w", env, err)
+		}
+		dst(v)
+		return nil
+	}
+	loads := []struct {
+		env string
+		dst func(string)
+	}{
+		{"MASTER_KEY", func(v string) { c.MasterKey = []byte(v) }},
+		{"ADMIN_TOKEN", func(v string) { c.AdminTokenHash = v }},
+		{"VAULT_PEPPER", func(v string) { c.Pepper = v }},
+		{"HMAC_SECRET", func(v string) { c.HMACSecret = []byte(v) }},
+		{"DB_MIG_PASSWORD", func(v string) { c.DBMigPassword = v }},
+		{"DB_APP_PASSWORD", func(v string) { c.DBAppPassword = v }},
+		{"REDIS_PASS", func(v string) { c.RedisPass = v }},
+		{"SMTP_USER", func(v string) { c.SMTPUser = v }},
+		{"SMTP_PASS", func(v string) { c.SMTPPass = v }},
+		{"SENDGRID_API_KEY", func(v string) { c.SendGridAPIKey = v }},
+		{"VAULT_OAUTH_GOOGLE_CLIENT_SECRET", func(v string) { c.OAuthGoogleClientSecret = v }},
+		{"VAULT_OAUTH_GITHUB_CLIENT_SECRET", func(v string) { c.OAuthGitHubClientSecret = v }},
+		{"VAULT_OAUTH_FACEBOOK_CLIENT_SECRET", func(v string) { c.OAuthFacebookClientSecret = v }},
+	}
+	for _, l := range loads {
+		if err := load(l.env, l.dst); err != nil {
+			return err
+		}
+	}
+	return nil
+}
```

**addsTest:** Table-driven tests in `internal/config` (do not modify existing): `Load()` with `VAULT_PROFILE=production` and no HMAC/pepper `_FILE` errors (fail closed); production + 16-byte HMAC errors (too short); production + valid 32-byte HMAC + non-empty pepper succeeds; dev with no secrets succeeds (warning only); `loadSecrets` surfaces an error when `HMAC_SECRET_FILE` points at a nonexistent/unreadable path but not when unset. Use `t.Setenv` + tempdir.

---

## M7 — EmbeddedTrustedUpstream auto-trusts RFC1918+loopback+XFF in any profile, not just embedded

- **id:** M7
- **severity:** MEDIUM
- **stillReal:** true

The shortcut was ungated by profile, so `VAULT_EMBEDDED_TRUSTED_UPSTREAM=true` in production silently auto-trusts all RFC1918+loopback and forces `X-Forwarded-For`, collapsing per-IP rate-limit/audit attribution on a flat network. The struct doc also omitted `127.0.0.0/8` and `::1/128`. Fix gates the shortcut to `ProfileEmbedded` and fails closed (returns an error) if set in any other profile — chosen over silently ignoring so a misconfigured prod deploy is caught at startup. `Load()` already returns `(*Config, error)` and `fmt` is imported. No deploy artifacts set this flag, so the new hard error breaks no existing deployments.

**Files:** `internal/config/config.go`

### `internal/config/config.go` — struct doc

```diff
 	// EmbeddedTrustedUpstream toggles a one-shot setup for vault42 running
 	// behind a sibling reverse proxy in the same private network — typical
 	// of embedded deployments where another app (e.g. Hermod coordinator)
 	// terminates TLS and forwards auth calls to vault42 over the cluster
-	// network. When true and TrustedProxies is empty, auto-populates with
-	// RFC1918 ranges (10/8, 172.16/12, 192.168/16) plus IPv6 ULA (fc00::/7).
-	// When true and RealIPHeader is empty, defaults to "X-Forwarded-For".
-	// (VAULT_EMBEDDED_TRUSTED_UPSTREAM). Default: false.
+	// network. Only honoured in ProfileEmbedded; setting it in any other
+	// profile is a hard configuration error (set TRUSTED_PROXIES /
+	// REAL_IP_HEADER explicitly instead). When true and TrustedProxies is
+	// empty, auto-populates with RFC1918 ranges (10/8, 172.16/12,
+	// 192.168/16), IPv6 ULA (fc00::/7), and loopback (127.0.0.0/8, ::1/128)
+	// for the sidecar pattern. When true and RealIPHeader is empty, defaults
+	// to "X-Forwarded-For". (VAULT_EMBEDDED_TRUSTED_UPSTREAM). Default: false.
 	EmbeddedTrustedUpstream bool
```

### `internal/config/config.go` — gate the shortcut

```diff
 	if c.EmbeddedTrustedUpstream {
+		// Fail closed: this auto-trusts whole private + loopback ranges and
+		// blindly honours X-Forwarded-For, which collapses per-IP rate
+		// limiting and audit attribution if the network is not actually a
+		// trusted sidecar topology. Restrict it to the embedded profile;
+		// any other profile must configure TRUSTED_PROXIES / REAL_IP_HEADER
+		// explicitly.
+		if c.Profile != ProfileEmbedded {
+			return nil, fmt.Errorf("VAULT_EMBEDDED_TRUSTED_UPSTREAM is only valid in the embedded profile (got %q); set TRUSTED_PROXIES and REAL_IP_HEADER explicitly instead", c.Profile)
+		}
 		if len(c.TrustedProxies) == 0 {
 			c.TrustedProxies = []string{
 				"10.0.0.0/8",     // RFC1918 large
 				"172.16.0.0/12",  // RFC1918 medium
 				"192.168.0.0/16", // RFC1918 small
 				"fc00::/7",       // IPv6 ULA
 				"127.0.0.0/8",    // loopback (sidecar pattern)
 				"::1/128",        // IPv6 loopback
 			}
 		}
 		if c.RealIPHeader == "" {
 			c.RealIPHeader = "X-Forwarded-For"
 		}
 	}
```

**addsTest:** New `internal/config/config_security_test.go` (do not modify existing): set `VAULT_EMBEDDED_TRUSTED_UPSTREAM=true` + production-profile env, assert the loader returns a non-nil error (fail closed). Second case: same flag with `VAULT_PROFILE=embedded`, assert no error and `TrustedProxies` contains `127.0.0.0/8` and `::1/128` and `RealIPHeader=="X-Forwarded-For"`.

---

## L1 — checkSessionLimit fails open on cache/count error, allowing the concurrent-session cap to be bypassed

- **id:** L1
- **severity:** LOW
- **stillReal:** true

`checkSessionLimit` (`internal/service/auth.go`) returns `nil` on `CountActiveFamilies` error ("fail open"). Downgraded to LOW because it's documented/unit-tested and the trigger (indexed COUNT on the user's own ID) isn't attacker-controllable. Fix keeps the default fail-open (so the existing `TestCheckSessionLimit` still passes) and adds an opt-in `VAULT_STRICT_SESSION_LIMIT` flag (default false) that fails closed **and** emits a high-severity audit `RateLimit` event. Wiring: config field + `Load()` + `AuthService` field + setter + `main.go`.

**Files:** `internal/config/config.go`, `internal/service/auth.go`, `cmd/vault/main.go`

### `internal/config/config.go` — struct field

```diff
 	// MaxSessionsPerUser limits the number of concurrent refresh token families per user (VAULT_MAX_SESSIONS_PER_USER). Default: 10.
 	MaxSessionsPerUser int
+	// StrictSessionLimit makes the concurrent-session check fail closed when the underlying count query errors, instead of allowing the login (VAULT_STRICT_SESSION_LIMIT). Default: false.
+	StrictSessionLimit bool
```

### `internal/config/config.go` — Load() init

```diff
-		MaxSessionsPerUser:  envInt("VAULT_MAX_SESSIONS_PER_USER", 10),
+		MaxSessionsPerUser:  envInt("VAULT_MAX_SESSIONS_PER_USER", 10),
+		StrictSessionLimit:  envBool("VAULT_STRICT_SESSION_LIMIT"),
```

### `internal/service/auth.go` — struct field

```diff
 	metrics            *metrics.Collector
 	maxSessionsPerUser int
+	strictSessionLimit bool
 	origin             string
```

### `internal/service/auth.go` — setter

```diff
 func (s *AuthService) SetMaxSessionsPerUser(n int) {
 	s.maxSessionsPerUser = n
 }
+
+// SetStrictSessionLimit controls how checkSessionLimit behaves when the
+// CountActiveFamilies query errors. When true, the check fails closed
+// (rejects the login) and emits a high-severity audit event; when false
+// (the default), it fails open so a transient count error does not block
+// logins.
+func (s *AuthService) SetStrictSessionLimit(strict bool) {
+	s.strictSessionLimit = strict
+}
```

### `internal/service/auth.go` — checkSessionLimit

```diff
 	count, err := s.tokens.CountActiveFamilies(ctx, userID)
 	if err != nil {
 		log.Printf("auth: session count check failed for user %s: %v", userID, err)
+		if s.strictSessionLimit {
+			// Fail closed: a count error must not silently disable the cap.
+			s.auditLog.Log(ctx, audit.RateLimit, userID, "", "", "", "", "", // #nosec G104 -- audit is best-effort, never blocks auth flow
+				map[string]interface{}{"reason": "session_limit_count_failed"}, 80)
+			return ErrTooManySessions
+		}
 		return nil // fail open — don't block login if the count query fails
 	}
```

### `cmd/vault/main.go`

```diff
 	authSvc.SetMaxSessionsPerUser(cfg.MaxSessionsPerUser)
+	authSvc.SetStrictSessionLimit(cfg.StrictSessionLimit)
```

**addsTest:** New file (e.g. `internal/service/auth_session_strict_test.go`; do **not** touch `auth_v076_test.go`): build via `newMockAuthService`, call `SetMaxSessionsPerUser(3)` + `SetStrictSessionLimit(true)`, set `CountActiveFamiliesFn` to return `(0, errors.New("count query failed"))`, assert `checkSessionLimit` returns `ErrTooManySessions`. Second case with `SetStrictSessionLimit(false)` + same erroring fn asserts `nil` (preserves default fail-open).

---

## L2 — DPoP jwk header accepts arbitrarily large RSA keys (no upper bound) → algorithmic-complexity DoS

- **id:** L2
- **severity:** LOW
- **stillReal:** true

`internal/crypto/dpop.go` enforces only the minimum (`n.BitLen() < 2048`) with no upper bound, and the RSA branch returns the attacker-controlled key (self-signed DPoP proof, modulus size fully attacker-chosen). Fix adds a 4096-bit upper bound mirroring the existing min-check style; 3072/4096 covers every legitimate client. `go build ./internal/crypto/` clean. Scope kept surgical to the self-signed DPoP path; `jwt.go` and `oidc_idtoken.go` parse keys from trusted sources (own signing key / provider JWKS) and are out of scope.

**Files:** `internal/crypto/dpop.go`

### `internal/crypto/dpop.go`

```diff
 		n := new(big.Int).SetBytes(nBytes)
 		if n.BitLen() < 2048 {
 			return nil, errors.New("RSA key too small: minimum 2048 bits required")
 		}
+		if n.BitLen() > 4096 {
+			return nil, errors.New("RSA key too large: maximum 4096 bits allowed")
+		}
```

**addsTest:** In `internal/crypto/dpop_test.go`, build a DPoP proof JWT whose `jwk` header embeds an RSA public key with modulus > 4096 bits (e.g. 8192-bit) and assert `ValidateDPoPProof` returns an error containing `"RSA key too large"`. Pair with a positive 2048/3072-bit case.

---

## L3 — Fail fast on empty/invalid VAULT_ORIGIN so JWT issuer/audience binding (and CORS/JWKS/cookie/OAuth/WebAuthn) can't be silently disabled

- **id:** L3
- **severity:** LOW
- **stillReal:** true

`Origin` loads straight from `os.Getenv("VAULT_ORIGIN")` with no fallback and no validation; no profile sets a default, so empty stays empty. `internal/jwt/validate.go` gates iss/aud checks on `!= ""`, so empty Origin silently skips both. Origin is also used for CORS, JWKS issuer, cookie domain, OAuth callback URLs, and WebAuthn RPID (LOW because the Helm chart ships a default origin). Fix: for `ProfileDev` only, default empty Origin to `https://localhost:8443` (matches the default `:8443` ListenAddr); for **all** profiles then require a non-empty absolute URL (scheme + host). Enforced before `return c, nil` so `main.go` (only non-test caller of `config.Load()`) fails fast. Tests construct `Config` structs directly, so they're unaffected. Deliberately did **not** tighten `validate.go` (would risk breaking unit tests exercising empty-expected iss/aud).

**Files:** `internal/config/config.go`

### `internal/config/config.go`

```diff
 	// Enforce HMAC secret minimum length in non-dev profiles
 	if len(c.HMACSecret) > 0 && len(c.HMACSecret) < 32 {
 		if c.Profile != ProfileDev {
 			return nil, fmt.Errorf("HMAC secret must be at least 32 bytes (got %d)", len(c.HMACSecret))
 		}
 		log.Println("SECURITY WARNING: HMAC secret is shorter than 32 bytes")
 	}
 
+	// Require a valid public origin. Origin is used as the JWT issuer/audience
+	// (iss/aud binding is silently skipped when empty), CORS allow-origin, JWKS
+	// issuer, cookie domain, OAuth callback URLs, and WebAuthn RP ID. Fail closed
+	// rather than boot with those defenses disabled. Dev gets a localhost default.
+	if c.Origin == "" && c.Profile == ProfileDev {
+		c.Origin = "https://localhost:8443"
+	}
+	if u, err := url.Parse(c.Origin); err != nil || u.Scheme == "" || u.Host == "" {
+		return nil, fmt.Errorf("VAULT_ORIGIN must be set to an absolute URL (e.g. https://auth.example.com), got %q", c.Origin)
+	}
+
 	return c, nil
```

> Requires the `net/url` import in `internal/config/config.go` if not already present.

**addsTest:** Table-driven `Load()` test for `VAULT_ORIGIN`: (1) production + unset -> error; (2) production + `"not-a-url"` -> error; (3) production + `"https://auth.example.com"` -> no error, `cfg.Origin` preserved; (4) dev + unset -> no error, `cfg.Origin == "https://localhost:8443"`. Use `t.Setenv`.

---

## L4 — Rate-limit local fallback is per-process, multiplying the effective limit across pods on cache failure

- **id:** L4
- **severity:** LOW
- **stillReal:** true

`RateLimit()` creates one per-process `localRateLimiter`; on `Increment` error it falls back to `local.increment`, so with N pods each enforces its own budget and the effective limit becomes N×configured during a cache outage. The DB-backed lockout is cross-pod-consistent but fails open on transient cache errors, so the middleware limiter is the only throttle that pod-multiplies. Fix adds a `FailClosed` flag to `RateLimitConfig`; the cache-failure path then rejects with 503 `rate_limiter_unavailable` (mirroring the `dpop_replay_check_unavailable` 503 pattern) instead of the per-pod fallback. Enabled for exactly the four auth-sensitive limiters the audit names (login, register, password reset, TOTP); others keep graceful degradation. Zero value = current behavior, so no existing tests break.

**Files:** `internal/middleware/ratelimit.go`, `internal/server/server.go`

### `internal/middleware/ratelimit.go` — config flag

```diff
 // RateLimitConfig defines rate limit parameters for an endpoint.
 type RateLimitConfig struct {
 	Limit   int
 	Window  time.Duration
 	KeyFunc func(r *http.Request) string
+	// FailClosed rejects requests with 503 when the distributed cache is
+	// unavailable instead of falling back to the per-process in-memory counter.
+	// Set this for security-sensitive limiters (login, register, password reset,
+	// TOTP): the in-memory fallback is per-pod, so under a cache outage the
+	// effective limit would otherwise multiply by the pod count, weakening
+	// brute-force / credential-stuffing protection. Leave false for limiters
+	// where graceful degradation is preferable to a hard outage.
+	FailClosed bool
 }
```

### `internal/middleware/ratelimit.go` — fail-closed path

```diff
 			count, err := c.Increment(ctx, key, cfg.Window)
 			if err != nil {
+				if cfg.FailClosed {
+					// Security-sensitive limiter: the in-memory fallback is per-pod and
+					// would multiply the effective limit across pods during a cache
+					// outage, so fail closed rather than weaken brute-force protection.
+					if fallbackWarned.CompareAndSwap(false, true) {
+						log.Printf("WARNING: rate limiter failing closed (cache unavailable)")
+					}
+					w.Header().Set("Retry-After", strconv.Itoa(int(cfg.Window.Seconds())))
+					httputil.WriteError(w, http.StatusServiceUnavailable, "rate_limiter_unavailable")
+					return
+				}
 				// Cache failure — use in-memory fallback instead of allowing unlimited requests
 				if fallbackWarned.CompareAndSwap(false, true) {
 					log.Printf("WARNING: rate limiter falling back to in-memory counter (cache unavailable)")
 				}
 				count = local.increment(key, cfg.Window)
 			}
```

> Requires `strconv` and the `httputil` package used by `WriteError` to be imported in `ratelimit.go` if not already present.

### `internal/server/server.go` — login + register

```diff
-	loginRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
-		Limit: 5, Window: 15 * time.Minute, KeyFunc: middleware.LoginRateLimitKey,
-	}, rlEnabled)
-	registerRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
-		Limit: 3, Window: time.Hour, KeyFunc: middleware.IPRateLimitKey,
-	}, rlEnabled)
+	loginRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
+		Limit: 5, Window: 15 * time.Minute, KeyFunc: middleware.LoginRateLimitKey, FailClosed: true,
+	}, rlEnabled)
+	registerRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
+		Limit: 3, Window: time.Hour, KeyFunc: middleware.IPRateLimitKey, FailClosed: true,
+	}, rlEnabled)
```

### `internal/server/server.go` — password reset + TOTP

```diff
-	passwordResetRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
-		Limit: 3, Window: time.Hour, KeyFunc: middleware.IPRateLimitKey,
-	}, rlEnabled)
-	totpRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
-		Limit: 5, Window: 5 * time.Minute, KeyFunc: middleware.IPRateLimitKey,
-	}, rlEnabled)
+	passwordResetRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
+		Limit: 3, Window: time.Hour, KeyFunc: middleware.IPRateLimitKey, FailClosed: true,
+	}, rlEnabled)
+	totpRL := middleware.RateLimit(d.Cache, middleware.RateLimitConfig{
+		Limit: 5, Window: 5 * time.Minute, KeyFunc: middleware.IPRateLimitKey, FailClosed: true,
+	}, rlEnabled)
```

**addsTest:** In `internal/middleware/ratelimit_test.go`: construct a `RateLimit` middleware with a `cache.Cache` stub whose `Increment` always errors, and `RateLimitConfig{Limit:5, Window:time.Minute, FailClosed:true, KeyFunc: ...}`, enabled=true. Assert one request returns HTTP 503 with body `rate_limiter_unavailable` and that `next.ServeHTTP` was NOT called. Sibling case with `FailClosed:false` asserts the request still passes through (HTTP 200).

---

## L5 — LoadSecret unconditionally zeroes+removes the secret file and swallows both errors

- **id:** L5
- **severity:** LOW
- **stillReal:** true

`internal/config/secrets.go` zeroes + removes the secret file after reading and discards both errors. On the canonical read-only mount this is a silent no-op; on a writable real keyfile it destroys the operator's secret on first read. Fix gates the destructive zero+remove behind `VAULT_SECRET_FILE_CONSUME=true` (defaults off) and logs best-effort failures via the package's existing `log` usage. Kept `#nosec` annotations; added `G306` to the `WriteFile` nosec since `0o400` can trip gosec.

**Files:** `internal/config/secrets.go`

### `internal/config/secrets.go` — imports

```diff
 import (
 	"fmt"
+	"log"
 	"os"
 	"path/filepath"
 	"strings"
 )
```

### `internal/config/secrets.go` — gated consume

```diff
 	data, err := os.ReadFile(path) // #nosec G304 -- path from operator env var (_FILE convention), cleaned with filepath.Clean
 	if err != nil {
 		return "", fmt.Errorf("read %s: %w", path, err)
 	}
-	// Zero the file contents and delete it (defense in depth)
-	_ = os.WriteFile(path, make([]byte, len(data)), 0o400) // #nosec G104 -- secret file zeroing is best-effort; path from operator env var
-	_ = os.Remove(path)                                    // #nosec G104 -- secret file deletion is best-effort
-	return strings.TrimSpace(string(data)), nil
+	// Zero the file contents and delete it (defense in depth). This is
+	// destructive and opt-in: the canonical deployment mounts secrets
+	// read-only, where it would be a silent no-op, and on a writable real
+	// keyfile it would destroy the operator's secret on first read. Only run
+	// it when explicitly requested, and surface best-effort failures so the
+	// operator learns the wipe did not happen rather than assuming it did.
+	if os.Getenv("VAULT_SECRET_FILE_CONSUME") == "true" {
+		if werr := os.WriteFile(path, make([]byte, len(data)), 0o400); werr != nil { // #nosec G104,G306 -- secret file zeroing is best-effort; path from operator env var
+			log.Printf("WARNING: failed to zero secret file %s (defense-in-depth wipe skipped): %v", path, werr)
+		}
+		if rerr := os.Remove(path); rerr != nil {
+			log.Printf("WARNING: failed to remove secret file %s (defense-in-depth wipe skipped): %v", path, rerr)
+		}
+	}
+	return strings.TrimSpace(string(data)), nil
```

> Note: `docs/cheatsheet.md:369` ("File is zeroed after reading") is now only accurate when `VAULT_SECRET_FILE_CONSUME=true`. Left untouched to keep the patch surgical; operator may want to update it.

**addsTest:** New cases: (1) `ENVKEY_FILE` set to a temp file, `VAULT_SECRET_FILE_CONSUME` unset -> `LoadSecret` returns the trimmed secret AND the temp file still exists with original contents (no zero/remove). (2) `VAULT_SECRET_FILE_CONSUME=true` -> file is removed after a successful read. (3) `VAULT_SECRET_FILE_CONSUME=true` with a read-only file/dir so `Remove` fails -> `LoadSecret` still returns the secret without error (failure logged, not fatal).

---

## L6 — Admin lifecycle audit events omit the structured target-ID column

- **id:** L6
- **severity:** LOW
- **stillReal:** true

`audit.Logger.Log` signature is `Log(ctx, eventType, userID, clientID, ip, ua, fpHash, deviceID, metadata, riskScore)` — the 4th positional arg (`clientID`) is the dedicated/indexed target column. Client lifecycle handlers pass `id` there, but `CreateAdmin` and `RevokeAdmin` pass `""` and stash the target only in free-form metadata. Patches pass the target admin `id` into the structured column for both, mirroring the client handlers. Metadata keys left intact (no shape regression). The broader query-filter/index gap (`AuditFilter` has no target/clientID filter) is out of scope for this surgical fix.

**Files:** `internal/adminapi/handler.go`

### `internal/adminapi/handler.go` — CreateAdmin

```diff
-	_ = h.auditLog.Log(r.Context(), audit.AdminAccountCreate, creator.ID, "", r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
-		"new_admin_id":       id,
+	_ = h.auditLog.Log(r.Context(), audit.AdminAccountCreate, creator.ID, id, r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
+		"new_admin_id":       id,
```

### `internal/adminapi/handler.go` — RevokeAdmin

```diff
-	_ = h.auditLog.Log(r.Context(), audit.AdminAccountRevoke, actor.ID, "", r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
-		"revoked_admin_id": id,
+	_ = h.auditLog.Log(r.Context(), audit.AdminAccountRevoke, actor.ID, id, r.RemoteAddr, r.UserAgent(), "", "", map[string]interface{}{
+		"revoked_admin_id": id,
```

**addsTest:** Optional (not added, to avoid touching tests): after calling `CreateAdmin`/`RevokeAdmin` against a fake audit logger, assert the recorded entry's `clientID`/target field equals the new/target admin id (not `""`), mirroring the existing `AdminClientCreate` assertion.

---

## L7 — LockUser accepts an unbounded, caller-controlled lock duration

- **id:** L7
- **severity:** LOW
- **stillReal:** true

`LockUser` (`internal/adminapi/handler.go`) applied the `ParseDuration` result with no upper/lower bound, so a positive value like `"1000000h"` was honored, letting an operator (UsersLock grant) impose an effectively permanent end-user lock. Fix extends the existing 24h fallback condition to also catch `dur <= 0` and `dur > 30 days`, clamping to the sane default. `go build ./internal/adminapi/` passes. LOW (loopback+mTLS admin gateway, audited, unlock path exists), but the clamp closes the indefinite-DoS abuse.

**Files:** `internal/adminapi/handler.go`

### `internal/adminapi/handler.go`

```diff
 	dur, err := time.ParseDuration(req.Duration)
-	if err != nil {
-		dur = 24 * time.Hour
-	}
+	if err != nil || dur <= 0 || dur > 30*24*time.Hour {
+		dur = 24 * time.Hour
+	}
 
 	until := time.Now().Add(dur)
```

**addsTest:** Add one case asserting that POSTing `{"duration":"1000000h"}` to `LockUser` clamps the resulting `until` to now+24h (within tolerance) rather than honoring the unbounded value; optionally assert a valid `"48h"` is honored verbatim.

---

## Skipped findings

None — every finding (M1–M7, L1–L7) was confirmed `stillReal: true` against current source. No skips.

---

## Checklist — real fixes to apply

> **Coordination:** M4, M5, M6, and L3 all edit the trailing HMAC-secret-length block at the end of `internal/config/config.go`'s `Load()`. Apply them together in one pass (M6's new HMAC/pepper block replaces the short-only check; then M4's TLS-cert guard, M5's TLS-disable guard, and L3's origin guard slot in before `return c, nil`). M6 also rewrites `loadSecrets()` and its call site. L1 adds further fields/init/setters in the same files. Build the combined edit, don't apply four separate identical-context replacements.

- [ ] **M1** — `internal/service/auth.go` (`ChallengeFingerprintMatches`), `internal/handler/mfa_helper.go` (enforce before `CompleteMFALogin`). Add `TestChallengeFingerprintMismatchRejected`.
- [ ] **M2** — `internal/server/server.go` (rate-limit `GET /auth/oauth2/authorize`). Optional 429 route test.
- [ ] **M3** — `internal/handler/oauth.go` (CSRF cookie binding: Authorize mint+set, Callback 4-part parse + verify, cookie helpers). Migrate 18 existing OAuth callback tests + add new CSRF/cookie behavior tests.
- [ ] **M4** — `internal/config/config.go` (fail closed when `TLSEnabled` + no cert and not `ForceSecureCookies`). Config test.
- [ ] **M5** — `internal/config/config.go` (fail closed on `TLS=false` in prod/honeypot without `VAULT_ALLOW_PLAINTEXT`) + `docs/config.md` correction. Config test.
- [ ] **M6** — `internal/config/config.go` (propagate `loadSecrets` error; non-dev fail-closed HMAC≥32 + pepper present; `loadSecrets` returns error, surfaces set-but-unreadable `_FILE`). Config tests.
- [ ] **M7** — `internal/config/config.go` (gate `EmbeddedTrustedUpstream` to `ProfileEmbedded`, fail closed elsewhere; struct doc lists loopback CIDRs). New `config_security_test.go`.
- [ ] **L1** — `internal/config/config.go` + `internal/service/auth.go` + `cmd/vault/main.go` (`VAULT_STRICT_SESSION_LIMIT` opt-in fail-closed + audit event). New `auth_session_strict_test.go`.
- [ ] **L2** — `internal/crypto/dpop.go` (4096-bit RSA upper bound). Test in `dpop_test.go`.
- [ ] **L3** — `internal/config/config.go` (require absolute `VAULT_ORIGIN`; dev localhost default; needs `net/url` import). Config table test.
- [ ] **L4** — `internal/middleware/ratelimit.go` (`FailClosed` flag + 503 path; needs `strconv`/`httputil`) + `internal/server/server.go` (set `FailClosed: true` on login/register/passwordReset/TOTP). Test in `ratelimit_test.go`.
- [ ] **L5** — `internal/config/secrets.go` (gate destructive wipe behind `VAULT_SECRET_FILE_CONSUME`; log best-effort failures; add `log` import). New consume tests.
- [ ] **L6** — `internal/adminapi/handler.go` (pass target `id` into the structured audit column for CreateAdmin + RevokeAdmin). Optional audit test.
- [ ] **L7** — `internal/adminapi/handler.go` (clamp LockUser duration to (0, 30d], else 24h default). Clamp test.
