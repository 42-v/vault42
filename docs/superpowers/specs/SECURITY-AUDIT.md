# vault42 0.8.9 — security audit (workflow-driven)

> Dated note: 2026-06-18. Workflow-driven audit. Each finding below was independently verified against the source tree at `/mnt/projects/vault42`. Verdicts (real/severity) reflect adversarial re-review, not just the initial report.

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH     | 2 |
| MEDIUM   | 7 |
| LOW      | 6 |
| INFO     | 0 |
| **Total** | **15** |

---

## HIGH

### H1 — MFA factor downgrade: any challenge-token holder can force email-OTP regardless of enrolled method

- **File:** `/mnt/projects/vault42/internal/handler/email_otp.go:53-72` (Resend); `:24-50` (Verify); enabled by `internal/service/auth.go:710-747` (`doSendEmailOTP`) and `:650-707` (`CompleteMFALogin`)
- **Severity:** HIGH

**Description.** The email-OTP resend/verify endpoints are gated only by a valid `2fa_challenge` token (`authedChallenge`) and never check which MFA methods the user actually enrolled. Login (`auth.go:438-471`) only advertises `email_otp` in `AvailableMethods` when the user has NO TOTP/WebAuthn method AND `MFARequired` is true; for a user whose real second factor is TOTP or a WebAuthn/FIDO2 key the challenge is issued with `AvailableMethods=["totp"]/["webauthn"]` and no email OTP is sent. However, `EmailOTPHandler.Resend` unconditionally calls `SendEmailOTP(claims.Subject, user.Email)` (`email_otp.go:66`) with no method gating, and `doSendEmailOTP` (`auth.go:722-747`) generates and stores an `email_otp:<userID>` code regardless of the user's MFA configuration. `EmailOTPHandler.Verify` then calls `VerifyEmailOTP` + `completeMFAIfChallenge` (`email_otp.go:39-47`), which issues full Bearer tokens. The same applies to the OAuth2 callback challenge (`handler/oauth.go:303-323`), which is also a `2fa_challenge` token. Net effect: the per-account second factor is silently downgradable from a phishing-resistant hardware key / TOTP to a 6-digit email code on every authentication. This defeats the security goal of TOTP/WebAuthn for a vault product, since the second factor's strength is reduced to control of the email inbox.

**Exploit.** Attacker who has the victim's password (so password auth succeeds and a `2fa_challenge` token is returned) and who can read the victim's email — e.g. a shared/compromised mailbox, a forwarding rule, or an already-compromised email account that the hardware key was specifically meant to protect against — calls `POST /auth/2fa/email-otp/resend` with the challenge token, receives the 6-digit code in the victim's inbox, then `POST /auth/2fa/email-otp/verify` with that code. `completeMFAIfChallenge` issues real access+refresh tokens, fully bypassing the victim's enrolled TOTP/WebAuthn factor without ever touching it.

**Fix.** Bind the allowed methods to the challenge. Either (a) embed the `AvailableMethods` list in the challenge token (or in a server-side `challenge_methods:<jti>` cache entry) at issue time, and in Resend/Verify (and the TOTP/backup/webauthn handlers) reject the request when the verified factor is not in that list; or (b) at minimum, in `EmailOTPHandler.Resend`/`Verify` and `doSendEmailOTP`, look up the user's MFA status (`mfaSvc.GetStatus`) and only permit `email_otp` when the user has no stronger method enrolled and `MFARequired` is true — mirroring exactly the gate Login uses at `auth.go:457`.

- [x] fixed — emailOTPAllowed gate (commit) 

---

### H2 — No per-account lockout on MFA verify endpoints — second factor brute-forceable via IP rotation

- **File:** `/mnt/projects/vault42/internal/handler/totp.go:92-155` (TOTP Verify); `email_otp.go:24-50`; `backup_codes.go:83-135`; rate limit at `server/server.go:262-264,349,362,365`
- **Severity:** HIGH

**Description.** All four MFA verify endpoints (TOTP, email-OTP, backup-code, WebAuthn) are protected only by `totpRL`, a per-IP rate limit of 5 requests / 5 minutes (`IPRateLimitKey`, `server.go:262-264`). Unlike the password login path — which enforces BOTH a per-user lockout (`recordFailedAttempt`/`isAccountLocked`, `auth.go:393`/`379`, 5 failures => 15-min account lock) AND a per-IP lockout (`recordFailedIP`/`isIPLocked`, threshold 20) — the second-factor verification has no per-account failure counter at all (grep confirms only `IncrementFailedLogin`/`recordFailedAttempt` exist in the password path). A `2fa_challenge` token is valid for 5 minutes (`token.go:126`) and is not consumed by a failed factor check (challenge single-use only fires on a SUCCESSFUL `CompleteMFALogin`, `auth.go:653-662`). An attacker holding a challenge token can therefore submit unlimited TOTP/backup/email-OTP guesses by rotating source IPs, with the only ceiling being 5 guesses per IP per 5 minutes. TOTP has 3 acceptable codes (±1 skew, `totp.go:54`) out of 10^6, and email-OTP is a single 6-digit code (10^6) re-fetchable via resend; with enough IPs (botnet/proxy pool) the 5-minute window is exploitable.

> Verifier note: confirmed exploitable specifically for **TOTP** (±1 skew = 3 valid codes / 10^6, wrong guess does not consume the secret). Email-OTP is NOT freely brute-forceable — `VerifyEmailOTP` (`auth.go:750-762`) does `GetAndDelete` before the HMAC check, so each wrong guess destroys the code (one guess per resend, sharing the same per-IP budget). Backup codes are 64-bit and WebAuthn is a cryptographic challenge — neither is guessable. The central defect (no per-account lockout + challenge not invalidated on failure + per-IP-only limit defeated by IP rotation) is real.

**Exploit.** Attacker obtains a `2fa_challenge` token (password known, or via the OAuth path). Using a rotating proxy/botnet IP pool, they fan out `POST /auth/2fa/totp/verify` (or `/email-otp/verify` after `/resend`) guesses, ≤5 per IP per 5 min, against the fixed challenge. Because no per-userID failure counter ever increments and the challenge is not invalidated on wrong guesses, the only effective limit is the size of the attacker's IP pool, making the 6-digit second factor brute-forceable within the challenge lifetime.

**Fix.** Add a per-userID failed-MFA counter analogous to the password lockout: in each MFA verify handler (or in `CompleteMFALogin`'s caller path), on a wrong code increment a cache counter `mfa_fail:<userID>` and reject (and ideally revoke the challenge) once it exceeds a small threshold (e.g. 5) within the lockout window — reuse `recordFailedAttempt`/`isAccountLocked` or the existing `CheckAccountLockout` helper. Also invalidate the challenge token (mark its jti consumed) after N failed attempts so a new password authentication is required.

- [ ] fixed

---

## MEDIUM

### M1 — 2FA challenge token's device fingerprint claim is never validated on MFA completion

- **File:** `/mnt/projects/vault42/internal/service/auth.go:650-662` (`CompleteMFALogin`); issuance at `internal/service/token.go:131`; helper at `internal/handler/mfa_helper.go:23-29`
- **Severity:** MEDIUM

**Description.** When a user passes first-factor (password), `IssueChallengeToken` embeds the originating device fingerprint into the challenge JWT (`token.go:131`: `Fingerprint: fingerprint`). That binding is never enforced when the challenge is later redeemed. In `completeMFAIfChallenge` (`mfa_helper.go:23-29`) the request fingerprint `fp` is recomputed from the *current* request and passed to `CompleteMFALogin` only to stamp the NEW refresh token. `CompleteMFALogin` (`auth.go:650`) and the `AuthChallenge` middleware (`middleware/auth.go:46-90`, which only checks sig/iss/aud/exp/type) never compare the request fingerprint against `claims.Fingerprint`. The fingerprint claim is therefore dead weight: the device/network binding the field was added to provide does not exist. (Refresh tokens DO enforce this binding — `auth.go:560` — so the challenge path is the inconsistent, weaker one.)

**Exploit.** Attacker obtains a victim's challenge token (issued in the `LoginResult` JSON body after the victim's password succeeds — e.g. via a leaking proxy/log, an XSS that reads the pre-2FA response, or referrer/history leakage of the SPA state). The 5-minute, single-use challenge token is the only thing standing between password-success and full session, gated by the second factor. The attacker presents the stolen challenge token from a completely different IP/UA/TLS fingerprint to `POST /auth/2fa/email-otp/verify` (or totp/backup-code) and, after supplying the second-factor code, receives a full Bearer + refresh session bound to the ATTACKER's fingerprint. Because the fingerprint claim is ignored, there is no anomaly detection or rejection for the device switch that the claim was specifically designed to catch.

> Verifier note: stealing the challenge token does NOT by itself bypass 2FA — `CompleteMFALogin` is only reached after the second factor verifies. The defect is that the device/network-switch signal the Fingerprint claim was added to detect is never evaluated, and the design is inconsistent with the refresh path that does enforce it. Defense-in-depth / missing-anomaly-detection gap.

**Fix.** In `CompleteMFALogin`, compare the embedded claim against the request fingerprint and reject on mismatch. Plumb `claims.Fingerprint` into the call (e.g. add a `challengeFP string` arg) and add: `if challengeFP != "" && !vaultcrypto.CompareFingerprints(challengeFP, fingerprint) { /* audit FingerprintAnomaly */ return nil, ErrTokenInvalid }`. In `mfa_helper.go` pass `claims.Fingerprint` through. Use the same `CompareFingerprints` helper already used on the refresh path (`auth.go:560`) so the two flows are consistent.

- [ ] fixed

---

### M2 — OAuth2 authorize endpoint has no rate limit, enabling unauthenticated cache-fill amplification

- **File:** `/mnt/projects/vault42/internal/server/server.go:322` (handler at `internal/handler/oauth.go:96`)
- **Severity:** MEDIUM

**Description.** `GET /auth/oauth2/authorize` is registered with a bare `mux.HandleFunc` (`server.go:322`) with no `RateLimit` wrapper, unlike its siblings `GET /auth/oauth2/callback/{provider}` (`loginRL`, line 323) and `POST /auth/oauth2/exchange` (`oauthExchangeRL`, line 324). The Authorize handler writes a cache entry on every request: `h.cache.Set(ctx, "oauth_state:"+nonce, verifier, 10*time.Minute)` (`oauth.go:96`), plus generates two `RandomHex(32)` values and an HMAC. Because the endpoint is fully unauthenticated, an attacker can issue unbounded requests, each persisting a 10-minute entry in the shared cache backend (the same cache used for rate-limit counters, lockout state, OTP signatures, password-reset tokens, and OAuth/exchange codes). At high request volume this is a cache-memory exhaustion / eviction-pressure DoS vector that can degrade or evict security-critical state.

> Verifier note: production Redis uses `allkeys-lru` + universal TTL + fail-soft consumers, so this is eviction PRESSURE (weakening of brute-force/OTP/reset state under sustained flooding), not a hard OOM/crash. The dev in-memory cache is unbounded but not the production path. Still a genuine rate-limiting gap; the cross-contamination with lockout/OTP/reset state keeps it at MEDIUM.

**Exploit.** Loop `GET /auth/oauth2/authorize?provider=google` as fast as possible from one or more hosts. Each hit allocates a fresh `oauth_state:<nonce>` key with a 10-minute TTL. Sustained traffic accumulates hundreds of thousands of live entries, pressuring the cache (e.g. Redis maxmemory eviction or in-process map growth) and potentially evicting/competing with lockout, OTP, and reset-token keys, weakening those controls or causing memory pressure.

**Fix.** Wrap the route in an IP-keyed rate limiter consistent with the other OAuth endpoints, e.g. `mux.Handle("GET /auth/oauth2/authorize", authorizeRL(http.HandlerFunc(oauthHandler.Authorize)))` using `middleware.RateLimit` with `KeyFunc: middleware.IPRateLimitKey` and a tight window (e.g. Limit 10/min). This matches the existing pattern already applied to callback and exchange.

- [ ] fixed

---

### M3 — OAuth login CSRF / session fixation: state is not bound to the initiating browser

- **File:** `/mnt/projects/vault42/internal/handler/oauth.go:68-112` (Authorize), `:136-176` (Callback)
- **Severity:** MEDIUM

**Description.** Authorize sets no cookie. The CSRF defense is an HMAC-signed `state` (`provider.nonce.expiry.sig`) plus a PKCE verifier cached server-globally under `oauth_state:<nonce>`. Nothing ties the in-flight flow to the victim's browser. On Callback, validation is: HMAC verifies (line 153), provider matches and not expired (lines 159-169), and the nonce-keyed verifier exists and is consumed atomically (line 172). All of these are satisfiable by ANY valid state the server itself minted for ANY browser. There is no per-browser secret (e.g. a state value mirrored in an HttpOnly cookie) compared at the callback. This is the classic missing-state-binding OAuth weakness: the `state` proves the server issued it, not that THIS browser started the flow.

**Exploit.** Attacker starts the OAuth flow himself from his own browser and authenticates against his OWN provider account (his Google/GitHub), but does NOT follow the final provider redirect. He captures the resulting callback URL `…/auth/oauth2/callback/google?state=<valid>&code=<attacker-code>`. Because state is HMAC-valid and the nonce->verifier entry is still live (10 min TTL) and unconsumed, he tricks a victim into loading that URL (img/link/auto-submit). The victim's browser hits Callback, the code is exchanged for the ATTACKER's identity, and `setRefreshCookie` (line 361) plants a refresh-token cookie for the attacker's account into the victim's browser. The victim is now silently logged into the attacker's account; anything the victim then saves (vault entries, notes, MFA enrollment, payment info) lands in the attacker-controlled account he can later log back into — a session-fixation / account-confusion attack. The same primitive also lets an attacker force-link his social identity onto flows in a victim's session.

> Verifier note: the fingerprint defense does NOT mitigate this — the fingerprint is computed from the victim's request and bound to the attacker-account tokens, so the planted refresh token refreshes cleanly. `docs/spec.md:854` lists the only OAuth-CSRF mitigation as "HMAC-signed state parameter with expiry" — exactly the control shown to be insufficient. MEDIUM because it needs user interaction with a delivered live callback URL within the 10-min window and an unconsumed provider code; damage model is account-confusion/data-misdirection.

**Fix.** Bind the flow to the browser. In Authorize, generate a random CSRF token, set it as a short-lived HttpOnly+Secure+SameSite=Lax cookie (Lax, not Strict, so it survives the provider's top-level redirect back), and include its hash inside the signed state payload (e.g. `provider.nonce.expiry.csrfHash`). In Callback, read the cookie, recompute the hash, and constant-time-compare it against the value embedded in state before doing the code exchange; reject and clear the cookie on mismatch or absence. This ensures the callback can only complete in the same browser that initiated Authorize.

- [ ] fixed

---

### M4 — TLSEnabled=true with no cert silently serves plaintext HTTP; config never validates cert presence

- **File:** `/mnt/projects/vault42/internal/config/config.go:264-266,396-439` (`Load`); consumed at `internal/server/server.go:160-164`
- **Severity:** MEDIUM

**Description.** `Load()` defaults `TLSEnabled` to true (via `setDefaultBool` in `applyProductionDefaults`, `profiles.go:104`) but leaves `TLSCertFile`/`TLSKeyFile` empty by default (`config.go:265-266`) and never validates that an enabled-TLS config actually has cert+key. The downstream server (`internal/server/server.go:160`) only serves TLS when `cfg.TLSEnabled && cfg.TLSCertFile != ""` — otherwise it silently falls back to plaintext `ListenAndServe()`. Notably the sibling admin-gateway DOES fail closed (`cmd/admin-gateway/config.go:95-100` returns an error if the cert/key path is missing), so the main JWT auth server is the outlier. Empirically, a production-profile `Load()` with no `TLS_*_FILE` set produces `TLSEnabled=true` and empty cert paths, which means the server boots on cleartext HTTP. Because `secureCookies := cfg.TLSEnabled || cfg.ForceSecureCookies` (`server.go:178`) is still true, the server also believes it is secure and sets the Secure cookie flag while actually serving over HTTP.

> Verifier note: the canonical Helm deployment is not exposed — `configmap.yaml:14` always sets `VAULT_TLS_ENABLED` explicitly (defaults false, TLS terminates at Cloudflare Tunnel/ingress) and instructs `forceSecureCookies=true`. The exploit manifests when run outside the chart (bare `docker run`) or via a chart misconfig (`tls.enabled=true` with empty `certFile`). Real fail-open default + confirmed inconsistency with admin-gateway; MEDIUM.

**Exploit.** An operator deploys with `VAULT_PROFILE=production` and forgets (or fat-fingers) `VAULT_TLS_CERT_FILE`/`VAULT_TLS_KEY_FILE`. The server comes up healthy on plaintext :8443 instead of refusing to boot. JWT access/refresh tokens, login credentials, TOTP codes, and OAuth state traverse the wire in cleartext; an on-path attacker (same L2 segment, malicious sidecar, misrouted ingress) captures session tokens and replays them. There is no startup error to alert the operator.

**Fix.** In `config.Load()`, after `applyProfileDefaults`, fail closed: `if c.TLSEnabled && !c.ForceSecureCookies && (c.TLSCertFile == "" || c.TLSKeyFile == "") { return nil, fmt.Errorf("VAULT_TLS_ENABLED=true requires VAULT_TLS_CERT_FILE and VAULT_TLS_KEY_FILE") }`. (`ForceSecureCookies` is the documented escape hatch for TLS-terminating proxies; allow plaintext only when it is explicitly set.) Mirror the admin-gateway's existing required-cert check.

- [ ] fixed

---

### M5 — VAULT_TLS_ENABLED=false silently disables TLS in production; behavior contradicts the documented 'cannot be disabled' guarantee

- **File:** `/mnt/projects/vault42/internal/config/profiles.go:104` (`setDefaultBool`), `:123-137` (impl); `config.go:264`
- **Severity:** MEDIUM

**Description.** `setDefaultBool` uses `os.LookupEnv` and `strconv.ParseBool`, so `VAULT_TLS_ENABLED=false` IS honored and overrides the profile default of true in every profile — including production. Empirically: production + `VAULT_TLS_ENABLED=false` yields `cfg.TLSEnabled=false`. However `docs/config.md:87` explicitly tells operators the opposite: "setting this to false via env var has no effect ... all profiles default it to true and setDefaultBool cannot distinguish unset from explicitly false. To disable TLS, modify the profile code." The code and the security documentation disagree about whether TLS can be turned off by an env var. This is a security-relevant footgun: an operator (or a compromised/injected env var, or a copy-pasted dev override) can flip a production deployment to plaintext, and the documentation actively reassures them this is impossible.

> Verifier note: the doc is the artifact that's wrong — `setDefaultBool` was written with `os.LookupEnv` specifically to distinguish unset from explicit-false, and the code comment states this intent. With TLS off, `secureCookies` tracks `TLSEnabled` so the Secure cookie flag also drops. Requires environment control to trigger; MEDIUM.

**Exploit.** An attacker who can influence environment (leaked Helm values, a misapplied dev `.env`, a supply-chain env injection, or simply an operator copying a dev snippet) sets `VAULT_TLS_ENABLED=false` on a production pod. The auth server serves cleartext HTTP and, because `secureCookies` tracks `TLSEnabled`, also drops the Secure cookie flag — exposing all auth tokens to network capture. Operators auditing against the docs would wrongly conclude the setting is inert.

**Fix.** Decide on one behavior and make code + docs agree. Safer: in production/honeypot profiles, refuse to honor `TLSEnabled=false` unless an explicit acknowledgement var (e.g. `VAULT_ALLOW_PLAINTEXT=true`) is set — e.g. after `applyProfileDefaults`: `if c.Profile == ProfileProduction && !c.TLSEnabled && !envBool("VAULT_ALLOW_PLAINTEXT") { return nil, fmt.Errorf("refusing to disable TLS in production") }`. At minimum, correct `docs/config.md:87` so operators know the toggle is live.

- [ ] fixed

---

### M6 — No validation that HMAC secret / pepper are present in production; empty values silently weaken signing and password hashing

- **File:** `/mnt/projects/vault42/internal/config/config.go:430-436` (HMAC length guard), `:441-481` (`loadSecrets`)
- **Severity:** MEDIUM

**Description.** The only HMAC validation in `Load()` is `if len(c.HMACSecret) > 0 && len(c.HMACSecret) < 32` (`config.go:431`) — it is skipped entirely when the secret is absent. `loadSecrets()` populates `HMACSecret`/`Pepper`/`MasterKey` only if the corresponding `_FILE` is set, and any `LoadSecret` error is swallowed (the `if ...; err == nil` pattern). There is no fail-closed in config or in `cmd/vault/main.go` for a missing `HMACSecret` or `Pepper`. A production-profile `Load()` with no secret files succeeds with `HMAClen=0`, `Pepperlen=0`. Downstream, `crypto.HMACSign` (`internal/crypto/hmac.go:11`) calls `hmac.New(sha256.New, key)` with no key-length check, so an empty key signs backup codes, OAuth state, and identity/blob HMACs. `crypto.applyPepper` (`internal/crypto/argon2.go:113`) silently no-ops when pepper is empty, so passwords are Argon2-hashed with NO server-side pepper. Both degrade security with zero diagnostics. (`MasterKey` is the one secret that does fail closed downstream — `crypto/aes.go:21` rejects non-32-byte keys — so encryption errors at runtime; HMAC and pepper do not.)

> Verifier note: confirmed fail-open. The clean attacker win is the missing pepper enabling offline password cracking after a DB-only compromise; empty-HMAC OAuth-state forgery alone is partially blunted by the PKCE verifier cache keyed by nonce. Operator-misconfiguration-gated (wrong/unset `_FILE` path); shipped deploy artifacts wire the secrets. MEDIUM.

**Exploit.** Operator omits `HMAC_SECRET_FILE` / `VAULT_PEPPER_FILE` (or the `_FILE` path is wrong and the swallowed `LoadSecret` error hides it). Server boots normally. With an empty HMAC key, an attacker who knows/guesses the key is empty can forge OAuth state tokens (CSRF on the social-login flow) and backup-code or identity/blob HMAC signatures. With an empty pepper, a database-only compromise lets the attacker crack password hashes offline — defeating the exact protection `applyPepper`'s own comment promises.

**Fix.** In `config.Load()`, for non-dev profiles require the critical secrets and fail closed: `if c.Profile != ProfileDev { if len(c.HMACSecret) < 32 { return nil, errors.New("HMAC_SECRET_FILE required (>=32 bytes)") }; if c.Pepper == "" { return nil, errors.New("VAULT_PEPPER_FILE required") } }`. Also stop swallowing `LoadSecret` errors silently in `loadSecrets` — distinguish 'not set' from 'set but unreadable' and surface the latter.

- [ ] fixed

---

### M7 — EmbeddedTrustedUpstream auto-trusts all RFC1918 + loopback and X-Forwarded-For in any profile, not just embedded

- **File:** `/mnt/projects/vault42/internal/config/config.go:306` (`envBool`, profile-independent), `:406-420` (auto-fill)
- **Severity:** MEDIUM

**Description.** `VAULT_EMBEDDED_TRUSTED_UPSTREAM` is read via `envBool` unconditionally (`config.go:306`) and the auto-fill block (`config.go:406-420`) runs regardless of profile. When set, it populates `TrustedProxies` with `10/8, 172.16/12, 192.168/16, fc00::/7, 127.0.0.0/8, ::1/128` and forces `RealIPHeader=X-Forwarded-For`. This activates in the production profile. Two concerns: (1) it is not gated to `ProfileEmbedded` despite the name and the struct doc describing it as 'typical of embedded deployments'; (2) the auto-trusted set silently includes loopback ranges (`127.0.0.0/8, ::1/128`) that are NOT listed in the struct doc comment at `config.go:145-146` (which only mentions RFC1918 + IPv6 ULA), so an operator reading the doc under-estimates what they trust. These ranges feed `ClientIP()`/X-Forwarded-For parsing used for rate-limit keying and audit attribution (consumed in `internal/middleware`, `internal/handler/*`).

> Verifier note: confirmed off by default, opt-in, and set in ZERO deploy artifacts. When enabled in a flat network it genuinely collapses XFF-based per-IP rate-limit/IP-wide-lockout/audit attribution. Per-USER lockout (keyed by user.ID) survives. Latent footgun → MEDIUM.

**Exploit.** In a flat or partially-flat network (or any deployment where an attacker can reach the pod from an RFC1918 source, e.g. a compromised neighbor pod/container without strict NetworkPolicy), the attacker sets X-Forwarded-For to an arbitrary IP. vault42 trusts it because the direct source is within the auto-trusted private ranges. The attacker then rotates the spoofed client IP per request to evade per-IP rate limiting on `/auth/login` (credential stuffing / brute force) and to poison audit-log attribution, framing arbitrary IPs.

**Fix.** Gate the shortcut to the embedded profile (`if c.EmbeddedTrustedUpstream && c.Profile == ProfileEmbedded`), or require it to be paired with an explicit acknowledgement in production. Remove loopback from the auto-set unless documented, and update the struct doc (`config.go:145-146`) to list every CIDR actually trusted (currently it omits `127.0.0.0/8` and `::1/128`).

- [ ] fixed

---

## LOW

### L1 — checkSessionLimit fails open on cache/count error, allowing the concurrent-session cap to be bypassed

- **File:** `/mnt/projects/vault42/internal/service/auth.go:902-915`
- **Severity:** LOW

**Description.** `checkSessionLimit` returns nil (allow login) whenever `tokens.CountActiveFamilies` returns an error (`auth.go:907-910`, "fail open — don't block login if the count query fails"). The `maxSessionsPerUser` control (used to cap concurrent refresh-token families per user) is therefore disabled whenever the underlying count query errors, e.g. during a DB hiccup or if an attacker can induce query failures. This is an availability-vs-security tradeoff but it silently removes a control that may be relied on for session-hijack containment.

> Verifier note: intentional, documented, and unit-tested fail-open on a defense-in-depth/hygiene control. Trigger is not attacker-controllable (parameterized indexed COUNT on the user's own ID) and the window is largely self-limiting (a full DB outage also fails the refresh-token INSERT, aborting login). LOW.

**Exploit.** Under DB load or a transient repository error, `CountActiveFamilies` errors and every Login / `CompleteMFALogin` proceeds without enforcing `maxSessionsPerUser`, letting a single account (e.g. a compromised credential being widely shared) open unlimited concurrent sessions during the degraded window.

**Fix.** If `maxSessionsPerUser` is a security control rather than a soft UX limit, fail closed (return a 503-style error) on count failure, or at least emit a high-severity audit/metric so the bypass is observable. If fail-open is intentional, document the accepted risk explicitly at the call sites (Login `auth.go:475`, `CompleteMFALogin` `auth.go:664`) and gate it behind a config flag so deployments that need hard enforcement can opt in.

- [ ] fixed

---

### L2 — DPoP jwk header accepts arbitrarily large RSA keys (no upper bound) → algorithmic-complexity DoS

- **File:** `/mnt/projects/vault42/internal/crypto/dpop.go:184` (RSA branch of `parseJWKHeader`); reached from `ValidateDPoPProof` at `dpop.go:64` and the self-signed verify at `dpop.go:71-76`
- **Severity:** LOW

**Description.** `parseJWKHeader` enforces only a *minimum* RSA modulus size (`if n.BitLen() < 2048`) for keys embedded in the attacker-controlled DPoP `jwk` header. There is no maximum. The DPoP proof is self-signed: the signature at `dpop.go:71-76` is verified with the public key the attacker themselves placed in the header, so the attacker fully controls the modulus size. `DPoPMaxSize` is 4 KiB (`dpop.go:23`). `rsa.VerifyPKCS1v15` (`internal/jwt/rs256.go:27`) performs a modular exponentiation whose cost grows ~quadratically with the modulus bit length, so verifying one large-modulus signature is far slower than a 2048-bit one. The verification runs inside the argon2-independent DPoP path with no per-request CPU budget. DPoP middleware (`internal/middleware/dpop.go:48`) sits behind the challenge-token middleware on the 2FA-verify endpoints, so it is reachable by any client holding a (cheap-to-obtain) challenge token; the signature verification happens before the JTI replay cache write, so replay-suppression does not blunt repeated distinct proofs.

> Verifier note: magnitude is overstated. The 4 KiB whole-JWT cap (signature is itself modulus-width, base64-inflated) rejects keys above ~9700-bit; realistic worst case is ~1.5-2 ms/verify (~30-40x, not 100x). Feature is off by default (`VAULT_DPOP_ENABLED`), and `totpRL` runs BEFORE the verify on the main 2FA endpoints. Residual concern: the WebAuthn verify endpoints lack the `totpRL` wrapper. Genuine missing-upper-bound; LOW.

**Exploit.** Obtain a challenge token (start a normal 2FA flow). For each request, generate a fresh huge-modulus RSA keypair, build a DPoP proof JWT with that key in the `jwk` header, valid `htm`/`htu`/`iat`/unique `jti`, and a correct RS256 self-signature. Send to a DPoP-protected endpoint. Each request forces a multi-millisecond RSA verification on the server; a handful of concurrent attackers (especially against the unthrottled WebAuthn verify path) saturate CPU and starve legitimate auth traffic (the pod is memory-budgeted at 512 MiB and argon2 is already concurrency-capped at 4, so CPU is the scarce resource).

**Fix.** Add an upper bound on the embedded RSA modulus in `parseJWKHeader`, e.g. after the existing `n.BitLen() < 2048` check add `if n.BitLen() > 4096 { return nil, errors.New("RSA key too large") }`. 3072/4096 covers every legitimate client. Mirror the same bound anywhere else attacker-supplied RSA JWKs are parsed, and rate-limit the WebAuthn verify endpoints.

- [ ] fixed

---

### L3 — No startup validation that VAULT_ORIGIN is non-empty disables JWT issuer/audience binding

- **File:** `/mnt/projects/vault42/internal/server/server.go:210-214` (also `internal/jwt/validate.go:50-69`, `internal/config/config.go:261`)
- **Severity:** LOW

**Description.** The Auth/AuthChallenge middleware is wired with `cfg.Origin` used as BOTH the expected issuer and audience: `middleware.Auth(d.Keys, cfg.Origin, cfg.Origin)` (`server.go:213`) / `middleware.AuthDynamic(... cfg.Origin, cfg.Origin)` (`server.go:210`). `cfg.Origin` comes straight from `os.Getenv("VAULT_ORIGIN")` (`config.go:261`) and there is NO `Validate()` / required-field check anywhere in `config.go` or `cmd/vault/main.go`. In `internal/jwt/validate.go`, issuer validation is gated on `if cfg.expectedIssuer != ""` (line 50) and audience validation on `if cfg.expectedAud != ""` (line 57). So if `VAULT_ORIGIN` is unset/empty, both iss and aud checks are silently skipped. The same empty Origin is also used to sign tokens (`main.go:199`), so this is a misconfiguration-amplifier rather than a direct cross-tenant bypass with the current single signing key, but it removes a defense and the code provides zero guardrail against it.

> Verifier note: the claimed token-confinement impact does NOT hold in this codebase — access and challenge tokens share the same audience and confinement is enforced by the separate `TokenType` claim + `allowed` map (independent of aud); refresh tokens are opaque (no aud); honeypot fake-JWTs are random-signature and rejected at signature verification regardless of iss/aud. Real defect = missing fail-fast on empty `VAULT_ORIGIN` (also breaks CORS, JWKS issuer, cookie domain, OAuth callback URLs, WebAuthn RPID), mitigated in practice by the Helm chart shipping a default origin. LOW.

**Exploit.** Operator deploys without `VAULT_ORIGIN` (or with it empty). Service starts normally (no fatal). All tokens are now signed and validated with empty iss/aud, so the iss check that would catch tokens from a different issuer is a no-op and aud binding is absent — removing a defense layer should a second issuer/audience or signing component ever be introduced.

**Fix.** Fail fast at startup: in config load (`config.go`) or `cmd/vault/main.go`, return/`log.Fatal` if `cfg.Origin == ""` (and ideally if it does not `url.Parse` to an absolute scheme+host). Additionally, make JWT validation reject empty expected issuer/audience as a programming error rather than silently skipping, OR have `authWithTypes` refuse to construct when issuer/audience is empty.

- [ ] fixed

---

### L4 — Rate-limit local fallback is per-process and per-middleware-instance, allowing limit multiplication across pods on cache failure

- **File:** `/mnt/projects/vault42/internal/middleware/ratelimit.go:166-187`
- **Severity:** LOW

**Description.** When the distributed cache errors, `RateLimit` falls back to an in-memory `localRateLimiter` created once per `RateLimit()` call (line 166) and stored only in this process's memory (`local.increment`, line 186). vault42 shares one signing key across pods for horizontal scaling (see `crypto/jwt.go:48-49` comment), so under cache outage each pod counts independently. With N pods the effective login/register/reset limit becomes N times the configured value (e.g. login 5/15min becomes 5*N), substantially weakening brute-force / credential-stuffing protection precisely during a cache incident. This is a documented degradation choice (fail-open vs fail-closed), so severity is LOW, but it is a real and quantifiable weakening of the lockout posture on the security-sensitive login/password-reset/TOTP limiters.

> Verifier note: the rate limiter is a secondary throttle; the primary brute-force control is the service-level per-user (5/15min) + per-IP (20/15min) lockout in `auth.go`, which has a separate cross-pod-consistent fallback (DB-backed) when `s.cache == nil` and so does not pod-multiply. Nuance: during a *transient* cache error (not `nil` cache), `isAccountLocked`/`isIPLocked` fail open entirely — documented fail-open posture. Real but minor; LOW.

**Exploit.** During a cache (Redis/Postgres) outage, an attacker spreads brute-force login attempts across the load-balanced pods. Each pod enforces only its local 5/15min budget, so total allowed attempts scale with pod count, accelerating password guessing while monitoring may still report 'rate limiting active'.

**Fix.** On cache failure for security-critical limiters (login, register, password reset, TOTP), prefer fail-closed (reject with 429/503) rather than fall back to a per-pod in-memory counter; or make the fallback shared/sticky (consistent-hash the key to a single pod) and alert loudly. At minimum, make the fail-open-vs-closed behavior configurable per limiter and default the auth-sensitive ones to closed.

- [ ] fixed

---

### L5 — LoadSecret destroys the operator's secret file and swallows the zeroing error, undermining the stated defense-in-depth guarantee

- **File:** `/mnt/projects/vault42/internal/config/secrets.go:22-24`
- **Severity:** LOW

**Description.** `LoadSecret` overwrites the secret file with zeros (`os.WriteFile` mode `0o400`) and then `os.Remove()`s it, with both errors discarded (`_ =`). On a read-only secret mount (the common Kubernetes Secret/tmpfs case) both calls fail silently, so the 'zero + delete' defense-in-depth never actually happens — yet the comment and the code claim it does. Conversely, if `_FILE` points at a writable real file (a bind-mounted host keyfile, a shared sops/age-decrypted file, or a misconfigured path), `LoadSecret` silently destroys the original on first read; after a pod restart the secret is gone and the service cannot recover. Because the error is swallowed, the operator gets no signal either way.

> Verifier note: the canonical deployment mounts secrets read-only (K8s `secret:` volume on tmpfs + `readOnlyRootFilesystem`), so both ops are harmless no-ops on the as-shipped path — the wipe is dead code and `docs/cheatsheet.md:369` ("File is zeroed after reading") is a false assurance. The destructive arm only applies to non-default writable mounts. Not attacker-exploitable; LOW.

**Exploit.** Not directly attacker-exploitable, but a real foot-gun: (a) operators believe secrets are wiped from disk post-read when on a read-only mount they are not (false sense of security); (b) a writable-mount misconfiguration leads to silent secret destruction and an availability failure that is hard to diagnose because the zeroing/remove errors are dropped.

**Fix.** Make the destructive behavior opt-in (e.g. only zero+remove when an explicit `VAULT_SECRET_FILE_CONSUME=true` is set), and at minimum log at debug/warn when `WriteFile`/`Remove` returns an error so operators learn the defense-in-depth step did not run. Keep `#nosec` annotations but don't silently discard both outcomes.

- [ ] fixed

---

### L6 — Admin lifecycle audit events omit the structured target-ID column (audit completeness gap)

- **File:** `/mnt/projects/vault42/internal/adminapi/handler.go:765-769,802-804`
- **Severity:** LOW

**Description.** `CreateAdmin` and `RevokeAdmin` write audit entries via `auditLog.Log(...)` but pass an empty string for the 3rd positional argument (clientID/target column in `audit.Logger.Log`, `audit.go:164`). The identity of the admin being created/revoked is only stored inside the free-form Metadata map (`new_admin_id` / `revoked_admin_id`), never in the dedicated indexed target field. By contrast, client lifecycle ops (`RevokeClient` `handler.go:532`, `CreateClient` `handler.go:507`, `RotateClientSecret` `handler.go:571`) correctly populate that column with the client id. Because `QueryAudit` (`handler.go:351`) filters on UserID/EventType but not on free-form metadata, an investigator cannot reliably query 'all events targeting admin X' for the most security-sensitive object class (other admins). This is a forensic/traceability gap, not an authz hole: the actor and target are still recorded somewhere, and all admin-management routes remain RBAC-gated (`AdminsCreate`/`AdminsRevoke` = super_admin only, `router.go:78-79`).

> Verifier note: confirmed inconsistency; the query gap is actually broader (no target/client_id filter exists for ANY object class, and client_id is unindexed). No missing log, no authz bypass — action is still attributable via event_type + metadata. Borderline INFO; LOW.

**Exploit.** A malicious or compromised super_admin creates a backdoor admin account and later revokes a legitimate one. During incident response the responder filters `auth.audit_log` by the target admin's UUID using the indexed target column and finds nothing, because the id only lives inside the JSON metadata blob, slowing or defeating attribution of the privilege change.

**Fix.** Pass the target admin id as the structured target argument, e.g. `h.auditLog.Log(ctx, audit.AdminAccountCreate, creator.ID, id, r.RemoteAddr, ...)` in `CreateAdmin` and `h.auditLog.Log(ctx, audit.AdminAccountRevoke, actor.ID, id, ...)` in `RevokeAdmin`, mirroring the client handlers, so the target is queryable via the indexed column rather than only free-form metadata. Consider adding a target/client_id filter + index to `AuditFilter`.

- [ ] fixed

---

### L7 — LockUser accepts an unbounded, caller-controlled lock duration

- **File:** `/mnt/projects/vault42/internal/adminapi/handler.go:249-260`
- **Severity:** LOW

**Description.** `LockUser` decodes a JSON body field `duration` and feeds it directly to `time.ParseDuration` with no upper bound, then locks the target end-user until `now+dur`. An operator (`UsersLock` is granted to operator+, `rbac.go:71`) can therefore lock a user account for an arbitrarily long period (e.g. `'8760000h'`). There is no maximum-duration clamp and no minimum either (a tiny/negative-effective value just falls back to 24h on parse error, but very large positive values are honored). The blast radius is limited: it requires an authenticated operator behind mTLS+loopback, and only affects end-user accounts (not admins), and an unlock path exists. It is a robustness/abuse-of-privilege issue rather than a privilege boundary break.

> Verifier note: grants essentially no new capability — an operator already holds lock+unlock and could re-lock in a loop for the same indefinite-DoS effect. Admin-gateway is loopback-only + mTLS, and every lock is audited (`audit.AdminUserLock` with target_user + until). Hardening nit; LOW.

**Exploit.** A lower-privileged but malicious operator account issues `POST /admin/users/{id}/lock` with `{"duration":"1000000h"}`, effectively permanently locking a target end user out of the vault. The action is recoverable only by another operator/super_admin noticing and calling unlock; meanwhile the victim is denied service indefinitely.

**Fix.** Clamp the parsed duration to a sane maximum (and a positive minimum) before applying, e.g. `if dur <= 0 || dur > 30*24*time.Hour { dur = 24 * time.Hour }` (or return 400 `invalid_duration`), so a single privileged call cannot impose an effectively permanent lock.

- [ ] fixed
