# JWT & Auth Attack Cheatsheet

Living document. Every attack vector here MUST have a corresponding test in `tests/attack/`, `tests/compliance/`, or `tests/unit/`. If it doesn't, write one.

---

## 1. JWT Token Attacks

### 1.1 Algorithm Confusion (CVE-2015-9235)

**Attack:** Change `alg` header from RS256 to HS256, sign with the public key as HMAC secret. Server verifies with the same public key and accepts.

**Defense:** Whitelist `alg` -- only accept RS256. Reject everything else at parse time.

**Test:** `tests/attack/alg_confusion_test.go` -- TestAlgConfusion

### 1.2 Algorithm None (CVE-2015-9235)

**Attack:** Set `alg: none` (or `None`, `NONE`, `nOnE`), strip signature. Libraries that honor `alg` from the header will skip verification.

**Defense:** Never trust `alg` from the token. Enforce RS256-only via `jwt.WithValidMethods`.

**Test:** `tests/attack/alg_none_test.go` -- TestAlgNone

### 1.3 Null/Empty Signature

**Attack:** Keep `alg: RS256` but set the signature segment to empty or a single `.`. Some parsers split on `.` and don't validate the third segment.

**Defense:** Parser rejects tokens with missing or empty signature.

**Test:** `tests/attack/null_signature_test.go` -- TestNullSignature

### 1.4 Key ID (kid) Injection

**Attack:** Set `kid` to path traversal (`../../../etc/passwd`), SQL injection (`' OR 1=1 --`), or URL (`https://evil.com/key.pem`). If the server uses `kid` to load a key from filesystem or database, the attacker controls which key is used.

**Defense:** Validate `kid` is UUID-format only (hex + dashes, max 64 chars). Look up keys only from an in-memory map or database by exact match. Never construct file paths from `kid`.

**Test:** `tests/attack/kid_injection_test.go` -- TestKIDPathTraversal

### 1.5 Header Injection (jku/x5u/x5c/jwk)

**Attack:** Add `jku` (JWK Set URL), `x5u` (X.509 URL), `x5c` (X.509 chain), or `jwk` (embedded key) headers pointing to attacker-controlled keys.

**Defense:** Reject any token containing `jku`, `x5u`, `x5c`, or `jwk` headers. Keys loaded only from local JWKS.

**Test:** `tests/attack/alg_none_test.go` (header validation in ParseAndValidate)

### 1.6 Expired Token Replay

**Attack:** Capture a valid JWT and replay it after expiration.

**Defense:** Enforce `exp` claim validation. Use short TTLs (5-15 min for access tokens).

**Test:** `tests/attack/expired_token_test.go` -- TestExpiredTokens

### 1.7 Future `nbf` (Not Before) Bypass

**Attack:** Create token with `nbf` far in the future, hoping servers don't validate it.

**Defense:** Enforce `nbf` claim validation.

**Test:** `tests/attack/future_nbf_test.go` -- TestFutureNBF

### 1.8 Missing Required Claims

**Attack:** Omit `exp`, `iss`, `aud`, `sub`, or other required claims. If the server doesn't check for their presence, the token may be accepted with no expiration or wrong scope.

**Defense:** Require all claims: `exp`, `iss`, `aud`, `sub`, `iat`. Reject tokens missing any of them.

**Test:** `tests/attack/missing_claims_test.go` -- TestMissingClaims

### 1.9 Wrong Issuer / Wrong Audience

**Attack:** Use a valid token from a different service (same key infrastructure) but with wrong `iss` or `aud`.

**Defense:** Validate `iss` and `aud` match expected values exactly.

**Tests:** `tests/attack/wrong_issuer_test.go`, `tests/attack/wrong_audience_test.go`

### 1.10 Oversized JWT (DoS)

**Attack:** Send a multi-megabyte JWT to exhaust parser memory or CPU.

**Defense:** Enforce max JWT size (8KB) before parsing.

**Test:** `tests/attack/oversized_jwt_test.go` -- TestOversizedJWT

### 1.11 JWKS Confusion / Key Rollover

**Attack:** During key rotation, if the old key is removed too quickly, valid tokens become invalid. If old keys linger too long, compromised keys remain trusted.

**Defense:** Overlap rotation window. Keep old keys in JWKS for at least `access_token_ttl` after rotation. Look up by `kid`, not by position.

**Test:** TODO -- test JWKS rotation overlap window

### 1.12 JWT Claim Type Confusion

**Attack:** Send `"roles": "admin"` (string) instead of `"roles": ["admin"]` (array). If deserialization is loose, the string may be treated as a single-element array.

**Defense:** Strict JSON typing in claims struct. `Roles []string` -- if the JSON has a string, deserialization fails.

**Test:** `tests/attack/jwt_type_confusion_test.go` -- TestJWT_RolesAsString, TestJWT_RolesAsObject, TestJWT_RolesAsNull

---

## 2. Authentication Attacks

### 2.1 User Enumeration via Timing

**Attack:** Measure response time difference between "user exists" (runs Argon2id) and "user doesn't exist" (returns immediately). The timing delta reveals whether an account exists.

**Defense:** Pre-computed dummy hash. When user is not found, run `VerifyPassword(password, dummyHash)` to burn the same CPU time as a real verification.

**Tests:** `tests/attack/timing_attack_test.go`, `tests/compliance/nist_800_63b_test.go` -- TestNIST_DummyHashTimingProtection

### 2.2 User Enumeration via Error Messages

**Attack:** Different error messages for "user not found" vs "wrong password" reveal account existence.

**Defense:** Identical error response for both cases: `{"error": "invalid_credentials"}`.

**Test:** `tests/compliance/nist_800_63b_test.go` -- TestNIST_DummyHashTimingProtection

### 2.3 Brute Force / Credential Stuffing

**Attack:** Automated login attempts with leaked credential lists.

**Defense:** Account lockout after N failed attempts (configurable threshold). Rate limiting per IP. Require CAPTCHA after threshold.

**Tests:** `tests/compliance/owasp_asvs_test.go` -- TestASVS_V2_2_1_AccountLockoutMechanism, `tests/attack/totp_replay_test.go` -- TestTOTPBruteForce

### 2.4 Password Spraying

**Attack:** Try one common password against many accounts (avoids per-account lockout).

**Defense:** Global rate limiting per IP across all accounts. HIBP breach check on registration rejects known-compromised passwords.

**Test:** `tests/attack/password_breach_test.go`

### 2.5 Credential Replay

**Attack:** Intercept and replay authentication credentials.

**Defense:** TLS everywhere. Fingerprint-bound tokens (IP + User-Agent + Accept-Language + TLS fingerprint). Refresh tokens are single-use with replay detection.

**Test:** `tests/attack/fingerprint_mismatch_test.go`

---

## 3. Session & Token Management Attacks

### 3.1 Refresh Token Replay

**Attack:** Steal a refresh token and use it to mint new access tokens indefinitely.

**Defense:** Single-use refresh tokens with family tracking. When a replayed refresh token is detected, the entire token family is revoked (nuclear option). Tokens stored as SHA-256 hashes, not plaintext.

**Tests:** `tests/compliance/nist_800_63b_test.go` -- TestNIST_RefreshTokenHashedStorage; `tests/compliance/nist_integration_test.go` -- TestNIST_RefreshTokenFamilyReplay

### 3.2 Session Fixation

**Attack:** Set a known session ID before authentication, then hijack the session after the victim authenticates.

**Defense:** Generate new tokens on every authentication. Never accept session tokens from the client pre-authentication.

**Test:** `tests/compliance/owasp_asvs_test.go` -- TestASVS_V3_2_1_NewTokenOnAuth

### 3.3 Cookie Theft (XSS → Token Exfiltration)

**Attack:** XSS in the application steals cookies containing refresh tokens.

**Defense:** `HttpOnly` (no JS access), `Secure` (HTTPS only), `SameSite=Strict` (no cross-site sending), `Path=/auth` (minimal scope).

**Test:** `tests/compliance/owasp_asvs_test.go` -- TestASVS_V3_4_CookieSecurityAttributes

### 3.4 Cross-Site Request Forgery (CSRF)

**Attack:** Attacker's page sends authenticated requests using the victim's cookies.

**Defense:** `SameSite=Strict` cookies prevent cross-origin sending. Fingerprint binding provides defense-in-depth (attacker's IP/UA differs).

**Test:** Cookie attributes tested in compliance suite

### 3.5 Fingerprint Binding Bypass

**Attack:** Attacker obtains a valid access token but uses it from a different IP/device.

**Defense:** SHA256(IP + User-Agent + Accept-Language + TLS fingerprint) embedded in token. Server recomputes and compares on every request. Constant-time comparison prevents timing leaks.

**Tests:** `tests/attack/fingerprint_mismatch_test.go` -- TestFingerprintMismatch, TestFingerprintConstantTime

---

## 4. Cryptographic Attacks

### 4.1 Argon2id Parameter Manipulation

**Attack:** Inject a hash with extreme parameters (`m=99999999,t=999`) into the database. Next login attempt causes OOM or multi-second blocking.

**Defense:** Upper bounds on parsed Argon2id parameters: memory <= 128 MiB, iterations <= 10, parallelism <= 4. Reject hashes exceeding these.

**Test:** `tests/compliance/nist_800_63b_test.go` -- TestNIST_Argon2idParameters

### 4.2 Argon2id Timing Leak on Malformed Hash

**Attack:** Send malformed hash format -- if parsing fails fast before Argon2id runs, the timing difference reveals whether the hash was valid format.

**Defense:** On parse error, still run `argon2.IDKey` with a dummy salt to consume the same time.

**Test:** `tests/attack/timing_attack_test.go` -- TestTimingAttackMalformedHash

### 4.3 AES-GCM Nonce Reuse

**Attack:** If two plaintexts are encrypted with the same key and nonce, XOR of ciphertexts reveals XOR of plaintexts (catastrophic for GCM).

**Defense:** Generate random 12-byte nonce for every encryption. Never reuse.

**Test:** `tests/compliance/owasp_asvs_test.go` -- TestASVS_V6_2_6_AESGCMNonceUniqueness

### 4.4 AES Key Length Enforcement

**Attack:** Accept a 16-byte key for "AES-256" -- actually AES-128, weaker than expected.

**Defense:** Reject any key that isn't exactly 32 bytes.

**Test:** `tests/compliance/nist_800_63b_test.go` -- TestNIST_AES256KeyLengthEnforced

### 4.5 AES Ciphertext Tampering

**Attack:** Flip bits in AES-GCM ciphertext to see if the server decrypts it anyway.

**Defense:** GCM authentication tag detects any modification. Return error, not corrupted plaintext.

**Tests:** `tests/attack/aes_test.go` -- TestAESTamperedCiphertext, TestAESTruncatedCiphertext, TestAESWrongKey

### 4.6 HMAC Key/Message Confusion

**Attack:** Swap key and message parameters. If HMAC(key, msg) == HMAC(msg, key) for some implementation, signature verification becomes meaningless.

**Defense:** Consistent parameter ordering. Function signature: `HMACVerify(message, key []byte, signature string)` -- key before signature.

**Test:** `tests/attack/hmac_test.go` -- TestHMACTamper

### 4.7 TOTP Replay

**Attack:** Capture a valid TOTP code and replay it within the same time window.

**Defense:** Track last-used TOTP time step. Reject codes for already-used time steps.

**Test:** `tests/attack/totp_replay_test.go` -- TestTOTPCodeDeterministic

### 4.8 TOTP Brute Force

**Attack:** 6-digit TOTP has 1M possibilities. With ±1 skew, 3 windows = 3M attempts to check.

**Defense:** Account lockout after N failed 2FA attempts. Rate limiting on 2FA endpoints.

**Test:** `tests/attack/totp_replay_test.go` -- TestTOTPBruteForce

### 4.9 Constant-Time Comparison Bypass

**Attack:** If secret comparisons use `==` (short-circuit), measure response time to determine how many bytes matched.

**Defense:** All secret comparisons use `crypto/subtle.ConstantTimeCompare` or equivalent.

**Tests:** `tests/attack/constant_time_test.go` -- TestSecureCompare, TestSecureCompareBytes

---

## 5. Injection Attacks

### 5.1 SQL Injection

**Attack:** Malicious input in email, password, or other fields reaches SQL queries unescaped.

**Defense:** Parameterized queries exclusively (pgx `$1` placeholders). Never string-concatenate user input into SQL.

**Test:** `tests/attack/sql_injection_test.go` -- TestArgon2idHandlesSpecialCharacters

### 5.2 XSS via Error Messages

**Attack:** Inject `<script>` tags in registration email field. If error messages echo the input, XSS executes.

**Defense:** JSON API responses -- never render user input as HTML. `Content-Type: application/json`. Security headers (`X-Content-Type-Options: nosniff`).

**Test:** `tests/attack/xss_injection_test.go` -- TestXSSSanitization

### 5.3 Header Injection (CRLF)

**Attack:** Inject `\r\n` in header values (e.g., User-Agent) to add arbitrary HTTP headers.

**Defense:** Go's `net/http` rejects CRLF in header values by default.

**Test:** `tests/attack/header_injection_test.go`

---

## 6. OAuth2 / OIDC Attacks

### 6.1 Authorization Code Interception

**Attack:** Intercept the authorization code during the redirect and exchange it before the legitimate client.

**Defense:** PKCE S256 enforcement. The code is useless without the `code_verifier` that only the legitimate client knows.

**Tests:** `internal/handler/oauth_test.go` -- TestOAuth_Authorize_PKCE_ChallengePassedToProvider, TestOAuth_Callback_PKCE_VerifierPassedToExchange, TestGitHubProvider_AuthURL_IncludesPKCE

### 6.2 State Parameter CSRF

**Attack:** Forge the OAuth callback URL without a valid `state` parameter to trick users into linking attacker-controlled accounts.

**Defense:** HMAC-signed state with provider name, nonce, and expiry. Validated on callback: signature checked, provider matched, expiry enforced, nonce atomically consumed (single-use via cache GetAndDelete).

**Tests:** `internal/handler/oauth_test.go` -- TestOAuth_Callback_MissingState, TestOAuth_Callback_InvalidState_BadHMAC, TestOAuth_Callback_InvalidState_WrongProvider, TestOAuth_Callback_ExpiredState, TestOAuth_Callback_InvalidOrReusedState

### 6.3 Open Redirect via redirect_uri

**Attack:** Manipulate `redirect_uri` to send tokens to attacker's domain.

**Defense:** Callback handler always redirects to `origin + "/oauth/callback"` -- the redirect target is hardcoded from server config, never from user input. Provider redirect URIs are set at construction time from config.

**Test:** `internal/handler/oauth_test.go` -- TestOAuth_Callback_RedirectAlwaysToOrigin

### 6.4 Token Substitution (IdP Mixup)

**Attack:** Exchange a token from Provider A at Provider B's endpoint. If the server doesn't validate the token source, the attacker can impersonate.

**Defense:** The HMAC-signed state embeds the provider name, which is validated against the callback URL path. A state for "github" is rejected on the "google" callback. Additionally, each provider's Exchange() and UserInfo() use that provider's specific endpoints -- tokens cannot cross providers.

**Test:** `internal/handler/oauth_test.go` -- TestOAuth_Callback_CrossProviderStateRejected

---

## 7. DPoP (Demonstration of Proof-of-Possession)

### 7.1 DPoP Proof Replay

**Attack:** Capture a DPoP proof and replay it to use someone else's token.

**Defense:** `jti` claim in DPoP proof must be unique. `iat` must be recent. Server tracks recently seen `jti` values.

**Test:** `tests/attack/dpop_mismatch_test.go` (partial -- method/URI mismatch tested)

### 7.2 DPoP Method/URI Mismatch

**Attack:** Use a DPoP proof generated for `GET /api/users` with a `POST /api/admin` request.

**Defense:** Validate `htm` (HTTP method) and `htu` (HTTP URI) claims match the actual request.

**Tests:** `tests/attack/dpop_mismatch_test.go` -- TestDPoPMethodMismatch, TestDPoPURIMismatch

### 7.3 DPoP Key Substitution

**Attack:** Generate a new key pair and create a valid DPoP proof, but use it with a token bound to a different key.

**Defense:** `jkt` (JWK Thumbprint) in the access token's `cnf` claim must match the public key in the DPoP proof.

**Test:** `tests/attack/dpop_mismatch_test.go` -- TestDPoPWrongKey

**Status: this defense is not reachable.** The thumbprint comparison in `middleware.DPoP` only runs when the access token carries `cnf.jkt`, and no vault42 issuance path sets that claim (see the `middleware.DPoP` doc comment, `internal/middleware/dpop.go`). Every request therefore takes the unbound path: a presented proof is checked against method, URI and access-token hash but never against a thumbprint the token committed to, and a request with **no** proof passes through. Treat `VAULT_DPOP_ENABLED` as experimental. Nothing in this section may be cited as a live mitigation until issuance populates `cnf.jkt`.

---

## 8. KMS Unwrap Oracle (`POST /kms/unwrap`)

`POST /kms/unwrap` is a key-release endpoint: every reachable request releases a plaintext. It is mounted only when `KMS_ROOT_KEY_FILE` is set (`internal/server/server.go`). Its whole design is a decryption-oracle defense, so it gets its own section.

### 8.1 Decryption Oracle via Differentiated Errors

**Attack:** Submit envelopes that fail at different stages -- unknown kid, malformed base64, truncated ciphertext, flipped GCM tag, correct ciphertext under the wrong kid -- and read the differences in status code, error string, response timing or audit outcome to learn which stage failed. That is a padding-oracle-shaped primitive against a KEK.

**Defense:** Every post-authorization failure collapses to one identical `400 unwrap_failed`. `kms.Unwrap` returns a single opaque `kms.ErrUnwrap` for all of them, and the handler discards it rather than surfacing it (`handler.unwrapFailed`, `KMSHandler.Unwrap`). Each attempt is audited with the same shape whatever the cause, so the audit log is not an oracle either. The endpoint reveals success versus failure and nothing more.

**Tests:** `internal/kms/kms_test.go` -- TestUnwrap_UniformFailure; `internal/handler/kms_test.go` -- TestKMSUnwrap_UniformFailure

### 8.2 Cross-kid Envelope Confusion

**Attack:** Take an envelope wrapped under `kid=A` and submit it as `kid=B`, hoping the two derived KEKs collide or that the kid is decorative.

**Defense:** Per-kid KEKs are HKDF-SHA256 derivations from the root secret under a versioned, domain-separated label (`kms.kekInfoPrefix`), and the kid is bound as AES-GCM AAD, so a ciphertext wrapped under one kid fails authentication under another even if the derived keys somehow collided. The failure is `ErrUnwrap` like every other, so the attempt does not confirm the kid exists.

**Test:** `internal/kms/kms_test.go` -- TestWrapUnwrap_RoundTrip, TestUnwrap_UniformFailure

### 8.3 Scope Bypass on a Machine Endpoint

**Attack:** Reach the unwrap oracle with an ordinary user access token, or with a client-credential token that was never granted `kms:unwrap`. The token is validly signed, so anything checking only "is this authenticated" lets it through.

**Defense:** The route chains `authMw` then `middleware.RequireScope("kms:unwrap")` at the mount site in `internal/server/server.go`. `RequireScope` reads the validated claims from context and returns `403 insufficient_scope` unless the exact scope string is present; it must be chained after an `Auth` middleware, and a missing claims value is `401`, not a pass. `KMSHandler.Unwrap` re-checks for nil claims as defense in depth.

**Tests:** `internal/middleware/requirescope_test.go` -- TestRequireScope; `internal/handler/kms_test.go` -- TestKMSUnwrap_AuthzChain, TestKMSUnwrap_Unauthenticated

### 8.4 Bearer Token Replay Against the Oracle

**Attack:** Capture one authorized unwrap request (token plus body) and replay it to re-release the plaintext for as long as the access token lives.

**Defense:** Incomplete, and accepted as such -- see [security.md](security.md) AR-10. What actually stands: a short access-token TTL, TLS, per-IP rate limiting that fails closed, and a synchronous audit record of every attempt. DPoP would close it by sender-constraining the token, but does not (§7.3). Do not deploy this endpoint on the assumption that replay is prevented.

**Test:** `internal/handler/kms_test.go` -- TestKMSUnwrap_DPoPRequiredWhenEnabled (covers the middleware wiring, not token binding)

### 8.5 Rate-Limit Amplification via Cache Outage

**Attack:** Take Redis down, then hammer the oracle. If the limiter degrades to a per-pod in-memory fallback, the effective release rate is multiplied by the replica count; if it degrades to "allow", it is unbounded.

**Defense:** The unwrap limiter is configured `FailClosed: true` (30/min per IP, at the mount site in `internal/server/server.go`), unlike the graceful-degradation policy used on ordinary auth endpoints. A cache failure rejects unwraps rather than widening the release rate (audit finding L4).

**Tests:** `internal/middleware/ratelimit_failclosed_test.go`; `tests/attack/rate_limit_bypass_test.go`

### 8.6 Key Material Extraction via Logs or Errors

**Attack:** Induce an error path or a verbose log line that echoes the envelope, the plaintext, the derived KEK or the root secret.

**Defense:** The audit record carries only the kid and the boolean outcome (`KMSHandler.audit`). The KEK is never returned in, or derivable from, any response, and the root secret is wiped on close (`internal/kms/kms_test.go` -- TestClose_WipesRoot). `kms.Unwrap` releases the wrapped payload only, never the Key-Encryption-Key.

**Tests:** `internal/kms/kms_test.go` -- TestClose_WipesRoot; `internal/handler/kms_test.go` -- TestKMSUnwrap_RoundTrip

---

## 9. Infrastructure & Deployment Attacks

### 9.1 Secret Exfiltration via Environment Variables

**Attack:** Environment variables are visible in `/proc/self/environ`, `docker inspect`, crash dumps, and log aggregators.

**Defense:** Secrets loaded via `_FILE` suffix convention -- env var points to a file path, not the secret itself. File is zeroed after reading.

**Test:** `tests/compliance/nist_800_63b_test.go` (secret loading tested indirectly)

### 9.2 Database Privilege Escalation

**Attack:** SQL injection or application bug allows attacker to `DELETE FROM audit_log` to cover tracks, or `ALTER TABLE` to weaken schema.

**Defense:** Two database roles: `vault_mig` (DDL, used only at startup, connection closed after migration) and `vault_app` (SELECT/INSERT/UPDATE only, NO DELETE on audit, NO DDL). Audit log is append-only at the database level.

**Test:** Architecture-level defense; tested via integration tests

### 9.3 Container Escape / Filesystem Write

**Attack:** If the container has a writable filesystem, an attacker who gains code execution can modify the binary, drop a web shell, or tamper with data.

**Defense:** Read-only root filesystem (`readOnlyRootFilesystem: true`). Distroless base image (no shell, no package manager). Non-root user. All capabilities dropped.

**Test:** Dockerfile/K8s manifest review

### 9.4 Cache Poisoning

**Attack:** If Redis is shared or unprotected, inject malicious data into the rate limit or session cache.

**Defense:** Dedicated Redis instance per environment. Graceful degradation -- auth never fails because cache is down. Cache only stores rate limit counters, not session data.

**Test:** Cache interface tests in `internal/cache/`

### 9.5 IP Spoofing via Header Injection

**Attack:** Bypass IP-based access control by injecting a fake `X-Forwarded-For` or `CF-Connecting-IP` header to impersonate an allowed IP.

**Defense:** Proxy headers (`X-Forwarded-For`, `REAL_IP_HEADER`) are only trusted when the direct TCP connection (`RemoteAddr`) comes from a configured `TRUSTED_PROXIES` CIDR. Direct connections from untrusted IPs always use `RemoteAddr`. Rightmost-trusted XFF parsing prevents left-side injection.

**Test:** `internal/middleware/ipaccess_test.go` -- TestClientIPRealIPHeaderNotTrusted, TestClientIPRealIPHeaderDisabled

### 9.6 Geo-Fence Bypass via Missing Header

**Attack:** Connect without the geo header (e.g. bypass Cloudflare via direct IP) to avoid country-based blocking.

**Defense:** When `GEO_IP_HEADER` is configured but the header is absent (not behind the proxy), geo checks are skipped -- the request is still subject to IP allowlist/blocklist. For strict enforcement, combine geo-fencing with an IP allowlist restricted to the proxy's CIDR ranges.

**Test:** `internal/middleware/ipaccess_test.go` -- TestIPAccessGeoNoHeaderIsDeniedUnderAnAllowlist, TestIPAccessGeoNoGeoHeaderConfigSkipsCheck

### 9.7 IP Blocklist Evasion via IPv4/IPv6 Duality

**Attack:** Access from the IPv6-mapped form of a blocked IPv4 address (e.g. `::ffff:192.0.2.1` when `192.0.2.0/24` is blocked).

**Defense:** `net.ParseCIDR` and `net.IP.Contains` in Go's stdlib handle IPv4-mapped IPv6 addresses correctly -- `::ffff:192.0.2.1` is contained in `192.0.2.0/24`.

**Test:** `internal/middleware/ipaccess_test.go` -- TestIPAccessIPv6CIDR

### 9.8 Health Endpoint Abuse Past IP Access Control

**Attack:** Use `/healthz` or `/readyz` (which bypass IP access control) to probe the service or extract information.

**Defense:** Health endpoints return only a static `{"status":"ok"}` body with no sensitive data. They are intentionally exempt from IP access control so that Kubernetes probes and load balancers work regardless of access restrictions.

**Test:** `internal/middleware/ipaccess_test.go` -- TestIPAccessHealthzBypass

---

## 10. Password Attacks

### 10.1 Weak Password Acceptance

**Attack:** Register with `password123` or other common passwords.

**Defense:** 15-character minimum (exceeds NIST SP 800-63B Rev 4 minimum of 8). HIBP breach check via k-anonymity range queries blocks known-compromised passwords. No composition rules (per NIST recommendation).

**Tests:** `tests/attack/password_breach_test.go`, `tests/compliance/nist_800_63b_test.go`

### 10.2 Password Hash Offline Attack

**Attack:** Exfiltrate password hashes from the database and crack offline.

**Defense:** Argon2id with 46 MiB memory cost makes GPU/ASIC attacks infeasible. Each hash takes ~150-200ms on a modern CPU. Unique 16-byte random salt per hash prevents rainbow tables.

**Test:** `tests/attack/password_breach_test.go` -- TestPasswordHashUniqueSalts

### 10.3 Password Truncation

**Attack:** Some hashing implementations silently truncate passwords at 72 bytes (bcrypt). Passwords differing only after byte 72 would have the same hash.

**Defense:** Argon2id accepts arbitrary-length input. Verify that `password + "X"` produces a different hash and that they don't cross-verify.

**Tests:** `tests/compliance/nist_800_63b_test.go` -- TestNIST_PasswordNoTruncation, `tests/compliance/owasp_asvs_test.go` -- TestASVS_V2_1_3_PasswordNoTruncation

### 10.4 Password Reset Token Prediction

**Attack:** If reset tokens are sequential or time-based, an attacker can predict the next token.

**Defense:** 256-bit cryptographically random reset tokens via `crypto/rand`. No sequential component.

**Test:** `tests/compliance/owasp_asvs_test.go` -- TestASVS_V2_5_1_PasswordResetTokenRandom

---

## 11. Supply Chain & Dependency Attacks

### 11.1 Dependency Confusion / Typosquatting

**Attack:** Publish a malicious package with a similar name to a legitimate dependency.

**Defense:** Minimal dependency surface (3 direct deps). Pin exact versions in `go.sum`. Review transitive dependencies.

**Test:** `go.sum` integrity; CI runs `govulncheck`

### 11.2 Known Vulnerability in Dependencies

**Attack:** Exploit CVEs in outdated dependencies (e.g., CVE-2025-30204 in golang-jwt < v5.2.2).

**Defense:** Nightly `govulncheck` in CI. README auto-shows latest versions. Immediate update policy for security-relevant deps.

**Test:** `.github/workflows/nightly-security.yml`

---

## Coverage Matrix

| Attack Vector | Test File | Status |
|---|---|---|
| Alg confusion (RS256→HS256) | `attack/alg_confusion_test.go` | Covered |
| Alg none | `attack/alg_none_test.go` | Covered |
| Null signature | `attack/null_signature_test.go` | Covered |
| kid path traversal | `attack/kid_injection_test.go` | Covered |
| kid boundary values | `attack/jwt_kid_boundary_test.go` | Covered |
| jku/x5u/x5c/jwk injection | `attack/alg_none_test.go` | Covered |
| Expired token replay | `attack/expired_token_test.go` | Covered |
| Future nbf | `attack/future_nbf_test.go` | Covered |
| Missing claims | `attack/missing_claims_test.go` | Covered |
| Wrong issuer | `attack/wrong_issuer_test.go` | Covered |
| Wrong audience | `attack/wrong_audience_test.go` | Covered |
| JWT audience edge cases | `attack/jwt_audience_edge_test.go` | Covered |
| Oversized JWT | `attack/oversized_jwt_test.go` | Covered |
| JWT DoS vectors | `attack/jwt_dos_test.go` | Covered |
| JWT time boundary | `attack/jwt_time_boundary_test.go` | Covered |
| JWT RFC 7519 compliance | `attack/jwt_rfc7519_test.go` | Covered |
| JWT type confusion | `attack/jwt_type_confusion_test.go` | Covered |
| JWT JSON tricks | `attack/jwt_json_tricks_test.go` | Covered |
| JWT ES256 format | `attack/jwt_es256_format_test.go` | Covered |
| JWT auth header abuse | `attack/jwt_auth_header_test.go` | Covered |
| JWT confusion attacks | `attack/jwt_confusion_test.go` | Covered |
| JWT fingerprint binding | `attack/jwt_fingerprint_binding_test.go` | Covered |
| User enumeration timing | `attack/timing_attack_test.go` | Covered |
| Brute force | `attack/totp_replay_test.go` | Covered |
| Fingerprint mismatch | `attack/fingerprint_mismatch_test.go` | Covered |
| Fingerprint manipulation | `attack/fingerprint_manipulation_test.go` | Covered |
| AES wrong key / tamper / truncate | `attack/aes_test.go` | Covered |
| HMAC tamper | `attack/hmac_test.go` | Covered |
| TOTP replay | `attack/totp_replay_test.go` | Covered |
| TOTP replay race | `attack/totp_replay_race_test.go` | Covered |
| TOTP window bypass | `attack/totp_window_test.go` | Covered |
| Argon2id parameter abuse | `attack/argon2_params_test.go` | Covered |
| Constant-time compare | `attack/constant_time_test.go` | Covered |
| SQL injection | `attack/sql_injection_test.go` | Covered |
| XSS | `attack/xss_injection_test.go` | Covered |
| CSRF | `attack/csrf_test.go` | Covered |
| Header injection (CRLF) | `attack/header_injection_test.go` | Covered |
| DPoP mismatch (htm/htu) | `attack/dpop_mismatch_test.go` | Covered |
| DPoP key substitution (`cnf.jkt`) | `attack/dpop_mismatch_test.go` | Not reachable -- issuance never sets `cnf.jkt` (§7.3) |
| KMS unwrap oracle uniformity | `kms/kms_test.go`, `handler/kms_test.go` | Covered |
| KMS cross-kid envelope confusion | `kms/kms_test.go` | Covered |
| KMS scope bypass (`kms:unwrap`) | `middleware/requirescope_test.go`, `handler/kms_test.go` | Covered |
| KMS bearer replay | `handler/kms_test.go` | Accepted risk (security.md AR-10) |
| KMS rate limit fail-closed | `middleware/ratelimit_failclosed_test.go` | Covered |
| KMS root key wipe on close | `kms/kms_test.go` | Covered |
| Password breach check | `attack/password_breach_test.go` | Covered |
| Password attack vectors | `attack/password_attack_test.go` | Covered |
| Password reset + HIBP | `attack/password_reset_hibp_test.go` | Covered |
| Email template injection | `attack/email_template_injection_test.go` | Covered |
| Encoding attacks | `attack/encoding_test.go` | Covered |
| Unicode attacks | `attack/unicode_test.go` | Covered |
| Max body bypass | `attack/maxbody_bypass_test.go` | Covered |
| Refresh token race | `attack/refresh_token_race_test.go` | Covered |
| Session fixation | `attack/session_fixation_test.go` | Covered |
| Cache atomicity | `attack/cache_atomicity_test.go` | Covered |
| Rate limit bypass | `attack/rate_limit_bypass_test.go` | Covered |
| Token substitution | `attack/token_substitution_test.go` | Covered |
| WebAuthn sign count | `attack/webauthn_signcount_test.go` | Covered |
| Honeypot evasion | `attack/honeypot_evasion_test.go` | Covered |
| IP spoofing via header injection | `middleware/ipaccess_test.go` | Covered |
| Geo-fence bypass (missing header) | `middleware/ipaccess_test.go` | Covered |
| IPv4/IPv6 blocklist evasion | `middleware/ipaccess_test.go` | Covered |
| Health endpoint IP bypass | `middleware/ipaccess_test.go` | Covered |
| Dynamic IP blocklist add/remove | `middleware/ipaccess_test.go` | Covered |
| PKCE S256 enforcement | `handler/oauth_test.go` | Covered |
| OAuth state CSRF | `handler/oauth_test.go` | Covered |
| OAuth redirect_uri open redirect | `handler/oauth_test.go` | Covered |
| IdP token substitution (cross-provider) | `handler/oauth_test.go` | Covered |
| OAuth provider error handling | `handler/oauth_test.go` | Covered |
| JWKS rotation overlap | -- | TODO |

---

## References

- [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html) -- Digital Identity Guidelines: Authentication
- [OWASP ASVS v4.0.3](https://owasp.org/www-project-application-security-verification-standard/) -- Application Security Verification Standard
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [RFC 7519](https://tools.ietf.org/html/rfc7519) -- JSON Web Token
- [RFC 7518](https://tools.ietf.org/html/rfc7518) -- JSON Web Algorithms
- [RFC 9449](https://tools.ietf.org/html/rfc9449) -- DPoP (Demonstration of Proof-of-Possession)
- [RFC 6238](https://tools.ietf.org/html/rfc6238) -- TOTP
- [RFC 7636](https://tools.ietf.org/html/rfc7636) -- PKCE
- [CVE-2015-9235](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-9235) -- JWT alg=none
- [CVE-2025-30204](https://github.com/advisories/GHSA-mh63-6h87-4cp4) -- golang-jwt parsing vulnerability
- [PortSwigger JWT Attacks](https://portswigger.net/web-security/jwt)
- [Auth0 JWT Handbook](https://auth0.com/resources/ebooks/jwt-handbook)
