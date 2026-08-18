# vault42 -- Standards Compliance Report

**vault42 1.0.0 · assessed 2026-08-10 · self-assessment**

vault42 has been assessed against six security and privacy standards at the
revisions listed below, each cited with its publication date and the source the
revision was verified against. Every requirement in scope is classified **Met**,
**Accepted Risk**, or **Not Applicable**. There are no unclassified requirements
and no open Gap findings.

> **367 requirements in scope across 6 standards: 295 Met, 26 Accepted Risk,
> 46 Not Applicable. 0 unclassified.**

Every **Met** requirement names at least one test in `tests/compliance/` that
runs on every CI build. Every **Accepted Risk** carries a rationale, a
compensating control, a residual-risk statement, a revisit condition and a named
accepting party. Every **Not Applicable** requirement carries the reason it does
not apply.

The requirement register is [`docs/compliance-register.json`](compliance-register.json):
one row per requirement, carrying the verbatim requirement text, its status, the
`file:line` implementing it and the name of the test that proves it. **CI fails
if any requirement marked Met names a test that does not exist**, so the register
cannot drift from the suite.

## What this report deliberately does not say

**There is no coverage percentage here.** Through 0.9.9 this document reported
"94.2% weighted coverage" over 242 requirements it did not enumerate, with no
published weighting model. Neither number could be checked by a reader, which
made both worthless as evidence and worse than useless under scrutiny. The
register replaces them: it publishes the denominator, so anyone can compute
whatever figure they consider meaningful and verify it.

**There is no "Partial" status.** "Partial" named a finding with no owner, no
rationale and no revisit date, which reads as neglect. Each former partial is now
either Met, or an accepted risk that states what was accepted, what compensates
for it, what remains, and the condition under which the decision is revisited.

**This is a self-assessment.** No third-party audit or certification has been
performed. The findings, the method and the full register are published so that
the assessment can be independently checked by anyone with a clone of this
repository.

---

## Scope

**In scope:** the Go authentication server (`cmd/vault`, `internal/`), the admin
gateway (`cmd/admin-gateway`, `internal/adminapi`), the database schema
(`migrations/`) and the shipped Helm chart (`charts/vault`).

**Out of scope, assessed separately:**

- `web/` -- the Vue single-page frontend
- `packages/` -- the C# and TypeScript client SDKs
- Operator deployment configuration beyond the shipped chart
- `cmd/bridge` and the honeypot profile, which are non-default deployment modes

**ASVS level: L2.** Every ASVS 5.0.0 requirement at L1 and L2 is classified. L3
requirements are outside the declared level; where one is nevertheless satisfied,
or deliberately not satisfied, it is recorded anyway rather than omitted.

---

## Standards and revisions

Each revision was verified against a primary source on 2026-08-10, not from
memory and not from a previous version of this document.

| Standard | Revision | Published | Verified against |
|---|---|---|---|
| OWASP Application Security Verification Standard | **5.0.0** | 2025-05-30 | Requirement text taken verbatim from `5.0/docs_en/...5.0.0_en.csv` in the [OWASP/ASVS repository](https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release); release date from the GitHub releases API |
| NIST SP 800-63B-4 -- *Digital Identity Guidelines: Authentication and Authenticator Management* | **4** | 2025-07 | [csrc.nist.gov](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) for title and supersession; section numbering against [pages.nist.gov/800-63-4/sp800-63b.html](https://pages.nist.gov/800-63-4/sp800-63b.html) including its own cross-references |
| NIST SP 800-53 -- *Security and Privacy Controls for Information Systems and Organizations* | **Rev 5, Release 5.2.0** | 2025-08-27 | Control titles verbatim from the [OSCAL catalog](https://github.com/usnistgov/oscal-content) (`NIST_SP-800-53_rev5_catalog.json`, metadata version 5.2.0); release date from the NIST summary-of-changes document |
| OWASP Top 10 | **2025** | *see note* | Category identifiers and names from [owasp.org/Top10/2025/](https://owasp.org/Top10/2025/) |
| GDPR (EU) 2016/679 | stable | 2016-04-27 | [EUR-Lex](https://eur-lex.europa.eu/eli/reg/2016/679/oj) |
| RFC 6238 / 6749 / 7636 / 8725 / 9449 / 9700 and OpenID Connect Core 1.0 | per clause | stable | [rfc-editor.org](https://www.rfc-editor.org/) |

> **Needs verification:** OWASP publishes no release date for the Top 10:2025
> edition on the project page, on the 2025 pages, or through the repository's
> releases API. The edition identifier and the ten category names are verified;
> the publication date is not asserted here because no primary source states one.

### What the re-baseline changed

**NIST SP 800-63B.** Through 0.9.9 this document was titled for the **withdrawn**
revision (*"Authentication & Lifecycle Management"*) while the tests linked the
Rev 4 URL and cited Rev 3 section numbers against it. An auditor clicking the
link the repository itself supplied landed on text that did not say what the test
claimed. The renumbering is not cosmetic:

| Rev 3 | Rev 4 | Topic |
|---|---|---|
| §5.1.1.x | **§3.1.1.x** | Memorized secrets, now called *passwords* |
| §5.2.2 | **§3.2.2** | Rate Limiting (Throttling) |
| §7.x | **§5.x** | Session Management |
| §7.2 | **§5.2** general, **§2.1.3 / §2.2.3 / §2.3.3** per AAL | Reauthentication |

The per-AAL reauthentication timeouts live under section 2, beneath each
assurance level, not under section 5. Anything citing §5.2.1, §5.2.2 or §5.2.3
for those timeouts is citing sections that do not exist.

One requirement got **stricter** and vault42 does **not** meet it. Rev 4
§3.1.1.2 raises the single-factor password floor from 8 characters to 15.
Through 1.0.0 this paragraph said 15 "is the minimum vault42 has enforced since
0.4", and `README.md` said the same. It is not. 15 is the shipped **default**
(`internal/config/config.go:403`); the enforced floor -- the value below which a
non-dev deployment refuses to start -- is **8**
(`passwordMinLengthFloor`, `internal/config/config.go:772`, checked at `:605`),
and the dev profile is exempt from it entirely. A production deployment may
legally set `VAULT_PASSWORD_MIN_LENGTH=8`.

That row is now an accepted risk, **CR-31**, rather than Met. ASVS V6.2.1, whose
text requires 8 and recommends 15, remains genuinely Met.
`TestNIST63B4_3_1_1_2_TheEnforcedPasswordFloorIsWhatTheDocsSay` reads both
numbers out of `config.go` and fails if this document, `README.md` or the
register state anything else -- and flips the row back to Met the day the floor
reaches 15.

One requirement got **harder**: Rev 4 §2.2.3 states that *"a definite
reauthentication overall timeout SHALL be established, which SHOULD be no more
than 24 hours at AAL2. The inactivity timeout SHOULD be no more than 1 hour."*
Through 0.9.9 refresh rotation issued a fresh full TTL every time, so the 7-day
window slid indefinitely and no definite timeout existed at all. That SHALL is
now satisfied: migration 013 gives every rotation family a stored birth date and
`VAULT_MAX_SESSION_LIFETIME` bounds its total age. The two SHOULDs are not, and
that residual is CR-14.

**OWASP ASVS 5.0.0.** The two new chapters, V9 (Self-contained Tokens) and V10
(OAuth and OIDC), let vault42 claim *more*, not less. Through 0.9.9 the JWT
hardening was filed under a session-management requirement and the OAuth work had
no ASVS home at all, so it was hived off into a bespoke "RFC family" section an
auditor had to take on trust. That section is now 36 rows inside the standard's
own numbering, and the RFC rows that remain cross-reference their ASVS
requirement rather than standing alone.

**OWASP Top 10:2025.** Two categories moved vault42's position. **A03 Software
Supply Chain Failures** is new, and it is the category vault42 was best placed to
evidence all along: SBOM, SLSA build provenance and keyless cosign signatures
have shipped since 0.8 and were cited nowhere. **A09** was renamed to
*Security Logging and **Alerting** Failures*, and that single word moves vault42
off Met, because nothing in the tree raises an alert. See CR-15.

---

## Corrections to the 0.9.9 report

Six claims in the previous version of this document were wrong on the facts.
They are listed here rather than quietly deleted, because a reader comparing
versions should be able to see what changed and why.

| Previous finding | Reality |
|---|---|
| **V6.2.2 Partial** -- "document the RFC 6238 SHA-1 constraint in the TOTP module" | The comment already existed, at `internal/crypto/totp.go:5`. The finding requested a remediation that had shipped. Now Met. |
| **OAUTH2-TOKEN-001 Partial** -- "verify that the prior refresh token is revoked on rotation" | The ordering was already correct and is the safe one: `MarkUsed` at `internal/service/auth.go:1173` precedes `Create` at `:1260`. An interrupted rotation loses the session rather than leaving two live tokens. Now Met and asserted by test. |
| **SC-7 Partial** -- "provide network-policy examples in the deployment documentation" | `charts/vault/templates/networkpolicy.yaml` is 259 lines and `charts/vault/values.yaml:283` enables it **by default**. Now Met. |
| **V6.4.1 Partial** -- "the runtime pepper and database password remain in memory" (2 fields) | There are **11** string-typed configuration secrets, not 2. Only `MasterKey`, `KMSRootKey` and `HMACSecret` are `[]byte` and zeroed. Scope corrected in `docs/security.md` AR-4 and in CR-25. |
| **V8.3.2 Partial** -- "decrypted identity plaintext is not explicitly wiped" | That buffer **is** wiped, at `internal/service/identity.go:200`, with a comment naming the requirement. This row used to add that the decrypted **RSA private signing key PEM** was the buffer left unwiped, citing `internal/keystore/keystore.go:297`. That was itself wrong: `:297` is a comment line, and the PEM is wiped on both paths, at `:211` and `:442`, exactly as [`security.md`](security.md) already said. The buffers genuinely not wiped are the decrypted blob plaintext and label (`internal/service/blob.go:243,267,307`). CR-25 now says so. |
| **AU-9 and GDPR-14** | The same finding, filed twice. The GDPR row even said "Tracked as AU-9 above" while being counted separately. Now one accepted risk, CR-24, referenced from both rows. |

There is also a class of error the register makes impossible to repeat: **four of
the five ASVS partials were filed under identifiers whose actual requirement text
is about something else entirely.**

| Cited as | Actual ASVS v4.0.3 text at that identifier |
|---|---|
| `V2-1-1` "generic error messages prevent user enumeration" | *"Verify that user set passwords are at least 12 characters in length."* |
| `V3-2-2` "session invalidation on login" | *"Verify that session tokens possess at least 64 bits of entropy."* |
| `V6.4.1` "secrets never logged or stored in plaintext" | *"Verify that a secrets management solution such as a key vault is used..."* |
| `V8.3.2` "secure deletion: overwrite memory holding sensitive data" | *"Verify that users have a method to remove or export their data on demand."* |

vault42 meets all four of those requirements as actually written. The register
carries verbatim requirement text for exactly this reason: a paraphrase can drift
until it describes a different requirement, and nothing catches it.

For completeness, the ASVS 5.0.0 mapping marks `v4.0.3-8.3.2` as **DELETED, NOT
IN SCOPE**. The memory-zeroing concern the old finding described has no L1 or L2
successor in the current standard; the only related requirement, V11.7.1 (full
memory encryption), is L3. The underlying gap is still recorded, as CR-25, rather
than being retired on a technicality.

---

## Summary by standard

| Standard | Met | Accepted Risk | N/A | Total |
|---|---:|---:|---:|---:|
| OWASP ASVS 5.0.0 (L1 + L2, plus recorded L3 decisions) | 205 | 16 | 42 | 263 |
| NIST SP 800-63B-4 | 26 | 3 | 2 | 31 |
| NIST SP 800-53 Rev 5 (Release 5.2.0) | 30 | 3 | 1 | 34 |
| OWASP Top 10:2025 | 9 | 1 | 0 | 10 |
| GDPR (EU) 2016/679 | 13 | 2 | 1 | 16 |
| RFC family and OpenID Connect | 12 | 1 | 0 | 13 |
| **Total** | **295** | **26** | **46** | **367** |

The 26 Accepted Risk rows collapse to **15 distinct accepted risks**: several
requirements across different standards describe the same underlying gap, and
each references one shared entry rather than being counted as an independent
finding. That is the double-counting the AU-9 and GDPR-14 duplication caused
previously.

### What moved, and why the N/A bucket shrank by seventeen

Twenty-one Not Applicable rows rested on three sentences that were false on the
facts. The V3 rationale said vault42 "ships no browser-facing application of its
own"; `internal/frontend` embeds the SPA into the binary, `Dockerfile:32` and
`.goreleaser.yaml:26-29` put a real Vue build there before compiling, and
`internal/server/server.go:640` serves it. The V5 rationale said vault42
"accepts no file uploads" and never "stores by client-supplied name";
`internal/handler/blob.go:52` calls `r.FormFile("file")` and
`PUT /user/blobs/named/{name}` stores under a caller-supplied name. The V1.3.7
rationale said "no template is built from input"; `internal/email/mailer.go:202`
parses an admin-supplied string on the live send path.

| Movement | Count | Rows |
|---|---:|---|
| N/A → **Met** | 9 | V3.4.2, V3.5.1, V3.5.2, V3.7.1, V3.7.2, V5.2.1, V5.2.3, V5.3.2, V5.4.2, plus V1.3.7 |
| N/A → **Accepted Risk** | 6 | V3.2.1, V3.4.3, V3.5.3, V3.5.4, V5.1.1, V5.4.1, plus V1.3.1 |
| **Met** → Accepted Risk | 1 | NIST SP 800-63B-4 §3.1.1.2 -- the password floor. See CR-31. |
| N/A, reason rewritten and now tested | 12 | V3.2.2, V3.5.5, V5.2.2, V5.3.1, V5.4.3, V1.3.4, V6.2.6, V6.7.1, V7.4.4, V10.4.1, V14.3.1, V15.3.6 |

Two of those rows -- **V3.4.3** and **V3.5.3** -- were real gaps hidden behind a
false N/A: neither Met nor accepted, while the closing line of this document
said there were no standing gaps. They are now CR-27 and CR-28.

The Met bucket grew and one Met row was **lost**: §3.1.1.2, where the register,
this document and `README.md` all said vault42 enforced a 15-character password
minimum. It ships 15 as the default and enforces a floor of 8.

---

## Accepted risks

Full text for each, including the compensating control, the residual risk and the
revisit condition, is in the `accepted_risks` section of
[`docs/compliance-register.json`](compliance-register.json).

### Two namespaces, deliberately disjoint

**`AR-nn` belongs to [`docs/security.md`](security.md)**, which defines AR-1
through AR-18. **`CR-nn` belongs to this register.** Go source comments and the
tests under `tests/attack/` cite `AR-nn` and always mean `docs/security.md`.

Through 1.0.0 both documents numbered from one sequence, and four numbers meant
different things in the two files:

| ID | `docs/security.md` | this register, before the rename |
|---|---|---|
| AR-14 | the admin role-escalation triggers are not a boundary against SQL that reaches the database | session timeouts |
| AR-15 | what keeps a forged signing key out of JWKS is the master key, not the grant | no alerting |
| AR-17 | what stops `vault_app` issuing itself a capability credential is a trigger, not the grant | no outbound egress allowlist |
| AR-18 | `vault_app` can still release an account lock, and owns every password hash | *(undefined)* |

A reader following a cross-reference landed on an unrelated risk, and the
sentence that used to close this document asserted that "AR-16 has since closed"
while `docs/security.md` AR-16 -- *a `mint:token` holder can assert any subject
the estate honors* -- was open, and remains open. The register's identifiers
were renumbered to `CR-nn` so the collision cannot recur.
`TestComplianceRegister_RiskIdentifierNamespacesDoNotCollide` fails on a new
collision, and on any `AR-nn` or `CR-nn` reference in `docs/` that resolves to
neither namespace.

| ID | Severity | What is accepted | Requirements affected |
|---|---|---|---|
| **CR-14** | Low | No inactivity timeout exists, and the absolute session lifetime defaults to 720 hours where SP 800-63B-4 §2.2.3 recommends no more than 24 at AAL2. The mandatory requirement that *a* definite timeout be established is met. | ASVS V7.1.1, V7.3.1 · 800-63B-4 §2.2.3, §5.2 · 800-53 AC-12 |
| **CR-15** | Medium | Security events are logged comprehensively but nothing alerts on them. `risk_score` is a hardcoded severity tag that no code reads, and the only outbound channel is installed in the honeypot profile only. | Top 10 A09:2025 · 800-53 AU-6 · GDPR Arts. 33, 34 |
| **CR-17** | Low | No allowlist is enforced at the outbound HTTP client layer. Every destination is operator-configured rather than caller-supplied, so the SSRF precondition is absent; the chart's NetworkPolicy enforces the allowlist at the network layer instead. | ASVS V1.3.6 |
| **CR-20** | Low | Authenticator loss is handled by operator escrow rather than repeated identity proofing. vault42 performs no identity proofing at enrollment, so there is no level to match. | ASVS V6.4.4 |
| **CR-21** | Low | Tokens carry no `acr`, `amr` or `aal` claim, so a resource server cannot require a specific authentication strength. The AAL constants exist and are tested but have no non-test caller. | ASVS V6.8.4, V10.3.4 |
| **CR-22** | Low | The identity provider's own session lifetime is not tracked, so a federated session is bound to vault42's lifetime only. | ASVS V7.6.1 |
| **CR-23** | Low | Outbound SMTP negotiates STARTTLS opportunistically with no minimum version. Mail carries no credential, only single-use short-lived links and codes. | ASVS V12.3.1 |
| **CR-24** | Medium | The audit log is not cryptographically chained and is not mirrored off-system. A chain whose signing key lives in the same process would not defend against the adversary it appears to address. | ASVS V16.4.3 · 800-53 AU-9 · GDPR Art. 5(2) |
| **CR-25** | Low | DPoP proofs are validated thoroughly but no token is sender-constrained, because no issuance path sets `cnf.jkt`. Separately, the decrypted blob plaintext and label are not zeroed (`internal/service/blob.go:243,267,307`). The signing-key PEM **is** zeroed; this row used to say otherwise. | RFC 9449 / RFC 9700, sender-constrained access tokens |
| **CR-26** | Low | Neither blob download path sets `Content-Disposition`, so nothing tells a browser that a blob navigated to directly is a download rather than a document. `nosniff` and owner-scoped reads bound it. | ASVS V3.2.1, V5.1.1, V5.4.1 |
| **CR-27** | Low | Neither Content-Security-Policy declares `object-src 'none'` or `base-uri 'none'`, which V3.4.3 names as the minimum. `default-src` does not cover `base-uri`. A two-token fix, and the one item here that should not survive to 1.1. | ASVS V3.4.3 |
| **CR-28** | Low | `GET /auth/verify-email` mutates state and no `Sec-Fetch-*` validation exists. The token is single-use and consumed atomically, which bounds it to one verification. | ASVS V3.5.3 |
| **CR-29** | Low | With `VAULT_SERVE_FRONTEND` on, the SPA and the API answer on one origin, so the same-origin policy separates neither. Off by default; the chart ships the SPA as a separate workload. | ASVS V3.5.4 |
| **CR-30** | Low | Admin email HTML is validated by a regex denylist rather than a sanitisation library. `super_admin`-only, `html/template` auto-escaping, and an email body rather than a same-origin page are the compensating controls. | ASVS V1.3.1 |
| **CR-31** | Medium | The 15-character password minimum is the shipped **default**; the enforced floor is 8 outside dev, and the dev profile has no floor. This document said "the minimum vault42 has enforced since 0.4". It was not. | 800-63B-4 §3.1.1.2 |

---

## Assessment method

**Assessed by:** vault42 maintainers, 2026-08-10, against the revisions in the
table above.

**How each row was reached.** Every requirement was read in its published text,
not in a paraphrase, and classified against source at a cited `file:line`. Where
a previous version of this document and the code disagreed, the code won and the
disagreement was recorded as a correction above.

**What "Met" means here.** A requirement is Met when at least one test in
`tests/compliance/` asserts it and that test runs in CI. Two thirds of the suite
asserts *properties* of the tree rather than the behaviour of one function,
because the second kind cannot see the failures that matter. `internal/rbac` sat
at 100% statement coverage while having no access-control test at all: line
coverage recorded that the permission table was *read*, not that it granted the
right things. The property tests are the answer to that:

- every `tls.Config` in the shipped tree declares a minimum version
- no shipped code sets `InsecureSkipVerify`
- every SQL call site in the repository layer is assembled only from literals,
  package constants and placeholder-only formatting, checked by a taint analysis
  over every such call site, with a negative control that proves the detector
  fires on four known-bad shapes
- every route outside a declared public allowlist passes through an
  authentication guard
- every mutating admin route is gated by a permission the read-only role does
  not hold, parsed out of the router
- every server-error response in the HTTP layer carries a fixed message literal,
  checked across every such call site the scan finds
- every third-party GitHub Action is pinned to a commit SHA

**What was not assessed.** The components listed under Scope as out of scope.
Nothing else was excluded.

**Container-backed tests.** Some requirements are proven against a real
PostgreSQL through testcontainers. Where no container runtime is reachable those
tests skip cleanly and say so, rather than failing; they run in CI. Every
requirement whose only evidence needs a database is marked as such in the
register.

**Reproducing this report.** Clone the repository and run:

```
go test ./tests/compliance/
```

To run only the register gate:

```
go test ./tests/compliance/ -run TestComplianceRegister
```

---

## Standing gaps not covered by an accepted risk

**None -- and the previous version of this sentence was false.** It said the
same words, and they were true of the register rather than of the system. Two
requirements were neither Met nor covered by any accepted risk, because both sat
behind a Not Applicable filed on a premise that was wrong on the facts:

- **ASVS V3.4.3** -- neither Content-Security-Policy declares `object-src 'none'`
  or `base-uri 'none'`
  (`internal/middleware/security_headers.go:12-13`). Now **CR-27**.
- **ASVS V3.5.3** -- `GET /auth/verify-email` mutates state
  (`internal/server/server.go:381`, `internal/handler/auth.go:194`) and no
  `Sec-Fetch-*` validation exists anywhere in the tree. Now **CR-28**.

The sentence is true again because those two rows were reclassified, not because
the gaps were not there. What made a false universal claim survivable was that
nothing checked the classification underneath it: a Met row has to name a test,
an N/A row asserting non-existence did not.
`TestComplianceRegister_NotApplicableNonExistenceClaimsNameAnExistingTest` now
requires one, and would have caught all twenty-one of the misclassified rows on
the day they were written.

**Correction.** This section previously said CR-14's mandatory half was
unwired and that `TestNIST63B4_2_2_3_TheAbsoluteBoundIsStillUnwired` would fail
when the wiring landed. Both halves were wrong. The wiring is present, at
`cmd/vault/main.go:353` -- `tokenSvc.SetMaxSessionLifetime(cfg.MaxSessionLifetime)`,
fed by the `VAULT_MAX_SESSION_LIFETIME` default at `internal/config/config.go:445`
-- and no test of that name has ever existed. The tests that do exist are
`TestNIST63B4_2_2_3_AbsoluteReauthenticationBoundIsImplemented`, which asserts
the mandatory SHALL is satisfied, and
`TestNIST63B4_2_2_3_TheOverallTimeoutIsEstablishedButNotAtTheRecommendedValue`,
which fails the day the 720-hour default drops inside the AAL2 SHOULD.

What remains open under CR-14 is only the two advisory halves: the 720-hour
default and the absence of an inactivity timeout.

A test named in a register row is checked by CI. A test named in prose was not,
which is how a name that resolves to nothing survived a release.
`TestComplianceDocs_EveryTestNamedInProseExists` closes that hole.

Both remaining trackers fail on closure rather than on regression, so a fix
cannot land without the register being updated in the same change. CR-19,
the login-outcome enumeration oracle, has since closed: account_locked, the
import-claim path, banned and disabled now all answer 401 invalid_credentials
without a valid password. CR-16 has since closed too: `RBACCheck` now writes an
`admin_authz_denied` record on a permission denial, so a failed authorization
decision reaches the audit log instead of leaving no trail.
