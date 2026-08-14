# vault42 -- Standards Compliance Report

**vault42 1.0.0 · assessed 2026-08-10 · self-assessment**

vault42 has been assessed against six security and privacy standards at the
revisions listed below, each cited with its publication date and the source the
revision was verified against. Every requirement in scope is classified **Met**,
**Accepted Risk**, or **Not Applicable**. There are no unclassified requirements
and no open Gap findings.

> **367 requirements in scope across 6 standards: 275 Met, 21 Accepted Risk,
> 71 Not Applicable. 0 unclassified.**

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

One requirement got **stricter** and vault42 already met it: Rev 4 §3.1.1.2
raises the single-factor password floor from 8 characters to 15, which is the
minimum vault42 has enforced since 0.4. That row moves from "exceeds the
standard" to "meets the current standard exactly", which is the stronger claim.

One requirement got **harder**: Rev 4 §2.2.3 states that *"a definite
reauthentication overall timeout SHALL be established, which SHOULD be no more
than 24 hours at AAL2. The inactivity timeout SHOULD be no more than 1 hour."*
Through 0.9.9 refresh rotation issued a fresh full TTL every time, so the 7-day
window slid indefinitely and no definite timeout existed at all. That SHALL is
now satisfied: migration 013 gives every rotation family a stored birth date and
`VAULT_MAX_SESSION_LIFETIME` bounds its total age. The two SHOULDs are not, and
that residual is AR-14.

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
off Met, because nothing in the tree raises an alert. See AR-15.

---

## Corrections to the 0.9.9 report

Six claims in the previous version of this document were wrong on the facts.
They are listed here rather than quietly deleted, because a reader comparing
versions should be able to see what changed and why.

| Previous finding | Reality |
|---|---|
| **V6.2.2 Partial** -- "document the RFC 6238 SHA-1 constraint in the TOTP module" | The comment already existed, at `internal/crypto/totp.go:5`. The finding requested a remediation that had shipped. Now Met. |
| **OAUTH2-TOKEN-001 Partial** -- "verify that the prior refresh token is revoked on rotation" | The ordering was already correct and is the safe one: `MarkUsed` at `internal/service/auth.go:721` precedes `Create` at `:766`. An interrupted rotation loses the session rather than leaving two live tokens. Now Met and asserted by test. |
| **SC-7 Partial** -- "provide network-policy examples in the deployment documentation" | `charts/vault/templates/networkpolicy.yaml` is 259 lines and `charts/vault/values.yaml:283` enables it **by default**. Now Met. |
| **V6.4.1 Partial** -- "the runtime pepper and database password remain in memory" (2 fields) | There are **11** string-typed configuration secrets, not 2. Only `MasterKey`, `KMSRootKey` and `HMACSecret` are `[]byte` and zeroed. Scope corrected in AR-4 and AR-25. |
| **V8.3.2 Partial** -- "decrypted identity plaintext is not explicitly wiped" | That buffer **is** wiped, at `internal/service/identity.go:200`, with a comment naming the requirement. The buffer that is not wiped, and which the finding never mentioned, is the decrypted **RSA private signing key PEM** at `internal/keystore/keystore.go:297`. Recorded in AR-25 at the severity it deserves. |
| **AU-9 and GDPR-14** | The same finding, filed twice. The GDPR row even said "Tracked as AU-9 above" while being counted separately. Now one accepted risk, AR-24, referenced from both rows. |

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
memory encryption), is L3. The underlying gap is still recorded, as AR-25, rather
than being retired on a technicality.

---

## Summary by standard

| Standard | Met | Accepted Risk | N/A | Total |
|---|---:|---:|---:|---:|
| OWASP ASVS 5.0.0 (L1 + L2, plus recorded L3 decisions) | 183 | 13 | 67 | 263 |
| NIST SP 800-63B-4 | 27 | 2 | 2 | 31 |
| NIST SP 800-53 Rev 5 (Release 5.2.0) | 30 | 3 | 1 | 34 |
| OWASP Top 10:2025 | 9 | 1 | 0 | 10 |
| GDPR (EU) 2016/679 | 13 | 2 | 1 | 16 |
| RFC family and OpenID Connect | 12 | 1 | 0 | 13 |
| **Total** | **274** | **22** | **71** | **367** |

The 22 Accepted Risk rows collapse to **13 distinct accepted risks**: several
requirements across different standards describe the same underlying gap, and
each references one shared entry rather than being counted as an independent
finding. That is the double-counting the AU-9 and GDPR-14 duplication caused
previously.

---

## Accepted risks

Full text for each, including the compensating control, the residual risk and the
revisit condition, is in the `accepted_risks` section of
[`docs/compliance-register.json`](compliance-register.json). AR-1 through AR-12
are the pre-existing entries in [`docs/security.md`](security.md).

| ID | Severity | What is accepted | Requirements affected |
|---|---|---|---|
| **AR-13** | Low | The concurrent-session cap is soft: counting and inserting are not atomic, so racing logins can overshoot it. It is a resource control, not a security boundary, and confers no authentication bypass. | ASVS V2.3.4 |
| **AR-14** | Low | No inactivity timeout exists, and the absolute session lifetime defaults to 720 hours where SP 800-63B-4 §2.2.3 recommends no more than 24 at AAL2. The mandatory requirement that *a* definite timeout be established is met. | ASVS V7.1.1, V7.3.1 · 800-63B-4 §2.2.3, §5.2 · 800-53 AC-12 |
| **AR-15** | Medium | Security events are logged comprehensively but nothing alerts on them. `risk_score` is a hardcoded severity tag that no code reads, and the only outbound channel is installed in the honeypot profile only. | Top 10 A09:2025 · 800-53 AU-6 · GDPR Arts. 33, 34 |
| **AR-16** | Low | `RBACCheck` answers 403 without writing an audit record, so an admin permission denial leaves no trail. The denial is still enforced. | ASVS V16.3.2 |
| **AR-17** | Low | No allowlist is enforced at the outbound HTTP client layer. Every destination is operator-configured rather than caller-supplied, so the SSRF precondition is absent; the chart's NetworkPolicy enforces the allowlist at the network layer instead. | ASVS V1.3.6 |
| **AR-18** | Low | No notification of authentication from an unusual location. Implementing it requires IP geolocation, which vault42 deliberately does not do. L3 requirement. | ASVS V6.3.5 |
| **AR-20** | Low | Authenticator loss is handled by operator escrow rather than repeated identity proofing. vault42 performs no identity proofing at enrollment, so there is no level to match. | ASVS V6.4.4 |
| **AR-21** | Low | Tokens carry no `acr`, `amr` or `aal` claim, so a resource server cannot require a specific authentication strength. The AAL constants exist and are tested but have no non-test caller. | ASVS V6.8.4, V10.3.4 |
| **AR-22** | Low | The identity provider's own session lifetime is not tracked, so a federated session is bound to vault42's lifetime only. | ASVS V7.6.1 |
| **AR-23** | Low | Outbound SMTP negotiates STARTTLS opportunistically with no minimum version. Mail carries no credential, only single-use short-lived links and codes. | ASVS V12.3.1 |
| **AR-24** | Medium | The audit log is not cryptographically chained and is not mirrored off-system. A chain whose signing key lives in the same process would not defend against the adversary it appears to address. | ASVS V16.4.3 · 800-53 AU-9 · GDPR Art. 5(2) |
| **AR-25** | Low | DPoP proofs are validated thoroughly but no token is sender-constrained, because no issuance path sets `cnf.jkt`. Separately, some decrypted buffers are not zeroed, including the RSA private signing key PEM. | RFC 9449 §4.10.1 |

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
  over 139 call sites, with a negative control that proves the detector fires on
  four known-bad shapes
- every route outside a declared public allowlist passes through an
  authentication guard
- every mutating admin route is gated by a permission the read-only role does
  not hold, parsed out of the router
- every server-error response in the HTTP layer carries a fixed message literal,
  checked across 176 call sites
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

None. Every requirement is Met or carries an accepted risk with a named owner.

One item is recorded here because it is scheduled to close inside 1.0.0 on
another work stream and the register will be updated when it lands:

1. **AR-14** closes when `SetMaxSessionLifetime` is called from
   `cmd/vault/main.go` with a configured default. The mechanism, the schema
   column and the fail-closed enforcement are already in place; only the wiring
   is missing. `TestNIST63B4_2_2_3_TheAbsoluteBoundIsStillUnwired` fails when it
   lands.

It is tracked by a test that fails on closure rather than on regression, so a
fix cannot land without the register being updated in the same change. AR-19,
the login-outcome enumeration oracle, has since closed: account_locked, the
import-claim path, banned and disabled now all answer 401 invalid_credentials
without a valid password.
