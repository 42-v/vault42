#!/usr/bin/env python3
"""Report exactly which statements a coverage profile leaves uncovered.

`go tool cover -func` rounds to one decimal and reports per-function totals, which
is the wrong shape for closing a coverage gap: it cannot tell you that a function
at 92% is missing one three-statement error branch at line 148, and it cannot be
diffed between two runs to prove a wave landed the blocks it was assigned.

This reads the raw profile instead. Under `-coverpkg` the same block appears once
per test binary, so blocks are OR-folded by key before anything is counted -- the
same fold `cov_total` in scripts/lib/coverage-env.sh applies, so the totals here
always agree with docs/test-coverage.md.

Usage:
    scripts/cov-gaps.py PROFILE                 # summary + per-file gap table
    scripts/cov-gaps.py PROFILE --file PATH     # every uncovered block in one file
    scripts/cov-gaps.py PROFILE --target 99.69  # covered-count needed to land a figure
    scripts/cov-gaps.py PROFILE --diff OTHER    # blocks OTHER covers that PROFILE does not
    scripts/cov-gaps.py PROFILE --json          # machine-readable, for tooling
    scripts/cov-gaps.py PROFILE --exclude FILE  # coverage of REACHABLE statements
    scripts/cov-gaps.py PROFILE --verify-exclusions     # the release gate

The exclusion set (.coverage-exclusions.json) is how 1.0.0 can claim "100.00% of
reachable statements" without the claim being unfalsifiable. Each entry names one
statement, freezes its source line verbatim, and carries the argument for why it
is not reachable. --verify-exclusions is what stops the set rotting or growing:
it fails when an excluded line has moved, changed text, or become covered, when
an entry is still unconfirmed, when the set has grown past its ratchet, when the
profile it is measured against is not the canonical one, and when covered +
excluded does not equal total.

The profile is not optional. Every one of those checks except the frozen-text
comparison needs a measurement, so a run without one would confirm that N strings
still sit at N line numbers and nothing else, then exit 0 wearing the name of a
release gate.
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_EXCLUSIONS = os.path.join(REPO_ROOT, ".coverage-exclusions.json")
BUCKETS = ("B", "C")
ENTRY_FIELDS = ("package", "file", "line", "occurrence", "source", "bucket",
                "justification", "confirmed")

# ---------------------------------------------------------------------------
# Ratchets. Measured from the canonical scripts/coverage.sh run, not chosen.
#
# The exclusion set constrains the denominator, so every check that reads it is
# only as good as the profile it is handed. load() accepts any file that starts
# with a mode: header, the identity check divides the profile's own numbers by
# each other, and release-check.sh --coverage-only takes a path from the caller.
# Nothing in that chain notices a profile from a narrower run: a `go test
# -coverprofile` over a handful of packages satisfies covered + excluded == total
# trivially and reports "100.00% of reachable" over a quarter of the tree.
#
# These three constants are what make the gate falsifiable. They live here rather
# than in .coverage-exclusions.json so that growing the set is a two-file diff,
# and the second file is the one a reviewer already opens.
#
# BASELINE_TOTAL_STATEMENTS is a floor, in the same spirit as GOLANGCI_MAX_ISSUES
# in scripts/release-check.sh: a profile smaller than the canonical run is either
# a subset run or a tree that lost code, and both need a human. When code is
# genuinely deleted, re-measure and lower it in the same review as the deletion.
# BASELINE_PACKAGES catches the shape the floor cannot: a package dropped from
# the run while enough statements remain to clear the count.
# Raised from 10345 to 10693 by the 1.0.0 security work. The floor tracks the
# canonical run, and that run grew by 348 statements because the audits added
# code rather than because the measurement widened: the https endpoint checks in
# internal/oauth2, the strict enum and boolean validation in internal/config, the
# --out and argv-warning paths in cmd/recover, the honeypot token parity work,
# and the expired-row reaper in internal/cache. Measured, not estimated: a full
# cov_run over every suite reports 10784, after the gate-closing tests and the
# vault_app privilege, honeypot parity and revocation-ordering work landed.
# Raised from 10784 to 10806 by the release-gate attack pass: +22 statements from
# the DPoP crit/jwk/curve refusals in internal/crypto, the erasure-race guard in
# internal/repository/postgres, the GitHub status and zero-id refusals plus the
# account-state link ordering in internal/oauth2 and internal/handler, and the
# tombstone-domain refusal in internal/sanitize. A full cov_run reports 10806,
# all 22 covered by the tests those fixes shipped.
# Raised from 10806 to 10831 by the second attack fleet: +25 statements from the
# admin-session reaper, bridge Connection-strip guard, MFA-lockout and MFA-status
# fail-closed paths, the OAuth and verify/begin lookup fail-closed branches, the
# admin-config redaction and audit-actor attribution, and the OIDC crit and OAuth
# device-binding fixes. A full cov_run reports 10831, all covered by the tests
# those fixes shipped; the two SQL migrations (025 tombstone-insert, 026
# signing-key retire) add no Go statements.
# Raised from 10831 to 10861 by wiring the admin-session reaper: +30 statements
# from internal/service/admin_session_retention.go (the scheduled sweeper that
# actually calls DeleteExpired on a ticker) and its three-line Start/Stop wiring
# in cmd/admin-gateway/main.go. A full cov_run reports 10861, all 30 covered by
# admin_session_retention_test.go and the admin-gateway integration test.
# Raised from 10861 to 10870 by the attack-pass batch: +9 net statements from the
# bridge rightmost-XFF walk and the servicedoc per-client byte-quota / used_bytes
# scoping and shared-read kill-switch gates (the cross-client SumBytesForSubject
# was removed and replaced with SumBytesForSubjectAndClient). Migration 027
# (retired keys need an expiry) adds no Go statements. A full cov_run reports
# 10870, all covered by the tests those fixes shipped; the five servicedoc
# bucket-C exclusions were unchanged in substance and only relocated (+31 lines)
# by the quota code inserted above them.
# Lowered from 10870 to 10844 by retiring the dead revoke-client and
# rotate-client-secret CLI handlers (26 statements deleted): both ran UPDATEs the
# vault_app role has never been granted on auth.clients (42501 since migration
# 001), so they were dead code, and client revocation/secret rotation already live
# on the admin gateway. A full cov_run reports 10844, still 100% of reachable
# (10796/10796); the floor drops with the deletion in the same review.
# Lowered from 10844 to 10842 by closing the password-reset timing oracle: hoisting
# the Argon2 burn and token generation ahead of the user lookup let the separate
# token-error return collapse into the single eligibility guard, a net 2 fewer
# statements. A full cov_run reports 10842, still 100% of reachable (10794/10794).
# Raised from 10842 to 10852 by the fourth-pass enumeration fixes: the two login
# lock branches now burn a dummy Argon2 and advance the per-IP failure counter
# before returning invalid_credentials, and the OAuth callback refuses an
# unverifiable first-time sign-in with a neutral redirect (net of the deleted
# signup-verification-mail branch). A full cov_run reports 10852, still 100% of
# reachable (10804/10804).
# Raised from 10852 to 11075 by the AR-18 country-geo login-notice and VPN/anon
# rate-limit feature: +223 statements, chiefly the internal/ipintel range-table
# package (decode/lookup/Default) and its wiring into internal/service/auth.go
# (notifyNewCountry), the ratelimit weighting, and cmd/vault/main.go. A full
# cov_run reports 11075.
# Raised from 11075 to 11917 by the 1.0.0 hardening pass, sixteen work streams
# and 218 commits: +842 statements. The bulk is new production code rather than
# a wider measurement — the service-document store and its repository and
# handler, the admin-gateway client-certificate pinning and CRL check, the
# scheduled signing-key rotation and keystore retention, the deferwork pool, the
# DPoP binding package, the first-boot provisioner, the config cross-plane and
# env checks, and the per-family session revocation work. The package set in
# cov_run did not change. A full cov_run reports 11917.
# Raised from 11917 to 11918. Not new work: 11917 was measured in the covrecon
# worktree, whose tree predates two changes that reached hard/integration
# afterwards — cmd/admin-gateway/main.go extracting verifyPlaneAgreement and
# gaining the service-document call the erasure cascade was missing. Diffing the
# two profiles block by block shows the whole difference inside that one file,
# 22 blocks reshaped for a net +1 statement, and nothing else moved. A full
# cov_run against hard/integration reports 11918.
# Raised from 11918 to 11928 by the client-address masking pass: +10 statements
# from httputil.ObfuscatedIP and the stdlib-only obfuscatedIP that cmd/bridge
# carries because it cannot import it, plus the call sites in
# internal/middleware, internal/adminapi and the four cmd/bridge files. A full
# cov_run reports 11928, all 10 covered.
# Raised from 11928 to 11950 by the reviewfix pass: +22 statements from the five
# correctness fixes. The lockout fail-closed latch and its two Increment error
# checks (internal/service/auth.go), the two unbounded escapes in
# enforceSessionLifetime, the post-Close synchronous write and isClosed poll in
# internal/audit/audit.go, and the CompareAndSwap guard in the audit and keystore
# sweepers. A full cov_run reports 11950, all 22 covered.
# Raised from 12220 to 12783 by re-measuring the merged 1.0.0 tree, and this note
# has to start by admitting that the number it replaces does not add up: the
# itemisation above stops at 11950 while the constant was standing at 12220, so
# 270 statements entered the floor without an account. That is the failure this
# comment block exists to prevent, so what follows is written against the last
# figure actually on record rather than against 12220.
#
# 11928 is that figure -- the hard/integration profile the 11918 -> 11928 entry
# was measured from. A cov_run on this tree reports 12783, and diffing the two
# profiles by package puts all 855 statements in code rather than in a wider
# measurement; the cov_run package set is unchanged.
#
#   +295  internal/email        the template-override store, its compile and
#                               validate path, and the branding renderer
#   +103  cmd/admin-gateway     client-certificate pinning, the CRL check and
#                               the session-reaper wiring
#    +85  internal/service
#    +63  internal/outbound     new package
#    +63  internal/alert        new package: the severity detector and log sink
#    +48  internal/adminapi
#    +45  internal/honeypot     the alert path and the captured request body
#    +41  internal/handler
#    +33  internal/audit
#    +27  internal/firstboot
#    +22  internal/metrics      the breach-check shed counter and its gate
#    +15  internal/server
#    +13  internal/repository/postgres
#    +11  internal/config
#     +9  internal/cli, +9 cmd/bridge, +7 cmd/vault, +6 internal/oauth2,
#         +4 internal/migrate, +2 internal/keystore
#     -6  internal/crypto       dead branches deleted
#    -40  internal/middleware   three exported controls deleted in a0ac1c8
#
# internal/alert and internal/outbound are added to BASELINE_PACKAGES below in
# the same review. A package the shape guard does not name can fall out of the
# run entirely and only the floor would notice, which is the one check a genuine
# deletion is expected to move.
#
# Raised to 12856 by the adversarial campaign's two fixes, diffed by package
# against the 12783 profile so the whole change is accounted for and none of it
# is a wider measurement:
#
#   +64  internal/email        the positive rule for what a secret pipeline may
#                              be, the $-rooted variable case, the {{template}}
#                              refusal, and the arms of both walks -- net of the
#                              three statements removed when the autolink walk's
#                              unreachable "did not advance" branch became one
#                              always-advancing step
#    +6  internal/outbound     ClientForIssuer's per-hop redirect check
BASELINE_TOTAL_STATEMENTS = 12853

# BASELINE_MAX_ENTRIES is a ratchet: the exclusion set may only shrink, so a new
# entry has to be paid for by covering a statement somewhere else or by an
# argument made here.
#
# Raised from 38 to 46 for 1.0.0. The arithmetic, so the next reader can check it
# rather than take it on trust:
#
#   38  the frozen baseline, entirely non-cmd, because cmd/ sat outside the
#       coverage measurement when it was set: 2615 non-test lines, including
#       cmd/recover, the offline erasure-recovery tool, which had no tests at all
#   +6  cmd/ entries, now that cmd/ is measured. None could have been counted in
#       38, because nothing was counting that tree
#   +2  the companion statements of two webauthn blocks that were ALREADY
#       excluded. Each holds a WriteError and a return, only the WriteError was
#       named, and the verifier rejects a block naming some of its statements.
#       These are not new exclusions; they are the rest of two old ones
#   =46
#
# Four entries were deleted in the same pass, as their statements became covered:
# two webauthn session-marshal arms reached by the new MFA audit tests, and two
# kms arms reached by the keystore work. So the non-cmd set reads 38 -> 40 while
# four genuine exclusions left it.
#
# The next person to raise this owes the same arithmetic: what entered the
# measurement, what is a new exclusion rather than a fuller statement of an old
# one, and what left the set entirely.
# Raised from 46 to 48 by the 1.0.0 security work, and the arithmetic again,
# because a ratchet that moves without one is not a ratchet:
#
#   46  the set as measured before the hardening audits
#   +1  cmd/recover/harden_linux.go:25, the prctl errno return. The file did not
#       exist when 46 was set: it arrives with the audit that made the recovery
#       tool undumpable while it holds the escrow key. Both prctl operands are
#       file-scope constants and the call needs no privilege, so the kernel
#       rejects it only under a seccomp rule or an LSM, a state a test cannot
#       enter in-process because a filter cannot be removed once installed and
#       would then catch the Go runtime's own prctl calls.
#   +1  cmd/recover/main.go:584, the f.Stat() error in readKeyFile, from the same
#       audit's key-permission warning. The descriptor is open eight lines above
#       and fstat has no failure mode on a valid descriptor for a local file.
#       The error must stay rather than be dropped: the mode it carries is what
#       drives the world-readable-key warning, so swallowing it would report
#       mode 0 and silence the warning.
#   =48
#
# Both are statements that did not exist when 46 was measured, so this is a
# like-for-like comparison rather than a loosened bar. The alternative offered
# was retiring two entries elsewhere; nothing else in the set had become
# coverable, and inventing a reason to delete a justified exclusion in order to
# make room is exactly the pressure this constant exists to resist.
# Raised from 48 to 50 by the AR-18 geo/VPN feature: +2 entries for the ipintel
# fail-open branch in cmd/vault/main.go (the WARNING log line and the
# ipintel.NewEmpty() substitution). The two statements are named rather than
# numbered on purpose: they have moved twice since this note was written, and
# the exclusion set holds their authoritative anchors.
# ipintel.Default() returns an error only when the embedded blob fails to decode
# (a build-time defect) and its VAULT_IPINTEL_DATA override is fail-open, so
# neither statement is reachable at runtime; they mirror the embedded-asset
# guards already excluded in internal/adminapi and internal/email. The three
# cmd/vault fatal branches the feature shifted (keystore init, honeypot key gen,
# honeypot rotation warning) were relocated in place, not added, and the empty-embed fallback in
# internal/ipintel/ipintel.go was covered by a test rather than excluded.
# Raised from 50 to 52 by the first-boot credential sink, and the arithmetic is
# written here now because it was not written then: the constant moved to 52
# while the itemisation stopped at 50, which is the one thing this comment block
# exists to prevent. The two entries are internal/firstboot/firstboot.go:226 and
# :227, the os.File.Stat error on the descriptor the function opened four lines
# above and has not closed. Both statements arrived with the file; neither
# existed when 50 was measured, so it is a like-for-like move rather than a
# loosened bar, and the pair is named in the set with the argument that fstat
# fails only with EBADF or EFAULT and this call site can produce neither.
# Lowered from 52 to 51 by covering internal/crypto/jwt.go:131, the modulus
# fallback in KIDFromPublicKey. Its exclusion argued that reaching it "would need
# the standard library to stop understanding RSA public keys", and that is not
# so: x509.MarshalPKIXPublicKey understands *rsa.PublicKey perfectly well and
# still refuses one whose modulus is nil, which is a value a caller can build.
# TestJWTEdge_KIDFallbackRunsForAKeyWithNoModulus in internal/crypto now executes
# the fallback and asserts what it does next -- pub.N.Bytes() panics on that same
# nil modulus -- which is the behaviour the keystore exclusion for
# internal/keystore/keystore.go:197 already rested on and nothing executed. The
# ratchet drops with the entry, in the same review as the test that retired it.
BASELINE_MAX_ENTRIES = 51

# The shape guard the statement floor cannot provide: a package dropped from the
# run while enough statements remain elsewhere to clear the count.
#
# The four cmd/ binaries belong here and were missing. cov_run has measured cmd/
# since the package set was widened (see scripts/lib/coverage-env.sh), and the
# statement floor was raised to include it, but this tuple was left at the
# internal/-only list it held beforehand. So cmd/recover could have fallen out of
# the run entirely and only the floor would have noticed, which is the one check
# a genuine deletion is expected to move.
#
# internal/repository is deliberately absent: repository.go declares interfaces
# and nothing else, so it contributes no instrumented statement and listing it
# would fail the check on a correct run. Its implementations live in
# internal/repository/postgres, which is listed.
BASELINE_PACKAGES = (
    "cmd/admin-gateway",
    "cmd/bridge",
    "cmd/recover",
    "cmd/vault",
    "internal/adminapi",
    "internal/alert",
    "internal/audit",
    "internal/cache",
    "internal/cli",
    "internal/config",
    "internal/crypto",
    "internal/deferwork",
    "internal/dpop",
    "internal/email",
    "internal/firstboot",
    "internal/frontend",
    "internal/handler",
    "internal/honeypot",
    "internal/httputil",
    "internal/ipintel",
    "internal/jwt",
    "internal/keystore",
    "internal/kms",
    "internal/metrics",
    "internal/middleware",
    "internal/migrate",
    "internal/model",
    "internal/oauth2",
    "internal/outbound",
    "internal/rbac",
    "internal/redis",
    "internal/repository/postgres",
    "internal/sanitize",
    "internal/seed",
    "internal/server",
    "internal/service",
    "internal/useragent",
)


def load(path):
    """Fold a coverage profile into {block_key: (statements, covered)}.

    A block key is "file.go:startLine.startCol,endLine.endCol". The same key
    appearing in several test binaries is one block: covered by any is covered.
    """
    blocks = {}
    with open(path) as fh:
        header = fh.readline()
        if not header.startswith("mode:"):
            sys.exit(f"{path}: not a coverage profile (no mode: header)")
        for line in fh:
            parts = line.split()
            if len(parts) < 3:
                continue
            key, stmts, count = parts[0], int(parts[1]), int(parts[2])
            prev = blocks.get(key)
            blocks[key] = (stmts, (prev[1] if prev else False) or count > 0)
    if not blocks:
        sys.exit(f"{path}: profile is empty")
    return blocks


def split_key(key):
    """Split a profile key into its file and its first and last line.

    A key looks like <path>:<startLine>.<col>,<endLine>.<col> -- the path, then
    the block's opening and closing positions.
    """
    path, _, span = key.rpartition(":")
    start, _, end = span.partition(",")
    return path, int(start.split(".")[0]), int(end.split(".")[0])


def module_path():
    """The module path from go.mod, or "" when it cannot be read.

    Only the staleness check needs this, and it degrades to checking nothing
    rather than failing a report that would otherwise be fine.
    """
    try:
        with open("go.mod") as fh:
            for line in fh:
                if line.startswith("module "):
                    return line.split(None, 1)[1].strip()
    except OSError:
        pass
    return ""


def check_profile_is_current(blocks, module):
    """Abort when the profile describes a file longer than the one on disk.

    A block whose start line is past its file's end cannot have come from the
    working tree, so the profile carries counters compiled from a different
    version of that file. On 2026-08-18 a shared 50 GB build cache served a
    stale `cmd/bridge`, and under `-coverpkg` every test binary instruments
    every listed package, so one stale entry put 90 phantom zero-count blocks
    into the whole-suite profile. That read as 145 statements neither covered
    nor excluded -- an invented coverage gap, in the gate the version number
    rests on.

    The failure is worth its own check because nothing else notices it.
    `go tool cover -func` reads function start lines out of the profile itself,
    so it reported every function at its correct line and fully covered while
    the profile carried blocks past the end of the file. Neither `-count=1` nor
    touching the source dislodges the entry: the first defeats only test-result
    caching and the second is irrelevant to a content-keyed cache.

    A phantom block can hide a real gap exactly as easily as invent one, so
    this refuses rather than warns.
    """
    prefix = module + "/"
    stale = []
    lengths = {}
    for key in blocks:
        path, start, _ = split_key(key)
        if not path.startswith(prefix):
            continue
        rel = path[len(prefix):]
        if rel not in lengths:
            try:
                with open(rel, "rb") as fh:
                    lengths[rel] = fh.read().count(b"\n")
            except OSError:
                lengths[rel] = None
        n = lengths[rel]
        if n is not None and start > n:
            stale.append((rel, start, n))

    if not stale:
        return
    stale.sort(key=lambda t: (-(t[1] - t[2]), t[0]))
    files = sorted({rel for rel, _, _ in stale})
    print(f"FAIL  the profile is stale: {plural(len(stale), 'block')} start past the end of "
          f"{plural(len(files), 'file')}", file=sys.stderr)
    for rel, start, n in stale[:5]:
        print(f"        {rel}: block starts at line {start}, file has {n}", file=sys.stderr)
    if len(stale) > 5:
        print(f"        ... and {len(stale) - 5} more", file=sys.stderr)
    print("      Those counters were compiled from a different version of the file, so every "
          "number below is measured against a tree that is not this one.\n"
          "      Run `go clean -cache` and measure again. To confirm without clearing a shared "
          "cache, re-run one package under GOCACHE=$(mktemp -d) and compare the block count.",
          file=sys.stderr)
    sys.exit(1)


def totals(blocks):
    total = sum(s for s, _ in blocks.values())
    covered = sum(s for s, c in blocks.values() if c)
    return total, covered


def pct(covered, total):
    return 100.0 * covered / total if total else 0.0


def reachable_targets(total, want):
    """The covered-counts that bracket `want`, and whether `want` is reachable.

    One statement moves the total by 100/total points, so most two-decimal figures
    are not reachable at a given statement count. Promising an unreachable number
    is how a release ends up quietly shipping a different one.
    """
    need = None
    for covered in range(total + 1):
        if round(pct(covered, total), 2) == round(want, 2):
            need = covered
            break
    lo = int(total * want / 100.0)
    return need, lo


def plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def repo_path(path):
    """Repo-relative name for a path inside the tree, absolute for one outside."""
    rel = os.path.relpath(os.path.abspath(path), REPO_ROOT)
    return os.path.abspath(path) if rel.startswith("..") else rel


def load_exclusions(path):
    """Parse and schema-check the exclusion document.

    Problems are returned rather than raised so the verifier can print all of
    them at once. A gate that reports one error per run turns a five-minute fix
    into five CI round-trips.
    """
    problems = []
    try:
        with open(path) as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        return None, [f"{path}: no exclusion file"]
    except json.JSONDecodeError as exc:
        return None, [f"{path}: not valid JSON: {exc}"]

    if not isinstance(doc, dict) or not isinstance(doc.get("entries"), list):
        return None, [f"{path}: expected an object with an 'entries' list"]

    seen = {}
    for i, e in enumerate(doc["entries"]):
        where = f"entry #{i + 1}"
        if not isinstance(e, dict):
            problems.append(f"{where}: not an object")
            continue
        missing = [f for f in ENTRY_FIELDS if f not in e]
        if missing:
            problems.append(f"{where}: missing {', '.join(missing)}")
            continue
        where = f"{e['file']}:{e['line']}"
        if e["bucket"] not in BUCKETS:
            problems.append(f"{where}: bucket {e['bucket']!r} is not one of {BUCKETS}")
        if not isinstance(e["line"], int) or e["line"] < 1:
            problems.append(f"{where}: line must be a positive integer")
        if not isinstance(e["occurrence"], int) or e["occurrence"] < 1:
            problems.append(f"{where}: occurrence must be a positive integer")
        if not isinstance(e["confirmed"], bool):
            problems.append(f"{where}: confirmed must be true or false")
        if len(str(e["justification"]).split()) < 6:
            problems.append(f"{where}: justification is too thin for a reviewer to check")
        if os.path.isabs(e["file"]) or ".." in e["file"].split("/"):
            problems.append(f"{where}: file must be a repo-relative path")
        if e["package"] != os.path.dirname(e["file"]):
            problems.append(f"{where}: package {e['package']!r} is not the file's directory")
        # Two keys, because an entry is addressed two ways and either collision
        # means two entries claim one statement: by line, and by the frozen text
        # plus which occurrence of it this is.
        keys = ((e["file"], e["line"]), (e["file"], e["source"], e["occurrence"]))
        dup = next((seen[k] for k in keys if k in seen), None)
        if dup is not None:
            problems.append(f"{where}: duplicate of entry #{dup + 1}")
        for k in keys:
            seen[k] = i
    return doc, problems


def check_sources(entries):
    """Confirm every entry still names the exact statement it froze.

    An entry identifies a statement by its frozen text and by which of the
    identical lines carrying that text it is; the line number is advisory, which
    is what .coverage-exclusions.json promises and what --relocate rewrites. So
    the match is "the occurrence-th line holding this text is the line named",
    not "this text appears at this line".

    The difference is the whole check. Eight entries freeze text that appears
    more than once in its file, and internal/handler/webauthn.go:77 and :190
    freeze a bare `return` that appears 37 times there. Comparing text at the
    named line alone accepts any of those 37 landing on line 77 after a refactor
    removed the block the entry was written for, and reports 40/40 matching.

    Requiring the occurrence to line up costs something in return: churn among
    the identical lines above an entry fails the gate even when the entry itself
    is untouched. That is the intended price of freezing text as unspecific as a
    bare return, and the fix is a re-review, which is what an exclusion is for.

    Returns (problems, moved), where `moved` maps an entry's index to the line
    its statement now sits on. Finding the statement elsewhere is a different
    failure from not finding it at all: the first is a refactor that moved it,
    the second is a statement that no longer exists.
    """
    problems, moved, cache = [], {}, {}
    for i, e in enumerate(entries):
        if e["file"] not in cache:
            try:
                with open(os.path.join(REPO_ROOT, e["file"])) as fh:
                    cache[e["file"]] = fh.read().split("\n")
            except OSError as exc:
                cache[e["file"]] = None
                problems.append(f"{e['file']}: cannot read ({exc.strerror})")
        src = cache[e["file"]]
        if src is None:
            continue
        hits = [n for n, line in enumerate(src, 1) if line == e["source"]]
        if len(hits) < e["occurrence"]:
            problems.append(f"{e['file']}:{e['line']}: the excluded statement is gone "
                            f"({len(hits)} lines match its frozen text, wanted "
                            f"#{e['occurrence']}). Delete the entry, or re-justify it "
                            f"against the new code.")
            continue
        at = hits[e["occurrence"] - 1]
        if at == e["line"]:
            continue
        moved[i] = at
        problems.append(f"{e['file']}:{e['line']}: occurrence #{e['occurrence']} of the frozen "
                        f"text is on line {at}, not {e['line']}. The statement moved, or a line "
                        f"identical to it appeared above; either way the entry no longer names "
                        f"what it was reviewed against. Re-review it and rerun with --relocate.")
    return problems, moved


# ---------------------------------------------------------------------------
# Justification citations.
#
# The anchors in this file are machine-checked: check_sources() proves that the
# occurrence-th line carrying an entry's frozen text is the line it names. The
# argument for the entry is not, and the argument is what a reviewer is actually
# asked to accept -- the anchor says which statement is excluded, the
# justification says why it is unreachable, and only the second one can be wrong
# in a way that matters.
#
# f692621 re-anchored 25 entries against the hardened tree and updated exactly
# one justification. Every machine-checked field was correct afterwards and 50/50
# anchors resolved, while five justifications had come to cite blank lines,
# comments and a bare closing brace. This file's own policy promises that a
# justification "must be checkable by reading the cited call sites and nothing
# else", and a citation that lands on a blank line cannot be read at all.
#
# So every path:NNN inside the prose is resolved the same way the anchors are.
# What this can prove is that the cited line still holds something: a citation
# resolving to a blank line, a comment or a bare delimiter is one that used to
# point at code and now points at where the code was. What it cannot prove is
# that the line holds the RIGHT code -- the ipintel fail-open entry once cited a
# line in cmd/vault/main.go that had since become an unrelated email-provider log
# line, which is a real statement and the wrong one. Proving that would mean
# freezing the cited text the way `source` freezes the anchor, at the cost of a
# re-review every time any cited line moves. The mechanical class is the one
# that drifts silently; the semantic class fails a reading of the justification,
# which is what the review is for.

# Extensions a citation may name. A reference to a file the checker cannot read
# as text is not resolvable, so the set is closed rather than open.
CITED_EXTENSIONS = ("go", "sql", "sh", "py", "ts", "js", "yaml", "yml", "conf", "json")

CITATION = re.compile(
    r"\b([A-Za-z0-9_.@-]+(?:/[A-Za-z0-9_.@-]+)*\.(?:" + "|".join(CITED_EXTENSIONS) + r")):(\d+)\b")

# A citation into a dependency's source, written in Go's module@version form.
# webauthn@v0.17.4/webauthn/registration.go:103 is a legitimate reference and no
# checkout of this repository can resolve it, so it is skipped -- but only in
# that explicit form, so an unresolvable repo path cannot hide behind the same
# exemption.
MODULE_CITATION = re.compile(r"@v[0-9]")

# Line-comment markers by extension. Go, TypeScript and JavaScript also get
# block-comment tracking below; the rest have none worth modelling.
LINE_COMMENT = {".go": "//", ".ts": "//", ".js": "//", ".sql": "--",
                ".sh": "#", ".py": "#", ".yaml": "#", ".yml": "#", ".conf": "#"}
BLOCK_COMMENT = (".go", ".ts", ".js")

# A line that carries only a delimiter closes something; it is never evidence of
# what the thing was.
BARE_DELIMITERS = frozenset(("{", "}", "(", ")", "[", "]", "},", "),", "],",
                             "};", ");", "})", "}),", "});"))

# Directories with no citable source in them. web/dist and coverage/ are build
# output, and node_modules would make the walk cost more than the rest of the
# gate put together.
SKIP_DIRS = frozenset((".git", "node_modules", "dist", "coverage", "tmp",
                       ".pnpm-store", "testdata"))


def index_tree():
    """basename -> [repo-relative path], for resolving partially-qualified refs."""
    index = defaultdict(list)
    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        rel_dir = os.path.relpath(dirpath, REPO_ROOT)
        for name in filenames:
            rel = name if rel_dir == "." else os.path.join(rel_dir, name)
            index[name].append(rel.replace(os.sep, "/"))
    return index


def resolve_citation(ref, home_dir, index):
    """Repo-relative path for a cited reference, or None with the reason.

    Justifications cite three ways and all three are readable to a person:
    the full repo-relative path, a bare basename meaning "the file this entry is
    about", and a partial path such as seed/seed.go. Each is resolved, and an
    ambiguous partial path is a failure rather than a guess -- the point is that
    a reader can follow the citation, and one that could mean two files cannot
    be followed either.
    """
    if os.path.exists(os.path.join(REPO_ROOT, ref)):
        return ref, None
    base = ref.rsplit("/", 1)[-1]
    if "/" not in ref and home_dir:
        local = f"{home_dir}/{ref}"
        if os.path.exists(os.path.join(REPO_ROOT, local)):
            return local, None
    matches = [p for p in index.get(base, ()) if p == ref or p.endswith("/" + ref)]
    if len(matches) == 1:
        return matches[0], None
    if not matches:
        return None, "no file in the tree matches it"
    return None, "it matches " + ", ".join(sorted(matches))


def classify_line(path, lineno, cache):
    """What sits at a cited line: 'code', or why it is not evidence."""
    if path not in cache:
        try:
            with open(os.path.join(REPO_ROOT, path)) as fh:
                cache[path] = fh.read().split("\n")
        except OSError:
            cache[path] = None
    lines = cache[path]
    if lines is None:
        return "the file cannot be read"
    if lineno > len(lines):
        return f"the file has {len(lines)} lines"
    ext = os.path.splitext(path)[1]

    in_block = False
    if ext in BLOCK_COMMENT:
        for raw in lines[:lineno - 1]:
            i, s = 0, raw.strip()
            while i < len(s):
                if not in_block and s.startswith("/*", i):
                    in_block, i = True, i + 2
                elif in_block and s.startswith("*/", i):
                    in_block, i = False, i + 2
                elif not in_block and s.startswith("//", i):
                    break
                else:
                    i += 1

    text = lines[lineno - 1].strip()
    if text == "":
        return "it is a blank line"
    if in_block:
        return "it is inside a block comment"
    marker = LINE_COMMENT.get(ext)
    if marker and text.startswith(marker):
        return "it is a comment line"
    if ext in BLOCK_COMMENT and text.startswith(("/*", "*")):
        return "it is a comment line"
    if text in BARE_DELIMITERS:
        return f"it is a bare {text!r}"
    return "code"


def check_citations(doc):
    """Resolve every path:NNN written in the policy text and the justifications.

    Returns (problems, checked).
    """
    problems, checked, cache = [], 0, {}
    index = index_tree()

    # This script's own prose is checked alongside the document's. The published
    # arithmetic for the 48 -> 50 raise cited the ipintel pair by a pair of line
    # numbers it had already moved off, and the exclusion set's justification for
    # the same pair cited the same stale line, so both drifted in the same way at
    # the same time. A gate that read one and not the other would have reported
    # the set clean while the reason for its size still pointed at the wrong lines.
    #
    # Neither of those two references names a line any more. A number written into
    # a narrative about a line that moved is a citation this gate must resolve
    # against today's tree, and it goes stale the next time the file is touched --
    # which is what happened to both of them. The rule for prose about history is
    # to name the statement, not the line it used to sit on.
    try:
        with open(os.path.abspath(__file__)) as fh:
            own_prose = fh.read()
    except OSError:
        own_prose = ""

    sources = [
        ("policy", "", "\n".join(doc.get("policy", ()))),
        (repo_path(__file__), "", own_prose),
    ]
    for e in doc.get("entries", ()):
        if not isinstance(e, dict) or "justification" not in e:
            continue
        sources.append((f"{e.get('file')}:{e.get('line')}",
                        os.path.dirname(str(e.get("file", ""))),
                        str(e["justification"])))

    for where, home_dir, text in sources:
        for match in CITATION.finditer(text):
            ref, lineno = match.group(1), int(match.group(2))
            # A module@version reference names a dependency's source, which no
            # checkout of this repository contains.
            if MODULE_CITATION.search(ref):
                continue
            checked += 1
            path, why = resolve_citation(ref, home_dir, index)
            if path is None:
                problems.append(f"{where}: the justification cites {ref}:{lineno} and {why}. "
                                f"Cite a path this tree contains, or write a dependency "
                                f"reference in module@version form so it is recognisable "
                                f"as one.")
                continue
            verdict = classify_line(path, lineno, cache)
            if verdict != "code":
                problems.append(f"{where}: the justification cites {ref}:{lineno} ({path}), and "
                                f"{verdict}. A reader following the citation lands where the "
                                f"code was rather than on the code. Re-derive the line.")
    return problems, checked


def index_profile(blocks, module):
    """{repo-relative file: [(start, end, statements, covered, key)]}."""
    prefix = module.rstrip("/") + "/" if module else ""
    by_file = defaultdict(list)
    for key, (stmts, covered) in blocks.items():
        path, start, end = split_key(key)
        if prefix and path.startswith(prefix):
            path = path[len(prefix):]
        by_file[path].append((start, end, stmts, covered, key))
    return by_file


def resolve_exclusions(blocks, doc):
    """Map every entry onto the profile block that contains it.

    A block is excluded only when the file names *every* statement in it. A
    two-statement block with one entry means the set is half-written, and
    catching that here says so, instead of surfacing later as an off-by-one in
    the covered + excluded == total assertion.
    """
    by_file = index_profile(blocks, doc.get("module", ""))
    problems = []
    per_block = defaultdict(list)
    for e in doc["entries"]:
        hits = [b for b in by_file.get(e["file"], []) if b[0] <= e["line"] <= b[1]]
        if not hits:
            problems.append(f"{e['file']}:{e['line']}: no instrumented statement here in "
                            f"the profile; the source moved, or its package was not measured")
            continue
        if any(b[3] for b in hits):
            problems.append(f"{e['file']}:{e['line']}: now COVERED, delete the exclusion")
            continue
        per_block[min(hits, key=lambda b: b[1] - b[0])[4]].append(e)

    excluded = {}
    for key, es in per_block.items():
        stmts = blocks[key][0]
        if len(es) != stmts:
            path, start, end = split_key(key)
            problems.append(f"{path}:{start}-{end}: block holds {stmts} statements but the "
                            f"exclusion file names {len(es)} of them")
            continue
        excluded[key] = stmts
    return excluded, problems


def check_canonical(blocks, total, module):
    """Confirm the profile is the canonical run, not a slice of it.

    Everything the gate asserts is relative to the profile it is given, so a
    profile that measures less of the tree makes every assertion easier. This is
    the only check that compares the measurement against something outside it.

    The statement floor names the figure it measured in both directions, so
    moving the ratchet is a one-line edit against a measured number rather than
    an argued one.
    """
    problems, notes = [], []
    if total < BASELINE_TOTAL_STATEMENTS:
        problems.append(f"profile holds {total} statements, the canonical run holds "
                        f"{BASELINE_TOTAL_STATEMENTS}. Almost always this is a subset run: "
                        f"`go test -coverprofile` over some packages rather than "
                        f"scripts/coverage.sh, whose -coverpkg=./internal/... instruments all "
                        f"of internal/ whichever suites run. Measure the canonical profile, or "
                        f"if code was deleted, lower BASELINE_TOTAL_STATEMENTS to {total} in "
                        f"the same review as the deletion.")
    elif total > BASELINE_TOTAL_STATEMENTS:
        notes.append(f"profile holds {total} statements, {total - BASELINE_TOTAL_STATEMENTS} "
                     f"over the floor; raise BASELINE_TOTAL_STATEMENTS to {total}")

    measured = {os.path.dirname(f) for f in index_profile(blocks, module)}
    missing = [p for p in BASELINE_PACKAGES if p not in measured]
    if missing:
        problems.append(f"{plural(len(missing), 'canonical package')} contribute no statement "
                        f"to this profile, so nothing in them was measured: "
                        + ", ".join(missing))
    return problems, notes


def verify_exclusions(args):
    """The release gate. Returns a process exit code."""
    path = args.exclude or DEFAULT_EXCLUSIONS
    shown = repo_path(path)
    doc, problems = load_exclusions(path)
    if doc is None:
        for p in problems:
            print(f"FAIL  {p}")
        return 1

    entries = doc["entries"]
    src_problems, moved = check_sources(entries)

    # --relocate is a rewrite tool, never a verdict: it exits nonzero whatever it
    # finds, including when it finds nothing. Returning 0 on an empty run would
    # make `--verify-exclusions --relocate` a green gate that measured nothing,
    # which is the bypass this mode would otherwise hand to a CI author.
    if args.relocate:
        if not moved:
            print(f"{shown}: nothing to relocate. Rerun without --relocate to verify the set.")
            return 1
        for i, line in moved.items():
            entries[i]["line"] = line
        with open(path, "w") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print(f"{shown}: relocated {plural(len(moved), 'line number')}. "
              f"Review the diff, then rerun to verify.")
        return 1

    problems += src_problems
    cite_problems, cited = check_citations(doc)
    problems += cite_problems
    buckets = defaultdict(int)
    for e in entries:
        buckets[e["bucket"]] += 1
    unconfirmed = [e for e in entries if not e["confirmed"]]

    notes = []
    # The set may only ever shrink. .coverage-exclusions.json says so in prose;
    # this is what makes it true. Same shape as GOLANGCI_MAX_ISSUES in
    # scripts/release-check.sh: over the ratchet fails, under it prints the
    # number to lower the ratchet to.
    if len(entries) > BASELINE_MAX_ENTRIES:
        problems.append(f"the set holds {len(entries)} entries, the ratchet is "
                        f"{BASELINE_MAX_ENTRIES}. The set may only shrink: cover the statement, "
                        f"delete the branch, or argue the case in review and raise "
                        f"BASELINE_MAX_ENTRIES in scripts/cov-gaps.py alongside it.")
    elif len(entries) < BASELINE_MAX_ENTRIES:
        notes.append(f"the set holds {len(entries)} entries, "
                     f"{BASELINE_MAX_ENTRIES - len(entries)} under the ratchet; "
                     f"lower BASELINE_MAX_ENTRIES to {len(entries)}")
    if unconfirmed:
        problems.append(f"{len(unconfirmed)} of {len(entries)} entries are confirmed=false. "
                        f"Check each against the profile and set confirmed=true, or delete it: "
                        + ", ".join(f"{e['file']}:{e['line']}" for e in unconfirmed))

    print(f"exclusions  {shown}")
    print(f"entries     {len(entries)} "
          f"({', '.join(f'{n} {b}' for b, n in sorted(buckets.items()))})")
    print(f"source      {len(entries) - len(src_problems)}/{len(entries)} match their frozen text")
    print(f"citations   {cited - len(cite_problems)}/{cited} in the prose resolve to code")

    if args.profile is None:
        # Without a measurement the only check that ran was the one above. Every
        # other assertion the gate exists to make -- that no excluded statement
        # has become covered, that the packages were measured at all, that
        # covered + excluded == total -- needs a profile, so this is a failure
        # and not a reduced mode.
        problems.append("no coverage profile. The frozen-text comparison is the only check that "
                        "runs without one, and on its own it proves that "
                        f"{plural(len(entries), 'string')} still sit at "
                        f"{plural(len(entries), 'line number')}. Pass the profile "
                        "scripts/coverage.sh writes.")
    else:
        blocks = load(args.profile)
        check_profile_is_current(blocks, doc.get("module", ""))
        total, covered = totals(blocks)
        canon_problems, canon_notes = check_canonical(blocks, total, doc.get("module", ""))
        problems += canon_problems
        notes += canon_notes
        excluded, prof_problems = resolve_exclusions(blocks, doc)
        problems += prof_problems
        n_excluded = sum(excluded.values())

        print(f"profile     {args.profile}")
        print(f"total       {total}")
        print(f"covered     {covered}")
        print(f"excluded    {n_excluded}")
        print(f"reachable   {total - n_excluded}")
        if total - n_excluded:
            print(f"coverage    {pct(covered, total - n_excluded):.2f}% of reachable "
                  f"({pct(covered, total):.2f}% of total)")
        if covered + n_excluded != total:
            gap = total - covered - n_excluded
            problems.append(f"covered + excluded = {covered + n_excluded}, total = {total}: "
                            f"{plural(gap, 'statement')} neither covered nor excluded")

    for n in notes:
        print(f"NOTE  {n}")

    if problems:
        print(f"\n{len(problems)} problem{'' if len(problems) == 1 else 's'}")
        for p in problems:
            print(f"FAIL  {p}")
        return 1
    print("\nOK")
    return 0


def report(blocks, args, excluded_n=0, full_total=None):
    total, covered = totals(blocks)
    if full_total is None:
        full_total = total
    uncovered_by_file = defaultdict(list)
    for key, (stmts, is_cov) in blocks.items():
        if is_cov:
            continue
        path, start, end = split_key(key)
        uncovered_by_file[path].append({"start": start, "end": end, "statements": stmts})

    if args.json:
        # total_statements is always the full instrumented count, so a consumer can
        # assert covered + excluded == total without knowing whether an exclusion
        # file was applied. reachable_statements is what the coverage figure is a
        # percentage of.
        print(json.dumps({
            "total_statements": full_total,
            "covered_statements": covered,
            "excluded_statements": excluded_n,
            "reachable_statements": full_total - excluded_n,
            "uncovered_statements": total - covered,
            "coverage": round(pct(covered, total), 2),
            "files": {
                f: sorted(v, key=lambda b: b["start"])
                for f, v in sorted(uncovered_by_file.items())
            },
        }, indent=2))
        return

    print(f"total      {total} statements")
    print(f"covered    {covered}")
    print(f"uncovered  {total - covered}")
    print(f"coverage   {pct(covered, total):.2f}%")

    if args.target is not None:
        need, lo = reachable_targets(total, args.target)
        print()
        if need is None:
            print(f"target {args.target:.2f}% is NOT reachable at {total} statements.")
            print(f"  {lo} covered -> {pct(lo, total):.2f}%")
            print(f"  {lo + 1} covered -> {pct(lo + 1, total):.2f}%")
            print("  pick a figure that lands on a whole statement.")
        else:
            print(f"target {args.target:.2f}% needs {need} covered "
                  f"(+{need - covered} from here, {total - need} may stay uncovered)")

    if args.file:
        hits = {f: v for f, v in uncovered_by_file.items() if args.file in f}
        if not hits:
            print(f"\nno uncovered blocks matching {args.file!r}")
            return
        for f, spans in sorted(hits.items()):
            print(f"\n{f}")
            for b in sorted(spans, key=lambda b: b["start"]):
                span = str(b["start"]) if b["start"] == b["end"] else f"{b['start']}-{b['end']}"
                print(f"  lines {span:>12}   {b['statements']} stmt")
        return

    print(f"\nuncovered blocks by file ({len(uncovered_by_file)} files)")
    print(f"{'statements':>10}  {'blocks':>6}  file")
    rows = sorted(
        ((sum(b["statements"] for b in v), len(v), f) for f, v in uncovered_by_file.items()),
        reverse=True,
    )
    for stmts, count, f in rows:
        print(f"{stmts:>10}  {count:>6}  {f}")


def diff(base, other):
    """Blocks `other` covers that `base` does not, and any regression the other way."""
    gained = sorted(
        (k for k, (_, c) in other.items() if c and k in base and not base[k][1]),
        key=lambda k: split_key(k),
    )
    lost = sorted(
        (k for k, (_, c) in base.items() if c and k in other and not other[k][1]),
        key=lambda k: split_key(k),
    )
    new_blocks = set(other) - set(base)
    gone_blocks = set(base) - set(other)

    gained_stmts = sum(other[k][0] for k in gained)
    lost_stmts = sum(base[k][0] for k in lost)

    print(f"newly covered  {len(gained)} blocks / {gained_stmts} statements")
    for k in gained:
        f, s, e = split_key(k)
        print(f"  + {f}:{s}-{e}  {other[k][0]} stmt")
    if lost:
        print(f"\nREGRESSED      {len(lost)} blocks / {lost_stmts} statements")
        for k in lost:
            f, s, e = split_key(k)
            print(f"  - {f}:{s}-{e}  {base[k][0]} stmt")
    if new_blocks or gone_blocks:
        print(f"\nblock set changed: {len(new_blocks)} new, {len(gone_blocks)} removed")
        print("  the source moved between runs, so the two totals are not comparable.")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("profile", nargs="?",
                    help="coverage profile from scripts/coverage.sh; only --relocate, "
                         "which never reports a pass, runs without one")
    ap.add_argument("--file", help="show every uncovered block in files matching this substring")
    ap.add_argument("--target", type=float,
                    help="covered-count needed to land this coverage figure")
    ap.add_argument("--diff", metavar="OTHER", help="blocks OTHER covers that PROFILE does not")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--exclude", metavar="FILE", nargs="?", const=DEFAULT_EXCLUSIONS,
                    help=f"exclusion set to subtract from the denominator "
                         f"(default {os.path.relpath(DEFAULT_EXCLUSIONS, REPO_ROOT)})")
    ap.add_argument("--verify-exclusions", action="store_true",
                    help="check the exclusion set against the source, against the ratchets "
                         "and against PROFILE; nonzero exit on any drift")
    ap.add_argument("--relocate", action="store_true",
                    help="with --verify-exclusions: rewrite only the line numbers of entries "
                         "whose frozen text moved, then exit nonzero so the diff gets reviewed")
    args = ap.parse_args()

    if args.verify_exclusions:
        sys.exit(verify_exclusions(args))
    if args.relocate:
        sys.exit("--relocate is only meaningful with --verify-exclusions")
    if not args.profile:
        sys.exit("a coverage profile is required (scripts/coverage.sh writes one)")

    blocks = load(args.profile)
    check_profile_is_current(blocks, module_path())
    if args.diff:
        diff(blocks, load(args.diff))
        return

    full_total, _ = totals(blocks)
    excluded_n = 0

    # --json always accounts for exclusions, even without --exclude: a consumer
    # checking covered + excluded == total cannot do so from a figure that silently
    # omits the exclusion set.
    #
    # A set that will not load or will not resolve is fatal in both modes. Passing
    # excluded=0 through instead hands every consumer a reachable figure equal to
    # raw total coverage, which is a plausible-looking number for a broken
    # exclusion set: it happens to trip release-check.sh's identity assertion, and
    # it does not trip anything in scripts/readme-gen.sh, which publishes it.
    exclusion_path = args.exclude or (DEFAULT_EXCLUSIONS if args.json else None)
    if exclusion_path:
        doc, problems = load_exclusions(exclusion_path)
        if doc is None:
            sys.exit("\n".join(problems))
        excluded, problems = resolve_exclusions(blocks, doc)
        if problems:
            print(f"{len(problems)} exclusions did not resolve against this profile; "
                  f"any reachable figure computed from it would be a guess:", file=sys.stderr)
            for p in problems:
                print(f"  {p}", file=sys.stderr)
            sys.exit(1)
        excluded_n = sum(excluded.values())
        if args.exclude:
            print(f"excluded   {excluded_n} statements of {full_total} "
                  f"({repo_path(exclusion_path)}), reachable {full_total - excluded_n}")
            blocks = {k: v for k, v in blocks.items() if k not in excluded}

    report(blocks, args, excluded_n=excluded_n, full_total=full_total)


if __name__ == "__main__":
    main()
