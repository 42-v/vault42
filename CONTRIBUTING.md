# Contributing to Vault42

This file covers the mechanics you cannot guess from the tree. It is not etiquette: every
rule here is something that will fail your pull request or silently break a release if you
do not know it.

Vault42 has a single maintainer (`.github/CODEOWNERS`). Expect review to be slow and
opinionated, and open an issue before writing anything large.

## The one thing that matters most

**`scripts/precommit.sh` is the gate, and nothing runs it for you.**

There is no git hook. `.git/hooks/` holds only `.sample` files, `core.hooksPath` is unset, and
`package.json` has no `husky`, `prepare` or `lint-staged` entry. If you do not type the command,
it does not run:

```bash
scripts/precommit.sh
```

It exits non-zero when something is wrong, and it performs six steps in order:

| Step | Script | What fails you |
|---|---|---|
| 1 | `scripts/precommit/01-build.sh` | build or `go vet` errors (hard gate, stops here) |
| 2 | `scripts/precommit/02-gosec.sh` | a gosec finding (skipped if gosec is not installed) |
| 3 | `scripts/precommit/03-go-tests.sh` | any Go test failure |
| 4 | `scripts/precommit/04-vue-tests.sh` | any frontend test failure |
| 5 | `scripts/precommit/05-stats.sh` | nothing; it collects the numbers step 6 needs |
| 6 | `scripts/precommit/06-docs.sh` | a generator error, which now propagates rather than being swallowed |

Step 6 rewrites generated files. Commit whatever it changes along with your work.

## Generated files: never edit by hand

Four things are produced by scripts. Editing them directly is wasted effort, and step 6 will
overwrite you.

| File | Generator |
|---|---|
| the badge block in `README.md`, between the `<!-- badges -->` and `<!-- /badges -->` sentinels | `scripts/readme-gen.sh` |
| `docs/badges.json` | `scripts/readme-gen.sh` |
| `docs/deps.md` | `scripts/readme-gen.sh` |
| `docs/test-coverage.md` | `scripts/coverage.sh` |

## Commit messages

Commits are linted as [Conventional Commits](https://www.conventionalcommits.org/) on every pull
request (`.github/workflows/commitlint.yml`), and so is the pull request title. Configuration
lives in `commitlint.config.js`. The allowed types are:

```text
feat  fix  docs  style  refactor  perf  test  build  ci  chore  revert  security
```

Subject case is unrestricted. A malformed message fails CI before any test runs.

Two inherited rules are worth knowing because neither is written in
`commitlint.config.js`. Body lines are capped at 100 characters and a longer one is an error, not
a warning, so wrap the body. `footer-leading-blank` is switched off on purpose: this repository
writes prose bodies, and the parser reads any line starting `word: value` as a malformed footer.

## Releases are tag-driven, and not yours to cut

`.github/workflows/release.yml` fires on a pushed `vX.Y.Z` tag (or `workflow_dispatch` to re-run
one). The tag must be an ancestor of `main` and its version must match what the tree declares,
or the run fails before publishing anything. It then builds and signs three multi-arch images,
packages and signs the Helm chart, builds binaries with SBOMs and a signed checksum file, pushes
both NuGet packages, and creates the GitHub release.

Nothing you can do in a pull request triggers a release, and that is deliberate: the previous
trigger read the version off the head commit's subject, which commitlint rejects, so every
release was cut by hand-editing a squash subject. That is how 0.8.6 was lost. Do not reintroduce
a version-prefixed commit subject as a release mechanism.

## What CI runs on your pull request

`.github/workflows/ci.yml`, which also runs on every push to `main`. All eighteen jobs, named as
they appear in the checks list:

| Job | What it does |
|---|---|
| Detect Go changes | computes the flags six jobs below are conditional on; when no Go file changed, those six skip |
| Tests | `go vet`, then `go test ./internal/... -race` with a coverage profile, then `./tests/attack/... ./tests/unit/... ./tests/fuzz/... ./tests/spec/...` under the race detector, then integration and compliance |
| Go coverage gate | a canonical coverage run checked by `scripts/release-check.sh --coverage-only`. Conditional |
| Go coverage gate (required) | watches the job above and fails when it was skipped. **Require this one in branch protection**, not the job it watches: a skipped job reports green |
| Frontend | builds `packages/vue` and `web`, then `test:coverage` for both, enforcing the thresholds in each `vite.config.ts`, then `eslint .` over the whole repository, `site/` included, at `--max-warnings 0` |
| golangci-lint | `.golangci.yml` on the diff as a gate, and a whole-tree run held against `.golangci-baseline.json`. Both fail the job; the whole-tree run is a ratchet, not a report |
| Security | calls `.github/workflows/nightly-security.yml`: govulncheck, gosec, trivy over source, image and frontend base, and the attack suite |
| Helm chart | `helm lint` plus a render of every values file, and a check that a default install resolves a published image tag |
| Version consistency | `scripts/version-bump.sh --check`: every manifest must agree, including the two version markers in `site/index.html` |
| Go module hygiene | `go mod verify` and `go mod tidy -diff`. Conditional |
| Fuzz Tests | JWT, Argon2, TOTP, email and DPoP for one minute each. Conditional |
| Build All Binaries | `vault`, `bridge`, `admin-gateway`. Conditional |
| GoReleaser config | validates `.goreleaser.yaml`. Conditional |
| Suites CI cannot run | compiles `tests/admin`, `tests/honeypot`, `tests/stress` and `tests/browser` under their build tags and collects the Playwright suite, then fails if any of them neither ran nor printed its skip notice |
| Hadolint | the six root Dockerfiles and `web/Dockerfile` |
| Lint (non-Go) | shellcheck over every tracked `*.sh`, `ruff check`, markdownlint and `yamllint --strict`. The four configurations these read were tuned to zero by hand and ran in no workflow until 1.0.1; two had already drifted back by then |
| .NET SDK coverage gate | builds `packages/dotnet` with `-warnaserror` and runs `scripts/dotnet-coverage.sh` at a floor of 100.00 with no exclusions file. Conditional |
| .NET SDK coverage gate (required) | watches the job above, for the same reason the Go one has a watcher |

`.github/workflows/commitlint.yml` lints the commits and the pull request title.

`.markdownlint-cli2.jsonc`, `.shellcheckrc`, `.yamllint.yml` and `ruff.toml` are read by the
Lint (non-Go) job. Until 1.0.1 they were read by nothing: each had been driven to zero by hand,
which described a moment rather than a property, and two of the four had drifted back before
anyone noticed.

Before a release, `scripts/release-check.sh` runs twelve gates, of which the security pass
(govulncheck, gosec, trivy fs, attack suite, coverage) is the first five. The other seven are
version consistency, module hygiene, the golangci ratchet, helm lint and template, documented
chart paths, a changelog section for the version being cut, and a clean working tree, so a
release can go red on a missing changelog entry alone.

`scripts/security-scan.sh` is a different tool, not a standalone equivalent: it adds `go vet`,
staticcheck, `pnpm audit` and hadolint, and it runs no trivy, no attack suite and no coverage.

## Documentation is part of the change

Keep the docs in step with the code in the same commit. In particular:

- **A new or changed environment variable** must appear in `docs/config.md` (or
  `docs/admin-gateway.md` / `docs/bridge.md` for those binaries) *and* carry a doc comment on
  its config-struct field. `README.md` advertises `docs/config.md` as the complete env-var
  reference; keep that true.
- **A new document** in `docs/` gets a row in `docs/README.md`.
- **A published file never links to an unpublished one.** Several documents are kept on disk but
  excluded by `.gitignore` (internal notes, the spec draft, dated security audits, the security
  review). A link or a "see also" pointing at one of those is a 404 on GitHub.
- **A new attack vector** belongs in `docs/cheatsheet.md`; a change to the middleware chain or
  request lifecycle belongs in `docs/architecture.md`; a deliberate weakening belongs in
  `docs/security.md` as a numbered accepted risk.
- **Never document a control that does not exist.** If the code only records something for later
  human review, say that. A policy asserting a control you lack is worse than lacking it.

## Code style

- Comments state what the code cannot: an invariant, a rationale, a caller obligation, a
  fail-open branch and the condition that makes it safe. Not what the next line does.
- No tracking comments. "Fixed in 0.9.4", "changed to constant-time", "was previously" -- history
  belongs in `git log` and `CHANGELOG.md`.
- Where code enforces a security property, the comment says what is guaranteed, why this
  construction, what the failure branch does, and what the caller must do. The `internal/kms`
  package doc and `RateLimitConfig.FailClosed` in `internal/middleware/ratelimit.go` are the
  reference.
- New dependencies are close to unacceptable. Three of `go.mod`'s six direct requires ship in the
  binary (`pgx/v5`, `go-webauthn`, `x/crypto`); the other three, testcontainers and `yaml.v3`, are
  imported by test files only, which is why the badge says three. The minimal-dependency rule is a
  security control, not an aesthetic. Bring a strong argument, and a test-only dependency is still
  a dependency.

## Security issues do not go here

Do not open a public issue, and do not send a pull request that reveals an unfixed
vulnerability. Email <vault@42-v.com>. See [SECURITY.md](SECURITY.md).

## License

Contributions are accepted under the MIT license in [LICENSE](LICENSE).
