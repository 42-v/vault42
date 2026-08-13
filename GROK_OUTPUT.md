# Task 009

## Commit message

```
security: keep mint and svcdoc audits under buffer pressure

POST /mint is a subject-assertion signing oracle. The JWT it
signs is indistinguishable from any other issued token, so
token_minted is the only record of who asked. Losing that under
VAULT_AUDIT_FLUSH_INTERVAL > 0 (the embedded profile default)
is worse than losing a password_change, which was already
critical.

svcdoc_put/get/delete are the trail of who accessed whose
service document. They are matched by prefix, the same way the
scrubber already treats the class, so a future svcdoc_ type
cannot silently fall back to the droppable buffer the way
token_minted did when it was added without updating
isCriticalEvent.

The five orphaned suites cannot run on a default GitHub Actions
runner. Each now prints a loud SKIP and names the env var that
makes the skip fatal. YAML for the test job is below; this
stream does not own .github/workflows.
```

## Decision per suite

None of the five can be a green *passing* gate on `ubuntu-latest`.
All five can (and should) be *invoked* so a skip is visible, the
same way `tests/e2e` is invoked with `VAULT_E2E_REQUIRED` unset.

| Suite | Runnable on GHA? | Why not (or what it would take) | Source-side |
|---|---|---|---|
| `tests/honeypot` | No | Needs locally-tagged `vault:dev` and `vault-bridge:dev` images plus five containers. Sibling containers are given host-mapped DB ports, which do not reach each other on the runner. Building both images every PR is a different job, and the topology is still wrong. | Untagged `TestMain` + notice test. Tagged `TestMain` skips if the images are missing. `scripts/t.sh honeypot`. |
| `tests/stress` | No | Load-generates against a live vault, uses `kubectl` to flip `email_verified`, talks to Mailpit. No cluster on the runner. | Untagged `TestMain` + notice test. Tagged `TestMain` skips if `/healthz` is down. `scripts/t.sh stress`. |
| `tests/admin` | No | Needs a running admin gateway, mTLS client certs, and `ADMIN_FIRST_PASSWORD` from pod logs. Its empty nested `go.mod` was removed so `go test ./tests/admin/...` is visible to the parent module. | `TestMain` used to log one line and `os.Exit(0)`. It now prints what did not run and names `VAULT_ADMIN_E2E_REQUIRED`. `scripts/t.sh admin`. |
| `tests/browser` | No | Nested module (`tests/browser/go.mod`) needing chromedp, Chrome, a live vault, kubectl and Mailpit. The parent `go test ./...` never even sees this directory. | Untagged `TestMain` + notice test. Tagged `TestMain` names `VAULT_BROWSER_REQUIRED`. `scripts/t.sh -tags browser`. |
| `tests/e2e-browser` | No | Playwright + Chromium + a deployed vault (and Mailpit). Not a GHA default, and there is no in-repo `webServer` that can stand in for Postgres/Redis/secrets. | `tests/e2e-browser/run.sh` is the TestMain. `scripts/t.sh e2e-browser` calls it. Direct `npx playwright test` fails via `global-setup.ts` rather than skipping. |

Not added to `COV_PKGS`. Coverage measures `internal/` + `cmd/` in-process. A skip-only package would spend a test binary on a profile it cannot change. The comment in `scripts/lib/coverage-env.sh` records that.

Do **not** set any `*_REQUIRED=1` env var in the test job. That would turn every PR red for a suite the runner cannot execute. The step name must say the suite skips, as the existing e2e step already does.

## YAML diff

Apply this to `.github/workflows/ci.yml` in the `test` job, immediately after the existing e2e step.

```diff
       - name: E2E tests (multireplica only; the cluster suite skips here)
         run: go test ./tests/e2e/... -count=1 -race -v -timeout 1800s 2>&1 | tee -a test-output.txt
 
+      # The five suites below cannot execute on this runner. Each prints a
+      # loud SKIP and names the env var that makes that skip fatal. Invoking
+      # them is what makes the gap visible. Do not set the REQUIRED vars
+      # here: that would fail the job for a missing cluster/images/browser.
+      - name: Honeypot E2E (skips without -tags honeypot_e2e and local images)
+        run: go test ./tests/honeypot/... -count=1 -v 2>&1 | tee -a test-output.txt
+
+      - name: Stress tests (skips without -tags stress and a live cluster)
+        run: go test ./tests/stress/... -count=1 -v 2>&1 | tee -a test-output.txt
+
+      - name: Admin gateway E2E (skips without ADMIN_FIRST_PASSWORD)
+        run: go test ./tests/admin/... -count=1 -v 2>&1 | tee -a test-output.txt
+
+      - name: Browser tests (skips without -tags browser and a live vault)
+        run: go test -C tests/browser -count=1 -v . 2>&1 | tee -a test-output.txt
+
+      - name: Playwright E2E (skips without a live vault)
+        run: bash tests/e2e-browser/run.sh 2>&1 | tee -a test-output.txt
+
       - name: Upload unit coverage
```

No change to `coverage-gate`. Adding these packages to `COV_PKGS` would not move the coverage number and would make a missing skip look like a coverage event.

## How to run a suite for real

```
scripts/t.sh honeypot          # -tags honeypot_e2e, needs vault:dev images
scripts/t.sh stress            # -tags stress, needs VAULT_STRESS_URL
scripts/t.sh admin             # needs ADMIN_FIRST_PASSWORD + mTLS certs
scripts/t.sh -tags browser     # needs a live vault + Chrome
scripts/t.sh e2e-browser       # needs a live vault + Playwright
```

Set the matching `VAULT_*_REQUIRED=1` anywhere a skip must not read as a pass.
