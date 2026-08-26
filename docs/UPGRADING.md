# Upgrading Vault42

What an upgrade changes outside the pod spec, and what happens when you need to go back.

Every procedure here was executed against a live k3s cluster (`v1.36.2+k3s1`) with Helm
3.16.3 and a real PostgreSQL 16, not rendered and reasoned about. Where something was not
executed, it says so.

---

## Before any upgrade

1. **Back up PostgreSQL.** Migrations are forward-only and there are no down migrations. The
   backup is the rollback plan; see [Rollback](#rollback-what-is-and-is-not-reversible).
2. **Verify the images.** `cosign verify`, per
   [SECURITY.md](../SECURITY.md#verifying-releases). An unverified image is not an upgrade.
3. **Check the Secret has every key the new chart mounts.** `helm get notes` lists them, and
   the list is generated from the chart rather than written by hand. Two of them fail
   quietly if missing: without `pepper` the production profile refuses to start
   (`VAULT_PEPPER_FILE required (>=32 bytes)`), and without `signing-key` each replica signs
   with its own ephemeral key, so tokens minted by one replica are rejected by the others.
4. **Re-apply anything set outside Helm.** `helm upgrade` regenerates the whole pod spec, so
   `kubectl set env` values are discarded. See
   [deployment-guide.md](deployment-guide.md#upgrades).

---

## 1.0.3 to 1.0.4

**Chart.** Nothing to do. `spec.selector` is unchanged, as it has been in every released
chart.

**Secret.** No new keys. The Deployment mounts the same eight it did in 1.0.3.

**Schema.** v1.0.3 shipped 39 migrations; this release ships 40, so an upgrade applies 1.
041 grants `UPDATE (roles)` on `auth.users` to `vault_admin`. It changes no data and no
column: it is what lets `PUT /admin/users/{id}/roles` write at all, because PostgreSQL checks
the column privilege on every target an UPDATE names, and 015 revoked the six columns 009 had
lent that role. Until it runs the route answers 500 in any deployment running as the real
role, and nothing else depends on it. Take the backup anyway: the point of step 1 is that you
have one when something else goes wrong.

**Behaviour.** One new route: `PUT /admin/users/{id}/roles`, which is what migration 041
grants the privilege for. Nothing existing changes shape -- no request path, token or
configuration behaves differently than it did in 1.0.3, and the route is additive, so a
deployment that never calls it is unaffected. An operator may also notice that `docs/deps.md`
and the README badge figures report numbers that differ slightly from 1.0.3's, because those
were being counted wrongly -- see [CHANGELOG.md](../CHANGELOG.md).

---

## 0.9.x to 1.0.0

**Chart.** Nothing to do. The Deployment's `spec.selector` is unchanged from every released
chart, deliberately — see [`helm upgrade` fails with `field is
immutable`](#helm-upgrade-fails-with-field-is-immutable) for why that matters and what to do
if a future release ever does change it.

**Secret.** 0.9.9's Deployment already mounted the same eight keys, so an installation that
was actually running needs no new key. An installation built from 0.9.9's `NOTES.txt`, which
listed five of them, was already broken before the upgrade.

**Schema.** v0.9.9 shipped 12 migrations and 1.0.0 shipped 39, so this upgrade applies 27 in
one go (033 is deliberately absent -- the runner sorts filenames and skips what is applied, so
gaps are harmless). Take the backup first.

Still current if you are coming from 0.9.x: 1.0.1 through 1.0.4 added no migrations, so the
count is the same 39 whichever of them you land on. This release is the first since 1.0.0 to
add one: 041 takes it to 40.

**Every idle session is logged out once.** This release adds an inactivity timeout,
`VAULT_INACTIVITY_TIMEOUT`, defaulting to `1h` — the figure NIST SP 800-63B-4 §2.2.3 gives
for AAL2. A refresh-token family that has gone longer than that without being rotated is
terminated on its next refresh, and the user logs in again. Sessions in active use are
unaffected: a client rotates about once per `VAULT_ACCESS_TOKEN_TTL`, which is 15 minutes by
default. What is affected is anything left overnight, including a "remember me" session, so
expect a burst of logins after the upgrade and one support question about it. Set a longer
duration, or `0` to disable the bound, if that is not what you want. There is no schema
change and nothing to migrate; the bound is measured from a column
`auth.refresh_tokens.created_at` has always carried.

**Migrating with more than one replica is now safe.** `migrate.Run` takes a session-level
advisory lock (key 4245) around the whole run, so the chart's default `replicaCount: 3` with
`autoMigrate: true` no longer means two of three pods die on `create schema_migrations:
duplicate key` or on whichever migration two of them reach together. The losers wait, then
find the schema already at their own version. The migration itself is still one transaction
per file.

---

## Rollback: what is and is not reversible

### `helm rollback` restores the chart, not the schema

Executed: after a failed upgrade, `helm rollback v42 -n <ns>` returns `Rollback was a
success!` and the release goes back to `deployed` at the previous chart. That is the whole
of what it does. The database stays where the migrations left it, so the previous binary
runs against a schema up to 23 migrations ahead of it.

### There are no down migrations, and this release does not add any

Not an oversight, and not something to fix by writing 23 `*_down.sql` files. Most of what
these migrations do cannot be undone into a *correct* state, only into the state the defect
was in:

| Shape | Migrations | Reversible? |
|---|---|---|
| Trigger and function definitions | 015-020, 023-026, 030-032, 034-036 | Mechanically yes — apply the previous definition. But each one is a fix, so "reverting" re-opens the hole it closed. |
| Privilege `REVOKE`s | 015, 018, 020, 024, 026, 029-032, 034, 036 | Mechanically yes, by `GRANT`ing back. Same objection, and see below for the one that bites in the other direction. |
| Added columns and defaults | 013 (`family_created_at`) | Dropping the column loses the backfilled family origins, so re-applying 013 later gives every existing session a fresh maximum lifetime. |
| Widened column types | 022 (`sign_count` INT → BIGINT) | Only if every stored value still fits in the narrower type. Nothing checks that for you. |
| `CHECK` constraints | 027, 035 | Yes, `DROP CONSTRAINT`. Both are added `NOT VALID`, so neither scanned on the way in. |
| Unique indexes over de-duplicated data | 021 (`credential_id`) | The index drops; the de-duplication that had to happen before it would apply does not come back. |

So the honest position is: **the rollback path for the schema is the backup you took in step
1**, not a script this repo can ship.

### The concrete break, if you roll the binary back anyway

Migration 029 does `REVOKE UPDATE (locked_until) ON auth.users FROM vault_app`. That is
correct for 1.0.0, where the only writer of that column is the admin gateway running as
`vault_admin`. 0.9.9's `internal/repository/postgres/user.go` runs
`UPDATE auth.users SET locked_until = $2 WHERE id = $1` as `vault_app`.

A 0.9.9 binary on a 1.0.0 schema therefore has a broken `lock-user` and `unlock-user`: the
`UPDATE` is denied. The privilege itself is gated by
`tests/integration/postgres_account_state_flags_test.go`, which asserts `vault_app` cannot
write `locked_until` and that `vault_admin` can.

### What to do instead of rolling back

* **Roll the image back, keep the schema, and accept the gap.** Workable for most of the 23,
  and the one known break above is an operator command, not a request path. Verify anything
  you depend on before you rely on this.
* **Restore the pre-upgrade backup.** The only route that puts the schema back. It costs
  every write since the backup, so it is a decision about data loss, not about versions.
* **Fix forward.** Usually the cheapest: the failure that made you want to roll back is
  nearly always in the binary or the config, and both roll independently of the schema.

---

## `helm upgrade` fails with `field is immutable`

```text
Error: UPGRADE FAILED: cannot patch "v42-vault-auth" with kind Deployment:
Deployment.apps "v42-vault-auth" is invalid: spec.selector: Invalid value:
{...}: field is immutable
```

A Deployment's `spec.selector` cannot be patched. 1.0.0 does not change it, so a supported
upgrade does not produce this — but a chart you have edited, or a future release that
narrows it, will, and the release is left `failed` with the objects Helm had already patched
(the Service and the ConfigMap) at the new version and the Deployment at the old one.

Two ways out, both executed on a live cluster against exactly this failure:

**Roll back**, if you want the release consistent again and will deal with the chart change
later:

```bash
helm rollback <release> -n <namespace>
```

**Or orphan-delete the Deployment and re-run the upgrade**, which keeps the pods serving
throughout:

```bash
# 1. Delete the Deployment object only. --cascade=orphan leaves the ReplicaSet
#    and every pod running, so traffic is uninterrupted.
kubectl delete deployment <release>-vault-auth -n <namespace> --cascade=orphan

# 2. Re-run the same upgrade. It now creates the Deployment rather than patching it.
helm upgrade <release> <chart> -n <namespace>
```

Observed on the rerun: `STATUS: deployed`, the new selector live, all three pods still
Running, and the orphaned ReplicaSet re-adopted by the new Deployment and scaled down by the
normal rolling update. Check `kubectl get rs -n <namespace>` afterwards and confirm nothing
is left owner-less.

Do this deliberately and not as a habit. Between the delete and the upgrade there is no
controller replacing pods that die.

---

## Retrieving a first-boot credential

Covered by `helm get notes`, and worth repeating for one reason: do not read it with
`kubectl debug ... -- cat`. An ephemeral container's command writes to that container's
stdout, which is a container log, so that form puts the credential into `kubectl logs` and
from there into whatever scrapes the cluster. Start the debug container idle and read the
file over `kubectl exec`, whose stream is not logged. If you have already used a form that
printed it, the credential is disclosed: rotate it, and note that deleting the pod does not
delete the log record.
