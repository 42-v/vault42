# vault-auth chart

Every workload this chart renders targets the Kubernetes [Pod Security Standards
"restricted"](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
profile out of the box: non-root with an explicit uid and gid, `fsGroup` matching
that gid, `seccompProfile: RuntimeDefault`, `allowPrivilegeEscalation: false`,
all capabilities dropped, and a read-only root filesystem with an `emptyDir`
wherever a process genuinely writes.

`tests/spec/chart_workload_hardening_test.go` renders every values profile and
asserts all of that, so a workload added without it fails CI rather than
shipping.

## Where the security context comes from

There are two places, and only two:

| | Source | Workloads |
|---|---|---|
| Product containers | `.Values.podSecurityContext` / `.Values.securityContext` | vault, bridge, honeypot vault, admin gateway |
| Bundled infrastructure | `vault.podSecurityContext` / `vault.containerSecurityContext` in `_helpers.tpl` | postgres, honeypot postgres, redis, mailpit, frontend, cloudflared |

The product containers read theirs from values because an operator may have to
tune them for a particular cluster. The bundled images take theirs from the
helpers because each runs as a different user and the number is a property of the
image, not a preference.

The helpers take the uid and gid as arguments for exactly that reason. There is
no shared default, because a wrong number does not fail the render: it fails the
pod at startup with a permission error that reads like a broken volume.

| Image | uid | gid |
|---|---|---|
| `ghcr.io/42-v/vault42*` (distroless nonroot) | 65532 | 65532 |
| `postgres:17-alpine` | 70 | 70 |
| `redis:7-alpine` | 999 | **1000** |
| `nginxinc/nginx-unprivileged` | 101 | 101 |
| `axllent/mailpit` | 65534 (`nobody`) | 65534 |
| `cloudflare/cloudflared` | 65532 | 65532 |

Each was read off the image itself. Note redis: its user is uid 999 in group
1000, which is not the symmetric pair it looks like it should be.

## The admin gateway needs a decision

`adminGateway.hostNetwork` defaults to **false**. Both the baseline and the
restricted Pod Security Standards profiles forbid `hostNetwork`, so a chart that
turned it on by default could not be installed into a namespace enforcing either.

The gateway will not render without an explicit choice between two postures:

- **`adminGateway.hostNetwork: true`** — the gateway binds the node's loopback,
  and only a connection from the node reaches it. This is the strongest posture
  and the one production wants. It needs a namespace whose Pod Security Standards
  policy permits `hostNetwork`, which means labelling the namespace `privileged`,
  or exempting this release, or running a policy engine with a rule for it.
  Without that the pod is rejected at admission.

- **`adminGateway.devMode: true`** — the admin plane is reachable through the
  cluster network. This turns off `LocalOnly` and `RejectProxyHeaders`, leaving
  the bearer session token as the remaining control, so whatever proxy sits in
  front of it has to carry the weight `LocalOnly` did.

Enabling the gateway with neither fails the render with a message saying so.

## Upgrading

**postgres and honeypot postgres now run as uid/gid 70.** The `fsGroup` was 999,
the postgres GID in the Debian image, against `postgres:17-alpine`, which is 70.
It worked only because the container ran as root and the entrypoint chowned
`PGDATA` before dropping privileges, which also means an existing data directory
is already owned by 70 and the new `fsGroup` matches what is on the volume. No
migration is needed.

**The honeypot database moves into a `pgdata` subdirectory.** It had no `PGDATA`,
so its data directory was the volume mount root, and a non-root postgres cannot
`chmod` that root to the mode `initdb` requires. The real StatefulSet already
used a subdirectory. An existing honeypot volume re-initialises empty; the
honeypot holds no data worth keeping by design, but it is a change, not a no-op.

**Seed credentials move from a ConfigMap to a Secret.** The mount path and
`VAULT_SEED_FILE` are unchanged. Delete the old `<release>-seed` ConfigMap after
upgrading; Helm will not, because the object changed kind. Set
`seed.existingSecret` to keep the credentials out of the values file entirely.

**`postgres.appPassword` is gone.** No template ever read it.

**mailpit and cloudflared are pinned by digest.** `mailpit.image.digest` and
`cloudflared.image.digest` win over their tags. Clear the digest to follow a tag
again; raise both deliberately rather than floating.
