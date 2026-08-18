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

## The Secrets you have to create first

**This chart creates no credential Secret.** It mounts them; something else has to
put them there. A `helm install` with none of them present passes `helm lint`,
`helm template` and `--dry-run`, and then sits in `ContainerCreating` forever with
the reason only visible in `kubectl describe pod`. Create them before installing.

| Secret | Default name | Mounted by | Required |
|---|---|---|---|
| Release credentials | `<release>-vault-auth`, or `secrets.existingSecret` | vault, bridge, admin gateway, postgres, redis | always |
| Honeypot credentials | `<release>-vault-auth-honeypot`, or `honeypotInstance.secrets.existingSecret` | honeypot vault, honeypot postgres | `bridge.enabled` only |
| Admin gateway mTLS | `adminGateway.tls.secretName` | admin gateway | `adminGateway.enabled` only |

Keys in the two credential Secrets are named by `secrets.keys`:

```
master-key  db-mig-password  db-app-password  hmac-secret
admin-token  redis-password  signing-key  pepper
```

The honeypot Secret carries **the same key names and different values**. That is
the whole point of it: the honeypot is the component this deployment invites
attackers into, so whatever it holds is what breaking the decoy yields. It used to
mount the release Secret, which meant the decoy held the production master key.
The chart now refuses to render if the two names resolve to the same Secret.

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

mTLS still requires a client certificate signed by `adminGateway.tls`. Two extra pins are optional and fail closed once set:

- `adminGateway.clientCNAllowlist` becomes `ADMIN_GW_CLIENT_CN_ALLOWLIST`. Empty accepts every certificate the client CA has signed and the gateway warns at startup (AR-9).
- `adminGateway.clientCRLFile` becomes `ADMIN_GW_CLIENT_CRL_FILE`. An unreadable path is fatal at boot. Empty checks nothing.

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

**`postgres.enabled: true` starts working.** The bundled postgres never got past
`initdb` in any profile: its init script's second here-document ended with an
indented `EOSQL` against a `<<-` that strips tabs and not spaces, so it was never
terminated, and bash parses the whole file before running any of it. The container
exited 2 under the entrypoint's `set -e`. `vault_app` was therefore never created.

**The honeypot needs its own Secret.** Bridge-mode releases upgrading to this
version must create `<release>-vault-auth-honeypot`, or point
`honeypotInstance.secrets.existingSecret` at one, before upgrading. The honeypot
pods will not start without it, which is the intended outcome: the alternative was
them starting with the production master key.

**`postgres.appPassword` is gone.** No template ever read it.

**`values-bridge.yaml` now sets the vault's own `trustedProxies`.** It only set
`bridge.trustedProxies`, which the bridge reads and the vault does not, so every
request in a bridge deployment resolved to the bridge pod's single address. Do not
take this line alone: it is only safe against a bridge that strips the client's
own upstream-trust headers, and it is worse than the misattribution it fixes
against a bridge that does not.

**mailpit and cloudflared are pinned by digest.** `mailpit.image.digest` and
`cloudflared.image.digest` win over their tags. Clear the digest to follow a tag
again; raise both deliberately rather than floating.
