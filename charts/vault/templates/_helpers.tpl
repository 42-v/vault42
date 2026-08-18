{{/*
Expand the name of the chart.
*/}}
{{- define "vault.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "vault.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "vault.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "vault.labels" -}}
helm.sh/chart: {{ include "vault.chart" . }}
{{ include "vault.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "vault.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vault.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "vault.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "vault.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Volume holding the first-boot credential file.

Memory-backed by default: the file carries a credential in cleartext for as long
as it exists, and a node's disk is a worse place for that than a tmpfs that dies
with the pod. An operator who needs to read it after the pod is gone names a
claim instead, which is a decision with a cost on both sides rather than a
default that quietly picks one.
*/}}
{{- define "vault.firstBootCredentialVolume" -}}
- name: first-boot-credential
{{- if .Values.firstBootCredential.existingClaim }}
  persistentVolumeClaim:
    claimName: {{ .Values.firstBootCredential.existingClaim }}
{{- else }}
  emptyDir:
    medium: Memory
    sizeLimit: {{ .Values.firstBootCredential.sizeLimit }}
{{- end }}
{{- end }}

{{/*
Mount for the first-boot credential file, at the directory holding it rather than
at the file: the writer creates the file itself, 0600, and refuses a path that
already exists as anything but a regular file no wider than that.
*/}}
{{- define "vault.firstBootCredentialMount" -}}
- name: first-boot-credential
  mountPath: {{ dir .Values.firstBootCredential.path }}
{{- end }}

{{/*
Secret name to use
*/}}
{{- define "vault.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- include "vault.fullname" . }}
{{- end }}
{{- end }}

{{/*
Every key the vault Deployment mounts out of that Secret, in the order its env
block names them, under the same conditions.

This exists because NOTES.txt used to carry a hand-written list of five, and the
Deployment mounts eight. The two the list left out are not cosmetic: without
`pepper` the production profile refuses to start at all ("VAULT_PEPPER_FILE
required (>=32 bytes) in production profile"), so an operator following the
instructions gets CrashLoopBackOff on a fresh install; and without `signing-key`
the process only warns, then each of the three default replicas signs with its
own ephemeral key, so a token minted by one is rejected by the other two.

Both templates still write their own conditions -- a helper cannot emit an env
block and a prose list from one source -- so the drift is closed by a gate
instead: tests/spec/chart_secret_key_notes_test.go renders this helper and the
Deployment side by side across the value profiles that switch each condition,
and fails when the two disagree.
*/}}
{{- define "vault.requiredSecretKeys" -}}
{{- $keys := list .Values.secrets.keys.masterKey .Values.secrets.keys.dbMigPassword .Values.secrets.keys.dbAppPassword .Values.secrets.keys.hmacSecret -}}
{{- if .Values.secrets.keys.adminToken -}}
{{- $keys = append $keys .Values.secrets.keys.adminToken -}}
{{- end -}}
{{- if and (eq .Values.cache.backend "redis") .Values.secrets.keys.redisPassword -}}
{{- $keys = append $keys .Values.secrets.keys.redisPassword -}}
{{- end -}}
{{- if .Values.secrets.keys.signingKey -}}
{{- $keys = append $keys .Values.secrets.keys.signingKey -}}
{{- end -}}
{{- if .Values.secrets.keys.pepper -}}
{{- $keys = append $keys .Values.secrets.keys.pepper -}}
{{- end -}}
{{- join ", " $keys -}}
{{- end }}

{{/*
Secret name for the honeypot instance.

Deliberately not the release Secret. The honeypot mounted the production one, so
the decoy whose whole purpose is to be broken into held the production master
key, HMAC secret, pepper, signing key, admin token and database passwords -- the
keys to the thing it exists to protect, on the one host in the deployment that is
advertised to attackers. docs/ describes the honeypot as isolated; this is what
makes that true.

The key names are the same as production's, because only the values have to
differ. Give it its own credentials: a honeypot holding a copy of the real master
key is not a honeypot, it is a second copy of the vault with the door open.
*/}}
{{- define "vault.honeypotSecretName" -}}
{{- $name := .Values.honeypotInstance.secrets.existingSecret | default (printf "%s-honeypot" (include "vault.fullname" .)) -}}
{{- if eq $name (include "vault.secretName" .) -}}
{{- fail (printf "honeypotInstance.secrets.existingSecret resolves to %q, which is the Secret the production vault mounts. The honeypot is the component this deployment invites attackers into; giving it the production master key, HMAC secret, pepper, signing key, admin token and database passwords means breaking the decoy is breaking the vault. Point it at a Secret holding the honeypot's own credentials, with the same keys and different values." $name) -}}
{{- end -}}
{{- $name -}}
{{- end }}

{{/*
Seed Secret name to use
*/}}
{{- define "vault.seedSecretName" -}}
{{- if .Values.seed.existingSecret }}
{{- .Values.seed.existingSecret }}
{{- else }}
{{- printf "%s-seed" (include "vault.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Pod-level securityContext for the Kubernetes Pod Security Standards "restricted"
profile. Call with the uid and gid the image's own user has:

  {{- include "vault.podSecurityContext" (dict "uid" 70 "gid" 70) | nindent 8 }}

There is deliberately no shared default. The images in this chart run as five
different users -- vault and cloudflared 65532, postgres-alpine 70, redis
999/1000, nginx-unprivileged 101, mailpit 65534 -- each read off the image
itself. A wrong number here does not fail the render; it fails the pod at
startup with a permission error that reads like a broken volume, which is how
this chart came to carry fsGroup 999 (the Debian postgres GID) against an alpine
image that is 70. fsGroup follows gid unless given, so the volume is always
owned by the group the process actually runs with.
*/}}
{{- define "vault.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ .uid | required "vault.podSecurityContext: uid is required, and must be the uid the image really runs as" }}
runAsGroup: {{ .gid | required "vault.podSecurityContext: gid is required, and must be the gid the image really runs as" }}
fsGroup: {{ .fsGroup | default .gid }}
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{/*
Container-level securityContext for the restricted profile.

readOnlyRootFilesystem is true unless the caller says otherwise, because the
safe posture is the one a new workload gets for free. Where a process genuinely
writes to a path inside its own image, mount an emptyDir on that path rather
than passing "readOnlyRootFilesystem" false: every image in this chart that
writes at runtime -- postgres to its socket dir, redis to its dump dir, nginx to
its cache -- is served by a volume, not by a relaxed setting.
*/}}
{{- define "vault.containerSecurityContext" -}}
allowPrivilegeEscalation: false
privileged: false
readOnlyRootFilesystem: {{ if hasKey . "readOnlyRootFilesystem" }}{{ .readOnlyRootFilesystem }}{{ else }}true{{ end }}
runAsNonRoot: true
capabilities:
  drop:
    - ALL
seccompProfile:
  type: RuntimeDefault
{{- end }}

{{/*
Image reference, digest first. Call with the image stanza plus the defaults the
template would otherwise inline:

  {{ include "vault.image" (dict "image" .Values.postgres.image "repository" "postgres" "tag" "17-alpine") }}

A tag names something the registry can move underneath a running release; a
digest names the bytes. Where a digest is set it wins, and the tag stays in
values as the human-readable record of which release that digest is.
*/}}
{{- define "vault.image" -}}
{{- $image := .image | default dict -}}
{{- $repository := $image.repository | default .repository -}}
{{- if not $repository -}}
{{- fail "vault.image: no image repository, and none supplied as a default" -}}
{{- end -}}
{{- if $image.digest -}}
{{- printf "%s@%s" $repository $image.digest -}}
{{- else -}}
{{- $tag := $image.tag | default .tag -}}
{{- if not $tag -}}
{{- fail (printf "vault.image: %s has neither a tag nor a digest" $repository) -}}
{{- end -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end -}}
{{- end }}
