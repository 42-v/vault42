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
