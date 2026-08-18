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
