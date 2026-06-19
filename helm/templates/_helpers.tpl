{{/*
Expand the name of the chart.
*/}}
{{- define "cryptosight-probe.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name (release-name + chart-name, ≤ 63 chars).
*/}}
{{- define "cryptosight-probe.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "cryptosight-probe.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Namespace — respects namespaceOverride.
*/}}
{{- define "cryptosight-probe.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride }}
{{- end }}

{{/*
Common labels applied to every resource.
*/}}
{{- define "cryptosight-probe.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "cryptosight-probe.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels — used by the DaemonSet selector and Service (if any).
*/}}
{{- define "cryptosight-probe.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cryptosight-probe.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "cryptosight-probe.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "cryptosight-probe.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Resolve the secret name that holds the API key.
When existingSecret.name is set, use that; otherwise use the auto-generated secret.
*/}}
{{- define "cryptosight-probe.secretName" -}}
{{- if .Values.probe.existingSecret.name }}
{{- .Values.probe.existingSecret.name }}
{{- else }}
{{- include "cryptosight-probe.fullname" . }}
{{- end }}
{{- end }}

{{/*
The key inside the secret that holds the API key value.
*/}}
{{- define "cryptosight-probe.secretApiKeyKey" -}}
{{- default "apiKey" .Values.probe.existingSecret.apiKeyKey }}
{{- end }}
