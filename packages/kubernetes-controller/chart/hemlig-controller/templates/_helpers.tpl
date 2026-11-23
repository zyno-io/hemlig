{{- define "hemlig-controller.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "hemlig-controller.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := include "hemlig-controller.name" . }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "hemlig-controller.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "hemlig-controller.labels" -}}
helm.sh/chart: {{ include "hemlig-controller.chart" . }}
{{ include "hemlig-controller.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "hemlig-controller.selectorLabels" -}}
app.kubernetes.io/name: {{ include "hemlig-controller.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "hemlig-controller.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "hemlig-controller.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- required "serviceAccount.name is required when serviceAccount.create is false" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Safe access for values blocks that releases created before Phase 5/6 lack (helm upgrade --reuse-values). */}}
{{- define "hemlig-controller.approval" -}}
{{- $cm := .Values.certManager | default dict -}}
{{- $ap := $cm.approval | default dict -}}
{{- dict "grant" (ternary $ap.grantDefaultApprover true (hasKey $ap "grantDefaultApprover")) "serviceAccount" ($ap.serviceAccount | default "cert-manager") "namespace" ($ap.namespace | default "cert-manager") | toJson -}}
{{- end -}}

{{- define "hemlig-controller.maxConcurrentRequests" -}}
{{- (.Values.certManager | default dict).maxConcurrentRequests | default 4 | int64 -}}
{{- end -}}

{{- define "hemlig-controller.bundleIntervalMs" -}}
{{- (.Values.trustBundles | default dict).refreshIntervalMilliseconds | default 300000 | int64 -}}
{{- end -}}
