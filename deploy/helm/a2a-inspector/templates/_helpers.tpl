{{- define "a2a-inspector.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "a2a-inspector.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- include "a2a-inspector.name" . -}}
{{- end -}}
{{- end -}}

{{- define "a2a-inspector.labels" -}}
app.kubernetes.io/name: {{ include "a2a-inspector.name" . }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "a2a-inspector.selectorLabels" -}}
app.kubernetes.io/name: {{ include "a2a-inspector.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "a2a-inspector.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "a2a-inspector.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "a2a-inspector.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{- define "a2a-inspector.pullPolicy" -}}
{{- .Values.image.pullPolicy | default .Values.global.imagePullPolicy | default "IfNotPresent" -}}
{{- end -}}
