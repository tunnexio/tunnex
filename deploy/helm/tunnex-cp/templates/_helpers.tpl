{{- define "tunnex-cp.name" -}}tunnex-cp{{- end -}}

{{- define "tunnex-cp.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tunnex-cp.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/name: {{ include "tunnex-cp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "tunnex-cp.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "tunnex-cp.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
img renders a full image ref. Usage: include "tunnex-cp.img" (dict "root" $ "repo" .Values.image.api)
*/}}
{{- define "tunnex-cp.img" -}}
{{- printf "%s/%s:%s" .root.Values.image.registry .repo .root.Values.image.tag -}}
{{- end -}}
