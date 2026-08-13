{{- define "tunnex-gateway.name" -}}tunnex-gateway{{- end -}}

{{- define "tunnex-gateway.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tunnex-gateway.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/name: {{ include "tunnex-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "tunnex-gateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "tunnex-gateway.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* The node-agent image ref. */}}
{{- define "tunnex-gateway.agentImage" -}}
{{- printf "%s/%s:%s" .Values.image.registry .Values.image.agent .Values.image.tag -}}
{{- end -}}

{{/* The Secret name the join token is read from (existing wins; else the chart-minted one). */}}
{{- define "tunnex-gateway.joinTokenSecret" -}}
{{- if .Values.existingJoinTokenSecret -}}
{{- .Values.existingJoinTokenSecret -}}
{{- else -}}
{{- printf "%s-join" (include "tunnex-gateway.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
acknowledgePrivileged gate (F7b): fail the render unless the operator has explicitly
acknowledged the privileged/hostNetwork posture. A `required`-style guard.
*/}}
{{- define "tunnex-gateway.ackGuard" -}}
{{- if not .Values.acknowledgePrivileged -}}
{{- fail "acknowledgePrivileged must be set to true: this chart runs a PRIVILEGED, hostNetwork pod with NET_ADMIN and /dev/net/tun (F4). Review values.yaml, then set acknowledgePrivileged=true to install." -}}
{{- end -}}
{{- end -}}
