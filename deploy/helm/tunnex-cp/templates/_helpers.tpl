{{- define "tunnex-cp.name" -}}tunnex-cp{{- end -}}

{{- define "tunnex-cp.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tunnex-cp.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" | quote }}
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

{{/* A headless peer identity resolves edge pod addresses, not its ClusterIP. */}}
{{- define "tunnex-cp.edgeProxyService" -}}
{{- printf "%s-edge-proxies" (include "tunnex-cp.fullname" . | trunc 50 | trimSuffix "-") -}}
{{- end -}}

{{- define "tunnex-cp.appAccessGuard" -}}
{{- if .Values.appAccess.enabled -}}
{{- if ne (int .Values.api.replicas) 1 -}}{{- fail "App Access currently requires api.replicas=1; shared restore/stream HA is unqualified" -}}{{- end -}}
{{- if not (regexMatch "^[^\\s@]+@sha256:[a-f0-9]{64}$" .Values.appAccess.proxy.image) -}}{{- fail "appAccess.proxy.image must be a signed immutable image@sha256" -}}{{- end -}}
{{- range $name,$value := dict "baseDomain" .Values.appAccess.baseDomain "restore.existingClaim" .Values.appAccess.restore.existingClaim "proxy.credentialSecret" .Values.appAccess.proxy.credentialSecret "proxy.publicTLSSecret" .Values.appAccess.proxy.publicTLSSecret "proxy.gatewayTLSSecret" .Values.appAccess.proxy.gatewayTLSSecret "proxy.agentCASecret" .Values.appAccess.proxy.agentCASecret -}}
{{- if not $value -}}{{- fail (printf "appAccess.%s is required; this chart never generates trust or credentials" $name) -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
