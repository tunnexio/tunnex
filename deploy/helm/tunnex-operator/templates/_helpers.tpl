{{- define "tunnex-operator.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tunnex-operator.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "tunnex-operator.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tunnex-operator.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
app.kubernetes.io/name: {{ include "tunnex-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "tunnex-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tunnex-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "tunnex-operator.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "tunnex-operator.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- required "serviceAccount.name is required when serviceAccount.create=false" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "tunnex-operator.image" -}}
{{- $base := printf "%s/%s" .Values.image.registry .Values.image.repository -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $base .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $base (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "tunnex-operator.validate" -}}
{{- $_ := required "controlPlane.url is required" .Values.controlPlane.url -}}
{{- if not (regexMatch "^https://(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\\[[0-9A-Fa-f:]+\\])(?::[0-9]{1,5})?(?:/[^[:space:]]*)?$" .Values.controlPlane.url) -}}
{{- fail "controlPlane.url must be an absolute https:// URL with a host" -}}
{{- end -}}
{{- $_ = required "controlPlane.organizationID is required" .Values.controlPlane.organizationID -}}
{{- if not (regexMatch "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$" .Values.controlPlane.organizationID) -}}
{{- fail "controlPlane.organizationID must be a UUID" -}}
{{- end -}}
{{- $_ = required "machineToken.existingSecret is required; raw machine tokens are never Helm values" .Values.machineToken.existingSecret -}}
{{- end -}}
