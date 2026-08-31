{{- define "tunnex-host-posture.name" -}}tunnex-host-posture{{- end -}}

{{- define "tunnex-host-posture.fullname" -}}
{{- include "tunnex-host-posture.name" . -}}
{{- end -}}

{{- define "tunnex-host-posture.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
app.kubernetes.io/name: {{ include "tunnex-host-posture.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: host-posture
{{- end -}}

{{- define "tunnex-host-posture.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tunnex-host-posture.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: host-posture
{{- end -}}

{{- define "tunnex-host-posture.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "tunnex-host-posture.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- required "serviceAccount.name is required when serviceAccount.create=false" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "tunnex-host-posture.image" -}}
{{- $repository := printf "%s/%s" .Values.image.registry .Values.image.agent -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $repository .Values.image.digest -}}
{{- else -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if not $tag -}}{{- fail "chart appVersion or image.tag is required when image.digest is empty" -}}{{- end -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "tunnex-host-posture.validate" -}}
{{- if ne .Release.Name "tunnex-host-posture" -}}
{{- fail "the cluster-singleton host-posture release name must be exactly tunnex-host-posture" -}}
{{- end -}}
{{- if ne .Release.Namespace "tunnex-system" -}}
{{- fail "the cluster-singleton host-posture release namespace must be exactly tunnex-system" -}}
{{- end -}}
{{- if not .Values.acknowledgePrivileged -}}
{{- fail "acknowledgePrivileged must be true: this cluster-singleton chart runs a privileged hostNetwork DaemonSet and mounts host /proc/sys plus /var/lib/tunnex/host-posture/v1" -}}
{{- end -}}
{{- if and (not .Values.rbac.create) .Values.serviceAccount.create -}}
{{- fail "rbac.create=false requires an externally managed ServiceAccount and read-only cluster Pod RBAC" -}}
{{- end -}}
{{- end -}}
