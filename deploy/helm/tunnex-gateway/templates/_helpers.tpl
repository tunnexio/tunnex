{{- define "tunnex-gateway.name" -}}tunnex-gateway{{- end -}}

{{- define "tunnex-gateway.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tunnex-gateway.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" | quote }}
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
{{- $repository := printf "%s/%s" .Values.image.registry .Values.image.agent -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $repository .Values.image.digest -}}
{{- else -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if not $tag -}}{{- fail "chart appVersion or image.tag is required when image.digest is empty" -}}{{- end -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end -}}
{{- end -}}

{{/* The Secret name the join token is read from (canonical existing, legacy existing, then chart-minted). */}}
{{- define "tunnex-gateway.joinTokenSecret" -}}
{{- if .Values.enrollment.existingSecret -}}
{{- .Values.enrollment.existingSecret -}}
{{- else if .Values.existingJoinTokenSecret -}}
{{- .Values.existingJoinTokenSecret -}}
{{- else -}}
{{- printf "%s-join" (include "tunnex-gateway.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* The durable identity claim. An explicit retained claim wins on reuse. */}}
{{- define "tunnex-gateway.stateClaimName" -}}
{{- default (printf "%s-state" (include "tunnex-gateway.fullname" .)) .Values.persistence.existingClaim -}}
{{- end -}}

{{/*
Direct Helm enroll must never stamp new provenance onto retained identity bytes.
This render-time lookup uses the Helm caller's existing Kubernetes credentials;
it runs before hooks or ordinary resources are applied, including with --no-hooks.
Offline template/client dry-run cannot inspect live objects and is only a preview.
*/}}
{{- define "tunnex-gateway.retainedEnrollGuard" -}}
{{- if and .Values.persistence.enabled (eq .Values.enrollment.mode "enroll") (not .Values.persistence.existingClaim) -}}
  {{- $claimName := include "tunnex-gateway.stateClaimName" . -}}
  {{- $claim := lookup "v1" "PersistentVolumeClaim" .Release.Namespace $claimName -}}
  {{- if $claim -}}
    {{- $annotations := default (dict) $claim.metadata.annotations -}}
    {{- $organization := default "" (index $annotations "tunnex.io/organization-id") -}}
    {{- $lifecycleClaim := default "" (index $annotations "tunnex.io/lifecycle-claim") -}}
    {{- $uuidPattern := "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" -}}
    {{- $nilUUID := "00000000-0000-0000-0000-000000000000" -}}
    {{- if or (not (regexMatch $uuidPattern $organization)) (not (regexMatch $uuidPattern $lifecycleClaim)) (eq $organization $nilUUID) (eq $lifecycleClaim $nilUUID) -}}
      {{- fail (printf "retained PVC %s/%s: enroll requires existing canonical non-nil organization and lifecycle-claim annotations; refusing to relabel retained identity state. An unannotated legacy claim requires explicit tokenless enrollment.mode=reuse with persistence.existingClaim" .Release.Namespace $claimName) -}}
    {{- end -}}
    {{- if or (ne $organization .Values.persistence.provenance.organizationID) (ne $lifecycleClaim .Values.persistence.provenance.lifecycleClaim) -}}
      {{- fail (printf "retained PVC %s/%s: organization and lifecycle-claim must exactly match persistence.provenance; refusing to relabel retained identity state" .Release.Namespace $claimName) -}}
    {{- end -}}
  {{- end -}}
{{- end -}}
{{- end -}}

{{/* Keep gateway and hook node placement byte-for-byte aligned. */}}
{{- define "tunnex-gateway.placement" -}}
{{- with .Values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
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

{{/*
Fail closed on lifecycle combinations that JSON Schema cannot prove against a
live retained claim. One release is one identity; Helm never rotates or purges it.
*/}}
{{- define "tunnex-gateway.configGuard" -}}
{{- $organization := .Values.persistence.provenance.organizationID -}}
{{- $lifecycleClaim := .Values.persistence.provenance.lifecycleClaim -}}
{{- if or $organization $lifecycleClaim -}}
  {{- $uuidPattern := "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" -}}
  {{- $nilUUID := "00000000-0000-0000-0000-000000000000" -}}
  {{- if or (not (regexMatch $uuidPattern $organization)) (not (regexMatch $uuidPattern $lifecycleClaim)) (eq $organization $nilUUID) (eq $lifecycleClaim $nilUUID) -}}
    {{- fail "persistence.provenance requires both organizationID and lifecycleClaim as canonical non-nil UUIDs, or both empty for a fresh legacy install" -}}
  {{- end -}}
{{- end -}}
{{- $mode := .Values.enrollment.mode -}}
{{- $sources := 0 -}}
{{- if .Values.enrollment.existingSecret -}}{{- $sources = add1 $sources -}}{{- end -}}
{{- if .Values.existingJoinTokenSecret -}}{{- $sources = add1 $sources -}}{{- end -}}
{{- if .Values.joinToken -}}{{- $sources = add1 $sources -}}{{- end -}}
{{- if eq $mode "enroll" -}}
  {{- if not .Values.nodeName -}}
    {{- fail "nodeName is required when enrollment.mode=enroll (the one-time token is pinned to that exact name)" -}}
  {{- end -}}
  {{- if ne $sources 1 -}}
    {{- fail "enrollment.mode=enroll requires exactly one token source: enrollment.existingSecret (preferred), existingJoinTokenSecret (legacy), or joinToken (insecure legacy)" -}}
  {{- end -}}
  {{- if .Values.persistence.existingClaim -}}
    {{- fail "enrollment.mode=enroll cannot use persistence.existingClaim; use reuse for retained identity state or a new release for a new identity" -}}
  {{- end -}}
{{- else if eq $mode "reuse" -}}
  {{- if ne $sources 0 -}}
    {{- fail "enrollment.mode=reuse accepts no join token; the retained claim is the identity authority" -}}
  {{- end -}}
  {{- if not .Values.persistence.enabled -}}
    {{- fail "enrollment.mode=reuse requires persistence.enabled=true" -}}
  {{- end -}}
  {{- if not .Values.persistence.existingClaim -}}
    {{- fail "persistence.existingClaim is required when enrollment.mode=reuse" -}}
  {{- end -}}
{{- else -}}
  {{- fail "enrollment.mode must be enroll or reuse; identity rotation is a separate guarded lifecycle" -}}
{{- end -}}
{{- if and .Values.persistence.existingClaim (not .Values.persistence.enabled) -}}
  {{- fail "persistence.existingClaim requires persistence.enabled=true" -}}
{{- end -}}
{{- if not .Values.joinTokenKey -}}
  {{- fail "joinTokenKey must not be empty" -}}
{{- end -}}
{{- if and (eq .Values.service.type "NodePort") (not .Values.endpoint) -}}
  {{- fail "endpoint is required when service.type=NodePort; Tunnex does not guess a node's reachable public address" -}}
{{- end -}}
{{- if and (eq .Values.service.type "NodePort") (le (int .Values.service.nodePort) 0) -}}
  {{- fail "service.nodePort must be explicitly selected when service.type=NodePort; an auto-assigned port cannot match the advertised endpoint" -}}
{{- end -}}
{{- if and (ne .Values.service.type "LoadBalancer") (ne .Values.service.type "NodePort") -}}
  {{- fail "service.type must be LoadBalancer or NodePort" -}}
{{- end -}}
{{- if .Values.endpoint -}}
  {{- $endpoint := toString .Values.endpoint -}}
  {{- if not (regexMatch "^([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?|\\[[0-9A-Fa-f:]+\\]):[0-9]{1,5}$" $endpoint) -}}
    {{- fail "endpoint must be a valid host:port (IPv6 addresses must be bracketed)" -}}
  {{- end -}}
  {{- $endpointPort := atoi (regexFind "[0-9]+$" $endpoint) -}}
  {{- if or (lt $endpointPort 1) (gt $endpointPort 65535) -}}
    {{- fail "endpoint port must be between 1 and 65535" -}}
  {{- end -}}
  {{- if and (eq .Values.service.type "LoadBalancer") (ne $endpointPort (int .Values.wireguard.port)) -}}
    {{- fail (printf "LoadBalancer endpoint port %d must equal wireguard.port %d so the advertised endpoint matches the listener and Service" $endpointPort (int .Values.wireguard.port)) -}}
  {{- end -}}
  {{- if and (eq .Values.service.type "NodePort") (ne $endpointPort (int .Values.service.nodePort)) -}}
    {{- fail (printf "NodePort endpoint port %d must equal service.nodePort %d" $endpointPort (int .Values.service.nodePort)) -}}
  {{- end -}}
{{- end -}}
{{- if and (not .Values.serviceAccount.create) (not .Values.serviceAccount.name) -}}
  {{- fail "serviceAccount.name is required when serviceAccount.create=false; refusing to grant gateway access to the namespace default ServiceAccount" -}}
{{- end -}}
{{- end -}}
