{{/* Shared paths prevent API/migrator TLS configuration drift. */}}
{{- define "tunnex-cp.databaseTLSMount" -}}
{{- if .Values.database.tls.existingSecret -}}
- name: database-tls
  mountPath: /etc/tunnex/database-tls
  readOnly: true
{{- end -}}
{{- end -}}

{{- define "tunnex-cp.databaseTLSVolume" -}}
{{- if .Values.database.tls.existingSecret -}}
- name: database-tls
  secret:
    secretName: {{ .Values.database.tls.existingSecret | quote }}
    # Root-owned, group-readable for the non-root API and migration processes.
    # No world-readable client private key.
    defaultMode: 0440
{{- end -}}
{{- end -}}
