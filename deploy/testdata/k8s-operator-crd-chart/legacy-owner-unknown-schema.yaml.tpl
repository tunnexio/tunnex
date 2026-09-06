{{- $existing := .Files.Get "contract-fixtures/tunnex.io_tunnexclusters.yaml" | fromYaml -}}
{{- $_ := set $existing.spec "conversion" (dict "strategy" "None") -}}
{{- $_ := set $existing.spec "scope" "Cluster" -}}
{{- $_ := set $existing.metadata "annotations" (dict
  "meta.helm.sh/release-name" "tunnex-operator"
  "meta.helm.sh/release-namespace" "tunnex-system"
) -}}
{{- include "tunnexOperatorCRDs.assertAdoptableExisting" (dict "name" "tunnexclusters.tunnex.io" "existing" $existing "release" "tunnex-operator-crds" "namespace" "tunnex-system" "generation" 1) -}}
apiVersion: v1
kind: ConfigMap
metadata:
  name: legacy-owner-unknown-schema-contract
