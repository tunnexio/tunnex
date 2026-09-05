{{- $existing := .Files.Get "contract-fixtures/tunnex.io_tunnexclusters.yaml" | fromYaml -}}
{{- $_ := set $existing.spec "conversion" (dict "strategy" "None") -}}
{{- $_ := set $existing.spec "scope" "Cluster" -}}
{{- include "tunnexOperatorCRDs.assertAdoptableExisting" (dict "name" "tunnexclusters.tunnex.io" "existing" $existing "release" "tunnex-operator-crds" "namespace" "tunnex-system" "generation" 1) -}}
apiVersion: v1
kind: ConfigMap
metadata:
  name: ownerless-unknown-schema-contract
