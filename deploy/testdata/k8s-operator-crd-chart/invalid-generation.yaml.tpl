{{- $existing := .Files.Get "contract-fixtures/tunnex.io_tunnexclusters.yaml" | fromYaml -}}
{{- $_ := set $existing.metadata "annotations" (dict
  "meta.helm.sh/release-name" "tunnex-operator-crds"
  "meta.helm.sh/release-namespace" "tunnex-system"
  "tunnex.io/schema-generation" "9999999999999999999"
) -}}
{{- include "tunnexOperatorCRDs.assertAdoptableExisting" (dict "name" "tunnexclusters.tunnex.io" "existing" $existing "release" "tunnex-operator-crds" "namespace" "tunnex-system" "generation" 1) -}}
apiVersion: v1
kind: ConfigMap
metadata:
  name: invalid-generation-contract
