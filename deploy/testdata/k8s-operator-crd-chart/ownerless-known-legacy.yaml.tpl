{{- $fixtures := list
  (dict "name" "tunnexclusters.tunnex.io" "file" "contract-fixtures/tunnexclusters-initial.yaml")
  (dict "name" "tunnexclusters.tunnex.io" "file" "contract-fixtures/tunnexclusters-connector.yaml")
  (dict "name" "tunnexclusters.tunnex.io" "file" "contract-fixtures/tunnex.io_tunnexclusters.yaml")
  (dict "name" "tunnexexposedservices.tunnex.io" "file" "contract-fixtures/tunnex.io_tunnexexposedservices.yaml")
  (dict "name" "tunnexgrants.tunnex.io" "file" "contract-fixtures/tunnex.io_tunnexgrants.yaml")
-}}
{{- range $fixture := $fixtures -}}
  {{- $existing := $.Files.Get $fixture.file | fromYaml -}}
  {{- $_ := set $existing.spec "conversion" (dict "strategy" "None") -}}
  {{- include "tunnexOperatorCRDs.assertAdoptableExisting" (dict "name" $fixture.name "existing" $existing "release" "tunnex-operator-crds" "namespace" "tunnex-system" "generation" 1) -}}
{{- end }}
apiVersion: v1
kind: ConfigMap
metadata:
  name: ownerless-known-legacy-contract
data:
  result: accepted
