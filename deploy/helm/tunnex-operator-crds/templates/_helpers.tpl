{{/*
Return a stable fingerprint for a CRD spec as observed through `lookup`.

The apiextensions API defaults an omitted conversion block to exactly
`conversion: {strategy: None}`.  That default is not present in the historical
source manifests, so remove only that exact server-owned shape.  Any webhook,
additional conversion field, or other spec change remains in the fingerprint
and therefore fails ownerless adoption.
*/}}
{{- define "tunnexOperatorCRDs.specFingerprint" -}}
{{- $spec := deepCopy ((get . "spec") | default dict) -}}
{{- $conversion := get $spec "conversion" -}}
{{- if kindIs "map" $conversion -}}
  {{- if and (eq (len $conversion) 1) (eq ((get $conversion "strategy") | default "") "None") -}}
    {{- $_ := unset $spec "conversion" -}}
  {{- end -}}
{{- end -}}
{{- toJson $spec | sha256sum -}}
{{- end -}}

{{/*
An ownerless CRD may be adopted only when its normalized spec is byte-for-byte
one of the Tunnex schemas that were historically installed with raw kubectl
manifests.  These hashes are SHA-256 over canonical JSON emitted by Helm's
`toJson` after the one API default above is removed.

Provenance:
  tunnexclusters initial       025368ab:apps/operator/config/crd/tunnex.io_tunnexclusters.yaml
  tunnexclusters + connector   3ccbaf71:apps/operator/config/crd/tunnex.io_tunnexclusters.yaml
  tunnexclusters generation 1  current source-parity manifest
  exposed-services / grants    025368ab source manifests (still source parity)
*/}}
{{- define "tunnexOperatorCRDs.assertKnownLegacy" -}}
{{- $fingerprints := dict
  "tunnexclusters.tunnex.io" (list
    "b1fed7c55a7656bf92b5d51ea20c387b8d3792178d795711170cdc46ce9e1f0e"
    "8d3c1d56ea463e9da05dff805e3a23a22b253472d0d444381fe9cb141bf95c96"
    "2bae69bb8db7a89999b1381c7a578755ff2e8c56b3884bec184443f815c32318"
  )
  "tunnexexposedservices.tunnex.io" (list
    "0181dc890b1dcf2e581dbac8804b5aba56681398f7f0ed0d18ab02075cffb554"
  )
  "tunnexgrants.tunnex.io" (list
    "993214052c315fe28160a72f20ed058007fd32cb9df5ed348e6721582a566a87"
  )
-}}
{{- $name := required "ownerless CRD adoption requires a CRD name" .name -}}
{{- $approved := (get $fingerprints $name) | default (list) -}}
{{- $actual := include "tunnexOperatorCRDs.specFingerprint" .existing -}}
{{- if not (has $actual $approved) -}}
  {{- fail (printf "CRD %s schema fingerprint %s is not an approved Tunnex legacy schema; refusing ownership takeover" $name $actual) -}}
{{- end -}}
{{- end -}}

{{/*
Validate one live CRD before Helm's --take-ownership path can apply anything.
The legacy operator release predates schema-generation, so it needs the same
exact fingerprint proof as an ownerless raw-manifest install. Once a valid
generation marker exists, monotonic generation is the source of truth.
*/}}
{{- define "tunnexOperatorCRDs.assertAdoptableExisting" -}}
{{- $name := required "CRD adoption requires a CRD name" .name -}}
{{- $existing := .existing -}}
{{- $release := .release -}}
{{- $namespace := .namespace -}}
{{- $generation := int64 .generation -}}
{{- $annotations := (get $existing.metadata "annotations") | default dict -}}
{{- $owner := (get $annotations "meta.helm.sh/release-name") | default "" -}}
{{- $ownerNamespace := (get $annotations "meta.helm.sh/release-namespace") | default "" -}}
{{- if and $owner (ne $owner $release) (ne $owner "tunnex-operator") -}}
  {{- fail (printf "CRD %s is owned by Helm release %s; refusing ownership takeover" $name $owner) -}}
{{- end -}}
{{- if and $ownerNamespace (ne $ownerNamespace $namespace) -}}
  {{- fail (printf "CRD %s is owned from namespace %s; expected %s" $name $ownerNamespace $namespace) -}}
{{- end -}}

{{- $generationMarked := hasKey $annotations "tunnex.io/schema-generation" -}}
{{- $existingGeneration := int64 0 -}}
{{- if $generationMarked -}}
  {{- $rawGeneration := get $annotations "tunnex.io/schema-generation" -}}
  {{- if not (regexMatch "^[1-9][0-9]{0,17}$" $rawGeneration) -}}
    {{- fail (printf "CRD %s has invalid schema generation %q; expected a canonical positive decimal of at most 18 digits" $name $rawGeneration) -}}
  {{- end -}}
  {{- $existingGeneration = int64 $rawGeneration -}}
{{- end -}}

{{- if or (not $owner) (and (eq $owner "tunnex-operator") (not $generationMarked)) -}}
  {{- include "tunnexOperatorCRDs.assertKnownLegacy" (dict "name" $name "existing" $existing) -}}
{{- end -}}
{{- if gt $existingGeneration $generation -}}
  {{- fail (printf "CRD %s schema generation %d is newer than chart generation %d; refusing downgrade" $name $existingGeneration $generation) -}}
{{- end -}}
{{- end -}}
