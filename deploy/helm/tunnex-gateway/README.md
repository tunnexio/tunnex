# Tunnex gateway Helm chart

Direct `helm install` and `helm upgrade` are supported chart operations. The
`tunnex k8s` CLI adds managed bootstrap delivery, CP identity verification and
lifecycle orchestration; you do not need to replace Helm to obtain the chart's
retained-PVC safety check.

## Existing storage guard

Normal connected Helm install/upgrade looks up the exact namespaced PVC before
applying resources. Enrollment behaves as follows:

| Existing PVC | Result |
| --- | --- |
| Absent | Fresh enrollment can proceed |
| Both canonical non-nil organization/claim annotations match supplied provenance | Matching retry/upgrade can proceed |
| Missing, partial, malformed or mismatched provenance | Refuse before applying resources |
| Kubernetes lookup forbidden or unavailable | Refuse, not assume absence |

Supply both `persistence.provenance.organizationID` and
`persistence.provenance.lifecycleClaim` from the actual lifecycle identity, or
leave both empty only for a fresh legacy installation. Never invent matching
labels, overwrite an old PVC's annotations or clear them to force enrollment.
These fields are not credentials. Matching labels do not replace the CLI's
independent CP consumed-claim and node-identity verification.

The guard runs during rendering, not as an optional hook: `--no-hooks` cannot
disable it. The Helm caller needs `get` access to the target namespaced PVC.
It is a render-time check, not atomic admission control: serialize lifecycle
operations and do not concurrently modify or replace the retained claim.

Offline `helm template` and client-side dry-runs cannot inspect live storage.
Use a connected Helm operation or `--dry-run=server` for lookup validation.
An offline GitOps renderer does not gain this guard by applying rendered YAML;
do not advertise that route as equivalent live-PVC protection.

## Explicit retained/legacy reuse

Use `enrollment.mode=reuse` with `persistence.existingClaim` and no token source
to mount an explicitly selected retained identity. Reuse does not emit/relabel
the PVC and does not create a new enrollment. This manual mode does not certify
CP provenance or supply the CLI's zero-touch adoption proof. Partial or malformed
provenance is not evidence of a valid legacy identity.

## Other installation requirements still apply

Read `values.yaml` and the chart NOTES for host-posture manager, privileged
acknowledgement, placement, persistent storage and reachable endpoint settings.
Keep real enrollment tokens in an externally created Secret referenced through
`enrollment.existingSecret`, never in `--set joinToken` or Helm values/history.
Use immutable images and wait for real readiness; a successful render or a
release with Pending pods is not an enrolled, functioning gateway.

See [Kubernetes lifecycle guidance](../../../docs/kubernetes-zero-touch.md)
and [guard decision/proof](../../../docs/S20.5-direct-helm-pvc-guard.md).
