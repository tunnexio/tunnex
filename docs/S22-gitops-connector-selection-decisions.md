# S22 GitOps connector selection — decisions

## Observed live failure

The GitOps `TunnexCluster` CR could resolve its site, but its registration request
omitted `connector_node_id`.  The released control-plane handler correctly refuses
that shape with `connector_node_required`: a Kubernetes cluster cannot serve a
synthetic VIP without an explicit active in-cluster gateway.

## Decisions

1. **D1 — declare the connector by logical gateway name.** `spec.connector` is
   required and is resolved by the operator through the existing read-only Nodes
   endpoint.  A Git manifest must not embed a per-environment UUID.
2. **D2 — resolve exactly within the selected site.** A same-named node at another
   site, or a missing connector, leaves the CR `Ready=False` and no CP mutation is
   attempted.  The CP remains the authority for active/eligible gateway validation.
3. **D3 — preserve the existing control-plane contract.** The operator forwards the
   resolved UUID as the already-supported `connector_node_id`; no new CP endpoint,
   RBAC permission, or database access is introduced.
4. **D4 — migration is additive.** Existing CRs without `spec.connector` are
   rejected by schema on new applies; the live failed walk CR is patched with the
   named connector after the updated CRD/operator deploy.

## Proof

Focused controller tests prove name resolution, site matching, and that the POST
contains the resolved connector ID.  The live AKS walk proves the reconciled CR,
then resumes expose/grant/revoke verification.
