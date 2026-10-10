# GCP site-to-site development

Started from main 8d344e3051270565d6057fba904fcf8692afa783 on 2026-10-10.

## Branches

- `gcp-s2s`: integration branch and shared IPsec configuration validation.
- `gcp-s2s-qualification`: offline evidence checker reuse and GCP qualification contracts.

These branches remain local. Cloud provisioning, deployment and publication are separate actions.

## Current code findings

- API: `apps/api/internal/ipsec/provider.go` owns disabled creation and encrypted PSK storage; `config_validation.go` validates AWS configuration.
- Database migration 0159 hardcodes the AWS profile, two tunnels, AWS inside ranges and AWS-named provider tables. Existing range conflict mirrors and lifecycle constraints must be preserved in an additive migration.
- Node: `runtime_material.go` admits only `aws-static-ipv4-v1`; kernel allocation and recovery assume two tunnels. `daemon.go` renders explicit site prefixes as CHILD traffic selectors.
- Web: `IPsecWorkspace.tsx` owns configuration, eligibility, apply/disable/delete and secret rotation. Reuse the workspace and preserve authority-scoped secret drafts.
- Existing policy grants, PSK envelopes, dedicated VICI ownership, journal cleanup, range validation, rotation and health projections are reusable foundations. They are not already qualified for GCP.

## Routing decision pending

GCP HA VPN requires BGP and Cloud Router. Classic VPN supports static routing.
Do not relabel an AWS static profile as GCP HA. The user has been asked which target to build first; provider-specific activation waits for that choice.

Sources reviewed 2026-10-10:
- https://docs.cloud.google.com/network-connectivity/docs/vpn/concepts/overview
- https://docs.cloud.google.com/network-connectivity/docs/vpn/how-to/creating-static-vpns
- https://docs.cloud.google.com/network-connectivity/docs/vpn/how-to/creating-ha-vpn

## First slice

Extract the existing local/remote IPv4 allowlist admission without changing AWS behavior. Reuse evidence integrity checks across cloud walks while keeping exact provider/environment checks in each entry point. Do not expose GCP creation or activation until storage, delivery, selectors and routing are implemented together.

## Next slices

1. Explicit GCP profile and validator for the chosen topology; provider-specific PSK and selector rules.
2. Additive schema, conflict guards, API/OpenAPI and generated types, disabled create/read/rotate/delete.
3. Versioned node capability and manifest, dedicated engine and route ownership; BGP lifecycle if HA selected.
4. Existing workspace provider selection, review and configuration fields; accurate readiness labels.
5. Local Linux wire proof, then a separately authorized GCP walk for bidirectional traffic, policy refusal, routing failure, rekey, recovery and cleanup.

A successful local validator or receipt checker does not prove a working GCP tunnel.
