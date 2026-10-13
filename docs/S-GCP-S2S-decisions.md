# GCP site-to-site development

Started from main 8d344e3051270565d6057fba904fcf8692afa783 on 2026-10-10.

## Branches

- `gcp-s2s`: integration branch and shared IPsec configuration validation.
- `gcp-s2s-qualification`: offline evidence checker reuse and GCP qualification contracts.

Branches remain local; required isolated owned cloud testing is authorized through the designated GCP bastion. Production publication remains separate.

## Current code findings

- API: `apps/api/internal/ipsec/provider.go` owns disabled creation and encrypted PSK storage; `config_validation.go` validates AWS configuration.
- Database migration 0159 hardcodes the AWS profile, two tunnels, AWS inside ranges and AWS-named provider tables. Existing range conflict mirrors and lifecycle constraints must be preserved in an additive migration.
- Node: `runtime_material.go` admits only `aws-static-ipv4-v1`; kernel allocation and recovery assume two tunnels. `daemon.go` renders explicit site prefixes as CHILD traffic selectors.
- Web: `IPsecWorkspace.tsx` owns configuration, eligibility, apply/disable/delete and secret rotation. Reuse the workspace and preserve authority-scoped secret drafts.
- Existing policy grants, PSK envelopes, dedicated VICI ownership, journal cleanup, range validation, rotation and health projections are reusable foundations. They are not already qualified for GCP.

## Provider scope and authority update

Founder-authorized handoff from AWS Tunnel on 2026-10-10 expands the scope to HA VPN + Cloud Router/BGP primary and Classic route-based static as a separate explicit profile. No additional routing-choice gate. Reuse current AWS/common BGP, static and private DNS foundations from the frozen key-free source snapshot; do not duplicate engines, policy authority, resolver or lifecycle store.

Frozen source receipt: `/private/tmp/private-dns-build-20261010-9/build-receipt.json`, verified SHA-256 `2e983e90f15c185030f55eda531a2fbef952fbd18ead2033cd1251509d258a59`; source snapshot digest `302d49400c6a4681b00c15a3cefd1f3de7d82b332556140fbf4e5dfe63fb9fde`. AWS source9 includes passive diagnostics for an unresolved live BGP authority failure; imported code is not production-qualified.

Agents own isolated provider/API, runtime and UI/DNS branches. Root owns qualification, integration docs and cloud lab. Provider owner is sole migration/generated-contract writer. Preserve newer-main dependency changes and existing shared-prefix/checker commits.

Corrected bastion `ssh cyberking9560@34.131.23.179` verified as `bastion-host`; active project `project-0048836f-6ba1-4a14-8da`, billing enabled, Compute API enabled, bastion in `asia-south2-b`. All gcloud commands run there. The initially supplied IP timed out and was replaced by the human. Required isolated owned live lab/test infrastructure is authorized; no remote Git push, PR, main merge or production publication.

Sources: Google Cloud VPN overview/topologies, Classic BGP deprecation, Cloud DNS best practices and Cloud VPN MTU considerations, rechecked 2026-10-10. Cloud inventory and resource plan are recorded in `S-GCP-0-cloud-lab.md`.

## First slice

Extract the existing local/remote IPv4 allowlist admission without changing AWS behavior. Reuse evidence integrity checks across cloud walks while keeping exact provider/environment checks in each entry point. Do not expose GCP creation or activation until storage, delivery, selectors and routing are implemented together.

## Story epic

The detailed story table and branch sequence are in [EPIC-gcp-site-to-site.md](EPIC-gcp-site-to-site.md). The 11-story scope includes explicit HA and Classic profiles plus standard private DNS.

## Next slices

1. Explicit GCP profile and validator for the chosen topology; provider-specific PSK and selector rules.
2. Additive schema, conflict guards, API/OpenAPI and generated types, disabled create/read/rotate/delete.
3. Versioned node capability and manifest, dedicated engine and route ownership; common BGP lifecycle for HA.
4. Existing workspace provider selection, review and configuration fields; accurate readiness labels.
5. Local Linux wire proof, then a separately authorized GCP walk for bidirectional traffic, policy refusal, routing failure, rekey, recovery and cleanup.

A successful local validator or receipt checker does not prove a working GCP tunnel.
