# Metadata contract proposal — integration held

The parent/admin task owns integration disposition. No shared OpenAPI, generated
contract, existing API handler or frontend files have been edited. New source
metadata definitions/catalog live in `apps/api/internal/sandboxes/image_profiles.{go,json}`.

Add optional `SandboxTemplate.image_profile: SandboxImageProfile` and optional
`SandboxTemplate.workspace_cap_bytes: int64` only if a registered provider knows
that cap. Existing `memory_mib` is a configured RAM cap. Unknown caps remain absent.
Keep every existing required field and existing enabled-template query unchanged.

Add optional `SandboxTemplateList.candidate_profiles: SandboxImageProfile[]`.
Populate from `sandboxes.CandidateImageProfiles()`. Candidates have no template
ID or launchable scope, and never go into the create selector or POST payload.
For registered images, `ImageProfileForDigest` matches exact platform/config
identity only; it never guesses measurements based on Ubuntu/name. Unknown images
must display “Not measured”/“Not specified”. Catalog publication cannot enable
org creation, register a provider image or bypass native qualification.

`SandboxImageProfile` fields (JSON names, types):

- `name`, `distro`, `image_digest`, `config_digest`, `evidence_context`,
  `measured_at`, `compatibility`, `qualification`: strings. Qualification enum
  candidate/native-qualified; measured_at is date. Existing data is all candidate.
- `architecture`: amd64/arm64 enum; `emulated`: boolean.
- `compressed_image_bytes`, `unpacked_image_bytes`, `idle_memory_bytes`: int64,
  minimum zero. These are observations with distinct methods, not resource caps.
- `included_tools`, `excluded_tools`: string arrays with actual versions where known.
- `measurement_memory_cap_bytes`, `measurement_workspace_cap_bytes`: int64,
  minimum zero. These are fixture bounds, not configured product limits.

UI: RuntimeSpecs shows distro/architecture, compressed download and unpacked disk,
“Measured idle RAM” with evidence context/emulation/date, and separate “RAM cap” /
“Workspace cap” rows. Show included/excluded tools and musl compatibility. A
candidate card is visibly “Awaiting native qualification”, has no Configure link,
and is excluded from approved environment counts. Render candidates alongside
registered Ubuntu configurations, preserving all existing create/readiness gates.
Do not claim Ubuntu/native size or RAM when absent.

Integration file scope:
`openapi/openapi.yaml`, generated `apps/api/internal/api/api.gen.go`,
`apps/cli/internal/api/api.gen.go`, `packages/shared/src/api.d.ts`,
`apps/api/internal/http/sandbox_handlers.go` (projection only),
`apps/web/src/components/SandboxChrome.tsx`,
`apps/web/src/pages/Sandboxes.tsx`, `apps/web/test/sandboxes.test.tsx`, and API
response tests. No migration, enabled-template insertion, RBAC or policies change.

Required integration tests: old responses lacking metadata still render/create;
unknown Ubuntu measurements stay unknown; candidates cannot be selected even
when organization creation is enabled; emulated idle observations never appear as
native RAM or configured caps; tool omissions and compatibility are visible;
OpenAPI regeneration is clean; both API editions and frontend typecheck/tests/build pass.
