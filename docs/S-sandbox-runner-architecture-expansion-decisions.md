# Portable runner architecture and multi-user admission

The user selected architecture expansion before PR preparation. The product
implementation separates host enrollment from workload authorization rather
than fixing a deployment to one operator's user or terminal identity.

## Locked boundaries

- A deployment profile identifies the organization, runtime and terminal
  gateways, supported host platform, immutable artifacts and resource envelope.
  It contains no selected human creator or terminal in organization admission.
  Explicit legacy bindings remain compatible and cannot change while retained
  work exists.
- An administrator enrolls a host. Its locally generated certificate key and
  probe key identify that enrollment. The enrolling administrator does not
  become the owner of later workloads and supplies no inherited policy grants.
- Each workload carries its authenticated creator, that creator's current owned
  terminal, selected template, public SSH keys, optional skills and immutable
  original expiry. Current membership, device, delegation and policy checks
  continue through launch, resume and Ready. The worker cannot replace those
  values when another member uses the host.
- The existing provider interface owns create, inspect, start, stop and delete.
  The API owns canonical policy, identity and lifecycle state. The authenticated
  transport carries bounded commands and observations; it owns no main database
  or policy issuer. Packaging is independent of a cloud account or research host.
- The first supported host profile is Ubuntu 26 AMD64 with the existing rootless
  Podman, cgroup and co-located gateway prerequisites. Public ARM64 binaries are
  compile artifacts. A new provider or host platform needs capability checks,
  its own exact artifact/profile and native qualification before admission.
- Capacity remains one shared retained workload, including a qualification
  trial until confirmed retirement. This permits sequential authorized users;
  it does not imply concurrent capacity, a larger resource envelope or a quota
  bypass. The runtime never raises lower organization/user quotas.
- Qualification is a distinct, bounded administrative grant. It may exercise
  only its exact workload while ordinary creation remains disabled. Native
  observations and explicit review govern readiness. Runner-side SSH probes are
  labeled as such; they are not independent terminal-side proof.
- The local terminal and existing Codex/Claude connect over ordinary SSH. Private
  user keys remain local. Skills stay selectable/configurable per workload.
  Hosted AI, inference routing and MCP are optional integrations.

## Acceptance and validation

Organization admission tests cover sequential members, concurrent quota races,
owned terminal selection, cross-owner refusal, withdrawal and restart identity.
Enrollment tests cover local CSR identity, exact-key retry, current authority,
cleanup-only revocation and qualification review. Combined HTTP and browser
checks exercise enrollment, controlled trial, review, Setup, template/skills/key
selection and connection instructions. Archive verification records actual
source, configuration digest and sizes; source fixtures do not qualify a host.

Additional providers and increased parallel capacity are later phases. Their
interfaces are separated now; unsupported execution is not enabled by an
architecture diagram or a successfully compiled binary. First-Ready-relative
TTL remains outside this scope; all expiry uses the original creation time.
