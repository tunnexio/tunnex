# Ubuntu sandbox image delivery

The runner installer consumes a prebuilt Docker image archive addressed by both
its file SHA256 and immutable image config digest. The previous Ubuntu final
layer recipe did not supply a dependency-base producer or package lock. This is
a product delivery gap, rather than a local test prerequisite.

## Decisions

* Locked: use Docker Official Ubuntu 26.04 per-architecture manifests and the
  official Ubuntu snapshot archive. Resolve the complete essential dependency
  closure with APT against signed snapshot metadata. Record exact metadata,
  package versions, sizes and SHA256 hashes. No mutable base or unversioned
  package is an input to image assembly.
* Locked: separate network fetch from offline image assembly. Fetching is a
  maintainer/release build step, not a host enrollment or sandbox launch step.
  Both dependency and final layers use locally verified inputs with network
  disabled and pulls refused. Package configuration is inhibited from starting
  services; no systemd/DBus runtime or host socket is introduced.
* Locked: provide an archive producer and public descriptor for ordinary
  deployment catalog configuration. A descriptor reports source and input pins
  and measured archive/image sizes. It cannot manufacture native qualification
  or enable a template automatically.
* Locked: require all existing AppArmor, networking, generation, trust,
  readiness, cleanup and resource controls. No Alpine substitution, tool
  renaming, protection changes, live pilot reuse or host activation.
* Deferred to native release qualification: repeatable clean Linux AMD64 builds,
  AppArmor/SSH/WireGuard/cgroup behavior, cleanup and startup measurements on the
  selected installation. ARM64 package/image builds do not permit activation.
* Rejected: claim byte-identical OCI archives merely from fixed packages.
  Build tooling and package postinstall timestamps can vary; immutable output
  digests are measured and verified, while byte reproducibility needs two-build
  evidence. The lock guarantees exact inputs and an auditable rebuild path.

## Stories and acceptance

1. Lock public inputs: signed metadata and complete APT closure for the pinned
   Ubuntu architecture; malformed/mutable pins and missing essential packages
   fail before build. This precedes all other slices.
2. Fetch/cache and dependency-base build: exact checksum/size validation,
   bounded downloads, no repository credential context, offline installation
   and dependency inventory. Missing/corrupt inputs fail before image mutation.
3. Archive delivery: committed-source final layer, immutable archive/config
   identity and source manifest, suitable for installer/catalog integration.
   Outputs retain an explicit unqualified status until separate evidence exists.
4. Fixtures and documentation: exercise offline invocation, input corruption,
   incomplete closure, identity mismatch and catalog descriptor behavior.
   Record which checks used synthetic tools and which built real artifacts.
