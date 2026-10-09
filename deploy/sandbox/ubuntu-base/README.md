# Ubuntu 26 sandbox image delivery

The essential dependency image has a supported source producer and a complete
AMD64 package lock. `public-inputs.json` records the real Docker Official Ubuntu
26.04 index and architecture manifests retrieved from its public registry.
`ubuntu26-amd64.lock.json` records the nine signed/index inputs from the official
`20261001T000000Z` snapshot, 55 APT-selected package downloads, their exact
versions/sizes/SHA256 hashes, and the expected complete installed inventory.

The lock was resolved by APT inside the exact official base, authenticating all
three pockets with its Ubuntu archive keyring. The resolver has no network,
mounts public metadata read-only, drops capabilities and cannot access operator
credentials. Frozen snapshots require disabling metadata date expiry; signature
verification remains required. Public registry pull/build calls use an empty
temporary auth configuration and never consult a saved registry credential.
Official sources: [Ubuntu snapshot service](https://snapshot.ubuntu.com/),
[Docker Official Ubuntu](https://hub.docker.com/_/ubuntu), and
[Ubuntu's signed archive](https://archive.ubuntu.com/ubuntu/dists/resolute/InRelease).

## Build and distribute once

Maintainers need Python stdlib, Git, Go **1.26.9** with the checked-in CLI module
cache already populated, and a local Linux Docker BuildKit/Podman Buildah engine
supporting read-only `RUN --mount=type=bind`. A build-context bind keeps downloaded
`.deb` archives out of the final image layers. This
build uses packages only at image assembly time. Customer machines receive the
finished archive; sandbox creation never installs packages, pulls an image or
requires Go. No systemd/DBus daemon, host socket or service orchestration runs
inside the workload image. `systemd-resolved` supplies the conventional
`resolvconf` CLI; its package presence does not start resolved.

From a clean committed checkout, choose new absolute cache/output directories:

```sh
python3 deploy/sandbox/ubuntu-base/delivery.py fetch \
  --lock deploy/sandbox/ubuntu-base/ubuntu26-amd64.lock.json --cache /srv/tunnex-build/cache
python3 deploy/sandbox/ubuntu-base/delivery.py preload-base \
  --lock deploy/sandbox/ubuntu-base/ubuntu26-amd64.lock.json --cache /srv/tunnex-build/cache --engine docker
python3 deploy/sandbox/ubuntu-base/archive.py \
  --lock deploy/sandbox/ubuntu-base/ubuntu26-amd64.lock.json --cache /srv/tunnex-build/cache \
  --output /srv/tunnex-build/new-image-output --engine docker --go go
```

`fetch` and `preload-base` are explicit network-enabled build preparation.
Archive assembly itself verifies all cached inputs, requires the pinned local
base, sets `network=none` and refuses pulls. It uses only committed allowlisted
recipes, the locked packages and a bootstrap executable compiled from an archive
of committed CLI source with readonly, offline Go resolution. Package scripts
are prevented from starting services with `policy-rc.d`; generated SSH host
keys are removed. Exact installed inventory is checked before export. It
preserves the standard Ubuntu WireGuard/ip/tool paths and all host protections.

The new output directory contains:

* `tunnex-sandbox-ubuntu26-linux-amd64.docker.tar`: one unprivileged workload image,
  compatible with the existing installer archive verifier and offline preload.
* `workload-image.json`: exact source SHA, base manifest and dependency lock
  digest, archive filename/hash/size, immutable config digest and measured
  unpacked size. Native qualification and service activation are explicitly false.
* `SHA256SUMS`: both output files, with bare filenames suitable for distribution.

The release lane can call `archive.verify_delivery(directory, source, arch,
lock_sha256)` before attaching/attesting the archive. This guard checks source,
architecture, inventory, labels, archive/config hashes and uid1001/workspace.
The binary/recipe bundle continues to declare `workload_images_built=false`;
this image is a separately verified artifact. Do not overwrite or reuse an
existing output directory after a failed build; preserve its log and choose
a new output directory.

## Deployment catalog handoff

Download and verify the release archive and descriptor once on the machine
being enrolled. The trusted deployment catalog supplies the archive location,
descriptor's `archive.sha256`, `config_digest`, `architecture`, matching template
ID and actual reviewed `qualification_evidence` to the runner's ordinary
installer/enrollment configuration. The installer's `images[]` contract accepts
those exact pins, verifies the archive, copies it locally, and preloads it before
actor activation. The descriptor is public build provenance, not an enrollment
credential; no token or private key belongs in it or its URL.

An image build is not native qualification. Template availability still needs
the existing explicit trusted profile/host qualification and gateway identity.
The enrollment UI must explain this deployment step without presenting an
unqualified image or disconnected runner as ready. The source workflow does
not auto-register a template, widen policy, enroll a machine or start services.
ARM64 has a real official base pin but lacks a committed dependency lock/native
qualification in this slice, and remains unavailable for activation.

## Updating the lock

Change `public-inputs.json` only after retrieving/reviewing the new official base
manifests and choosing a snapshot. `delivery.py resolve --architecture amd64
--engine docker --cache NEW_ABSOLUTE_CACHE --output NEW_LOCK` fetches public
signed metadata, anonymously preloads the exact base, resolves its APT closure
offline and creates a new immutable lock. Inspect the package/version diff,
build again and requalify the resulting image/host combination before making
it selectable. Corrupt cached inputs fail closed rather than silently changing
the lock. Fixed inputs provide an auditable rebuild path; byte-identical OCI
output still requires separate two-build evidence because build tool versions
and package postinstall timestamps can vary.

Run source fixtures with `python3 -m unittest discover -s deploy/sandbox/ubuntu-base
-p 'test_*.py'`. These exercise malformed inputs, corruption and offline
invocations; they do not substitute for AppArmor, WireGuard, SSH, deadlines,
cleanup or startup-latency qualification on the selected Linux host.
