# Offline Linux sandbox installer

The dashboard's **Add sandbox runner** flow uses the same installer through
the public, source-pinned `enroll.py` asset. Its generated command includes only
the enrollment UUID, HTTPS API/artifact locations, edition and public hashes.
Paste the separately shown short-lived bootstrap token into its hidden terminal
prompt. The command never puts the token in arguments, an environment variable,
a URL or a log. Initial bootstrap requires normal system-trusted HTTPS; install
an organization's custom API trust through its normal host trust procedure first.

On the selected existing gateway host, the launcher verifies the full bundle
before executing its packaged Go enrollment client. That client generates a
TLS private key/CSR and a separate dedicated SSH probe key locally, receives only
the signed client certificate and public trust/configuration, and preserves the
same key/CSR/probe pair for exact retries. It selects an unoccupied service
UID/GID and subordinate range and discovers the actual block device backing its
storage; gateway, controller, organization and image trust stay pinned by the
configured public enrollment profile. It downloads and verifies the approved
image archives before invoking the real bounded installer. It does not install
host packages or change AppArmor, routes or firewall policy.

Installation writes stopped, disabled services. A separate terminal `ACTIVATE`
acknowledgment starts the existing helper, actor and transport without enabling
them for reboot. The dashboard obtains connection and readiness from the real
controller; an installed or structurally supported host does not become Ready
from launcher output. Trusted native qualification remains a distinct gate.
Re-running the exact command retains completed installation and private
identity. Inspect a partial installation instead of deleting or adopting it;
cancel/revoke the enrollment in the dashboard to withdraw its authority. The
existing absolute900-second workload fence continues to apply during offline
recovery. Private machine files stay under root-owned mode0700 enrollment
staging; user SSH private keys are never involved in this enrollment.

This stdlib-only installer prepares the same bounded runtime on a supported
Linux host without a cloud provider API, download, package installation or
credential generation. All IDs, paths, service UID/subUIDs, org/gateway/image
pins and controller trust references are supplied by the operator.
`example.json` contains placeholders, including a synthetic public key; replace
every identity, checksum and qualification reference with verified inputs.

The supported contract is Linux AMD64, an existing systemd version with
`DelegateSubgroup` (254 or later), unified cgroup v2 with cpu/memory/pids/io,
native rootless overlay, the packaged Podman/runc and subordinate mapping tools,
ext4/loop mounts, WireGuard/ip/nft, and the existing local Docker gateway
inspector. `newuidmap`/`newgidmap` must already retain their packaged setuid
permissions. The selected IO block device must contain the installation backing
files. Do not change AppArmor, routes, firewalls or rename tools to make a check
pass. An unsupported host is refused. ARM64 artifacts are compile-only;
this installer refuses native ARM64 activation.

Use a reviewed public bundle from the exact intended source commit and a
SHA256-pinned local Docker-format archive for each native-qualified image. An
OCI manifest digest is different from the immutable config digest used here.
Provide existing private runner TLS and probe files in mode0600, owned by root
or the selected dedicated service UID. The probe key is a dedicated runtime
identity; never supply a human's private SSH key. The installer does not issue
certificates, enroll accounts or modify the control plane. Controller certificate
renewal and organization/catalog opt-in remain explicit operator actions.

```sh
python3 deploy/sandbox/install/install.py plan --config=/absolute/operator.json
sudo python3 deploy/sandbox/install/install.py check --config=/absolute/operator.json
sudo python3 deploy/sandbox/install/install.py install --config=/absolute/operator.json
```

`plan` verifies local artifact hashes and renders the unit/runtime configuration.
`check` reads host capabilities, identity collisions and a finite public Docker
metadata projection for the pinned existing gateway. Neither writes host state.
`install` creates the explicitly selected dedicated identity if absent, reserves
only its nonoverlapping subUID/subGID range, installs verified executables and
existing private runtime identities, prepares quota-backed ext4 filesystems and
writes units. It never starts, enables, stops or replaces an active service.
Existing foreign paths/units and changed pins are refused. Repeating a completed
installation with identical config/artifacts verifies installed public hashes
and reports `already-installed`; a partial installation requires operator
inspection instead of automatic deletion/adoption.

The units use a shared224MiB/256-task/zero-swap actor+transport aggregate and
32MiB/s read /8MiB/s write limits on the explicitly selected backing device.
There is one retained workload slot:128MiB,1CPU,64PIDs, at most900 seconds from
Create. Assets/workspace share256MiB; Podman storage has a separately selected
512–8192MiB backing ceiling. The helper retains64MiB/32tasks and only the existing
network/namespace capabilities. Actor loss kills its entire process tree. The
independent native guard keeps exact cgroup placement/ownership, freeze/kill,
absolute TTL and late-descendant fences. No per-workload service manager or DBus
is introduced.

Services and mount units remain stopped and disabled after installation. At the
first separately authorized actor start, `ExecStartPre` verifies/imports only
the pinned local images into the dedicated store; later starts skip existing
matching config IDs. This completes before the actor accepts work. Every sandbox
launch continues to use `pull=never`, prebuilt dependencies and the immutable
image. Transport restart leaves the retained actor/deadline guard running.

Host structural checks and offline installation do **not** prove native behavior
on a newly selected host. Before enabling organization creation, qualify that
host's native overlay, AppArmor-compatible networking, cgroup freeze/kill and
late-child behavior, SSH/SFTP, stop/resume and full expiry/retirement under its
configured caps. Existing AMD64 receipts remain evidence for their recorded
image/host scope. A nonempty operator qualification reference is an attestation,
not an installer-generated proof or an instant-start guarantee. Keep the API
runtime binding and profile/image pins identical to this runner's `Binding`;
use explicit organization admission and current authorized human devices.
First-Ready-relative usable TTL remains unimplemented.

Synthetic validation runs without host installation:

```sh
python3 -B -m unittest discover -s deploy/sandbox/install -p 'test_*.py'
```
