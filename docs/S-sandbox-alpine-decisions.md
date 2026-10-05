# Alpine sandbox profile decisions

- Locked: separate opt-in build recipe; existing Ubuntu image and provider/readiness contracts unchanged. No template registration or selectable profile until native rootless qualification.
- Locked: official Alpine 3.23 digest, build-time packages only; static CGO-disabled bootstrap. Python preserves existing checked unprivileged entrypoint. Bash, OpenSSH/SFTP, WireGuard, iproute2, coreutils, openresolv, setpriv and nftables are included. Node and git are absent.
- Locked: local Docker SSH/file checks are substitutes, not native rootless/AppArmor/network qualification. Record compressed image layers, logical image disk size and idle cgroup memory independently of caps.
- Deferred to Alpine native activation: exact provider image digest, rootless uid maps, AppArmor, network helper/probes, persistence and teardown, both architectures, UI size/compatibility labels and selectable registration. Parent owns deployment approval.
- Target: 10–50 MB compressed, not a guarantee. musl cannot run arbitrary glibc binaries.

## Lightweight variants (authorized continuation)

- Locked: Minimal uses a checked Bash entrypoint and excludes Python, Node and git; Python adds python3; Node.js adds nodejs/npm. Shared base preserves tools, uid1001 and SSH/SFTP paths. Package versions and immutable images are measured separately on amd64/arm64.
- Locked: Bash entrypoint retains the existing identity, runtime directory ownership/type/write-mode checks and absolute foreground sshd exec. Ubuntu Python entrypoint is unchanged.
- Metadata proposal held for admin-task coordination: optional template image_profile and separate candidate_profiles without template IDs, with distro/architecture, immutable digest, compressed/unpacked/idle measured bytes and evidence context, tools/compatibility/qualification. Configured caps remain distinct. Shared OpenAPI/API/UI edits await ownership resolution.

- Locked implementation finding: asset-backed Podman creation forced Python regardless of image CMD. Use the qualified immutable image CMD instead; Ubuntu retains its existing Python CMD, Alpine uses its fixed checked Bash CMD. All uid/mount/network/security/readiness/lifecycle controls remain unchanged. Native qualification still required before registering any new image.
