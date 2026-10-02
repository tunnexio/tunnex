# Managed-agent automatic host preparation: clean VM walk

Date: 2026-10-02. Decision record: [host bootstrap decisions](S-agent-bootstrap-host-dependencies-decisions.md).
Evidence: [sanitized verification](../walk-artifacts/agent-bootstrap-host-20261002/verification.json).

## Actual clean-host result

A separate Ubuntu 24.04 amd64 EC2 instance was launched without user-data or a
package-preparation script. WireGuard tools and `releaseverify` were absent;
the distribution supplied curl, jq, iproute2 and a working resolvconf link.
The command was generated directly by the changed frontend function, using a
real, single-use enrollment token from the existing sandbox control plane.

The first attempt exposed a privilege-preflight bug: `sudo -v` requested a
password even though `sudo -n true` succeeded under Ubuntu's mixed sudoers
rules. It stopped before installing dependencies or redeeming the token.
The corrected preflight and regression tests now cover that case. The same
unused token then completed the generated command with exit code 0.

The command installed the missing WireGuard package, downloaded and checked the
verifier before executing it, verified the signed runtime artifacts, enrolled
the host, and started the managed system service. The control plane reported
active, connected, ready, non-stale status with desired/applied revision 1.
The credential file was mode 0600. A real service restart preserved WireGuard
identity and returned to active. The user's original test agent remained ready.
No model, network or MCP grant was added by this test. The temporary proof agent
was revoked and removed after verification, its VM was terminated, and the public
fixture directory was removed. The CP, bastion and original test agent were kept.

## Publisher fixture boundary

The new assets cannot exist in an official release before this change is merged
and published. This walk therefore used an explicitly isolated HTTPS static
fixture. The published v0.1.37 runtime manifest and all three runtime/unit assets
were first checked against the existing release public key. A disposable
in-memory test key signed a fixture manifest and separate verifier descriptor;
the new parser verified their signatures and hashes. The verifier binaries were
built from the review worktree with pinned Go 1.26.8; the fixture's older runtime
source binding is for this enrollment test only. It is not a same-source
production publication claim.

Only public fixture assets were served, through a separate static directory.
The control-plane release trust, deployment settings, existing services and
production signing keys were not changed. Runtime enrollment used the real CP;
the fixture metadata was supplied to the generated command directly, so this
walk does not claim that the deployed CP already fetches the new descriptor.
The API projection and failure-before-token-mint behavior have separate tests.

## Remaining release acceptance

Both Linux architectures are built and checked by CI, with detached signing,
asset readback and source/draft guards before release promotion. Executable
shell tests cover both architectures, dependency/resolver failures, altered
artifacts, existing-install refusal and legacy releases. Those tests substitute
for a real clean arm64/Debian walk; the cloud proof here is Ubuntu amd64.

The named trigger for unmodified installer acceptance is the first signed
release containing this change: install an agent from its normal UI-generated
command, without test metadata or staged assets. The old release's explicit
preinstalled-verifier path remains supported. This work does not grant model
access or resolve the separately recorded private control-plane HTTPS issue.
