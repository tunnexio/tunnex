# Upgrade descriptor transfer under systemd PrivateTmp

The v0.1.34 to v0.1.35 dashboard upgrade authenticates the release and creates a verified database backup, then fails while the target API verifier reads the descriptor. The host runner uses `PrivateTmp=true`; its temporary catalog file is absent from the Docker daemon namespace. A bind mount created with `-v` therefore presents a directory to the container.

## Decisions

- Keep the runner temporary-directory isolation and the signed API digest trust chain.
- Send the already authenticated descriptor to the disposable target verifier on standard input. Create its temporary file inside that container, with networking disabled. Do not bind a host temporary path or relax file permissions.
- Regression coverage must check exact descriptor bytes, the approved API digest, verification arguments, and rejection before deployment mutation when the target verifier fails. An empty descriptor or a host bind must fail the regression.
- Repair the installed helper after validation while keeping the application upgrade under the user's dashboard control. Preserve the existing failed-run backup, current applications, encryption keys, and gateway identity.

## Validation

All three host-upgrade contract suites pass. A real probe executed the changed verifier block under systemd `PrivateTmp=true`: the signed v0.1.35 descriptor succeeded, its AI image pin was exported, a tampered descriptor was rejected, and the retained AI configuration passed validation. Application files and gateway runtime remained unchanged. See [live evidence](../walk-artifacts/upgrade-private-tmp-20261001.md).
