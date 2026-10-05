# Control-plane enrollment profile

`profile.py` is an offline, Python standard-library deployment tool. It turns a
reviewed public distribution manifest and its exact workload descriptor into
the supported `/etc/tunnex/sandbox-runtime.json` configuration. Repeated template,
profile, archive, image and source pins are derived once. No Go or SQL editing is
needed. The qualification trial prepares the exact disabled template; Sandbox
Setup publishes it after qualification and fresh health are confirmed.

Use the source SHA and distribution SHA256 from the independently reviewed
release/checksum record, then download those public files through your ordinary
artifact process. The tool verifies both hashes, source, Linux AMD64 support,
immutable dependency/base/config pins and bounded measured sizes. It does not
fetch anything, verify the archive bytes itself, or attest native qualification.
The image producer/release guard verifies the actual archive; the machine
installer verifies downloaded archive bytes again.

The existing control-plane issuer and controller certificate must already exist
through the deployment's normal certificate process. Supply their absolute file
references. Only the explicitly public runner CA certificate (and optional
public API CA certificate) is read. Private controller/CA key paths are copied
as references and never opened. The API performs full X.509 CA, signing and TLS
checks at startup; the generator only validates public PEM encoding.

For example, on the control-plane host, substitute the reviewed identifiers,
pins, private addresses and existing certificate paths below. The `SOURCE` and
`DISTRIBUTION_SHA256` values are required trusted inputs, never inferred approval:

```sh
python3 deploy/sandbox/install/profile.py \
  --distribution /srv/tunnex-artifacts/sandbox-distribution.json \
  --distribution-sha256 "$DISTRIBUTION_SHA256" \
  --workload-descriptor /srv/tunnex-artifacts/workload-image.json \
  --source-sha "$SOURCE" --edition open \
  --org-id "$ORG_ID" --gateway-node-id "$GATEWAY_NODE_ID" \
  --gateway-container-id "$GATEWAY_CONTAINER_ID" \
  --gateway-image-digest "$GATEWAY_IMAGE_DIGEST" --gateway-interface wg0 \
  --controller-listen 10.1.0.3:9443 --controller-url https://10.1.0.3:9443 \
  --controller-server-name sandbox-controller.example.internal \
  --controller-uri spiffe://tunnex/sandbox-controller/team \
  --runner-uri spiffe://tunnex/sandbox-runner/team \
  --api-url https://tunnex.example.internal \
  --controller-certificate-file /etc/tunnex/sandbox-controller-cert.pem \
  --controller-private-key-file /etc/tunnex/sandbox-controller-key.pem \
  --runner-ca-file /etc/tunnex/sandbox-runner-ca.pem \
  --runner-ca-key-file /etc/tunnex/sandbox-runner-ca-key.pem \
  --output /etc/tunnex/sandbox-runtime.json
```

Run as the intended config owner in an existing owned directory that is not
group/world writable. The output is mode `0600`; existing files and symlinks are
refused. Keep the existing configuration during cleanup or while work is retained.
An updated image/source changes its deterministic identities and requires its
own enrollment/qualification after the original runner and work are retired.
The tool writes no database records and performs no enrollment or activation.

When runtime and terminal gateways differ, supply all three public pins:
`--terminal-gateway-node-id`, `--terminal-gateway-endpoint` and
`--runtime-gateway-endpoint`. Terminal endpoint values are private IPv4 plus port;
the controller listener also accepts private IPv6 with brackets. The terminal
choices remain each creating user's owned human
devices; the profile contains no fixed creator or terminal-device ID.

Deployment then explicitly sets `TUNNEX_SANDBOX_RUNTIME_CONFIG_FILE` to
`/etc/tunnex/sandbox-runtime.json` and `TUNNEX_SANDBOX_MODULE=on` through its normal
service configuration. This is a separate operator action: the tool changes no
service, account, organization flag, firewall or policy. The module remains
unavailable on invalid issuer/listener configuration. On the dashboard, an
authorized administrator enrolls the machine, conducts the bounded native trial,
reviews its exact proof, publishes the compatible template and enables the
organization through Sandbox Setup. None of those approvals is created here.

The image's required evidence field is an explicit
`pending-native-qualification:<descriptor SHA256>` identifier. It is a candidate
binding reference, not an attestation. The enrollment service independently
denies ordinary work and Ready until the actual trial, reviewed proof and fresh
authenticated health pass. The first supported host remains Ubuntu 26.04 AMD64
with the documented preinstalled Podman, cgroup, subordinate-map, overlay,
co-located gateway and systemd supervisor prerequisites. It has one shared
retained slot, 128 MiB, one CPU, 64 PIDs and the original 900-second maximum TTL.
No dependencies are installed at sandbox launch; workloads run without systemd
or DBus. ARM64 bundles do not imply supported runtime activation.

Verify the generator with:

```sh
cd deploy/sandbox/install
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_profile.py
```
