# Signed local installation bundles

Use this explicit mode to qualify an unpublished build without publishing images
or patching an installed server. The ordinary `get.tunnex.io` path, CI signing
key and signed public release descriptor are unchanged. A local bundle is not a
published release and does not claim release-channel or multi-platform coverage.
The initial supported server/gateway platform is **Linux AMD64**. Its separately
versioned client artifact is a **macOS universal PKG**.

## Trust and contents

Obtain and check the canonical `deploy/install.sh` and `deploy/install-bundle.py`
entrypoints through a trusted operator channel. They are the code that performs
verification; placing untrusted code beside a signed descriptor does not make
that code trusted. Supply an independently verified **Ed25519 PEM public key**
outside the bundle directory. The installer never trusts a key from the bundle.
Python 3.11+ and OpenSSL with Ed25519 support must already be available; the normal
installer prepares Docker/Compose when needed. Preparing host dependencies and
obtaining a public TLS certificate may require network access. The product
artifacts themselves are local and never fetched from a registry in this mode.

The bundle directory contains `bundle.json`, a detached 64-byte
`bundle.json.sig`, installer payload, Docker archives and the client PKG.
Sign the exact bytes of `bundle.json`, without JSON reserialization, using:

```sh
openssl pkeyutl -sign -rawin -inkey /protected/local-signing-key.pem \
  -in bundle.json -out bundle.json.sig
```

The private key stays outside the delivered bundle. A public key can be exported
with `openssl pkey -in /protected/local-signing-key.pem -pubout -out trusted.pem`.
Operator provisioning of that public key remains independent of bundle delivery.

Descriptor v1 has exactly these fields (values shown below are schematic):

```json
{
  "schema_version": 1,
  "kind": "tunnex-local-install-bundle",
  "platform": "linux/amd64",
  "source_sha": "40-character exact server Git commit",
  "version": "0.1.42-local.1",
  "files": {
    "deploy/install.sh": {"sha256": "64 lowercase hex characters", "bytes": 1234},
    "images/node-agent.tar": {"sha256": "64 lowercase hex characters", "bytes": 1234},
    "client/Tunnex-local.pkg": {"sha256": "64 lowercase hex characters", "bytes": 1234}
  },
  "images": {
    "node-agent": {
      "archive": "images/node-agent.tar",
      "image_id": "sha256:64 lowercase hex characters",
      "os": "linux",
      "architecture": "amd64",
      "source_sha": "same exact server Git commit"
    }
  },
  "client": {
    "path": "client/Tunnex-local.pkg",
    "source_sha": "40-character exact client Git commit",
    "version": "0.1.14-local.1",
    "platform": "darwin/universal"
  }
}
```

The schematic descriptor omits required entries for readability. `files` must
include all archives, the PKG, and these canonical source files:

- `deploy/install.sh`, `deploy/install-bundle.py`, `deploy/tunnex.yml`
- `deploy/upgrade.sh`, `deploy/upgrade-runner.sh`, `deploy/ai-bootstrap.sh`
- `deploy/ai-gateway/config-managed.json`

`images` must contain exactly `api`, `web`, `nginx`, `node-agent`, `ai-engine`,
`postgres`, `redis`, and `caddy`, each with the illustrated fields. Each archive
path is unique and must be in `files`. The API, web, nginx and node-agent source
commits must equal `source_sha`; dependencies may have `source_sha: null` or their
own exact source commit. Artifact production must retain its source/build receipts;
the signature binds those declared origins but does not reconstruct source from
compiled image layers. The client has its own source/version/platform provenance.
Do not use an old platform image with a newly invented source field.

Paths are relative, regular files without traversal or symlinks. Unknown fields,
duplicate JSON keys, missing roles, wrong sizes/hashes, an internal key path,
wrong signature or mismatched platform are refused. Loaded Docker image IDs and
platforms are inspected before first startup. These are **Docker config image
IDs**, not registry manifest digests; no tag resolution is necessary after load.

## Fresh server installation

Choose a new directory and Compose project. Existing `.env`, `tunnex.yml`, project
containers or project data volumes cause refusal rather than reuse or deletion.
Use ordinary installer inputs for URL, TLS, administrator and organization:

```sh
sudo env TUNNEX_LOCAL_BUNDLE_DIR=/srv/tunnex-bundle \
  TUNNEX_LOCAL_BUNDLE_PUBLIC_KEY=/root/trusted-local-bundle.pem \
  TUNNEX_DIR=/opt/tunnex-fresh TUNNEX_COMPOSE_PROJECT=tunnex_fresh \
  TUNNEX_PUBLIC_BASE_URL=https://cp.example.com \
  TUNNEX_ADMIN_EMAIL=owner@example.com TUNNEX_SMTP=skip \
  TUNNEX_BOOTSTRAP_ORG_NAME='My organization' \
  TUNNEX_GATEWAY_PLACEMENT=separate \
  sh /srv/tunnex-bundle/deploy/install.sh --yes
```

Every Compose image and the API's advertised `TUNNEX_NODE_AGENT_IMAGE` is selected
from the verified bundle before the first `up`; all local `up`/`run` operations use
`--pull never`. The usual first-administrator password change, organization policy,
licence activation, gateway join-token authorization and device approval remain
normal product operations. No authentication, database or licence bypass exists.

The install retains descriptor/signature/trust-key and load receipts under
`local-bundle/`, together with the exact verified Mac package. Completion prints
its path; the public dashboard download link remains the published-client link.
Transfer this private PKG explicitly to the intended test client. Signing and
notarization status comes from that package's receipt, not from bundle signing.

The public release updater and privileged host upgrade runner are not installed
for local mode; `upgrade.sh` refuses public-channel upgrades. The local descriptor
is not passed off as CI release metadata. Managed-agent release/bootstrap catalog
metadata is consequently unavailable in this mode. Preserve retained data and
use a separately reviewed upgrade procedure; this fresh-install mode is not an
upgrade/rollback tool.

## Separate gateway preparation and enrollment

Transfer the same bundle and independently trusted key to a fresh Linux AMD64
gateway, then run the canonical installer in preparation mode:

```sh
sudo env TUNNEX_LOCAL_BUNDLE_DIR=/srv/tunnex-bundle \
  TUNNEX_LOCAL_BUNDLE_PUBLIC_KEY=/root/trusted-local-bundle.pem \
  sh /srv/tunnex-bundle/deploy/install.sh --gateway-bundle --yes
```

This prepares Docker/Compose, checks TUN support (attempting the normal `tun`
module load if needed), refuses an existing `tunnex-node` container or
`tunnex_node_state` identity volume, and loads/inspects only the signed node image.
It neither enrolls nor starts a node. Linux WireGuard/network support and the
normal host/cloud firewall prerequisites remain required; firewall policy is not
modified. Generate a join token in this bundle's fresh CP and run its normal
complete enrollment command. The CP supplies the exact already-loaded image ID;
identity and keys are created by the normal enrollment flow, with no later image
override. `--dry-run` verifies the bundle and previews either mode without loading
images or changing host configuration.

## Qualification

`python3 deploy/install-local-bundle_test.py` uses real Ed25519 signatures and a
mock Docker boundary. It exercises the canonical first-install flow and verifies
all image pins at the first start, plus failure paths. It does not claim a real
Linux installation or desktop connection. Fresh-host, normal enrollment and
traffic acceptance must be recorded separately against the exact bundle hash.
