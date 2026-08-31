# Kubernetes gateways: install and operate without host patches

Tunnex implements one provider-neutral Kubernetes gateway lifecycle intended
for AKS, EKS, GKE Standard, and ordinary self-managed Kubernetes. The installer
discovers the Kubernetes and Linux capabilities it actually sees; a
cloud-provider label never grants cloud access or selects a hidden
provider-specific script.

Provider-neutral design is not itself a support claim. A provider is verified
only after its release notes name a completed live wire proof; until then its
status is compatibility-intended. No live provider wire proof has yet been
published for this lifecycle.

The normal path is `tunnex k8s`. Do not copy a join token into Helm values:
Helm retains values in release history. Before minting, the CLI creates an
owned token-blind lifecycle anchor. It then mints or idempotently redelivers one
single-use token, streams it directly to an immutable short-lived Kubernetes
Secret, waits for the real gateway readiness probe, proves the exact claim was
consumed, and removes the Secret and anchor with UID/resource-version
preconditions.

## Before you begin

You need:

- a logged-in Tunnex CLI session with permission to enroll gateways;
- `kubectl` pointing at the target cluster and Helm 3.14 or newer on the same
  workstation;
- one default StorageClass, or the name you will pass with `--storage-class`;
- permission to install the cluster-singleton privileged
  `tunnex-host-posture` DaemonSet and a host-network gateway with only
  `NET_ADMIN` plus `NET_BIND_SERVICE`; and
- UDP `51820` reachable through a Kubernetes `LoadBalancer`, or an explicit
  reachable node address and selected NodePort when using `NodePort`.

The provider-neutral host-posture release has one fixed cluster identity:
release `tunnex-host-posture` in namespace `tunnex-system`. The CLI discovers
and reuses that singleton for gateway releases in any namespace, and refuses a
second host-posture release name or namespace. It runs one manager on every
Linux node and broadly tolerates taints, so a gateway cannot land on a tainted
Linux node with no lifecycle manager. A manager without an exact,
contract-valid live gateway Pod UID on that same node remains inert; placement
alone never authorizes host mutation. Before the first live gateway owner
mutates the host, it journals the exact original sysctl values, prepares and
continuously verifies
`/dev/net/tun`, IPv4 forwarding, reverse-path filtering, WireGuard, and its
marked nft/CNI artifacts. On last-owner removal it restores only values that
still equal the Tunnex-owned setting and removes only exact journaled
artifacts. A credentialless, non-privileged gateway init waits for two
advancing manager heartbeats containing its exact Pod UID; it has no Kubernetes
or Tunnex credential, join token, or gateway state volume.

## 1. Review the plan

Choose a stable node identity. It remains the same across pod restarts and
state-preserving upgrades.

```bash
tunnex k8s plan \
  --node-name prod-aks-gateway-a \
  --release prod-gateway-a \
  --namespace tunnex
```

The plan is redacted and ends with a SHA-256 digest. With more than one Tunnex
organization, add `--org <id-or-slug>`; the CLI refuses to guess.

For a local source checkout, run the plan with the local chart path:

```bash
tunnex k8s plan \
  --node-name prod-aks-gateway-a \
  --release prod-gateway-a \
  --chart ./deploy/helm/tunnex-gateway
```

To test an explicitly published version instead:

```bash
CLI_VERSION="$(tunnex version)"
CHART_VERSION="${CLI_VERSION#v}"
case "$CHART_VERSION" in dev|unknown|"")
  echo "Use a released CLI or set CHART_VERSION to an explicitly published chart version." >&2
  exit 1
esac

tunnex k8s plan \
  --node-name prod-aks-gateway-a \
  --release prod-gateway-a \
  --chart-version "$CHART_VERSION"
```

A released CLI automatically selects the matching chart from
`oci://ghcr.io/tunnexio/charts/tunnex-gateway`.

### Private pre-release qualification

Maintainers may qualify a not-yet-public build without presenting it as a
customer release. Start from a clean committed checkout and provide only
already-built image digest references—never a registry credential or mutable
tag:

```bash
CANDIDATE_DIR=/tmp/tunnex-k8s-walk-candidate
deploy/k8s-walk-candidate-package.sh \
  --output "$CANDIDATE_DIR" \
  --api-image '<registry>/tunnex-api@sha256:<64-hex-digest>' \
  --web-image '<registry>/tunnex-web@sha256:<64-hex-digest>' \
  --nginx-image '<registry>/tunnex-nginx@sha256:<64-hex-digest>' \
  --migrate-image '<registry>/tunnex-migrate@sha256:<64-hex-digest>' \
  --node-image '<registry>/tunnex-node-agent@sha256:<64-hex-digest>' \
  --operator-image '<registry>/tunnex-operator@sha256:<64-hex-digest>'

(cd "$CANDIDATE_DIR" && sha256sum -c SHA256SUMS)
CANDIDATE_VERSION=$(jq -r .candidate_version \
  "$CANDIDATE_DIR/candidate-manifest.json")
```

The bundle contains a Linux amd64 CLI, four byte-reproducible chart packages,
their checksums, and a token-free manifest binding every input to the full
source commit. The CLI, charts, and node runtime use a bounded
`0.0.0-walk.sha<32-hex-source-prefix>` candidate version so enrollment stays
within the API's 50-character `agent_version` contract; that abbreviation is
not source provenance. The packager stamps only the CLI and charts: the
separate node-image build must pass this exact value as its Dockerfile `VERSION`
input, and qualification must record that input plus the exact post-enrollment
control-plane `agent_version` readback with no runtime override. Always verify
the manifest's full `source.sha`, artifact checksums, and image digests, and
refuse a reused candidate version whose full source SHA differs. The command
does not log in, upload, deploy, or change a cluster. Private registry
publication and deployment are separate authorized operations; after
publication, prove that each pulled chart has the recorded checksum and use the
manifest's node/operator image digests explicitly. This is pre-release walk
evidence only. It does not create a Git tag, public release, customer support
claim, or permission to bypass the normal version-tag release workflow.

## 2. Install the gateway

```bash
tunnex k8s install \
  --node-name prod-aks-gateway-a \
  --release prod-gateway-a \
  --namespace tunnex \
  --yes
```

For `LoadBalancer`, the gateway reads its own Service status and publishes the
first valid IP address or hostname. An explicit `--endpoint host:port` wins.
`NodePort` never guesses a public node address, so it requires one:

```bash
tunnex k8s install \
  --node-name prod-edge-gateway \
  --release prod-edge \
  --service-type NodePort \
  --node-port 31820 \
  --endpoint gateway.example.com:31820 \
  --yes
```

The explicit endpoint port must equal `--node-port`; this prevents the control
plane from publishing an address that the Service did not actually allocate.

If your Kubernetes load-balancer controller or private registry needs existing
operator-managed inputs, bind them into the same reviewed plan. Tunnex passes
them unchanged and verifies the non-secret Service/Deployment readback; it does
not create a cloud IP, invent a provider annotation, or read a pull Secret:

```bash
tunnex k8s install \
  --node-name prod-aks-gateway-a \
  --release prod-gateway-a \
  --load-balancer-ip 203.0.113.10 \
  --service-annotation 'controller.example/static-address=prod-gateway-a' \
  --image-pull-secret private-registry \
  --yes
```

For a labelled or tainted dedicated gateway pool, placement is explicit and
gateway-scoped. These flags do not narrow or move the shared host manager:

```bash
tunnex k8s install \
  --node-name prod-gateway-a \
  --release prod-gateway-a \
  --gateway-node-selector 'tunnex.io/gateway=true' \
  --gateway-toleration 'dedicated=tunnex:NoSchedule' \
  --yes
```

`--gateway-node-selector` and `--gateway-toleration` are repeatable. A
toleration without `=VALUE` uses Kubernetes `Exists`; one with a value uses
`Equal`. The optional effect is `NoSchedule`, `PreferNoSchedule`, or
`NoExecute`. All placement inputs are canonicalized into the plan digest and
read back from the live Deployment before success.

Success means the Deployment is available, `/readyz` is healthy, the endpoint
has been reported to Tunnex, the shared host-posture DaemonSet is healthy, and
the bootstrap claim is consumed before its Secret and lifecycle anchor are
deleted. A failed install keeps only the exact recovery state needed for a
bounded retry and prints object names, never the token value.

## 3. Verify and register the cluster

```bash
tunnex k8s status --release prod-gateway-a --namespace tunnex
tunnex k8s diagnostics --release prod-gateway-a --namespace tunnex
```

Then open **Kubernetes** in the Tunnex dashboard:

1. register the cluster and select the Site plus this in-cluster connector;
2. enter the synthetic VIP range, Kubernetes Service CIDR, and DNS zone;
3. expose a private Kubernetes Service; and
4. create the access grant that allows the intended user or group.

Diagnostics exclude Secret bodies, private keys, certificates, service-account
tokens, and legacy Helm values that might contain a raw token.

## High availability

Install each HA member as its own release and identity. Never share a join
Secret or PVC between A and B.

```bash
tunnex k8s install --node-name prod-gateway-a --release prod-gateway-a --yes
tunnex k8s install --node-name prod-gateway-b --release prod-gateway-b --yes
```

After both gateways are connected, create the connector pool and enable HA in
the dashboard. Pool membership, promotion and safe drain remain control-plane
operations; Helm does not infer them.

## Upgrade, rollback, uninstall, and recovery

```bash
tunnex k8s upgrade --release prod-gateway-a --yes
tunnex k8s rollback --release prod-gateway-a --revision 3 --yes
tunnex k8s uninstall --release prod-gateway-a --namespace tunnex --yes
```

Upgrade and rollback are atomic Helm operations and wait for real readiness.
Before an upgrade, Tunnex reads the current contract-marked Deployment and
shows the exact provider-neutral placement, image-pull Secret names, current
image, and requested target image in the approval plan. It sends complete
image and placement values to Helm, including explicit empty values, then reads
the live Deployment back exactly; an old tag, digest, pull Secret, selector, or
toleration cannot survive silently through Helm value reuse. Use `--image` only
when you intentionally want an explicit digest-pinned target.
Uninstall retains the PVC by default because it contains the gateway identity,
WireGuard key and HA safety evidence.

Reinstall from retained state without minting another token:

```bash
tunnex k8s install \
  --node-name prod-gateway-a \
  --release prod-gateway-a \
  --mode reuse \
  --existing-claim prod-gateway-a-tunnex-gateway-state \
  --yes
```

Retry the same install command after an interrupted or expired bootstrap. The
owned lifecycle anchor lets the CLI redeliver or remint the exact claim without
creating a second identity. If you intentionally abandon a partial install,
use the typed recovery command printed by the CLI; it invalidates the exact
control-plane claim, removes only matching bootstrap metadata, and retains any
PVC:

```bash
CLAIM_ID='<claim UUID printed by the failed install>'
tunnex k8s abort-install \
  --release prod-gateway-a \
  --claim "$CLAIM_ID" \
  --confirm "ABORT $CLAIM_ID"
```

State deletion is deliberately separate and irreversible. A zero-touch CLI
enroll-mode PVC carries only token-blind organization and lifecycle-claim
UUIDs, which the CLI reads back exactly before lifecycle cleanup. Before
deletion, the CLI proves that exact control-plane claim is `consumed` or
`aborted`, and refuses while the release, lifecycle anchor, owner-bound
bootstrap Secret, live mount, or non-terminal claim remains. Reuse mode never
rewrites provenance on an existing PVC. The normal path requires the exact
claim name as confirmation:

```bash
tunnex k8s purge-state \
  --release prod-gateway-a \
  --claim prod-gateway-a-tunnex-gateway-state \
  --confirm "DELETE prod-gateway-a-tunnex-gateway-state"
```

A PVC created before lifecycle provenance was introduced, or by a direct/manual
Helm install outside the proof-bearing zero-touch lifecycle, has neither
annotation. After independently verifying that it is genuinely legacy, use the
separate loud path; the ordinary confirmation is intentionally rejected:

```bash
tunnex k8s purge-state \
  --release prod-gateway-a \
  --claim prod-gateway-a-tunnex-gateway-state \
  --legacy-without-lifecycle-proof \
  --confirm "DELETE LEGACY prod-gateway-a-tunnex-gateway-state"
```

One missing annotation, a malformed UUID, a different organization, or a
claim response that does not match the PVC is not legacy and cannot be
overridden by this flag.

## Optional GitOps operator

The operator uses a separate monotonic CRD chart for `TunnexCluster`,
`TunnexExposedService`, and `TunnexGrant`. It is an API client only: it receives
no data-plane privileges and its ClusterRole is limited to those CRDs, their
status, and Events. The CRDs are retained when the operator is uninstalled.
The optional GitOps lifecycle requires Kubernetes 1.29 or newer so the CRD's
CEL provider/platform admission rules have stable semantics.

Create the machine-credential Secret outside Helm so the token never enters
Helm history. The following reads it without echo and streams it on stdin:

```bash
kubectl create namespace tunnex-system --dry-run=client -o yaml | kubectl apply -f -
read -rs TUNNEX_MACHINE_TOKEN
printf '%s' "$TUNNEX_MACHINE_TOKEN" | kubectl -n tunnex-system create secret generic \
  tunnex-operator-credential --from-file=token=/dev/stdin
unset TUNNEX_MACHINE_TOKEN
```

First install or upgrade the version-matched CRD lifecycle. This chart contains
only the three exact Tunnex CRDs. Its live preflight accepts the current CRD
release and the known legacy `tunnex-operator` release. For an ownerless legacy
install it compares the complete API-normalized schema with source-controlled
Tunnex fingerprints before allowing `--take-ownership`; an unknown, manually
changed, or newer unannotated same-name CRD is refused before Helm applies
anything:

```bash
CLI_VERSION="$(tunnex version)"
CHART_VERSION="${CLI_VERSION#v}"
case "$CHART_VERSION" in dev|unknown|"")
  echo "Use a released CLI or set CHART_VERSION to an explicitly published chart version." >&2
  exit 1
esac

helm upgrade --install tunnex-operator-crds \
  oci://ghcr.io/tunnexio/charts/tunnex-operator-crds \
  --version "$CHART_VERSION" \
  --namespace tunnex-system --create-namespace \
  --take-ownership --wait

kubectl wait --for=condition=Established --timeout=120s \
  crd/tunnexclusters.tunnex.io \
  crd/tunnexexposedservices.tunnex.io \
  crd/tunnexgrants.tunnex.io
```

Never run `helm rollback` on the CRD release; upgrade it monotonically. A normal
operator rollback cannot change the separately owned schemas.

Then install or upgrade the version-matched operator with non-secret values
only. These OCI commands become valid after the matching release publishes all
four charts (host posture, gateway, CRDs, and operator):

```bash
helm upgrade --install tunnex-operator \
  oci://ghcr.io/tunnexio/charts/tunnex-operator \
  --version "$CHART_VERSION" \
  --namespace tunnex-system --create-namespace \
  --set-string controlPlane.url="$TUNNEX_CONTROL_PLANE_URL" \
  --set-string controlPlane.organizationID="$TUNNEX_ORGANIZATION_ID" \
  --set-string machineToken.existingSecret=tunnex-operator-credential \
  --atomic --wait
```

Set `TUNNEX_CONTROL_PLANE_URL` (for example,
`https://internal.tunnex.app`) and `TUNNEX_ORGANIZATION_ID` before running the
operator command. The chart validates HTTPS and the organization UUID.

To rotate the operator credential, create a new immutable Secret name and run
the operator Helm upgrade with `machineToken.existingSecret` set to that name.
The changed name rolls the pod; delete the old Secret only after `/readyz`
authenticates the new credential against the configured organization.

Provider and platform in a `TunnexCluster` CR are optional presentation
metadata. If supplied, they must be one exact pair: `aws/eks`, `azure/aks`,
`gcp/gke_standard`, or `self_managed/kubernetes`. They never select networking
behavior.

## When installation refuses

Treat refusal as a preflight result, not as a prompt to patch the cluster by
hand. Common named causes are:

- no or multiple default StorageClasses: pass `--storage-class`;
- `NodePort` without a reachable endpoint: pass `--endpoint`;
- admission policy blocks the privileged cluster-singleton host-posture
  DaemonSet: approve the documented manager posture or use a compatible node
  pool;
- missing `/dev/net/tun`, forwarding, nftables, or UDP support: fix the node
  image or cluster policy; and
- CNI mechanism is unknown, ambiguous, or permission-blocked: keep the typed
  diagnostic and do not infer success; and
- `not an approved Tunnex legacy schema`: export and back up the existing CRD,
  compare its ownership and schema with the matching Tunnex release, and resolve
  that provenance before retrying. Do not delete it or treat
  `--take-ownership` as an override.

Manual Secret/PVC edits, host sysctl/nft commands, CNI patches, and rollout
restarts are not part of a successful installation. If one is needed, record
the run as inconclusive and fix the lifecycle contract before retrying.
