# GCP managed IKE component acceptance

Run only with a disposable Linux Docker daemon. This fixture creates its own internal network (`198.18.222.0/24`) and named, labeled gateway/peer containers. Existing network or container names refuse creation. Only newly created fixture resources are removed. NET_ADMIN belongs to these containers; no host namespace or SYS_ADMIN is used.

Build `apps/node/internal/ipsec` as a Linux test binary for the Docker host architecture. Place it where Docker can mount it. Supply the exact immutable image ID of the pinned node package containing strongSwan 6.1.0. The production node embedded in the image is not executed; this runs the separately source-bound test binary against the pinned daemon package.

```sh
GCP_COMPONENT_IMAGE=sha256:<verified-image-id> \
GCP_COMPONENT_TEST_BINARY=/absolute/docker-visible/ipsec.test \
GCP_COMPONENT_SOURCE_COMMIT=<test-binary-source-commit> \
GCP_COMPONENT_RECEIPT_DIR=/absolute/new-receipt-directory \
python3 deploy/ipsec/gcp-component-native.py
```

The source-bound `TestGCPDaemonComponentPhase` accepts bounded JSON on stdin: `ProfileID`, `Role` (`gateway` or `peer`), `Phase`, and fixed two-slot `PSKs`. Classic requires an empty inactive second PSK. `TestGCPDaemonComponentServe` owns the production daemon supervisor between phases. Explicit phases cover stage, initiate, observe, rekey, refused and cleanup. The test-only stage-bad-proposal phase injects an incompatible IKE proposal through the existing production stage request. Keys are disposable synthetic constants, never customer keys.

HA establishes two real IKE/CHILD pairs; Classic establishes one. Exact real daemon/kernel addresses, request/interface IDs, broad route-based selectors, two states and three policies per active tunnel are checked. Real rekey must replace inbound/outbound SPIs after overlap retires. Wrong keys and incompatible proposals must leave no installed SAs/states/policies. Cleanup and recreation repeat the same owned path. A permanent prefix refusal guard is applied and independently read back before every stage; no application permission is granted.

`run.log` and `receipt.json` contain key-free evidence and source, binary, fixture, script and image identities. This is managed strongSwan interoperability component proof. It does not prove control-plane eligibility, delivery authority, BGP sessions, application grants/packets, or live Google Cloud interoperability. Those require the genuine enrolled gateway path and separate receipts.
