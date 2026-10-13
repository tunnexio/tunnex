# Accepted worker refresh and real CP integration checklist

This is a preparation checklist. Do not execute serving refresh or activation until the root has accepted Story7 and explicitly released that step. Keep source and Git local; no push. Package/component receipts, a read-only platform probe and an AWS console tunnel state do not authorize or prove a product apply.

## Preconditions and immutable inputs

1. Root accepts the final worker/controller source and Story7 crash/lifecycle proof. The production image must contain the patched private zebra/libfrr, signed pinned bgpd/vtysh, pinned strongSwan and the bounded independently cross-validated Docker DNS compatibility fix. Both ARM64 local and AMD64 cloud artifacts must use actual qualified node binaries from the same accepted source snapshot. The local Compose entrypoint serves the mounted `/binaries/tunnex-node`; the production image independently contains `/usr/local/bin/tunnex-node`. Capture both binary SHA values and their source digests separately; matching source does not imply byte-identical binaries because image linker flags differ.
2. Preserve `.runtime/gateway-before-refresh.json`, `.runtime/integrated-topology.json`, the CP database, gateway state volume, real enrollment/node/certificate and runtime journal. The captured baseline container is `88afca184ef9...`. Never delete volumes, reset journals or generate a replacement node UUID. Parent serving migrations may advance only through the normal accepted API migration path; historical tests still use disposable child databases.
3. Local CP and gateway readiness must pass before refresh. Current read-only platform receipt `.runtime/platform-dns-fixed-proof.json` proves the source fix works against the existing managed daemon but attaches no receipt to the serving controller; its serving capability remains unchanged until the worker refresh.
4. Coordinate the API restart window with the root's browser work. Preserve synthetic fixture accounts/sessions and site bindings. The existing local site is `01a11624-0197-7273-b5c1-31ae442a05b9`, gateway node `01a115fb-f7d4-794f-80b6-84f507a94152`, approved prefix `10.10.0.0/24`.

## Local ARM64 refresh order

From the feature checkout, after the explicit release:

```sh
sh tests/ipsec-bgp-local/verify.sh
sh tests/ipsec-bgp-local/prepare.sh
```

Preparation validates exact Go1.26.8 (`GOTOOLCHAIN=local`), builds API/node `.next` files, then stages the production image. All compilation, image readback and before/after source digest checks must pass before atomic file renames publish mounted binaries and image selection. Failed compile/image/source checks retain the existing serving binary/env; only private temporary build evidence changes. Read `.runtime/build.txt` for the exact immutable image, `image_internal_node_sha256`, `serving_mounted_node_sha256`, `mounted_node_source_sha256` and `image_source_sha256`. Review the accepted source/digests before restarting; do not reuse a component test binary as the serving node.

Restart only the owned API against the new source binary; wait for health and clean accepted migration before restarting the gateway. Then recreate only the owned gateway on the accepted immutable image while retaining its existing `/state` volume:

```sh
sh tests/ipsec-bgp-local/run.sh restart api
# Wait for actual API /healthz; verify accepted migration is clean.
sh tests/ipsec-bgp-local/run.sh up -d --no-deps --force-recreate gateway
sh tests/ipsec-bgp-local/verify.sh
accepted_node_image=$(sed -n 's/^BGPLOCAL_NODE_IMAGE=//p' tests/ipsec-bgp-local/.runtime/env)
python3 tests/ipsec-bgp-local/gateway-refresh-proof.py rebind --expected-image "$accepted_node_image"
python3 tests/ipsec-bgp-local/prepare-integrated-topology.py
python3 tests/ipsec-bgp-local/prepare-public-aliases.py
```

The explicit rebind requires the old container to be absent and the new container to match the original state volume, organization/node/certificate and runtime configuration. The topology helper then reconnects the exact previously recorded owned bridges and reapplies isolated public aliases. New namespace/interface identities must be observed by the product; never copy old ifindices into authority. If the guard refuses, investigate the actual difference; do not overwrite the before proof or silently relax its comparison.

Read back the mounted serving binary independently after recreation and compare it with `serving_mounted_node_sha256` in the reviewed build manifest:

```sh
tests/ipsec-bgp-local/docker-local.sh exec tunnexs2sbgplocal1007-gateway-1 sha256sum /binaries/tunnex-node
```

The image internal binary SHA is separate evidence; the mounted node is the actual executable for this local harness. Native test binaries use Go test syntax such as `-test.run '^TestOwnedPlatformDiagnostic$' -test.v`, and may never replace that serving executable.

Readiness must remain healthy. Check actual authenticated eligibility and typed version/capability reports after fresh heartbeat. Do not inject capabilities or treat a fresh heartbeat alone as qualification.

## Normal local API fixture order

The mode0600 config `.runtime/integrated-local-api.json` uses normal owner login; credentials never enter command arguments or output. The helper records nonsecret exact identities in `.runtime/integrated-local-api-state.json`. Current exact target resource is `01a116b4-4043-7e4c-be1f-ec0142043472`, `10.20.0.2/32`, TCP18080. No grant or connection was created during inactive preparation. The two earlier invalid/unsupported provider requests were resolved by exact normal GET404 and their refused UUIDs retained.

```sh
python3 tests/ipsec-bgp-local/api-fixture.py --private-config tests/ipsec-bgp-local/.runtime/integrated-local-api.json --state tests/ipsec-bgp-local/.runtime/integrated-local-api-state.json inspect
python3 tests/ipsec-bgp-local/probe-integrated.py deny
python3 tests/ipsec-bgp-local/api-fixture.py --private-config tests/ipsec-bgp-local/.runtime/integrated-local-api.json --state tests/ipsec-bgp-local/.runtime/integrated-local-api-state.json provider-disabled
python3 tests/ipsec-bgp-local/prepare-peer-config.py --private-config tests/ipsec-bgp-local/.runtime/integrated-local-api.json --state tests/ipsec-bgp-local/.runtime/integrated-local-api-state.json --output tests/ipsec-bgp-local/.runtime/integrated-peer.json
```

A disabled create still performs actual prerequisite/reservation validation. If any response is uncertain, use `resolve-provider` before attempting another create. Never fabricate identities. The private peer scaffold flips the actual provider tunnels/ASN/inside addresses and uses independent peer namespace ownership; it cannot acknowledge CP deliveries or grant the product gateway authority.

After the separate activation release, start only the standalone peer scaffold using the runtime agent's reviewed dynamic test-only interfaces. Enable the connection through normal authenticated intent API with the actual expected revision. The product gateway must fetch material, get leases, use the qualified worker factory, report status and acknowledge through its real mTLS session. Do not use synthetic component phases on the gateway.

First prove two sessions/accepted and installed exact remote route with no application rule; forwarded TCP remains denied. Then set enforcing mode only in the approved fixture scope and create the actual site→exact TCP resource rule using `grant`. Wait for fresh CP policy/lease convergence; run `probe-integrated.py allow` and capture CHILD bytes/kernel Go-owned routes/status. Use `withdraw` to remove exactly the recorded rule; after convergence, prove forwarding denied again. Exercise independent tunnel loss, worker crash/restart, lease expiration and exact cleanup in the accepted sequence. Keep old delivery/cleanup identities/journals intact.

## AMD64 cloud refresh and VGW proof

All AWS CLI discovery/provisioning remains exclusively on `ubuntu@16.170.207.192`. Fresh gateway `i-09d129f71f43119c7` is reached through that bastion. Do not modify its preexisting `sa-cloud` services. Upload accepted source/build artifacts by SSH, without Git push, into a fresh `/home/ubuntu/tunnex-bgp-lab/builds/<manifest>` directory; never overwrite a running executable in place.

Before the accepted cloud replacement, capture exact current container, owned bridge/network, state volume and CP node/certificate identities plus freshness. The old cloud gateway container is `abd6aeec558e...`, node `01a1161a-9529-7478-b62f-a27f25222aa0`. Build and qualify the native AMD64 production runtime, then stop/recreate only that exact owned gateway using the new accepted image/binary and the same state volume, private environment and owned bridge IP172.30.88.2. Preserve the API/database/Redis containers, scoped host route10.85/16→172.30.88.2 and narrow firewall rules. Verify exact same enrollment/certificate and healthy readiness before any provider setup.

The cloud CP currently has no provider/intent/apply and IPsec opt-in false; `.runtime/cloud-current-status.json` captures this read-only state and both AWS tunnels Down/0routes. Prepare an authorized synthetic normal-login account or complete the fixture's normal first-boot authentication flow; do not bypass auth or change the local/root browser accounts. Create/bind an owned site, approve10.84.2/24 and opt in through actual APIs. Wait for the qualified worker's actual capabilities. Parse real VPN/PSKs only from the bastion's private AWS config, never local console logs. Create a disabled provider normally; enable only after the activation release. Use a target resource10.85.1.10/32/TCP8080 and independent source10.84.2.10.

Actual VGW proof must include no-rule denial, narrow-rule forwarding response, encrypted CHILD byte changes, both peer states and exact accepted/installed prefixes, authenticated fresh CP status, rule withdrawal denial and lifecycle cleanup. AWS Up status alone is insufficient. Never confuse isolated local public aliases/synthetic PSKs with actual AWS proof.

## Later TGW

Do not provision TGW until VGW acceptance. Prefer legal new target10.86/16 and customerLAN10.84.3/24, fresh inside ranges and normal API reservation checks on the existing owned CP/gateway. Retained cleanup guards deliberately reject old overlapping prefixes/identities. If reuse is refused, preserve that result and choose a new independently authorized fixture; never erase ownership history to force acceptance.
