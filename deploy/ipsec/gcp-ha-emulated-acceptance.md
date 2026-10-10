# Genuine control-plane HA emulator acceptance

This separate external HA peer proves local CP delivery, two strongSwan tunnels, FRR and guarded traffic; it does not qualify Google Cloud interoperability.

| Resource | Existing Classic | New HA slice |
| --- | --- | --- |
| Gateway outside | 33.0.0.10 | Same enrolled gateway |
| Peer outside | 33.0.0.20 | 33.0.0.30 and .31 in one new namespace |
| Local prefix/source | 10.70.0.0/24, .10 | Same approved site |
| Remote prefix/target | 10.73.0.0/24, .10 | Separate 10.74.0.0/24, .10 |
| Inside | Unnumbered | 169.254.74.0/30 and .4/30 |
| ASN | None | Gateway65001, peer65002; maximum prefixes1 |

Root first checks address/network/ASN collisions. Keep the synthetic outside bridge internal. Attach only new owned peer and target namespaces with scoped NET_ADMIN; preserve Classic resources, grants and delivery.

Normal API create uses fresh connection/tunnel IDs, profile `gcp-ha-bgp-ipv4-v1`, mode `ipv4-bgp`, customer outside33.0.0.10, local10.70/24 and remote10.74/24. BGP local ASN65001, remote ASN65002, router ID10.70.0.1, maximum prefixes1. Tunnel1 outside33.0.0.30, inside169.254.74.0/30, customer169.254.74.1/cloud169.254.74.2; tunnel2 outside33.0.0.31, inside169.254.74.4/30, customer169.254.74.5/cloud169.254.74.6. Supply distinct private PSKs through the existing private request path. Save disabled, then enable with ordinary desired-revision CAS. Never manually create leases, deliveries or journal records.

Fetch exact genuine material through the enrolled gateway mTLS path into a private0600 file. The helper verifies canonical digest, explicit profile, revision, kernel allocations, secret bindings and prefix bounds, then reverses intent for the external peer. It cannot acknowledge gateway delivery:

```sh
python3 deploy/ipsec/gcp-ha-peer-prepare.py /private/material.json /private/peer.json \
  --peer-gateway-id FRESH-EXTERNAL-PEER-UUID --generation FRESH-GENERATION-UUID \
  --local-target 10.74.0.10 --remote-target 10.70.0.10
```

Use existing strict `TestBGPStandalonePeerNative`: private config must be root-owned0600 inside the owned container; run `stage`, `initiate`, then `serve`. Use an immutable source-hashed test binary and pinned daemon image. Peer eth0 holds both outside addresses; eth1 reaches only10.74/24. Common FRR handles the reversed inside pairs and ASNs. No fabricated gateway authority.

Acceptance: genuine applied ACK/public status; two IKE/CHILD SAs and two established BGP sessions; exact learned prefix/owned route; denied TCP18080 before normal grant, private marker after grant, bounded denial after revoke/expiry. Stop one owned peer connection to prove surviving traffic/asymmetric guard; stop both to prove withdrawal and denial; restore and prove convergence. Disable/delete through normal API, verify cleanup ACK and retained prefix guard, then remove only newly owned resources. Save key-free source/image/binary hashes and outcomes. Never print raw XFRM state, PSKs, identity files or private material.

Classic UDP extension: after the old known serve PID exits (or SIGTERM), verify denial and absent owned return route. Add only `{"source":"10.70.0.10","destination":"10.73.0.10","protocol":"udp","port":9000}` to private Services and restart `serve` using its immutable binary. Do not restage installed connections, overwrite executing binaries or broaden LAN ACLs. A normal API grant remains required. The old line103 combined nft denial and route readback failures; the fixture now distinguishes these stages. That aggregate error alone cannot establish rekey or production failure.
