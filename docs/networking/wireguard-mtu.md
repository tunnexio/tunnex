# WireGuard requested and effective MTU

The control plane requests MTU 1420 for ordinary gateway interfaces. The agent
applies a default cap of 1380 through the normal Linux interface owner, which
also limits the request to the smallest qualified default-route link MTU minus
80. A lower desired MTU or physical-underlay limit remains lower. An explicit
`TUNNEX_WG_MTU_CAP` from 1280 through 1420 overrides the default cap. This leaves
margin for remote Internet paths even when the gateway's cloud NIC advertises a
jumbo MTU; it is a compatibility default, not endpoint-specific PMTU discovery.

The 80-byte allowance follows [upstream wg-quick's automatic MTU calculation](https://git.zx2c4.com/wireguard-tools/tree/src/wg-quick/linux.bash) (blob `18e266c952b466e8797c73fd1aa4f2187f7ec658`, line 142). This is a conservative local-link ceiling, not discovery of every downstream path's PMTU. A different endpoint-specific route or a smaller remote path can still require further qualification.

The node clears its MTU observation at the start of Configure and reports a new `wireguard_applied_mtu` only after a successful owner update, stable underlay observations when available, and exact current WireGuard link MTU/UP readback. The authenticated capability report carries this observation. Underlay inspection failure retains the capped request with a fixed warning; it does not claim underlay qualification. An interface readback failure fails Configure and leaves no applied observation.

Ordinary server-issued static configurations and runtime mode configuration use a valid 1280–1420 observation from the gateway whose endpoint and key they actually dial. A hub-selected dial uses that hub's observation, never the assigned spoke's. Missing, malformed, future, or older-than-90-second reports use the conservative fallback 1380; fresh verified reports still accept values through 1420. The authenticated sandbox profile remains 1280. Existing static configurations are not rewritten; customers must obtain a newly issued configuration to receive the effective value. Managed desktop clients with same-mode configuration refresh receive it on reconnect.

The report is a configuration hint. It grants no network access, changes no policy hash or request deadline, and supplies no IPsec or DNS authority.

Local qualification includes a mocked execution of the actual Linux Configure owner: the original f9 implementation keeps 1420 on a 1460 underlay and fails the regression, while the candidate applies 1380 and later returns to 1420 on a 1500 underlay. This model does not execute kernel WireGuard. Cloud acceptance of the candidate requires a controlled replacement, actual owner/readback and newly issued client configuration, followed by the original large DNS response test and complete cleanup.
