# Owned Azure runtime qualification

Run these operations only on the owned peer host. No Azure CLI or cloud changes are required. Set `GW` to the verified existing gateway container and `CLIENT_NS` to the existing client namespace. Preserve the current image, enrollment, journal and connection IDs. All application probes must originate from `10.233.10.2`, not the gateway. The normal private owner API helper provides independent configuration/application/tunnel/BGP status; `application_state=applied` alone is not packet health.

## Selected tunnel failure and return

1. Save key-free normal API status immediately before the fault: `active_slot`, selection/report sequence, observed time, both tunnel states, BGP peer states and installed route slot. The fixed wire slots are one-based: slot 1 is `52.140.60.21`; slot 2 is `20.219.125.34`.
2. Start the existing packet probe from the real client namespace for 60 seconds, retaining fresh and persistent TCP/UDP results and server-observed source. Use the same existing `probe-packets.py` invocation that passed baseline; include the resolver probes in a separate window if their execution would obscure packet timing.
3. While that probe runs, block the actually selected slot from the peer HOST:

   ```sh
   sudo python3 owned-tunnel-fault.py block --container "$GW" --slot 1 --seconds 90
   ```

   Change `--slot` only to the freshly observed selected slot. This helper checks the owner label and owned bridge, then filters only that container's encrypted transport to/from that one Azure instance. It does not terminate/adopt charon/FRR, modify gateway nftables, touch runtime guards, edit journals, or change control-plane intent. The helper automatically removes its marked fault table on completion/interruption. A hard kill/power failure requires the reviewed `clear` action; do not flush host rules.
4. Observe key-free API status every 5 seconds in a separate process. Expect peer failure to be observed before any selection claim. Save at least three fresh observations and the existing minimum 10-second recovery hold; a sequence change alone is insufficient. The failure bound includes actual Azure/FRR detection (`neighbor timers 10 30`, IKE DPD delay 10 seconds) and recovery policy. Measure observed loss/last-success gaps rather than asserting zero downtime.
5. Start a second 60-second client probe window before the 90-second fault clears. Continue status observations through return. Require traffic on the surviving permitted route, source preservation, fresh status, and eventually both peers/tunnels healthy again. Do not require automatic failback if current policy retains the healthy selection.
6. Verify the fault table is absent with the helper's `clear` action. Capture actual application/service counters as separate packet evidence; do not infer them from API state.

## MTU, DF and MSS

Read link metadata only, without XFRM state or daemon configuration:

```sh
sudo docker exec "$GW" /sbin/ip -j link show
sudo docker exec "$GW" /sbin/ip -j -4 route show 10.231.0.0/16
```

Record the real owned XFRM interface names, indices and MTUs. The Azure profile caps its inner MTU at 1390 on a normal 1500-byte underlay, giving IPv4 TCP MSS 1350; a smaller observed underlay can reduce both. Use the actual measured MTU `M`, not a presumed ceiling.

From the real client namespace, send IPv4 ICMP DF probes to the owned target `10.231.1.4`: one with payload `M-28`, one with `M-27`. `-c 3 -W 2` bounds each observation. For measured `M=1390`:

```sh
sudo ip netns exec "$CLIENT_NS" ping -4 -M do -c 3 -W 2 -s 1362 10.231.1.4
sudo ip netns exec "$CLIENT_NS" ping -4 -M do -c 3 -W 2 -s 1363 10.231.1.4
```

A successful boundary plus actual `fragmentation needed`/PMTU feedback above it supports the DF result. An ICMP timeout alone is inconclusive, because target/cloud ICMP policy may refuse echo or feedback. Do not change that policy to manufacture a result.

Use a bounded SYN-only capture on the measured selected XFRM interface while opening fresh client TCP connections to port 8080:

```sh
sudo docker exec "$GW" tcpdump -nn -v -s 128 -c 6 -i "$SELECTED_XFRM" 'src host 10.233.10.2 and dst host 10.231.1.4 and tcp dst port 8080 and (tcp[tcpflags] & tcp-syn != 0)'
```

Bound the capture externally to 15 seconds if fewer SYNs arrive. Print header/options only; do not enable payload hex/ASCII output or save broad packet captures. Record the observed MSS and compare with `M-40`. A LAN-side capture shows the client's offered MSS; the selected XFRM egress capture shows the post-clamp SYN. Run the same bounded application probe and a sufficiently large response to verify useful traffic, separately from the header proof. Missing tcpdump is a packaging limitation, not evidence of a clamp.

## Lifecycle and fail-closed observation

Do not use ordinary `docker restart` as a namespace-preserving recovery test. It replaces the gateway network namespace, can delete the moved veth, and leaves recovery evidence bound to the old namespace. A genuine agent restart requires a reviewed supervisor/pod namespace anchor and the existing stop/restore receipt contract; never edit namespace fields or discard retained journals.

The immediate safe lifecycle observation is an owned gateway pause/unpause in the SAME namespace. Start real client probes first, pause only this container, observe authorization expiry/failure, and unpause in a guaranteed host-side `finally`/trap. Choose the pause interval from actual permit expiry, not a guessed timeout. Continue fresh API status and traffic observations after unpause; require normal fresh authority before traffic returns. Pause/unpause is a process-suspension test and must not be reported as a restart.

For a clean ordinary recreation, first use normal desired-revision CAS disable and wait for real cleanup completion while observing denied traffic. Preserve retained journal evidence and exact ownership. Recreate only the owned gateway with LAN routes installed before agent startup, then enable via normal CAS and prove fresh activation. That is disable/recreate/re-enable qualification, distinct from in-place restart recovery.

All conclusions must identify exact source/image/binary, timestamps, actual packet source, fault interval, observed loss, fresh status sequences and any missing MTU/lifecycle proof.

## Both-instance failure

After the single-instance fault has fully cleared and both peers are freshly healthy, run the same owned host helper with `--slot both --seconds 90`. This targets exactly the two fixed Azure instances, never an arbitrary peer. Run overlapping bounded client probe windows and fresh API observations. Once both paths are observed failed and permits withdrawn, require zero successful fresh/persistent TCP and UDP samples in a measured tail; report detection/withdrawal latency separately from that tail. No success during an early detection interval may be described as post-withdrawal forwarding. After automatic fault cleanup, require actual peer/SA return, fresh normal authority/status, installed selected route and client traffic; do not infer recovery from the fault table disappearing.

Fault events carry `observed_at` UTC on start, successful clear and refusal. The duration controls the fault wait; cleanup runs in `finally` independently of the external packet/status observers. Explicit recovery now requires `sudo python3 owned-tunnel-fault.py clear --container "$GW"`, rechecking the actual owned bridge identity. nft 1.0.2 may omit its table comment from JSON: clearing therefore attests both the complete numeric textual owner/table/rule grammar and the exact JSON chain/rule expressions, allowing only counters and the known `raw=-300` priority rendering. An observation failure is not treated as absence. A refused cleanup leaves evidence and requires reviewed recovery; it does not establish a bounded-duration or return-to-both-peers result. The first live run exceeded its requested duration because of this parser refusal; keep that failure separate from the surviving-slot packet proof and subsequent explicit recovery.
