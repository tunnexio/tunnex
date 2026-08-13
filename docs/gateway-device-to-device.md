# Device-to-device connectivity (spoke-to-spoke via the gateway)

Two devices on the same org pool (e.g. `10.99.0.2` and `10.99.0.3`) reaching each other is a
**standard hub-and-spoke VPN behavior**: devices peer only with the gateway, so device→device
traffic is **forwarded by the gateway** (WireGuard crypto-routes it out to the other peer).
Verified live 2026-07-10 (Mac↔Windows, `ping` + TCP).

The **client** side already supports it — a split-tunnel device gets `AllowedIPs = <org pool
CIDR>` (`apps/api/internal/devices/config.go`), so the whole `/24` routes into the tunnel and
each end accepts the other's source IP. The manual bits today are on the **gateway** and the
**endpoint OS firewall**.

## What's required (manual today — S3.7 productizes the gateway side)

### 1. Gateway (the node-agent host / its netns)
- `net.ipv4.ip_forward = 1` (the compose already sets it for the node-agent container).
- `FORWARD` allows `wg0 → wg0` (often already ACCEPT by policy; add explicitly if not).

The node-agent runs WireGuard in its **container netns**, so apply from the host:
```bash
PID=$(sudo docker inspect -f '{{.State.Pid}}' tunnex-node-agent-1)
sudo nsenter -t "$PID" -n iptables -I FORWARD -i wg0 -o wg0 -j ACCEPT
# verify (pkts count climbs while pinging = forwarding works):
sudo nsenter -t "$PID" -n iptables -L FORWARD -v -n | grep 'wg0 * wg0'
```
Not persistent (lost on container restart) — re-apply, or let **S3.7** install it.

### 2. Endpoint OS firewall (per device — normal OS config, not Tunnex)
The gateway forwarding the packet is not enough; the **target device** must answer.
- **Windows** blocks inbound ICMP + ports by default:
  ```powershell
  New-NetFirewallRule -DisplayName "Allow ICMPv4-In" -Protocol ICMPv4 -IcmpType 8 -Direction Inbound -Action Allow
  # per-service: netsh advfirewall firewall add rule name="svc" dir=in action=allow protocol=TCP localport=<port>
  ```
- **macOS** answers ping by default, but the app firewall's **stealth mode** silently drops it —
  disable stealth mode (System Settings → Network → Firewall → Options) or test over TCP.

### Diagnosing
- Gateway `wg0→wg0` pkts **climb** while pinging → gateway forwards; a remaining failure is the
  **endpoint firewall**.
- Counter **stays 0** → the sender isn't routing the peer IP into the tunnel (`route -n get` /
  `route print` must show the tunnel interface).
- Use a **TCP test** (`python3 -m http.server` + `curl`) to bypass ICMP — the honest end-to-end
  check when an endpoint runs stealth mode.

## Roadmap
- **S3.7 (parked)** — gateway routing/NAT: the node-agent installs the `FORWARD` rules (and, for
  full-tunnel, egress NAT) itself, so device-to-device + real internet egress become managed, not
  manual. This doc's step 1 is exactly what S3.7 automates.
- **EPIC 7 (Zero Trust)** — *who* may reach *whom*. Today the org subnet is flat (any device can
  reach any other, given forwarding + firewall). Policy-based isolation is EPIC 7; until then,
  reachability is at the network layer only.
