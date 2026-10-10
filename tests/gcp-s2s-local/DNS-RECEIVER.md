# Local emulator DNS receiver

This fixture supplies deterministic DNS answers behind the owned local IPsec peer. It is an emulator, not Cloud DNS, and does not forward any query to another resolver. Preparing/building it does not start a receiver or change the lab.

It reuses the node module's locked `golang.org/x/net/dns/dnsmessage` codec and the UDP/TCP wire framing already exercised in node `fqdnrpc`/`dnsforward` tests. It has no new dependencies.

From `apps/node`, qualify and build:

```sh
GOFLAGS=-mod=readonly go test -race ../../tests/gcp-s2s-local/dns-receiver.go ../../tests/gcp-s2s-local/dns-receiver_test.go
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOFLAGS=-mod=readonly go build -trimpath -o ../../tests/gcp-s2s-local/.runtime/bin/dns-receiver ../../tests/gcp-s2s-local/dns-receiver.go
```

Only after the root lab owner authorizes starting the owned peer receiver, copy/mount that exact binary into the emulator target container and run **inside its network namespace**:

```sh
/binaries/dns-receiver -listen 10.73.0.10:53 -answer-ip 10.73.0.10 -counters /state/dns-receiver-counts.json
```

The counters parent directory must exist and be fixture-owned. No host port publication is required. The default bind is loopback `127.0.0.1:1053`; the private DNS receiver address and port 53 require explicit arguments. Stop with SIGTERM. The TCP listener has a three-second deadline and at most 32 concurrent connections. Malformed, response, multi-question and oversized queries are dropped. Unknown names return NXDOMAIN; supported names queried for unavailable types such as AAAA return NOERROR with no answer. TTL is five seconds.

| Name | UDP | TCP |
| --- | --- | --- |
| `app.localemulated.gcp.lab.test` | A `10.73.0.10` | A `10.73.0.10` |
| `alias.localemulated.gcp.lab.test` | CNAME to app plus its A record | Same |
| `tcp.localemulated.gcp.lab.test` | TC bit, no answers | A `10.73.0.10` |
| Any unknown name | NXDOMAIN | NXDOMAIN |

The atomic JSON counters file has `version: 1` and `counts` keyed by `udp:<fqdn>.` or `tcp:<fqdn>.`. Each entry counts processed `queries`, constructed answer records (`answers`), `truncated` replies and `nxdomain` replies. For forced fallback, expect both `udp:tcp.localemulated.gcp.lab.test.` with `truncated > 0` and `tcp:tcp.localemulated.gcp.lab.test.` with `answers > 0`. These counters prove receiver processing, not application reachability or Google Cloud operation. Packet captures and actual CP/gateway authority remain separate evidence.

Use the normal resolver-profile API/UI to bind the enabled owned local Classic connection: provider `google_cloud`, suffix `localemulated.gcp.lab.test`, endpoint `10.73.0.10:53` separately for UDP/TCP, and a source address actually owned by the gateway within approved `10.70.0.0/24`. The `ipsec_path.configuration_revision` is the provider configuration revision, not desired revision. The IPsec route does not grant access: ordinary exact scoped access rules must separately authorize the client and DNS endpoint for both UDP/TCP 53. Do not use the gateway's underlay or WireGuard address as a substitute for its approved LAN source.
