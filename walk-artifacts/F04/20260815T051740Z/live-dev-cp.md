# F04 AWS dev control-plane live walk — 2026-08-15

Target: authorized development control plane `ubuntu@54.66.253.232`.
Source: `bd8efbcaccdba8b299e91be127fa2d5380f223a1`.
No credential, token, private key, raw WireGuard configuration, or session cookie is recorded here.

## Deployment and data

- API, web, nginx, and node-agent ran the `ai-agent-bd8efbc` images and reported healthy.
- The live migration binary advanced the retained database from schema `87|clean` to `93|clean`.
- The Enterprise edition remained active.
- A signed disposable descriptor projected immutable tag
  `tunnex-build-bd8efbcaccdba8b299e91be127fa2d5380f223a1`, source SHA
  `bd8efbcaccdba8b299e91be127fa2d5380f223a1`, key id `f04-dev-cp-test`,
  and runtime binary `tunnex-agent-runtime`.

## Bootstrap and apply

- Organization runtime opt-in: HTTP `200`, persisted `enabled=true`.
- Bootstrap issue: HTTP `201`; release metadata matched the signed descriptor.
- Bootstrap redeem: HTTP `200`; disposable device
  `01a003ea-a43c-7c78-bea5-373772da700b`, assigned address `10.99.0.8`.
- Returned config retained the private-key placeholder and the runtime credential was present once.
- Config, runtime credential, and durable state were all mode `0600`.
- Device approval: HTTP `204`.
- The shipped runtime image ran with real `/dev/net/tun` and `NET_ADMIN`.
- Durable state advanced to revision `1`; WireGuard interface `runtime` existed and its
  latest-handshake epoch was non-zero.
- Server status was desired/applied/attempted `1/1/1`, client `sha-bd8efbc`,
  `connectivity=connected`, `stale=false`, with no error code.

## Last-good and restart

- Disconnecting only the runtime container from the control-plane network for six seconds
  left the process running, revision `1`, interface `runtime`, and the last-good config hash
  unchanged. Reconnection restored normal polling without mutation.
- A whole-container restart destroys its network namespace and is not a valid substitute for
  a systemd process restart. The accepted restart leg therefore used a long-lived privileged
  namespace and restarted only `tunnex-agent-runtime`.
- While the runtime process was stopped, interface `runtime` remained present. After restart,
  there was exactly one runtime process, revision remained `1`, the config hash was unchanged,
  the handshake stayed non-zero, and server status remained connected and non-stale.

## Fail-closed offboarding

- Canonical revoke: HTTP `204`.
- The next runtime poll received the uniform machine-auth refusal; the runtime process exited
  and disabled the WireGuard interface.
- Final process count was `0`, the interface was absent, the old bearer polled with HTTP `401`
  and `unauthenticated`, and the canonical profile status was `revoked`.

Result: the F04 production API and shipped runtime path passed the real poll/apply/report,
last-good outage, process restart, handshake, and revoke-disable live wire on the AWS dev CP.
