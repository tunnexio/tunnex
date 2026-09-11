# NAT traversal infrastructure walk — 2026-09-11

User explicitly authorized required infrastructure creation and a NAT traversal walk.
All AWS CLI operations executed through ubuntu@15.206.183.232 in account735391218823,
ap-south-1. Existing stopped NAT lab resides in another VPC/key context; left unchanged.
No production product code changed. Server source d94d239b; client remote main345a098.
User confirms installed desktop v0.1.3 (f9d2df3), which predates relay PR#6.

## Created and configured

- EC2 i-0b13ab11bf9c17989, t3.micro,12GiB encrypted gp3, IMDSv2 required.
- Public13.207.205.201, private172.31.19.184, CP VPC/subnet.
- Security group sg-0f756e018e716fee6: SSH only CP public/32; TCP80 ACME,
  TCP443 TURN TLS; UDP49160–49200 only relay public/32 for paired allocations.
- coturn Ubuntu package4.6.1-2build2. This is a lab qualification, not an upstream
  release/capacity/security certification. Configuration follows upstream
  https://github.com/coturn/coturn/blob/master/examples/etc/turnserver.conf.
- Valid certificate for relay.13.207.205.201.sslip.io, expires2026-12-10.
  Certbot timer plus deploy hook copies certs with restricted permissions and
  restarts coturn on renewal. Renewal itself has not been exercised.
- TURN REST shared-secret authentication; peer destinations restricted to this
  relay's own public/private addresses,4 allocations/user,40 total,1MiB/s per
  allocation,10MiB/s aggregate cap. No public unauthenticated relay configured.
- Fixed initial TCP443 bind permission failure using systemd AmbientCapabilities
  CAP_NET_BIND_SERVICE, preserving the unprivileged turnserver service user.
- CP Demo organization Settings / Network relay enabled through logged-in UI:
  turns:relay.13.207.205.201.sslip.io:443?transport=tcp
  UI readback: Enabled; secret configured and input cleared.
- CP host private runtime /home/ubuntu/nat-walk-20260911 contains instance/SG IDs,
  restricted SSH key and relay secret. No secrets committed or printed.

## Observed proof and limits

PASS: current production icewire implementation copies gathered two TURN
allocations from CP over TLS TCP443. Probe removes host candidates from the
exchanged offers; both selected paths report relay and actual payload echo matches.
PASS: actual coturn restart, followed by fresh allocation/ICE/payload echo.
This is reconnect-after-restart, NOT automatic recovery of an established session.
PASS: incorrect shared secret yields no TURN candidate/usable connection.
PASS: CP API/node remain running; existing peer and handshake retained.

These probes use short-lived synthetic TURN credentials and two test ICE agents.
They do NOT prove CP-issued session credentials, native Mac WireGuard traffic,
application allow/deny policy, automatic direct-to-relay fallback, general STUN
hole punching, or full-tunnel relay. No global firewall or personal Mac PF edits.
The probe's relay-only candidate selection is not a physical network UDP-block test.

BLOCKER for full desktop walk: installed v0.1.3 lacks relay support. Next required
wire proof after installing a relay-capable client/helper: use split tunnel,
block direct UDP only in an isolated test scope, observe Relay, access an allowed
service, refuse a denied service, restore direct connectivity and verify cleanup.
No newer desktop release or installation was performed here.

## Retention and rollback

New instance left running for the user's follow-up test and incurs AWS charges.
No Elastic IP: stopping/starting may change address and requires URL/cert/config update.
To revert configuration, disable Relay fallback in Demo Settings / Network. Prior
profile was Off with no URL/secret. Then stop or terminate only the new instance
through CP AWS CLI after the test is finished; remove its dedicated SG/key when unused.
Existing CP, databases and older stopped lab hosts were not recreated or removed.
