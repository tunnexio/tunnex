# Source-only TCP8081 customer transfer using installed standard tools

No new target/client source upload. This plan does not execute commands. Root
must bind current gateway CID/executable/namespace/certificate, normal API
provider/delivery, target1353 and route/SG/firewall baselines before execution.
The rejected source-upload path remains rejected; these are standard installed
`nc`, `timeout`, `dd`, `sha256sum`, `stat`, `ss` operations reviewed separately.

Read-only inventory through designated16/EIC confirms `/usr/bin/nc`, `timeout`,
`sha256sum`, `dd` on both85.1.10 and84.2.10; `socat` absent. Key remains16.
Target is i-0cd8ee7ba1e099092; client i-0cc22d71958707b0d. Existing8080/PID1353
must remain unchanged. AWS CLI executes exclusively on16.

## Minimal fixture changes, after root review

Use a fresh root-private run directory independently on each endpoint, with a
fresh recorded64hex nonce. Directory creation is exclusive, not `mkdir -p`.
Use `umask077`; generate4MiB synthetic bytes with existing `dd`, record size/hash
before listener/client operations. No script or repository-source copy occurs.

Target's download payload:

```sh
umask 077
mkdir -m 700 /var/tmp/EXACT_NEW_NONCE_DIRECTORY
dd if=/dev/urandom of=/var/tmp/EXACT_NEW_NONCE_DIRECTORY/download.bin bs=1048576 count=4 status=none
stat -c '%s %u %a %i' /var/tmp/EXACT_NEW_NONCE_DIRECTORY/download.bin
sha256sum /var/tmp/EXACT_NEW_NONCE_DIRECTORY/download.bin
```

Client's upload payload uses the same command shape, named `upload.bin`. Capture
normal API exactTCP8081 resource and site→resource grant independently using
already authorized normal login/cookie and standard HTTP requests; no DB/token
fabrication. Before grant, a fresh bounded connection must be denied, with
actual gateway protected DROP counter increment. Wait measured grant/lease
convergence before running the full duplex exchange.

Add only target SG0c90b1ec6f9eb24ff ingressTCP8081 from84.2.10/32 (record returned
new ruleID). Existing default egress permits replies; client SG002b60 unchanged.
Retain original SSH/ICMP/8080 and EIC targetSG0cdd. Add only the two exact
source/destination/interface DOCKER-USER rules from the prior source-only plan,
with fresh nonce comments and fulltuple pending/readback before mutation.
No route/MTU/sysctl/NAT changes.

## One bounded full duplex encrypted connection

On target, SSH executes a standard shell command with the reviewed fresh paths:

```sh
timeout --signal=TERM --kill-after=2s 45s nc -N -l 10.85.1.10 8081 < /var/tmp/EXACT_NEW_NONCE_DIRECTORY/download.bin > /var/tmp/EXACT_NEW_NONCE_DIRECTORY/upload-received.bin
```

Bind PID/start/exe/cmdline and `ss` actual85.1.10:8081 listener before client starts;
STDIN/STDOUT refer only to synthetic payloads. Never touch existing1353. Listener
is one-shot: no broad `-k` server, no executable-on-connect, no shell callbacks.
If it exits/fails, preserve logs/files and do not implicitly recreate the fixture.

On client, after actualsourcebound routeget85.1.10 reports84.2.10/ens5:

```sh
timeout --signal=TERM --kill-after=2s 45s nc -N -s 10.84.2.10 10.85.1.10 8081 < /var/tmp/EXACT_NEW_NONCE_DIRECTORY/upload.bin > /var/tmp/EXACT_NEW_NONCE_DIRECTORY/download-received.bin
```

`-N` is OpenBSD nc half-close on STDIN EOF; verify installedhelp before execution.
Both directions send4MiB on the same client-originated TCP connection. Require
both commands exit0, both received sizes exactly4194304, client uploadSHA equal
target upload-receivedSHA and target downloadSHA equal client download-receivedSHA.
Record elapsed timing separately; no constant-data compression shortcut.

## Independent wire proof and cleanup

Capture bounded SYN/SYNACK header text only for exact84.2.10↔85.1.10TCP8081,
actual relevant XFRM/physical/route MTUs, selectedslot, normal CP grant/lease and
NFT/SAs byte+packet counters before/after. No rawPCAP/payload. Application hashes
alone do not prove encryption. Encrypted counters must correlate with actual
negotiatedCBC256/SHA256/NAT-T/current owned route/interface and conn flow.

Withdraw only recorded8081 normal policy; prove a subsequent fresh connection
denied after measured convergence. Remove only exact newSG ruleID and two
recorded fulltuple hostrules after current ownership readback. Target listener
should already exit; if stilllive terminate only recorded PID/start/exe/cmdline.
Never kill1353. Preserve syntheticfiles/receipts initially; optional later
cleanup must name exact private directory/files, no wildcard/root cleanup.
Verify existing8080, all foreign routes/firewall/resources/policies, provider,
certificate/license and target1353 unchanged. No DF/PMTUD/failover claim from
this transfer alone.
