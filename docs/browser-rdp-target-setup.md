# Browser RDP setup

Register the server as **Windows** with its private IP, gateway, RDP port (default 3389), Windows accounts and verified RDP certificate fingerprint.

On the target, enable Remote Desktop with Network Level Authentication. Allow the RDP port in Windows Firewall and the network security group only from the selected gateway. When the gateway runs on the control-plane host, use that host's private IP or security group as the source.

Verify the RDP listener certificate through a trusted management session or authenticated cloud console. The registration fingerprint is the SHA256 fingerprint of the certificate, not the SSH host key. Run the account check, enable the server, then grant each account explicitly. A passed RDP check verifies reachability, NLA negotiation and the certificate; account credentials are checked when the user connects.

The browser must use HTTPS. For a private test certificate, trust its independently verified certificate before connecting. Production deployments should use a certificate trusted by customers' browsers.

Users enter Windows credentials for each connection. Credentials are transmitted over HTTPS and retained in memory only for connection establishment; they are not stored in the database or recordings. Windows desktop recording, clipboard transfer, drive redirection, audio and printing are currently unavailable.

## Gateway RDP adapter

Run Guacamole's RDP adapter in the gateway's network namespace, listening on loopback only. Set `TUNNEX_GUACD_ADDR=127.0.0.1:4822` on the gateway. For a Compose service named `gateway`, the optional sidecar is:

```yaml
services:
  gateway:
    environment:
      TUNNEX_GUACD_ADDR: 127.0.0.1:4822
  guacd:
    image: guacamole/guacd@sha256:8974eaa9ba32f713daf311e7cc8cd7e4cdfba1edea39eed75524e78ef4b08f4f
    network_mode: service:gateway
    restart: unless-stopped
    entrypoint: [/opt/guacamole/sbin/guacd]
    command: [-f, -b, 127.0.0.1, -l, '4822', -p, /tmp/guacd.pid, -L, warning]
```

Do not publish the adapter port. The gateway requires an adapter with certificate pinning support and refuses connections when that support is missing. Recreate the adapter after recreating the gateway's network namespace.

Linux automatic setup requires a supported Linux distribution, Python 3, OpenSSH and systemd. It does not configure macOS or Windows targets.
