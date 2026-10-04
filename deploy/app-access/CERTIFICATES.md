# Certificate renewal and expiry

The public browser leaf, gateway listener leaf and private authority leaf have
different trust roles. Renew each against its existing trust boundary. A public
leaf must cover the registered application hostname. The gateway leaf must be
issued by the enrolled gateway trust CA with SAN `tunnex-app-proxy`; the private
authority uses `tunnex-app-authority`. Do not substitute a public certificate for
the gateway CA or broaden gateway trust to make a handshake pass.

After the control plane has bootstrapped its own master key and enrollment CA,
provision the gateway listener pair offline with the shipping API image's helper:

```sh
backupctl app-proxy-certificate --output-dir /PRIVATE_PARENT/new-gateway-tls
```

Run it with that control plane's database and existing master-key configuration,
and the same external restore marker configured for API/proxy. The helper needs
write access to the restore-marker directory for its stable lock; serving mounts
remain read-only. The absolute parent directory must already exist with mode0700,
without symlinks, and the output directory must not exist. It emits
`gateway-cert.pem`, `gateway-key.pem` and public `agent-ca.pem` as exclusive0600
files in a new0700 directory. Only fingerprints, server name, serial and effective
expiry go to stdout. No root CA key is exported or initialized. A missing master
or CA, pending restore, dirty/unsupported schema or incomplete installation
authority refuses issuance. Partial output is retained privately on I/O failure;
inspect it and choose a fresh output directory rather than overwriting it.

Use the emitted pair for the fixed `tunnex-app-proxy` gateway listener and its
public CA for the existing authority/enrollment trust settings. This certificate
is not the browser-facing public certificate or an enrolled gateway client
credential. Provision the separate proxy credential with `app-proxy-issue` and
obtain browser-trusted public TLS separately. Renewal creates a fresh directory
and leaf under the same CA; verify and select it before a controlled proxy
restart. Issuance does not change a running listener, app grants or entitlement.

The shipping standalone proxy loads public/gateway certificate-key pairs and
authority/client CA bundles at startup. Replacing those files does **not** hot
reload the running process. Before expiry, validate the replacement chain,
hostname, validity interval and matching private key, write the reviewed pair to
the private secret directory, and perform a controlled proxy restart. Retain the
external restore volume and marker configuration. A pending restore barrier
continues to refuse startup. The restart closes existing streams; eligible
sessions can reconnect through current authority afterward. This single-instance
procedure has an availability interruption and makes no HA claim.

New TLS handshakes reject expired server and client chains. Admitted gateway
channels also cap their initial and renewed authority leases at the earliest
expiry in the verified client certificate chain, including issuer certificates.
The independent lease watchdog closes an active channel at that deadline even
when a serial-based authority check would otherwise keep allowing it. A new
handshake with a renewed certificate must still pass current certificate-serial,
assignment and feature checks. Gateway control renewal retains the existing
rotating `GetClientCertificate` seam; renewing a key pair does not create or
publish an assignment.

Local qualification uses a separate no-host-port child, actual shipping proxy
binary, fresh test CA and an unsigned cached qualification image. It demonstrates
expired public/client refusal, same-CA public renewal requiring restart, renewed
client acceptance, and a positive-to-expired server handshake transition. Shared
transport tests additionally demonstrate real TLS1.3/mTLS positive traffic and
successful lease renewal followed by active-channel closure at client expiry.
The injected test authority is not production publication evidence. These checks
do not qualify production CA issuance, a live enrolled-node automatic renewal
cycle, signed release artifacts, public browser trust or HA rollout.
