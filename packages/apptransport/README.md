# App Access transport

This stdlib-only Go module supplies shared origin policy and an HTTP/1 outbound
CONNECT broker. The enrolled node initiates every connection. The receiving
broker becomes an HTTP client over that accepted socket; there is no inbound
node listener or public-to-node dial. Origin checks use a fixed `origin_check` connector endpoint returning bounded
diagnostic JSON. AA4 adds a separate `browser_proxy` broker/streaming origin
forwarder; production publication and session authority remain withdrawn until
AA5/6. Purpose-specific channels cannot be mixed. Positive browser tests inject
explicit test-only authority; see `apps/app-proxy/README.md`.

The API authenticates verified client certificate serials through its existing
node/org authority. Admission and renewable leases check current serial, active
node, entitlement, opt-in and exact org/gateway/app/revision/digest/generation.
Headers only confirm server-owned assignment. A lease cannot exceed five seconds
for checks or four seconds for browser channels;
renewal runs every two seconds. An independent expiry watchdog closes the socket
even if a renewal callback stalls; late admission results are refused. Pending
admissions reserve capacity before invoking authority, and the shared 128-callback
semaphore remains held until callbacks actually return, including retired sockets. Stale identity, rotation, withdrawal or authority
failure closes channels. The node TLS clone retains the atomic current-certificate
callback and requires TLS 1.3 with HTTP/1 ALPN. Ordinary control remains unchanged.

The broker bounds admitted channels to 128 globally and two ready channels per
binding, removes idle EOF/expired entries eagerly, expires ready channels after
15 seconds, and forcibly closes claimed check channels after ten seconds. Browser channels
are bounded by independently renewable route and request/session leases instead. Dial queue
wait is five seconds. These limits cover authenticated channels; listener TLS,
header and preauthentication capacity limits belong to the API acceptor.
The node also bounds all connection attempts to 128 across assignment replacement,
64 assignments, eight active origin checks, 32 waiting checks and eight checks per
desired response. Checks have ten-second total deadlines, 32KiB headers and discard
at most 64KiB of body. CONNECT response headers have a real 32KiB read limit.
Successful consumed streams replenish immediately; failed connections back off
from one to 30 seconds with jitter. Missing old-runtime capability does not opt in.

Origin policy permits at most 32 sorted, deduplicated, masked CIDRs. Empty means
public addresses only. Private destinations require private-contained explicit
ranges. Blankets and ranges containing special/reserved destinations are refused.
Mapped IPv4 addresses normalize before validation. Every DNS answer must be safe;
the actual dial uses a validated numeric IP and never resolves the hostname again.
Registered hostname remains Host/SNI. Control endpoint hosts and every resolved
control IP, loopback, metadata, link-local, multicast, unspecified, transition and
special-use destinations are refused. Failure to resolve control endpoint identity
fails App Access checks/browser requests closed. DNS results are refreshed for
every probe and streaming request.
The conservative special-use list follows the IANA IPv4/IPv6 registries and needs
review when those registries change.

CA input accepts certificate PEM only, at most 32KiB/eight certificates, each with
CA constraints and certificate-signing usage. Canonical certificate ordering yields
a SHA-256 PEM digest. Origin TLS uses system roots plus reviewed private CA roots
and verifies the registered hostname. Probes never follow redirects, use environment
proxies, send control credentials/cookies, or return bodies/headers/raw errors.
A bounded HTTP response is required; 401 and 302 demonstrate connectivity without
claiming application authorization or following the redirect.

Run shared tests with Go 1.26.9: `go test -race ./...`. Node adapter tests live in
`apps/node/internal/appaccess`; command builds target Linux. Loopback HTTP/TLS tests
need permission to listen locally. Tests prove mTLS identity rotation, selected
outbound channels, exact bindings, cancellation, TLS chain/hostname/downgrade
refusal, special-use/mixed DNS denial, capacity reclamation and header/body guards.
Counts and deadlines are bounded by implementation; no measured RSS/load/HA claim
is made. This module adds no third-party dependency; it uses the repository's
existing Go toolchain and standard-library licenses.
