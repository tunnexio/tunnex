# Native Beam publisher transport

`NewConnector(ConnectorOptions)` captures an immutable Beam binding, ephemeral
certificate/private key, proxy CA and fixed numeric loopback app. It never
listens, installs a helper, writes credentials or depends on Node/Electron.
The standalone CLI owns publication, current share/source expiry, heartbeat and
bounded Stop cleanup. `Run(ctx)` blocks until cancellation or the immutable
certificate ceiling; `Ready()` reports a currently admitted idle/active channel,
so the CLI must combine it with a fresh `CheckTarget(ctx, target)` result before
sending `origin_ready=true`. Pass `certificate_expires_at`, rather than the
refreshable readiness proof snapshot, as `ExpiresAt`. The connector also clamps
that ceiling to the actual leaf certificate's NotAfter.

Outbound CONNECT uses TLS 1.3, the returned CA, mTLS, exact server identity
`tunnex-beam-proxy`, `/beam/channel` and the shared immutable binding headers.
The pool retains two idle channels and at most 32 active streams, 34 total
reservations. Failed admissions use bounded jittered backoff. Context cancellation
closes every peer/origin socket and waits for all workers. Broker authority
leases remain responsible for current source/readiness/reviewer withdrawal.

Only `127.0.0.1` or `::1` and an explicit port may be selected. HTTPS always
verifies that numeric address against SANs, independently of the public HTTP
Host; optional development CA trust never disables verification. Registered
origin-policy and gateway/AppAccess behavior are unchanged. Requests must have
an exact public Host, relative path, immutable binding and unique stream ID.
Shared header/credential, cookie and redirect helpers enforce origin isolation.
Beam additionally removes every reserved `__Host-tunnex_` cookie. Declared HTTP
trailers are refused, preventing late credentials from bypassing header checks.

Headers are bounded to 32 KiB and request/response bodies to 16 MiB. Oversized
declared uploads receive 413 and connection close before body/origin access.
Unknown-length bodies stream through a counter; rejected bodies are never
drained. SSE stays streamed under backpressure. A request header has a 5 s budget;
HTTP upload a 30 s read budget and local HTTP response headers a 15 s budget. A
pending WebSocket local dial/upgrade has one absolute 2 s budget, cleared only
after an accepted 101, including when the client sent early upgrade head bytes.

WebSocket compression is not negotiated and unexpected origin extensions are
refused. A 14-byte scratch validates each directional frame header; payload is
copied with bounded streaming buffers. Limits are 1 MiB/frame, 16 MiB fragmented
message and 1024 fragments. Client masking, server unmasking, RSV/opcodes,
continuations, canonical lengths and control FIN/125-byte bounds are enforced.
Both buffered upgrade heads enter the same validators. Subprotocols such as
`vite-hmr` remain forwarded.

Qualification uses ephemeral local CA/key fixtures and real TLS gateway/origin
sockets. Tests cover HTTP/SSE/WebSocket concurrency, numeric HTTPS SAN failures,
32+2 capacity, expiry/cancel/backoff, credential/response isolation, upload/header
limits, malformed/oversized frames, fragmented/control chunk boundaries, blocked
reader backpressure and current-authority withdrawal during established streams
or a pending upgrade with early head bytes. Run the complete module with
`go test -race ./...` from `packages/apptransport`.
