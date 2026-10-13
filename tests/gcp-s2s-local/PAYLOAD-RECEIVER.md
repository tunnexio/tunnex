# Owned local HTTP payload receiver

This standard-library fixture measures bounded byte transfer behind the isolated emulator. It creates no grants, forwards nothing, stores no payload, and emits no request logs. Root starts it only on the known owned container address; no host port publication is required.

```sh
python3 -B tests/gcp-s2s-local/payload_receiver_test.py
python3 /fixtures/payload-receiver.py --listen 10.73.0.10:18080 --marker TUNNEX_OWNED_CLASSIC_TARGET
```

`--listen` is required and accepts explicit IPv4/port only; wildcard/multicast binds are rejected. `--marker` preserves a chosen owned marker for GET `/` (maximum 4096 UTF-8 bytes). GET `/bytes/N` returns N deterministic bytes repeating values 0..255, for 0..1048576 inclusive. `Content-Length` and `X-Payload-SHA256` describe the response body. POST `/upload` requires exactly one Content-Length and at most 1 MiB; its JSON receipt includes `received_length` and `received_sha256`. Transfer-Encoding/chunked uploads are rejected. Connections close after each request and reads have a five-second timeout. This is a bounded local test fixture, not a production HTTP server.

Use actual normal exact protocol/port access grants and the existing peer ACL. Compare caller-computed download/upload digests and lengths with these values. A large TCP body exercises stream transfer and segmentation; it does not alone prove a specific path MTU, absence of fragmentation, or Google Cloud behavior. Combine with actual kernel/interface observations and captures for those claims. Root separately controls stopping/replacing the exact known owned receiver processes.
