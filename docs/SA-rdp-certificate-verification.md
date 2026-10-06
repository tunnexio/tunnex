# RDP certificate verification and CodeQL alert 188

The RDP readiness probe uses exact-certificate SHA-256 pinning. The administrator independently verifies the Windows RDP certificate fingerprint and saves it in the server configuration. This trust model supports Windows self-signed certificates without treating a public CA or DNS hostname as the resource identity.

`pinnedRDPTLSConfig` disables Go's default public-CA/hostname check, but installs a mandatory `VerifyPeerCertificate` callback. The callback rejects a missing peer certificate and any fingerprint mismatch. No empty or malformed pin bypass exists. TLS still verifies possession of the certificate's private key. A changed server certificate requires administrator verification and a new pin.

The actual desktop connection independently configures guacd with `ignore-cert=false`, `cert-tofu=false` and the same SHA-256 certificate fingerprint. The gateway refuses an adapter without certificate-pinning support.

CodeQL `go/disabled-certificate-check` alert 188 flags the literal `InsecureSkipVerify: true` without accounting for this alternative identity verification. The finding is a false positive for missing server authentication, rather than a reason to suppress all instances of the rule. The rule remains enabled; no query or workflow exclusions were added.

Evidence: `TestRDPCertificatePinHandshake` performs real TLS handshakes using a self-signed certificate. The matching pin succeeds; changed, missing and malformed pins fail with `errHostKeyMismatch`. `TestRDPCertificatePin` covers missing-certificate rejection. The complete gateway serveraccess package passed under the Go race detector on 2026-10-06.

These tests qualify the probe's TLS authentication. They do not establish full Windows browser desktop login or production release acceptance.
