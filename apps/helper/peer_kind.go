package helper

// HelperVersion is the helper build version.
const HelperVersion = "0.1.0"

// CallerAuthKind reports whether the compiled caller-path resolver is the REAL
// "native" resolver or a fail-closed "stub". It is surfaced at startup and by
// --version so a STUB build — which refuses every caller — is immediately
// distinguishable and can never be silently shipped or silently refusing. (macOS
// MUST be built CGO_ENABLED=1 to get "native"; a CGO-off macOS build reports
// "stub" and rejects all callers by design.)
func CallerAuthKind() string { return peerAuthKind }
