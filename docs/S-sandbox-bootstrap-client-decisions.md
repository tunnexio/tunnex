# Sandbox bootstrap client and transport decisions

Source implementation remains authorized; availability stays closed pending qualification.

Add a distinct token-authenticated sandbox bootstrap route using the existing tested devices.Create transaction and current sandbox runtime binding. Request contains only one-time bootstrap token and client public key. Response returns sandbox/peer/generation metadata, split-tunnel config template and separate runtime credential exactly once; no agent profile or user/organization spoofing fields. No ordinary CLI login/token flow or browser token issue endpoint is introduced. Missing qualified provisioner refuses before token redemption.

The preloaded sandbox runtime client generates WireGuard keys locally, uses HTTPS with normal certificate verification, bounds response size/time and never logs tokens/config/private keys. Validate returned identity/generation, runtime credential prefix/entropy, exact single key placeholder and expected split-tunnel shape before persisting. One owned empty0700 handoff directory contains0600 config/credential/state files. Preflight paths before single-use redemption, refuse existing/symlink destinations and preserve user files. An uncertain POST response is an error with no automatic second redemption; durable worker operation recovery remains a separate requirement.

No runtime image download/install is part of this client. Image packaging must build/copy verified local source binaries into a reproducible immutable image before launch. The client itself does not apply network config or mark Ready; a qualified privileged setup coordinator and unprivileged workload remain separate. No systemd/DBus orchestration is required.
