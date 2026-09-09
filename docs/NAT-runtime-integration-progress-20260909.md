# NAT runtime integration — historical development checkpoint

Superseded by `NAT-consolidated-aws-20260909.md` and the committed live ledgers.
Server runtime has now been consolidated in 0b1dd15, client in 55f4267. The
uncommitted/untested statements below describe the earlier snapshot, not current
completion status. Hosted-database candidate qualification currently has a
transaction-timeout failure; no completed-story claim is made.

Working lane: `codex/nat1-session-contract` in the existing NAT-1 worktree.
Product edits remain uncommitted pending integration and review. Do not interpret
this note as a final PLAN pointer or a completed story.

Implemented in this lane:

- Certificate-bound gateway signaling, sealed organization relay profile,
  scoped short-lived credentials, and the Settings → Network relay card.
- Authoritative device/gateway WireGuard public keys in mailbox responses.
- Pion v4.4.2 gateway carrier, fixed loopback kernel-WireGuard bridge, bounded
  sessions and paginated discovery. It does not install peers or change policy.
- Gateway runtime attached to ownership-projected listener configuration,
  enabled only with the real `wgctrl` backend.
- Authoritative authorization refusal stops forwarding; control requests use
  the remaining authorization deadline. Transient failures do not renew it.

Verified locally in this continuation:

- Node control, candidate validation, and runtime pagination/port tests pass
  with the race detector.
- Linux amd64 node executable builds.
- Focused API connectivity/profile/relay HTTP tests pass in both editions;
  the open-edition run also uses the race detector.
- `git diff --check` passes.

The macOS invocation of the complete node-agent test package did not compile:
existing Linux egress/Kubernetes symbols have no matching macOS implementation.
The Linux executable build is not a substitute for the Linux test suite.

Still required, before calling this usable:

1. Client/helper managed-Connect signaling and encrypted bind wiring now exists
   as uncommitted source in `tunnex-client` branch `codex/nat0-desktop-proof`.
   See its `docs/NAT-1-managed-connect-progress-20260909.md`. Client's 298 tests
   and helper race tests passed; real wire qualification is still outstanding.
2. Lifecycle and authorization-deadline integration tests, including forwarding
   teardown, generation rollover, and relay loss. The new runtime unit tests do
   not prove those live behaviors.
3. Real Mac → AWS connection with direct UDP blocked, relay nomination, allowed
   service success and denied service failure, using the ordinary product path.
4. Visual UI checks, Linux node tests, complete applicable gates, independent
   review, and exact-head CI. No merge or release performed.

This continuation has not changed AWS infrastructure or the installed helper.
Historical AWS API tests remain API evidence, not proof of this new runtime.
