# F05.1 — Runtime bearer rotation decisions

Status: **In progress — runtime bearer slice only**. WireGuard key rotation is
F05.2 and is not implemented or claimed here.

## Essential contract

- An owner/admin holding `agent_credential:rotate` requests one rotation for an
  active managed agent. Plain members receive the same 403 and the released
  route does not request or render rotation status for them.
- The agent generates `tnx_runtime_` successor plaintext locally. The control
  plane accepts and stores only its 32-byte SHA-256 hash while the current
  bearer authenticates the request. API/UI projections contain only revision,
  state, and the one-hour deadline.
- PostgreSQL permits one current and at most one candidate. Repeating the same
  requested revision/hash is idempotent. The first successful poll/report with
  the candidate atomically promotes it and makes the old bearer return the
  uniform 401 response.
- The runtime writes candidate, previous, and live credential files atomically
  with mode 0600. A definite candidate 401 restores the old bearer. An unknown
  response preserves the candidate plus previous credential so restart can
  prove the outcome. Credential-only rotation never applies or restarts the
  WireGuard tunnel.
- Suspension cancels request/candidate state while retaining the proven current
  bearer for resume. Revocation/deletion invalidates current and candidate rows
  in the same device lifecycle transaction; F04 performs the existing clean
  tunnel offboard on the next uniform 401.
- Migration 0094 backfills legacy credentials as revision 1/current. Down is
  allowed only for pristine legacy state and refuses before deleting rows or
  hashes after any rotation request/history exists.

No generic credential framework, plaintext delivery endpoint, credential hash
projection, scheduler, bootstrap-token rotation, gateway certificate rotation,
or WireGuard key change is in F05.1.

## AWS DEV live checklist (not yet executed)

1. Deploy exact content commit to the authorized development CP only; verify
   schema 94 clean and keep the previous API/web/runtime images recorded.
2. On the Ubuntu agent VM, record active service, mode-0600 credential file,
   current WireGuard interface, and a real gateway-reported handshake.
3. In the released Agents route, request rotation as owner; refetch must show
   requested revision/deadline and no bearer/hash in network payload or DOM.
4. Observe the same runtime PID generate/prepare/switch, then refetch `current`
   at the new revision. Old bearer must return the uniform 401; successor poll
   and report succeed; service and tunnel remain active with no apply churn.
5. Repeat with one interrupted prepare response and one runtime restart. The
   same candidate hash is retried, the credential file stays 0600, and the
   established tunnel remains present.
6. Request another rotation, suspend before promotion, and prove candidate 401;
   resume with the previous current bearer. Then revoke and prove both current
   and candidate 401 plus F04 clean inactive offboard.
7. Run exact-head default+enterprise API, CLI, web, generation, migration
   rollback, diff, and secret scans. Clean only disposable F05 resources.
