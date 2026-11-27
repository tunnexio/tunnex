# AI-SEC-2: enforce MCP tool policy where the agent cannot go around it

Status: decisions locked by the founder on 2026-11-27. Implementation in progress. Lands on the same security PR as AI-SEC-1
(`story/ai-sec-1`, not pushed).

## Problem

A live walk on two GCP machines (control plane + gateway + a Postgres-backed
test MCP server on one, a managed agent on the other; branch build `876f4078`)
tested what an agent can do through MCP. The limits that exist work: default
deny, argument constraints, rate limit, step-up bound to the exact arguments
and single use, schema-change blocking, and fast withdrawal (policy about 3 s,
network rule about 6 s, group removal about 13 s).

Seven gaps were confirmed live.

1. **The tool policy can be bypassed from the agent host.** Policy is enforced
   only by the loopback proxy on the agent host
   (`apps/cli/internal/cli/mcp_proxy.go`). The agent needs a network rule to
   the MCP server's address, and that rule lets any process on the host POST to
   the server directly. With no tool policy configured at all, `run_sql` ran
   through a direct call. For an MCP server that has no login of its own, the
   tool policy is advisory.
2. **Nothing a tool does is recorded.** Tool calls, denials, step-up requests
   and approvals write no audit row. An approved refund left no trace.
3. **Approvers approve blind.** An approval request carries the tool name and
   schema hash, not the arguments. There is no deny; a request can only expire
   after five minutes. Each refused retry adds another pending row.
4. **A changed tool description is not noticed.** Only `inputSchema` is hashed.
   The test server rewrote an allowed tool's description to carry an injected
   instruction and the tool kept working with no flag.
5. **`tools/list` is not filtered.** The agent sees every tool, including the
   ones it may not call.
6. **An allowed tool without constraints does not enforce its own schema.**
   A wrong type and an undeclared argument were forwarded.
7. **An unreachable upstream hangs.** `tools/list` took more than 15 seconds
   to fail, with no clear error.

Also read from code, not yet walked: the OAuth access token for an MCP server
is leased to the runtime on the agent host, and the rate limiter is in memory
in that one process.

## Decisions

- Locked: **the gateway enforces MCP policy.** The gateway gains an MCP
  listener on its tunnel address, built like the existing VPN AI listener
  (`apps/node/internal/aivpn`): it identifies the caller from the tunnel
  source address and WireGuard key, never from a header the caller sends. For
  each `tools/call` it asks the control plane for a decision over the node
  mTLS channel and forwards to the MCP server from the gateway only when the
  answer is allow.
  - The loopback proxy stays at `127.0.0.1:17100` so agent clients do not
    change. It becomes a forwarder to the gateway listener and keeps the
    AI-SEC-1 Host, Origin and Content-Type guard.
  - The control plane owns the decision: allow-list, argument constraints,
    rate limit (shared store, not process memory) and step-up.
  - Rejected: keep enforcement on the agent host and restrict the direct path
    with a local firewall rule by process owner. Anything running as root on
    the host removes it, and the host is the thing being limited.
  - Rejected: have the control plane call the MCP server. It usually cannot
    reach a private server; the gateway already can.
- Locked: **the direct path is closed.** For every MCP endpoint assigned to
  an agent through a profile, the policy compiler emits a deny for that agent
  device to the endpoint's address and port, ahead of any allow. Saving a rule
  that would open such an endpoint to an agent shows why it has no effect.
  Users and other devices are not affected.
  - Existing installations: an agent that reached its MCP server through a
    direct rule keeps working through the gateway once its runtime is updated;
    a runtime that predates this change loses MCP until it updates. Release
    notes must say so. A first search of the runtime and `agentruntime` code
    found no self-update, so the working assumption is that an old runtime is
    updated by running a new install command. Confirm before this is locked;
    if true, the old direct path needs a dated grace period, not a hard cut.
  - Limit that stays: a public MCP server with no login cannot be protected by
    Tunnex, because the agent host can reach it over its own internet. The
    profile page says so instead of implying a policy applies.
- Locked: **the OAuth token stays off the agent host.** The lease goes to the
  gateway for the single forwarded call. The agent host never holds a token it
  could replay against the server.
- Locked: **what tools do is recorded.**
  - Audit log: denials (with the reason), step-up requested, approved, denied,
    expired, and each step-up call that ran.
  - Agent Activity, with retention: every allowed call (tool, server, time,
    result status, argument hash). Not the audit log, because volume is
    unbounded.
- Locked: **approvals show what is being approved.** The request stores and
  shows the arguments (capped at 4 KiB, removed with the request). A deny
  action is added. A repeat of the same pending call returns the existing
  request instead of adding a row.
- Locked: **a tool is pinned by its whole definition.** The hash covers name,
  description and input schema. A change to any of them moves the tool to
  "changed, review" and denies it until an administrator accepts the new
  definition. Existing rules pin the definition seen at the first inventory
  after upgrade.
- Locked: **`tools/list` returns only callable tools**, and an allowed tool's
  arguments are checked against its observed schema (types, required,
  undeclared arguments) even when no extra constraint is set.
- Locked: an unreachable upstream fails within five seconds with
  "MCP upstream is unavailable".
- Deferred to AI-UX-1: the approvals inbox with countdown, the per-agent reach
  list, group-level tool policy.

## Founder decisions (2026-11-27)

1. The direct path is closed automatically, with a dated grace period for
   runtimes that predate this change if they cannot update themselves.
2. Allowed calls go to agent Activity with retention, not the audit log.
3. Approvers see the call arguments.

## Amendments after the implementation plan (2026-11-27)

Code reading for the plan changed how four decisions are built. The intent of
each locked decision is unchanged.

- The compiled policy is allow-only today. Closing the direct path needs a new
  deny list in the policy artifact, rendered before the mesh accepts and before
  the compiled allows, and that raises the artifact version to 16. A gateway
  that predates it would refuse the artifact and deny everything, so a deny is
  emitted for a device only when its gateway reports the MCP capability.
- The runtime cannot update itself (the unit runs with a read-only system and
  no update code exists). Organizations that already have MCP assignments get
  a 30-day grace date; new ones are closed from the start. During grace a
  runtime that has not been reinstalled keeps the old path. After grace, a
  gateway that still lacks the capability gets no MCP at all (no upstream, no
  token lease) rather than a deny it cannot read; the agent MCP tab says to
  upgrade the gateway.
- An MCP endpoint given as a hostname can only be closed for addresses the
  gateway already resolves for an FQDN resource of the same name. The profile
  page says so and suggests an IP address or a dedicated FQDN resource. Full
  closure for hostnames is a follow-up.
- Discovery moves to the gateway. The allow-list is no longer built from a
  tool list the agent host reports, and the agent needs no route to the
  server. The control plane computes definition hashes itself.
- Limits in this version: the MCP server must be reachable from the agent's
  own gateway; the gateway listener needs the kernel WireGuard backend; an
  open connection is cut when its deny arrives.

## As built: runtime update

Found in the live walk: the notice told an administrator to reinstall the
agent before the grace date, but the install command refuses a host that
already runs the runtime. The only way through was to remove the agent and
enrol it again as a new device, which loses its group membership, rules and
MCP policy.

- Locked: **an enrolled agent's runtime is updated in place.** The agent
  page, Runtime tab, has "Update runtime". It shows a command to run on the
  agent's host. The agent keeps its identity, access and MCP settings.
  - Rejected: let the install command replace an existing installation. It
    redeems a token and writes a new credential and key, so the host would
    come back as a different device.
  - Rejected: self-update from the runtime. The unit runs with a read-only
    system; that stays.
- The update command takes no install token and does not call the control
  plane. It downloads the signed release descriptor and the separately signed
  verifier, verifies them with the deployment's pinned public key carried in
  the command, and checks the runtime binary and the unit against the signed
  digests. This is the same shell the install command runs
  (`runtimeHostChecks`, `runtimeReleaseVars`, `runtimeVerifierVars`,
  `runtimeVerifiedDownload` in `apps/web/src/lib/agentview.ts`), not a copy.
- It replaces only `/usr/local/bin/tunnex-agent-runtime` and the unit file,
  each by a rename in its own directory, then reloads systemd and restarts the
  service. It does not read or write the runtime credential, the WireGuard
  configuration or interface, or the runtime state.
- It refuses, changing nothing, when the host has no complete installation
  (runtime, unit and credential), when any verification or download fails, or
  when the host is unsupported. If the service does not start, or is not
  running three seconds after the restart, the previous runtime and unit are
  put back and the service is restarted. Every failure ends with one line
  saying what was or was not changed.
- No version ordering. The signed descriptor carries a version string and a
  source commit, not a sequence, so the command installs the verified release
  the control plane serves, including the same one again.
- The install command still refuses an enrolled host, before it asks for the
  token. A complete installation is told to use "Update runtime". A leftover
  file or interface from an earlier installation is named and must be removed
  first, because the update command would refuse it too.
- `GET /api/v1/organizations/{orgId}/agents/runtime-release` returns the same
  `AgentBootstrapRelease` as the bootstrap-token response, on the same
  `agent:enroll` permission, without issuing a token. It answers 503
  `bootstrap_unavailable` when no signed release is configured. "Update
  runtime" is shown for an active agent to a member who holds that permission.
- The notices now read "Update this agent's runtime before <date> to keep MCP
  working" and link to the Runtime tab.
- Open: the control plane does not know which runtime release a host runs
  beyond the reported client version, so the page does not say whether an
  update is needed. The MCP notice is the only prompt.
- Substitute: proven by the executed-shell tests with a faked host
  (`apps/web/test/agentbootstrap-host.test.ts`). The real proof, an update on
  an enrolled systemd host with a signed release, is due at the next walk on
  the GCP test machines.

## Validation

- Tests first: gateway listener (identity from tunnel evidence only, forged
  identity headers ignored), decision endpoint (allow, each denial reason,
  rate limit across two gateways, step-up bind and single use, deny action,
  duplicate pending request), compiler (deny emitted for assigned endpoints,
  users unaffected), definition hash (description change denies), list
  filtering, schema check, audit and activity rows.
- `make generate-check` (contract changes), changed Go packages in both
  editions, web unit suite, typecheck, build, gofmt.
- Real walk on the GCP test machines, repeating the seven cases above. The
  direct call that ran `run_sql` must fail, and the approved refund must appear
  in the audit log.

## End-to-end walk (two GCP machines, signed test release)

Control plane, gateway, AI engine and a Postgres-backed test MCP server on one
machine; a managed agent on another. Builds `3ab909eb` and `2a9cf331`.

- Old runtime against the new control plane: MCP kept working on the old path
  and the organization showed a grace date 30 days out.
- New runtime: a direct call from the agent host to the MCP server failed (the
  gateway dropped it ahead of the allow rule that still existed); the same
  tools worked through the loopback address. Forged identity headers sent to
  the gateway listener were ignored.
- Policy: tools not allowed were denied; an allowed tool refused a wrong type
  and an undeclared argument with no extra constraint set; `tools/list`
  returned only the callable tools; the rate limit held.
- Approvals: the request showed the arguments; a repeat of the same call
  returned the same request; approval ran exactly that call once; deny worked
  and a second deny answered 409.
- Records: audit rows for requested, approved, consumed, denied, expired and
  each denied call with its reason; activity rows for every call.
- Definition change: a rewritten description blocked the tool at once, the
  policy showed it as changed, and accepting the new version restored it with
  audit rows for both.
- Runtime update: the install command on an enrolled host refused. The new
  "Update runtime" command, taken from the console, replaced the runtime with
  no token, left the credential and tunnel untouched, and MCP worked through
  the gateway afterwards. Running it twice was harmless.
- AI Gateway transport: with "Inside the VPN" off the relay route answered
  `403 ai_vpn_http_disabled`; with it on the same request passed the transport
  check and reached policy.
- Revoke: within about five seconds MCP stopped, the tunnel was cut and the
  runtime service stopped itself.
- Test suites on Linux: gateway suite passed; API suite passed in both
  editions (87 packages each). Two packages need more than ten minutes on a
  4-vCPU machine and were run with a longer limit there.
- Not walked: a full MCP OAuth sign-in (needs an OAuth MCP server; covered by
  `mcpoauth` tests), hostname endpoints, an MCP server behind a second gateway.
