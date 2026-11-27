# AI-UX-1: AI agents and MCP, one clear path from "add an agent" to "see what it did"

Status: decisions locked under the founder's instruction of 2026-11-27 to make
the recommended changes for the whole AI agent and MCP flow. Second pull
request (experience); the security work is AI-SEC-1 and AI-SEC-2.

## Problem

Two walks (local stack and two GCP machines) and a full page review followed an
administrator through the daily jobs: add an agent, give it access, connect an
MCP server, approve a risky call, find out what the agent did, take access
away. Security holds after AI-SEC-1 and AI-SEC-2. The path does not:

1. **Features hide behind other features' switches.** "Add agent" stays blocked
   until "Runtime synchronization" is turned on in Settings; MCP needs "Agent
   groups & policy templates". Community shows a switch that answers 503.
2. **Install ends in silence.** After the command is issued the panel offers
   "I've saved it" and nothing says whether the agent arrived. Install fails on
   Ubuntu 24.04 without systemd-resolved (`openresolv` has no candidate). A
   host with no terminal cannot supply the install token.
3. **Access is invisible.** Nothing lists what an agent can reach. After
   AI-SEC-1 an agent that relied on its owner's rules has no access and no
   quick way to get the right rules.
4. **Connecting an MCP server takes four screens and an API-shaped mind.**
   Create a profile, create a group, add the agent, assign the profile, add a
   network rule, wait for discovery, then tick tools one agent at a time.
5. **One MCP server per agent.** A second profile makes the runtime poll fail.
6. **Approvals have no home.** Requests appear only inside one agent's tab,
   nobody is notified, and the agent gets an immediate error and must retry.
7. **Nothing shows what the agent did.**
8. **Small wrong things:** "Back to mcp", "No models available" when the
   gateway is simply off, the redirect that drops the port.

## Decisions

### Turning it on
- Locked: every agent and MCP page turns on what it needs in place, with one
  sentence on what the switch does. Settings → Features keeps the same
  switches; they are no longer the only door.
- Locked: MCP has its own switch and no longer depends on "Agent groups &
  policy templates". Existing organizations that had that switch on get MCP on.
- Locked: on an edition that cannot use a feature the control is disabled and
  says which plan includes it. No switch that fails after the click.

### Adding an agent
- Locked: the install step shows live status: waiting, enrolled, tunnel
  connected, with the time. If nothing arrives in ten minutes it shows the
  three most likely causes and how to check each on the host.
- Locked: the install script works on Ubuntu 24.04 without systemd-resolved
  (it uses the resolver the host has instead of requiring `openresolv`).
- Locked: a host with no terminal can supply the token from a root-only file
  named in the command. The script reads it once and removes it. The token
  still never appears in the command or in shell history.

### Access
- Locked: the agent Access tab lists what the agent can reach now (each rule,
  destination and port) and what it was refused recently.
- Locked: an agent with no rule gets "Create rules from the owner's access": a
  preview of the owner's current destinations as agent rules, each one
  tickable, nothing created until confirmed.

### Connecting an MCP server
- Locked: one guided action, "Connect MCP server", from an agent or an agent
  group: enter the address, the gateway reads the tool list, the administrator
  chooses per tool **Allow**, **Ask first** or **Off**, and saves. It creates
  the profile, group membership and assignment underneath. No network rule is
  needed (AI-SEC-2).
- Locked: tool policy is set on the agent group and applies to every agent in
  it. A per-agent policy, where one exists, keeps overriding, so current
  installations do not change.
- Locked: tools are shown with the words the server gives plus a plain marker
  the administrator sets: reads, changes data, or destructive. New tools start
  as Off. Nothing is inferred from the tool name.
- Locked: an agent can have several MCP servers. Each is reached at
  `http://127.0.0.1:17100/<server name>`; the first one also answers at the
  bare address so existing clients keep working.
- Locked: the MCP tab shows the address with ready-to-paste client snippets.

### Approvals
- Locked: an Approvals inbox for the organization with a count in the sidebar:
  agent, tool, arguments, who is asking, time left, Approve and Deny.
- Locked: a pending request can be delivered through Alert delivery, where the
  organization has it on.
- Locked: the gateway holds an "Ask first" call for up to 45 seconds. Approved
  in time, the call runs and the agent sees a normal result. Otherwise the
  agent gets the existing "requires step-up approval" error with the request
  id, and a retry of the same call after approval runs.

### Seeing what happened
- Locked: the agent Activity tab lists MCP calls (tool, server, result, time,
  approval if any) with filters for denied and approved, and CSV export.

### Small fixes
- Locked: correct labels and empty states listed under Problem 8.

### AI Gateway (added 2026-11-27 on the founder's instruction)
- Locked: when the gateway is off, every AI Gateway page says so in one banner
  with the reason (not enabled, no transport chosen, no provider credential, no
  engine installed) and the control that fixes it, in place. "No models
  available" is shown only when the gateway is on and truly has none.
- Locked: the AI Gateway switch is never silently disabled. If transport must
  be chosen first, the switch opens that choice instead of sitting grey.
- Locked: AI Gateway → Access shows agents and agent groups beside users and
  groups, so model access for an agent is granted where model access is
  granted for everyone else.
- Locked: budgets can be set for a user group, and usage is shown per user and
  per agent (requests, tokens, cost, against the budget).
- Locked: deleting a provider credential that is in use lists what uses it
  (models, policies, agents) with links, instead of a bare refusal.

### Documentation
- Locked: the AI agents, MCP security and AI Gateway pages in `tunnex-web` are
  rewritten to match, as a pull request the founder merges.

## Amendments after the implementation plan (2026-11-27)

- One pull request on `story/ai-ux-1`, stacked on the security branch, built in
  stages: turning on and install; connect flow, group policy and several
  servers; approvals inbox and activity; access; AI Gateway.
- Install on a host without `resolvconf`: the real cause is the DNS line the
  runtime writes into the tunnel configuration. The script no longer fails and
  the runtime leaves that line out. On such a host, private DNS names pushed
  through the tunnel do not resolve; the install output and the Runtime tab
  say so.
- The connect dialog waits for the gateway's next discovery pass (about 35
  seconds) and shows that it is reading the tool list.
- Tool policy precedence is per MCP server: where an agent already has its own
  policy for a server, that policy decides (an empty one still denies all);
  otherwise the group's policy decides.
- A held "Ask first" call works only with a runtime installed after this
  change; an older runtime gets the immediate error as today. Built last.
- Per-agent usage against a budget is in scope. Budgets for user groups and
  usage per user are deferred to their own story: usage is attributed per team
  and per agent today, not per user.
- The "redirect that drops the port" could not be found in code; it is treated
  as a test-stack configuration effect unless the walk shows it again.

## Order of work

1. After AI-SEC-2 lands: MCP switch, in-place enabling, honest licensing,
   install status, install fixes, small fixes.
2. Connect flow, group tool policy, several servers.
3. Approvals inbox and held calls, Activity.
4. Access list and rules from the owner's access.
5. AI Gateway pages.
6. Documentation.

## Validation

- Tests first for each item (web unit tests for every new state; API tests for
  the group policy precedence, several servers, held approval, token file).
- Typecheck, build, web unit suite, changed Go packages, `make generate-check`,
  install-script tests.
- Real walk on the GCP test machines: a new administrator adds an agent,
  connects the test MCP server and approves a refund without leaving the agent
  and MCP pages and without creating a network rule.
