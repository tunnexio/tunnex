# F01–F04 manual UI checklist

Use this checklist on the released **AI agents** page. For every row, mark exactly one:

- `[x] OK` — observed result matches Expected.
- `[x] NOT OK` — result differs; add the visible error or screenshot name in Notes.
- `[x] BLOCKED` — prerequisite is unavailable; state which prerequisite.
- `[x] N/A` — only when the step does not apply to this test organization.

Do not paste passwords, bootstrap tokens, private keys, runtime credentials, copied commands, or raw license text into this file.

## Run information

| Field | Value |
|---|---|
| Tester |  |
| Date/time |  |
| URL | `http://127.0.0.1:18086/agents` |
| Branch/build | `ai-agent-platform-foundation` /  |
| Test organization |  |
| Owner/admin account |  |
| Plain-member account |  |
| Disposable agent prefix | `manual-f0104-` |

## Preconditions

| ID | Check | Expected | Result | Notes |
|---|---|---|---|---|
| PRE-01 | Log in as an owner/admin and open **AI agents**. | Page loads without an API/reachability error. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| PRE-02 | Check the **Connects through gateway** list. | At least one gateway shows both its name and a reachable endpoint. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| PRE-03 | Confirm the organization has Scale/Enterprise access. | Agent page, quota card, and runtime controls are available to the authorized owner/admin. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| PRE-04 | Prepare a separate browser profile for a plain member. | Owner/admin and member sessions can be tested without sharing cookies. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |

## F01 — Agent identity and lifecycle

| ID | Action | Expected | Result | Notes |
|---|---|---|---|---|
| F01-01 | As owner/admin, expand an existing agent by clicking its name. | **Agent metadata** opens with Environment, Runtime, Labels, and lifecycle action. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F01-02 | Set Environment to `manual-test`, Runtime to `linux`, and Labels to `{"purpose":"manual-ui"}`. Click **Save metadata**. | Save succeeds without an error. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F01-03 | Collapse/reopen the agent, then refresh the browser. | The three metadata values persist after refetch. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F01-04 | Enter invalid Labels such as `not-json`, then try to save. | UI shows the JSON-object validation error and does not replace the saved labels. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F01-05 | Click **Suspend agent**, then confirm suspension. | Confirmation appears; after success the lifecycle action changes to **Resume agent**. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F01-06 | Refresh the page and expand the same agent. | Suspended state persists and **Resume agent** is still shown. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F01-07 | Click **Resume agent**, confirm, refresh, and expand again. | Active state persists and the action returns to **Suspend agent**. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F01-08 | Log in as the plain member and open **AI agents**. | **Authorised by**, Remove, metadata editor, lifecycle controls, quota card, and runtime synchronization control are absent—not merely disabled. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F01-09 | As the plain member, switch to another organization while the agent page is loading. | No agent, gateway, profile, owner, or runtime fact from the previous organization remains visible. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |

## F02 — Multiple agents and organization quota

| ID | Action | Expected | Result | Notes |
|---|---|---|---|---|
| F02-01 | As owner/admin, locate **Managed-agent quota**. | Card explains that pending, active, and suspended count; revoked/deleted do not. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F02-02 | Enter `-1` or `1.5`, then click **Save quota**. | UI refuses it with the non-negative whole-number message. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F02-03 | Enter `2` and click **Save quota**. | UI shows **Quota saved from server response.** | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F02-04 | Refresh the page. | Maximum identities remains `2`. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F02-05 | Enrol and connect two disposable agents through the same gateway. | Both agents appear as distinct rows with distinct addresses; neither replaces the other. | ☐ OK ☐ NOT OK ☐ BLOCKED | Requires two Linux agent hosts/processes. |
| F02-06 | Attempt to connect a third disposable agent while quota is `2`. | Third enrollment is refused; the two existing agents remain unchanged. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F02-07 | Revoke/remove one disposable agent, then connect a replacement. | Replacement succeeds; the unaffected existing agent remains present. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F02-08 | Clear **Maximum identities** and save. Refresh the page. | Blank value persists and represents Unlimited. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F02-09 | Log in as the plain member. | Managed-agent quota card is absent from the DOM. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |

## F03 — Managed enrollment and bootstrap

| ID | Action | Expected | Result | Notes |
|---|---|---|---|---|
| F03-01 | As owner/admin, enter a unique Agent name and select a gateway. | Gateway option shows both gateway name and endpoint; **Enrol agent** becomes enabled. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F03-02 | Click **Enrol agent**. | A one-time **Connect your agent** modal appears with **Copy command** and download action. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F03-03 | Visually inspect the command without recording it. | It contains pinned release metadata/verification steps; it does not contain a generated private key. | ☐ OK ☐ NOT OK ☐ BLOCKED | Never paste the command into Notes. |
| F03-04 | Dismiss the modal and refresh the page. | The one-time command is not shown again from page history. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F03-05 | Issue a fresh command and run it once on a disposable supported Linux host. | Signed artifacts verify, bootstrap succeeds, and the new agent appears in the table. | ☐ OK ☐ NOT OK ☐ BLOCKED | Requires Linux/systemd host. |
| F03-06 | Run the same already-used command again. | Replay is refused; no second agent or replacement credential is created. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F03-07 | Click **Remove** for the disposable agent. | Confirmation says it will revoke first, then remove the roster row. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F03-08 | Click **Revoke and remove**, then refresh. | Agent row is gone and its old runtime/bootstrap credential no longer reconnects. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F03-09 | Log in as the plain member. | Enrollment controls and one-time command are unavailable according to permissions; no token/command appears in the DOM. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |

## F04 — Runtime configuration synchronization

| ID | Action | Expected | Result | Notes |
|---|---|---|---|---|
| F04-01 | As owner/admin, locate **Runtime synchronization**. | Card says the feature is off by default and shows Enable or Disable according to server state. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F04-02 | Toggle runtime synchronization, refresh, then toggle it back to the intended test state. | Server-confirmed state persists after each refresh. | ☐ OK ☐ NOT OK ☐ BLOCKED | Leave enabled for remaining F04 steps. |
| F04-03 | Expand a connected managed agent. | Runtime panel shows Desired revision, Applied revision, Last attempted revision, Connectivity, Last seen, and Runtime status. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F04-04 | Wait for a healthy report, then refresh. | Desired and Applied revisions match; Connectivity is `connected`; Runtime status is `current`; Last seen is populated. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F04-05 | Stop the disposable agent runtime process, wait through the configured stale window, then refresh. | UI does not fabricate healthy data; it reports stale/disconnected/unknown according to the server payload. | ☐ OK ☐ NOT OK ☐ BLOCKED | Requires control of the disposable Linux host. |
| F04-06 | Restart the runtime process and refresh after it reports. | Connectivity returns to `connected`, Runtime status to `current`, and Applied revision does not move backwards. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F04-07 | Suspend the agent and confirm. | Runtime stops receiving configuration; after refresh the agent remains suspended and no false connected/current claim is shown. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F04-08 | Resume/rebootstrap the disposable agent as required by the UI flow. | Runtime reconnects, applies the current revision, and the runtime panel returns to connected/current. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| F04-09 | Log in as the plain member. | Runtime synchronization card and protected runtime/profile facts are absent from the DOM. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |

## Cleanup

| ID | Action | Expected | Result | Notes |
|---|---|---|---|---|
| CLEAN-01 | Remove every `manual-f0104-*` disposable agent. | Each is revoked before its row disappears. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| CLEAN-02 | Restore quota and runtime synchronization to their original values. | Refresh shows the original organization settings. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |
| CLEAN-03 | Delete local command/config/credential scratch from disposable agent hosts. | No bootstrap token, private key, runtime credential, or copied command remains. | ☐ OK ☐ NOT OK ☐ BLOCKED |  |

## Result summary

| Story | Result | Failed or blocked step IDs | Notes |
|---|---|---|---|
| F01 | ☐ PASS ☐ FAIL ☐ BLOCKED |  |  |
| F02 | ☐ PASS ☐ FAIL ☐ BLOCKED |  |  |
| F03 | ☐ PASS ☐ FAIL ☐ BLOCKED |  |  |
| F04 | ☐ PASS ☐ FAIL ☐ BLOCKED |  |  |

## Scope boundary

This checklist validates the released UI, its real API mutations, persistence after refresh, permission-gated DOM absence, and operator-visible runtime state. It does **not** replace code review, migration rollback, generated-code drift checks, concurrent database tests, signed-artifact verification logs, systemd hardening inspection, or exact-head CI. Those remain separate engineering gates.
