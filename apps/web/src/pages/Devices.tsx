import { useEffect, useState, type FormEvent } from "react";
import { useOrg } from "../lib/useOrg";
import { QRCodeSVG } from "qrcode.react";
import { PRODUCT_NAME } from "../brand";
import {
  api,
  apiErrorMessage,
  type Device,
  type Node,
  type Org,
} from "../lib/api";
import { relativeAge } from "../lib/format";
import {
  defaultDeviceNode,
  requiresGatewayChoice,
  selectableNodes,
} from "../lib/nodepick";
import {
  Badge,
  Button,
  DataTable,
  ErrorText,
  Field,
  Input,
  Modal,
  PageHeader,
  StatusDot,
} from "../components/ui";
import { OneTimeSecretModal } from "../components/OneTimeSecret";
import {
  addressLabel,
  applyDeviceFilter,
  deviceFilterCounts,
  deviceProtocol,
  postureBadge,
  postureFailureSummary,
  posturePlatformSupported,
  type DeviceFilter,
} from "../lib/postureview";
import {
  exportCeremony,
  shouldRenderQR,
  type ExportKind,
} from "../lib/deviceexport";

// lastSeen renders honest recency ("last seen 42s ago"), never a faked live claim
// — WireGuard only knows the last handshake time (online is derived from it). The
// recency math is shared with the dashboard via relativeAge.
export function lastSeen(at?: string, hasWgKey = true): string {
  if (!at) {
    // WF-OVPN-walk-1: an OpenVPN device is NOT a WireGuard peer (WF-OVPN-10) — it carries no WG
    // public key and so has no handshake-telemetry analog; its last_handshake_at is ALWAYS null.
    // Rendering "never connected" for a device that may hold a live OVPN session is a dead-while-green
    // health-surface lie (the green-while-dead law, inverted). Render honest-unknown instead — absence
    // of a signal is NOT a negative claim (the desync_unknown honest-state law). Real OVPN last-seen
    // (a status/management telemetry channel) is a deferred story, not a second liveness plane built here.
    return hasWgKey ? "never connected" : "liveness not reported";
  }
  return `last seen ${relativeAge(at)}`;
}

export function deviceModeLabel(fullTunnel?: boolean): string {
  return fullTunnel ? "Full tunnel" : "Split tunnel";
}

export default function Devices() {
  // ⛔ THE ORG COMES FROM THE SEAM (S12.5) — the page no longer picks index zero out of a list it
  // fetched itself, which is what made a second organization unreachable.
  const { org: currentOrg, loading: orgLoading, failed: orgFailed } = useOrg();
  const [org, setOrg] = useState<Org | null>(null);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  // OWNER sub-line. A SECOND-CLASS read: `Device` serves `user_id` and no email, so the roster supplies the
  // label. An empty map means the sub-line is simply absent — never an id, never "unknown owner".
  const [ownerEmail, setOwnerEmail] = useState<Map<string, string>>(new Map());
  // ⛔ CLIENT-SIDE FILTER over rows ALREADY LOADED — no new request, no server round-trip, and the counts come
  // from the SAME array the table renders so the chip and the table can never disagree.
  const [filter, setFilter] = useState<DeviceFilter>("all");
  const counts = deviceFilterCounts(devices);
  const shown = applyDeviceFilter(devices, filter);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [fullTunnel, setFullTunnel] = useState(false);
  // ⛔ S14.21b: the operator's gateway choice. Empty means "not chosen yet", which is DIFFERENT from
  // "no gateway available" — the form renders those two as different sentences.
  const [nodeId, setNodeId] = useState<string>("");
  // The one-time export secret (a WireGuard .conf or an OpenVPN .ovpn) + which kind it is (so the
  // ceremony renders a QR for WG only). Cleared on dismiss — never re-fetched (D2).
  const [secret, setSecret] = useState<string | null>(null);
  const [secretKind, setSecretKind] = useState<ExportKind>("wireguard");
  // WF-OVPN-5: an exported profile for a device that enrolled PENDING (enterprise device approval) is a
  // working-LOOKING file that cannot connect until an admin approves — the reassuring-success trap. Surface
  // it at issuance (the export response already carries the device status).
  const [pendingExport, setPendingExport] = useState(false);
  // The device transport the user is creating. OpenVPN is offered ONLY when the org has opted in
  // (D-S9.5-OPTIN(a): absent, not disabled — no dead affordance).
  const [kind, setKind] = useState<ExportKind>("wireguard");
  const [busy, setBusy] = useState(false);
  const [creating, setCreating] = useState(false);
  // ⛔ THE DIALOG'S OWN ERROR. A create failure was written to the PAGE-level error, which renders behind
  // the modal — the operator sees a dialog that did nothing, with the explanation on the obscured page. A
  // message about a dialog belongs in the dialog.
  const [createError, setCreateError] = useState<string | null>(null);
  const ovpnEnabled = org?.ovpn_enabled === true;

  async function loadDevices(orgId: string) {
    const { data, error } = await api.GET(
      "/api/v1/organizations/{orgId}/devices",
      { params: { path: { orgId } } },
    );
    if (error) {
      setError(apiErrorMessage(error, "Could not load devices."));
      return;
    }
    setDevices(data ?? []);
    // Fired after the devices land, awaited separately: a failed roster read degrades the OWNER sub-line and
    // nothing else. The device list is this screen's subject; the owner's email is a courtesy.
    const m = await api.GET("/api/v1/organizations/{orgId}/members", {
      params: { path: { orgId } },
    });
    if (!m.error && m.data)
      setOwnerEmail(
        new Map(
          (m.data as Array<{ user_id: string; email?: string }>)
            .filter((x) => x.email)
            .map((x) => [x.user_id, x.email as string]),
        ),
      );
  }

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        // ⭐ THE ORG-LIST FETCH IS GONE FROM THIS PAGE (S12.5). It existed only to be indexed at zero.
        // OrgProvider reads the list once for the whole shell; a page that re-fetched it would not merely
        // waste a request, it would pick an org the switcher has no way to change.
        const orgErr = null;
        if (cancelled) return;
        if (orgErr) {
          setError(
            apiErrorMessage(orgErr, "Could not load your organizations."),
          );
          return;
        }
        // ⛔ LOADING IS NOT ABSENCE (S12.5). The provider resolves the org list asynchronously, so this
        // effect runs once with currentOrg === null before the answer exists. Treating that as "you have no
        // organization" renders a confident, false statement — and because the second pass only sets the
        // data, the stale error stayed on screen BESIDE the correct org name.
        //
        // ⚠ THREE STATES, NOT TWO: still loading (say nothing), the read failed (say THAT), genuinely no
        // membership (say that). Collapsing the first into the third is how a slow network becomes an
        // accusation that the user does not belong here.
        if (orgLoading) return;
        const first = currentOrg;
        if (!first) {
          setError(
            orgFailed
              ? "Could not load your organizations."
              : "You are not a member of any organization yet.",
          );
          return;
        }
        setOrg(first);
        const { data: ns, error: nodeErr } = await api.GET(
          "/api/v1/organizations/{orgId}/nodes",
          {
            params: { path: { orgId: first.id } },
          },
        );
        if (cancelled) return;
        if (nodeErr) {
          setError(apiErrorMessage(nodeErr, "Could not load gateway nodes."));
          return;
        }
        setNodes(ns ?? []);
        if (!cancelled) await loadDevices(first.id);
      } catch {
        if (!cancelled) setError("Could not reach the API.");
      }
    })();
    return () => {
      cancelled = true;
    };
    // ⛔ currentOrg IS A DEPENDENCY, AND ITS ABSENCE WAS A REAL BUG THE TESTS CAUGHT (S12.5).
    //
    // The provider resolves the org list ASYNCHRONOUSLY, so on this effect's first run `currentOrg` is still
    // null. With `[]` deps the effect never ran again: the page rendered "You are not a member of any
    // organization yet" — a confident, wrong statement — and stayed there forever, for every user.
    //
    // ⚠ THE SAME DEPENDENCY ALSO MAKES THE SWITCHER WORK. One line, two properties: without it the page
    // either never loads at all, or loads once and then lies about which tenant it is showing.
  }, [currentOrg]);

  async function create(e: FormEvent) {
    e.preventDefault();
    // ⛔ S13.1 — RE-APPLIED ACROSS THE EPIC 14 REWRITE. The target gateway is chosen by ONE rule
    // (lib/nodepick), which excludes REVOKED gateways. This was `nodes[0]`, indexing a list that
    // includes revoked rows ordered by created_at — so on any deployment whose oldest gateway had
    // been revoked, every new device was homed on a dead one and handed a one-time config that
    // could never connect. Refusing beats falling back: a one-time secret cannot be re-issued.
    //
    // ⚠ THE REWRITE ADDED A THIRD CALL SITE. The fix was written against two; `main` now has three,
    // and a conflict resolution that took either side wholesale would have dropped it silently.
    // ⛔ S14.21b: the CHOSEN gateway wins; the default applies only when there is exactly one.
    // `defaultDeviceNode` returns null when several are eligible — it will not pick for the operator,
    // because nothing in the payload lets it pick correctly (see lib/nodepick).
    const chosen = selectableNodes(nodes).find((n) => n.id === nodeId);
    const target = chosen ?? defaultDeviceNode(nodes);
    if (!org || !target) return;
    setBusy(true);
    setCreateError(null);
    setSecret(null);
    if (kind === "openvpn") {
      // OpenVPN export: mint an OVPN device + its one-time .ovpn (opt-in gated server-side).
      const { data, error } = await api.POST(
        "/api/v1/organizations/{orgId}/ovpn-profiles",
        {
          params: { path: { orgId: org.id } },
          body: { name, node_id: target.id, full_tunnel: fullTunnel },
        },
      );
      setBusy(false);
      if (error || !data) {
        setCreateError(
          apiErrorMessage(error, "Could not create the OpenVPN profile."),
        );
        return;
      }
      setName("");
      setSecretKind("openvpn");
      setPendingExport(data.device?.status === "pending"); // WF-OVPN-5: warn if it won't connect until approved
      setSecret(data.profile); // shown once — the client key is never re-served
      await loadDevices(org.id);
      return;
    }
    // WireGuard export: a web download/QR is a STATIC export (its client can't poll routed ranges),
    // so provisioning="static" bakes the approved ranges + DNS (Part-2) and records the snapshot.
    const { data, error } = await api.POST(
      "/api/v1/organizations/{orgId}/devices",
      {
        params: { path: { orgId: org.id } },
        body: {
          name,
          node_id: target.id,
          full_tunnel: fullTunnel,
          provisioning: "static",
        },
      },
    );
    setBusy(false);
    if (error || !data) {
      setCreateError(apiErrorMessage(error, "Could not create the device."));
      return;
    }
    setCreating(false);
    setName("");
    setSecretKind("wireguard");
    setSecret(data.config ?? null); // shown once — the private key is never re-served
    await loadDevices(org.id);
  }

  async function revoke(id: string) {
    if (!org) return;
    setError(null);
    const { error } = await api.POST(
      "/api/v1/organizations/{orgId}/devices/{deviceId}/revoke",
      {
        params: { path: { orgId: org.id, deviceId: id } },
      },
    );
    if (error) {
      setError(apiErrorMessage(error, "Could not revoke the device."));
      return;
    }
  }

  /**
   * ⛔ APPROVE / REJECT WERE UNREACHABLE FROM THE SCREEN THAT SHOWS PENDING DEVICES.
   *
   * This page lists a device with a `pending` badge and its Actions cell rendered `null` — Revoke was offered
   * for `active` only. The endpoints existed and their sole call site was the Device-approval card on Access
   * Policies, so an operator looking at the pending device had to already know it was governed from another
   * screen entirely.
   *
   * > **A STATE A SURFACE DISPLAYS AND CANNOT ACT ON IS A DEAD END** — and `pending` is the one state on this
   * > roster that exists precisely because someone must decide about it.
   */
  async function decide(id: string, action: "approve" | "reject") {
    if (!org) return;
    setError(null);
    const { error } = await api.POST(
      action === "approve"
        ? "/api/v1/organizations/{orgId}/devices/{deviceId}/approve"
        : "/api/v1/organizations/{orgId}/devices/{deviceId}/reject",
      { params: { path: { orgId: org.id, deviceId: id } } },
    );
    if (error) {
      setError(apiErrorMessage(error, `Could not ${action} the device.`));
      return;
    }
  }

  /**
   * ⛔ REMOVE IS NOT REVOKE, AND THE ORDER MATTERS. Revoke kills the credential; remove takes the dead row
   * off the roster. The server refuses to remove anything that is not already revoked, because removing a
   * LIVE device would leave a working credential with no surface to revoke it from.
   *
   * ⚠ AND IT IS A SOFT DELETE SERVER-SIDE — the revocation record and the OpenVPN CRL entry survive. A hard
   * delete would cascade into `ovpn_client_certs` and drop the serial out of the CRL, un-revoking the
   * credential on the wire.
   */
  async function remove(id: string) {
    if (!org) return;
    setError(null);
    const { error } = await api.DELETE(
      "/api/v1/organizations/{orgId}/devices/{deviceId}",
      { params: { path: { orgId: org.id, deviceId: id } } },
    );
    if (error) {
      setError(apiErrorMessage(error, "Could not remove the device."));
      return;
    }
  }

  /**
   * ⛔ ONE REFETCH AFTER THE BATCH, NOT ONE PER ROW — this is the "I have to reload the page" defect.
   *
   * Each mutation used to refetch on its own, so a bulk action on N rows fired N identical GETs
   * CONCURRENTLY. They resolve in arbitrary order and the LAST to land wins — which may be a snapshot taken
   * before the later mutations committed. The list then shows a state that was briefly true and is not any
   * more, and the only way out is a manual reload.
   *
   * > **N CONCURRENT READS OF A CHANGING RESOURCE DO NOT CONVERGE ON THE NEWEST ONE.** They converge on
   * > whichever the network happened to deliver last.
   *
   * ⚠ THE SELECTION IS DELIBERATELY *NOT* CLEARED. It self-corrects: once the rows are approved, `Approve`
   * reports "only a device awaiting approval can be approved" and disables itself. Force-clearing would mean
   * remounting the table, which would also discard the operator's filter, sort and page — throwing away
   * three things to fix one that was not broken.
   */
  async function runBatch(fn: () => Promise<unknown>) {
    await fn();
    if (org) await loadDevices(org.id);
  }

  function download() {
    if (!secret) return;
    // The private key is served exactly once, so this download must not fail:
    // the anchor is attached to the DOM (Firefox ignores clicks on detached
    // anchors) and the object URL is revoked on the next tick (not synchronously,
    // which can abort the save before the browser reads the Blob).
    const url = URL.createObjectURL(new Blob([secret], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `${PRODUCT_NAME}.${exportCeremony(secretKind).ext}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
      <div style={{ display: "flex", alignItems: "flex-end", gap: "14px" }}>
        <div style={{ flex: 1 }}>
          <PageHeader title="Devices" subtitle={org ? org.name : "…"} />
        </div>
        {/* ⛔ THE CREATE FORM MOVES INTO A MODAL, matching Add rule. Inline, it was a permanently-open
            four-control card sitting between the page title and the roster — the roster is what this screen
            is FOR, and it began below a form most visits do not use. A trigger costs one click on the rare
            visit and gives the list the top of the page on every other one. */}
        <Button
          onClick={() => {
            setCreateError(null);
            setCreating(true);
          }}
        >
          Add device
        </Button>
      </div>

      <ErrorText>{error}</ErrorText>

      {creating && (
        <Modal
          title="Add device"
          size="wide"
          onDismiss={() => setCreating(false)}
          actions={
            <>
              <Button variant="ghost" onClick={() => setCreating(false)}>
                Cancel
              </Button>
              {/* ⚠ THE SUBMIT LIVES IN THE MODAL'S ACTION ROW, so the form is driven by `form=` rather than
                  by a nested button — the disabled rules and the busy/OpenVPN labels are unchanged. */}
              {/* ⚠ THE DISABLED CONDITION IS THE FORM'S OWN, CARRIED VERBATIM. My first version added
                  `!name.trim()` — a rule this form never had. Moving a control is not licence to change what
                  it permits, and an invented guard is indistinguishable from a real one once it ships. */}
              <Button
                type="submit"
                form="add-device-form"
                disabled={
                  busy ||
                  selectableNodes(nodes).length === 0 ||
                  // Several eligible and none chosen: the button must not act on a guess.
                  (requiresGatewayChoice(nodes) && nodeId === "")
                }
              >
                {busy
                  ? "Creating…"
                  : kind === "openvpn"
                    ? "Export OpenVPN profile"
                    : "Create device"}
              </Button>
            </>
          }
        >
          <form id="add-device-form" onSubmit={create}>
            <div className="flex flex-wrap items-end gap-3">
              <div className="min-w-[12rem] flex-1">
                <Field label="New device name">
                  <Input
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    required
                    placeholder="my-laptop"
                  />
                </Field>
              </div>
              {/* The transport selector is present ONLY when the org has opted into OpenVPN
                (D-S9.5-OPTIN(a): absent, not a disabled affordance). Otherwise WireGuard is implicit. */}
              {ovpnEnabled && (
                <Field label="Type">
                  <select
                    value={kind}
                    onChange={(e) => setKind(e.target.value as ExportKind)}
                    className="rounded-md border border-white/10 bg-ink-950 px-2 py-1.5 text-sm text-slate-200"
                  >
                    <option value="wireguard">WireGuard</option>
                    <option value="openvpn">OpenVPN</option>
                  </select>
                </Field>
              )}
              {/* WF-OVPN-3: full tunnel is a per-device choice for BOTH transports. For WireGuard it shapes
                the exported config's AllowedIPs; for OpenVPN the server pushes redirect-gateway per client.
                Either way the gateway must be able to source-NAT egress (gateway_no_egress refuses otherwise). */}
              <label className="flex items-center gap-2 text-sm text-slate-300">
                <input
                  type="checkbox"
                  checked={fullTunnel}
                  onChange={(e) => setFullTunnel(e.target.checked)}
                />
                Full tunnel
              </label>
            </div>
            {/* ⛔ S14.21b: ASK, DO NOT GUESS. The old rule was "the first active gateway in created_at
              order", which on a real fleet homed a laptop onto an in-cluster Kubernetes gateway
              because it happened to be enrolled first. Nothing in the payload distinguishes a gateway
              that can serve a laptop from one that cannot — so the product stops pretending it can. */}
            {requiresGatewayChoice(nodes) && (
              <Field label="Gateway">
                <select
                  id="device-gateway"
                  value={nodeId}
                  onChange={(e) => setNodeId(e.target.value)}
                  className="w-full rounded-md border border-line bg-surface-inset px-3 py-2 text-sm text-ink-body"
                >
                  <option value="">Choose a gateway…</option>
                  {selectableNodes(nodes).map((n) => (
                    <option key={n.id} value={n.id}>
                      {n.name}
                    </option>
                  ))}
                </select>
                <p className="mt-1 text-xs text-ink-secondary">
                  This device connects through the gateway you pick. There is no
                  safe default when several are enrolled — the config is issued
                  once and cannot be re-issued.
                </p>
              </Field>
            )}

            {/* Counts SELECTABLE gateways, not all rows: a fleet whose only gateway is revoked showed no
              warning at all and offered an enabled button. */}
            {selectableNodes(nodes).length === 0 && (
              <p className="mt-3 text-xs text-amber-400">
                No gateway node is enrolled yet - enroll one to create devices.
              </p>
            )}
          </form>
          {/* ⛔ IN THE DIALOG, WHERE THE ACTION WAS TAKEN. This is the exact message the founder saw
              rendered on the page BEHIND the modal — "this gateway can't route full-tunnel internet traffic
              yet; use split tunnel" — a refusal the operator could not read without dismissing the thing
              that caused it. */}
          <ErrorText>{createError}</ErrorText>
        </Modal>
      )}

      {/* The one-time config CEREMONY: the most security-sensitive moment in the
          app. The shared OneTimeSecretModal shows it exactly once (amber, blocks
          the page); the config lives only in page state, is never re-fetched, and
          must be acknowledged to dismiss. Navigating away also discards it. */}
      {secret && (
        <OneTimeSecretModal
          title={exportCeremony(secretKind).title}
          caption={
            <>
              This file contains your device&rsquo;s{" "}
              <span className="text-warn">private key</span>. It is shown{" "}
              <span className="font-semibold">exactly once</span> and cannot be
              retrieved again - save it now.{" "}
              {/* The honesty line (Part-2): a static profile bakes the CURRENT site routes; a subnet
                  added later won&rsquo;t appear until the profile is re-exported. Stated at issuance. */}
              <span className="text-slate-300">
                {exportCeremony(secretKind).honesty}
              </span>
            </>
          }
          secret={secret}
          leadingActions={
            <Button onClick={download}>
              Download {PRODUCT_NAME}.{exportCeremony(secretKind).ext}
            </Button>
          }
          onDismiss={() => {
            setSecret(null);
            setPendingExport(false);
          }}
        >
          {/* WF-OVPN-5: reassuring-success guard — a pending device's profile is real but won't connect
              until an admin approves it. Said at issuance so the operator isn't left debugging an
              "authentication failed" later. */}
          {pendingExport && (
            <div className="mt-3 rounded-md border border-warn/40 bg-warn/10 p-3 text-sm text-warn">
              This device is{" "}
              <span className="font-semibold">pending approval</span> - the
              profile is valid but won&rsquo;t connect until an admin approves
              the device.
            </div>
          )}
          {/* WireGuard only: a QR the official WG apps import natively. It lives inside the modal, so
              dismissing clears the secret and the QR is never re-rendered (D2 — no re-view). OpenVPN
              Connect has no native QR import, so no QR for .ovpn (Part-4 caveat). */}
          {shouldRenderQR(secretKind, secret) && (
            <div className="mt-3 flex flex-col items-center gap-1 rounded-md bg-white p-3">
              <QRCodeSVG value={secret} size={168} />
            </div>
          )}
        </OneTimeSecretModal>
      )}

      {/* S14.3 slice A: a real <table>. Devices are the most tabular surface in the product — name, address,
          state, posture are the same four facts per row — and rendering them as <li> blocks meant the tier
          could only find a device by matching its name as free text. Now: getByRole("row") / ("cell").
          Every badge keeps its TEXT: the status was never carried by colour alone and must not start now. */}
      {/* The chips. Counts derive from the SAME function the table filters with, so the two cannot disagree. */}
      <div className="mt-6 flex flex-wrap items-center gap-2">
        {(
          [
            ["all", "All", counts.all],
            ["attention", "Needs attention", counts.attention],
            ["revoked", "Revoked", counts.revoked],
          ] as Array<[DeviceFilter, string, number]>
        ).map(([key, label, n]) => (
          <button
            key={key}
            type="button"
            aria-pressed={filter === key}
            onClick={() => setFilter(key)}
            className={`rounded-full border px-3 py-1 text-xs ${
              filter === key
                ? "border-white/40 bg-white/[.16] text-white"
                : "border-white/10 text-slate-400 hover:text-slate-200"
            }`}
          >
            {label} ({n})
          </button>
        ))}
        {counts.revoked > 0 && filter === "all" && (
          // Stated rather than left to arithmetic: `All` includes revoked and the other two do not, so
          // attention + revoked < all, which reads as a bug unless the screen says why.
          <span className="text-[11px] text-slate-500">
            {counts.revoked} revoked, shown under All
          </span>
        )}
      </div>

      <div className="mt-3">
        <DataTable
          caption="Devices"
          rows={shown}
          rowKey={(d) => d.id}
          // ⛔ THE VERBS LEAVE THE ROWS — and APPROVE / REJECT ARRIVE, which this screen never had.
          // `unavailable` states each rule rather than encoding it in a button that simply does not render:
          // a pending device's Actions cell used to be blank, which says nothing about why.
          rowActions={[
            {
              key: "approve",
              label: "Approve",
              unavailable: (d) =>
                d.status === "pending"
                  ? null
                  : "Only a device awaiting approval can be approved.",
              run: (ds) => {
                void runBatch(() =>
                  Promise.all(ds.map((d) => decide(d.id, "approve"))),
                );
              },
            },
            {
              key: "reject",
              label: "Reject",
              danger: true,
              unavailable: (d) =>
                d.status === "pending"
                  ? null
                  : "Only a device awaiting approval can be rejected.",
              run: (ds) => {
                void runBatch(() =>
                  Promise.all(ds.map((d) => decide(d.id, "reject"))),
                );
              },
            },
            {
              key: "revoke",
              label: "Revoke",
              danger: true,
              // ⚠ Revoking a REVOKED device is a no-op the server would report as success — worse than
              // absent. Pending is rejected, not revoked; the two words are different decisions.
              unavailable: (d) =>
                d.status === "active"
                  ? null
                  : `A ${d.status} device cannot be revoked.`,
              run: (ds) => {
                void runBatch(() => Promise.all(ds.map((d) => revoke(d.id))));
              },
            },
            {
              key: "remove",
              label: "Remove",
              danger: true,
              // ⚠ REVOKED ONLY, mirroring the server's own refusal. The reason is stated rather than the
              // control silently missing: "why can I not remove this" is exactly the question a blank
              // disabled button leaves an operator holding.
              unavailable: (d) =>
                d.status === "revoked"
                  ? null
                  : "Only a revoked device can be removed. Revoke it first.",
              run: (ds) => {
                void runBatch(() => Promise.all(ds.map((d) => remove(d.id))));
              },
            },
          ]}
          empty="No devices yet."
          failed={error != null}
          columns={[
            {
              key: "name",
              header: "Device",
              // ⚠ THE OWNER'S EMAIL IS SEARCHABLE EVEN WHEN THE SUB-LINE IS ABSENT. The cell hides it when
              // the members read failed; the search key does not, so "find every device of this person"
              // keeps working on a page that could not render the label.
              sortValue: (d) => `${d.name} ${ownerEmail.get(d.user_id) ?? ""}`,
              cell: (d) => (
                <span className="flex flex-col gap-0.5">
                  <span className="text-sm text-white">{d.name}</span>
                  {/* ⛔ OWNER. `Device` serves `user_id`, never an email, so this is a client-side join over the
                      members roster. NON-FATAL: a failed members read leaves the sub-line ABSENT rather than
                      rendering an id — an opaque uuid is worse than no line, and worse still is "unknown owner",
                      which would claim the device is unowned. */}
                  {ownerEmail.get(d.user_id) !== undefined && (
                    <span className="text-[11px] text-slate-500">
                      {ownerEmail.get(d.user_id)}
                    </span>
                  )}
                </span>
              ),
            },
            {
              key: "protocol",
              header: "Protocol",
              sortValue: (d) => deviceProtocol(d.public_key),
              cell: (d) => (
                // ⛔ DERIVED FROM `public_key`, because there is NO `protocol` FIELD ON Device — measured. An
                // OpenVPN device is minted with "no WireGuard key", so an empty key IS the discriminator, and
                // `public_key` is REQUIRED so it cannot go absent without a schema change.
                <span className="font-mono text-xs text-slate-500">
                  {deviceProtocol(d.public_key)}
                </span>
              ),
            },
            {
              key: "mode",
              header: "Mode",
              sortValue: (d) => (d.full_tunnel ? "full tunnel" : "split tunnel"),
              cell: (d) => (
                <span className="text-xs text-slate-500">{deviceModeLabel(d.full_tunnel)}</span>
              ),
            },
            {
              key: "address",
              header: "Address",
              sortValue: (d) => addressLabel(d.assigned_ip),
              cell: (d) => (
                <span
                  className={`font-mono text-xs ${
                    d.assigned_ip ? "text-slate-500" : "text-slate-600 italic"
                  }`}
                >
                  {addressLabel(d.assigned_ip)}
                </span>
              ),
            },
            {
              key: "state",
              header: "State",
              // ⛔ THE SEARCH KEY CARRIES THE STATE AS TEXT, because the cell renders it as a Badge and a
              // coloured dot. Without this a search for "revoked" would miss every revoked device — the row
              // would be invisible to a search for the very state its badge is announcing.
              sortValue: (d) =>
                d.status === "revoked"
                  ? "revoked"
                  : d.status === "pending"
                    ? "pending"
                    : lastSeen(d.last_handshake_at, !!d.public_key),
              cell: (d) =>
                d.status === "revoked" ? (
                  <Badge tone="danger">revoked</Badge>
                ) : d.status === "pending" ? (
                  <Badge tone="warn">pending</Badge>
                ) : (
                  <span className="inline-flex items-center gap-1 text-xs text-slate-400">
                    <StatusDot tone={d.online ? "on" : "off"} />
                    {lastSeen(d.last_handshake_at, !!d.public_key)}
                  </span>
                ),
            },
            {
              key: "posture",
              header: "Posture",
              cell: (d) => {
                if (d.status === "revoked") return null;
                // S7.5.3: present only when the org has posture checks configured. "not reported"/"stale"
                // render distinctly from ok — an admin must never read unknown as a pass, because absence is
                // not compliance.
                // ⛔ N/A IS NOT "NOT REPORTED", AND THE DIFFERENCE IS ACTIONABLE. "not reported" is a device
                // that COULD report and has not — an admin should chase it. N/A is a platform with no reporting
                // client at all, so there is nothing to chase. Rendering an iPad as "not reported" invites a
                // hunt for a report that will never exist.
                if (!posturePlatformSupported(d.platform))
                  return (
                    <span className="text-xs text-slate-600 italic">
                      n/a on this platform
                    </span>
                  );
                const pb = postureBadge(d);
                const failure = postureFailureSummary(d.health_failed_checks);
                return (
                  <>
                    {pb && <Badge tone={pb.tone}>{pb.label}</Badge>}
                    {failure && (
                      <div className="mt-1 text-xs text-ink-secondary" data-posture-failure={d.id}>
                        {failure}
                      </div>
                    )}
                    {/* S9.1 Part-2: a static profile whose baked site routes no longer match the org's current
                        ranges — the never-silently-broken law, made visible. */}
                    {d.needs_reexport && (
                      <span
                        className="ml-2 text-xs text-amber-400"
                        title="This device's exported profile predates a site-range change - re-export and re-import it."
                      >
                        re-export needed
                      </span>
                    )}
                  </>
                );
              },
            },
          ]}
        />
      </div>
    </div>
  );
}
