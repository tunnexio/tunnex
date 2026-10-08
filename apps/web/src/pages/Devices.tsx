import "../network-workspaces.css";
import "../devices-workspace.css";
import "../device-detail-workspace.css";
import "../app-access-workspace.css";
import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { QRCodeSVG } from "qrcode.react";
import { PRODUCT_NAME } from "../brand";
import { api, apiErrorMessage, loadOne, type Device, type Node } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";
import { relativeAge } from "../lib/format";
import { formatBytes } from "../lib/hubsetview";
import { defaultDeviceNode, requiresGatewayChoice, selectableNodes } from "../lib/nodepick";
import { Button, ErrorText, Field, Input, Loading, Modal, Select } from "../components/ui";
import { LoadRetry } from "../components/LoadRetry";
import { OneTimeSecretModal } from "../components/OneTimeSecret";
import { DevicesTabRail } from "../components/DevicesTabRail";
import DevicesInventory from "../components/DevicesInventory";
import { ResourceSummary } from "../components/ResourceSummary";
import AppAccessRowMenu from "../components/AppAccessRowMenu";
import { addressLabel, deviceProtocol, diskFactLabel, postureBadge, postureFailureSummary, posturePlatformSupported } from "../lib/postureview";
import { exportCeremony, shouldRenderQR, type ExportKind } from "../lib/deviceexport";

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
  const { org } = useOrg();
  const { state } = useAuth();
  const actor = state.status === "authed" ? state.user.id + ":" + state.user.email_verified : state.status;
  return <DevicesWorkspace key={(org?.id ?? "no-organization") + ":" + actor} />;
}

type DeviceAction = "revoke" | "remove";
type DeviceStage = "overview" | "connection" | "posture";

function DevicesWorkspace() {
  const { state } = useAuth();
  const emailVerified = state.status === "authed" && state.user.email_verified;
  const { org, loading: orgLoading, failed: orgFailed } = useOrg();
  const [nodes, setNodes] = useState<Node[]>([]);
  const [nodesLoading, setNodesLoading] = useState(true);
  const [nodesError, setNodesError] = useState<string | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [devicesLoading, setDevicesLoading] = useState(true);
  const [devicesLoaded, setDevicesLoaded] = useState(false);
  const [devicesLoadError, setDevicesLoadError] = useState<string | null>(null);
  const [ownerEmail, setOwnerEmail] = useState<Map<string, string>>(new Map());
  const [inspectedId, setInspectedId] = useState<string | null>(null);
  const [stage, setStage] = useState<DeviceStage>("overview");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [confirmation, setConfirmation] = useState<{ action: DeviceAction; devices: Device[] } | null>(null);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [nodeId, setNodeId] = useState("");
  const [fullTunnel, setFullTunnel] = useState(false);
  const [kind, setKind] = useState<ExportKind>("wireguard");
  const [createError, setCreateError] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [secretKind, setSecretKind] = useState<ExportKind>("wireguard");
  const [pendingExport, setPendingExport] = useState(false);
  const [busy, setBusy] = useState(false);
  const alive = useRef(true);
  const readEpoch = useRef(0);
  const nodeEpoch = useRef(0);
  const mutation = useRef(false);
  const ready = useRef(false);
  const gatewayReady = useRef(false);
  const detailHeading = useRef<HTMLHeadingElement>(null);
  const stageHeading = useRef<HTMLHeadingElement>(null);
  const snapshot = useRef(devices);
  snapshot.current = devices;
  const inspected = devices.find(device => device.id === inspectedId);
  const ovpnEnabled = org?.ovpn_enabled === true;
  const orgId = org?.id ?? "";

  useEffect(() => {
    alive.current = true;
    return () => { alive.current = false; readEpoch.current++; nodeEpoch.current++; ready.current = false; gatewayReady.current = false; };
  }, []);

  const loadDevices = useCallback(async () => {
    if (!orgId) return;
    const attempt = ++readEpoch.current;
    ready.current = false;
    setDevicesLoading(true);
    setDevicesLoadError(null);
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/devices", { params: { path: { orgId } } }));
    if (!alive.current || attempt !== readEpoch.current) return;
    if (!result.ok || !Array.isArray(result.data)) {
      setDevicesLoadError(result.ok ? "The server did not return a device inventory." : result.error);
      setDevicesLoading(false);
      return;
    }
    const current = result.data as Device[];
    snapshot.current = current;
    setDevices(current);
    ready.current = true;
    setDevicesLoaded(true);
    setDevicesLoading(false);
    setOwnerEmail(new Map());
    // Owner labels are optional; a failed roster does not turn a loaded fleet into an error.
    const members = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId } } }));
    if (!alive.current || attempt !== readEpoch.current) return;
    if (members.ok && Array.isArray(members.data)) {
      setOwnerEmail(new Map(members.data.filter(member => member.email).map(member => [member.user_id, member.email])));
    }
  }, [orgId]);

  const loadNodes = useCallback(async () => {
    if (!orgId) return;
    const attempt = ++nodeEpoch.current;
    gatewayReady.current = false;
    setNodesLoading(true);
    setNodesError(null);
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/nodes", { params: { path: { orgId } } }));
    if (!alive.current || attempt !== nodeEpoch.current) return;
    if (!result.ok || !Array.isArray(result.data)) {
      setNodes([]);
      setNodesError(result.ok ? "The server did not return the gateway list." : result.error);
      setNodesLoading(false);
      return;
    }
    setNodes(result.data as Node[]);
    gatewayReady.current = true;
    setNodesLoading(false);
  }, [orgId]);

  useEffect(() => { void loadDevices(); void loadNodes(); }, [loadDevices, loadNodes]);
  useEffect(() => { if (!ovpnEnabled) setKind("wireguard"); }, [ovpnEnabled]);
  useEffect(() => { if (inspectedId) detailHeading.current?.focus(); }, [inspectedId]);
  useEffect(() => { if (inspectedId) stageHeading.current?.focus(); }, [stage]);

  function requestAction(action: DeviceAction, targets: Device[]) {
    if (!emailVerified || !alive.current || mutation.current || !ready.current || !targets.length) return;
    const current = targets.map(target => snapshot.current.find(device => device.id === target.id));
    if (current.some(device => !device || (action === "revoke" ? device.status !== "active" : device.status !== "revoked"))) {
      setError("The selected device state changed. Refresh the list before trying again.");
      return;
    }
    setError(null);
    setNotice(null);
    setConfirmation({ action, devices: current as Device[] });
  }

  async function decide() {
    if (!emailVerified || !alive.current || mutation.current || !ready.current || !confirmation || !orgId) return;
    const { action, devices: targets } = confirmation;
    if (targets.some(target => !snapshot.current.some(device => device.id === target.id && device.status === target.status && (action === "revoke" ? device.status === "active" : device.status === "revoked")))) {
      setConfirmation(null);
      setError("The selected device state changed. Review the current list before trying again.");
      return;
    }
    mutation.current = true;
    setBusy(true);
    setError(null);
    setNotice(null);
    const results = await Promise.all(targets.map(async device => {
      try {
        const result = action === "revoke"
          ? await api.POST("/api/v1/organizations/{orgId}/devices/{deviceId}/revoke", { params: { path: { orgId, deviceId: device.id } } })
          : await api.DELETE("/api/v1/organizations/{orgId}/devices/{deviceId}", { params: { path: { orgId, deviceId: device.id } } });
        return { device, error: result.error ? apiErrorMessage(result.error, "Could not " + action + " the device.") : null };
      } catch {
        return { device, error: "Could not confirm " + (action === "revoke" ? "revocation" : "removal") + ". Refresh its state before trying again." };
      }
    }));
    if (!alive.current) return;
    const failed = results.filter(result => result.error);
    const succeeded = results.length - failed.length;
    const verb = action === "revoke" ? "revoked" : "removed";
    setConfirmation(null);
    if (failed.length) setError(succeeded + " of " + results.length + " devices " + verb + ". " + failed.map(result => result.device.name + ": " + result.error).join(" "));
    else setNotice(succeeded + " device" + (succeeded === 1 ? "" : "s") + " " + verb + ".");
    if (action === "remove" && results.some(result => !result.error && result.device.id === inspectedId)) setInspectedId(null);
    await loadDevices();
    mutation.current = false;
    if (alive.current) setBusy(false);
  }

  async function create(event: FormEvent) {
    event.preventDefault();
    const target = selectableNodes(nodes).find(node => node.id === nodeId) ?? defaultDeviceNode(nodes);
    if (!emailVerified || !alive.current || mutation.current || !gatewayReady.current || !orgId || !target || (kind === "openvpn" && !ovpnEnabled)) return;
    mutation.current = true;
    setBusy(true);
    setCreateError(null);
    setSecret(null);
    try {
      const result = kind === "openvpn"
        ? await api.POST("/api/v1/organizations/{orgId}/ovpn-profiles", { params: { path: { orgId } }, body: { name, node_id: target.id, full_tunnel: fullTunnel } })
        : await api.POST("/api/v1/organizations/{orgId}/devices", { params: { path: { orgId } }, body: { name, node_id: target.id, full_tunnel: fullTunnel, provisioning: "static" } });
      if (!alive.current) return;
      if (result.error) {
        setCreateError(apiErrorMessage(result.error, kind === "openvpn" ? "Could not create the OpenVPN profile." : "Could not create the device."));
        return;
      }
      if (!result.data) {
        setCreateError("Could not confirm device creation. Its one-time configuration was not returned. Refresh the device list before trying again.");
        await loadDevices();
        return;
      }
      const data = result.data;
      const exported = "profile" in data ? data.profile : data.config;
      if (typeof exported !== "string" || !exported) {
        setCreateError(data.device?.id ? "The device was created, but its one-time configuration was not returned. Refresh the device list before trying again." : "Could not confirm device creation or retrieve its one-time configuration. Refresh the device list before trying again.");
        await loadDevices();
        return;
      }
      setCreating(false);
      setName("");
      setSecretKind(kind);
      setPendingExport(data.device?.status === "pending");
      setSecret(exported);
      await loadDevices();
    } catch {
      if (alive.current) setCreateError("Could not confirm device creation. Refresh the device list before trying again.");
    } finally {
      mutation.current = false;
      if (alive.current) setBusy(false);
    }
  }

  function download() {
    if (!secret) return;
    const url = URL.createObjectURL(new Blob([secret], { type: "text/plain" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = PRODUCT_NAME + "." + exportCeremony(secretKind).ext;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  function inspect(id: string) { if (ready.current && !mutation.current) { setInspectedId(id); setStage("overview"); } }
  const deviceActions = inspected && emailVerified ? [
    { key: "revoke", label: "Revoke", danger: true, disabledReason: busy || devicesLoading ? "Wait for the current request." : inspected.status === "active" ? null : "A " + inspected.status + " device cannot be revoked.", onSelect: () => requestAction("revoke", [inspected]) },
    { key: "remove", label: "Remove", danger: true, disabledReason: busy || devicesLoading ? "Wait for the current request." : inspected.status === "revoked" ? null : "Only a revoked device can be removed. Revoke it first.", onSelect: () => requestAction("remove", [inspected]) },
  ] : [];

  if (orgLoading) return <div className="devices-workspace"><Loading label="Loading your organization…" /></div>;
  if (!org) return <div className="devices-workspace"><ErrorText>{orgFailed ? "Could not load your organizations." : "You are not a member of any organization yet."}</ErrorText></div>;

  return <div className="network-management devices-workspace devices-management">
    <h1 className="sr-only">Devices</h1>
    <DevicesTabRail actions={emailVerified ? <Button disabled={nodesLoading || Boolean(nodesError) || busy} onClick={() => { setCreateError(null); setCreating(true); }}>Add device</Button> : undefined} />
    <ErrorText>{error}</ErrorText>
    {notice && <p role="status" className="device-action-notice">{notice}</p>}
    {devicesLoading && <Loading label="Loading devices…" />}
    {devicesLoadError && <LoadRetry error={devicesLoadError} onRetry={loadDevices} />}
    {nodesError && <LoadRetry error={nodesError} onRetry={loadNodes} />}
    {devicesLoaded && <div hidden={devicesLoading || Boolean(devicesLoadError) || inspectedId !== null}>
      <DevicesInventory canMutate={emailVerified} devices={devices} nodes={nodes} ownerEmail={ownerEmail} busy={busy || devicesLoading} lastSeenLabel={device => lastSeen(device.last_handshake_at, !!device.public_key)} onInspect={inspect} onRequestAction={requestAction} onRefresh={() => { void loadDevices(); void loadNodes(); }} />
    </div>}
    {inspectedId && !devicesLoading && !devicesLoadError && (inspected ? <section className="device-detail" aria-label={inspected.name}>
      <nav aria-label="Breadcrumb" className="device-breadcrumb"><button type="button" onClick={() => setInspectedId(null)}>Devices</button><span aria-hidden="true">/</span><span>{inspected.name}</span></nav>
      <header className="device-detail-header"><div><h2 ref={detailHeading} tabIndex={-1}>{inspected.name}</h2><p>{inspected.platform || "Platform not reported"} · {deviceProtocol(inspected.public_key)} · {inspected.status}</p></div><AppAccessRowMenu label={"Device actions for " + inspected.name} actions={deviceActions} /></header>
      <div className="device-detail-layout">
        <nav aria-label="Device detail sections" className="device-detail-path">{(["overview", "connection", "posture"] as DeviceStage[]).map(value => <button key={value} type="button" aria-current={stage === value ? "step" : undefined} onClick={() => setStage(value)}>{value === "overview" ? "Overview" : value === "connection" ? "Connection" : "Posture"}</button>)}</nav>
        <section className="device-detail-stage" aria-labelledby="device-stage-heading"><h3 className="sr-only" ref={stageHeading} tabIndex={-1} id="device-stage-heading">{stage === "overview" ? "Overview" : stage === "connection" ? "Connection" : "Posture"}</h3>
          {stage === "overview" && <><ResourceSummary title="Device settings"><DeviceFacts summary facts={[
            ["Owner", ownerEmail.get(inspected.user_id) ?? inspected.owner_email ?? "Owner record unavailable"],
            ["Lifecycle", inspected.status],
            ["Platform", inspected.platform || "Not reported"],
            ["Enrolled", displayTime(inspected.created_at)],
            ["Address", addressLabel(inspected.assigned_ip)],
          ]} /><details className="device-detail-disclosure"><summary>Device identity</summary><DeviceFacts summary facts={[["Device ID", inspected.id], ["Gateway ID", inspected.node_id], ["Owner ID", inspected.user_id]]} /></details></ResourceSummary></>}
          {stage === "connection" && <><ResourceSummary title="Connection settings"><DeviceFacts summary facts={[
            ["Gateway", nodes.find(node => node.id === inspected.node_id)?.name || "Gateway record unavailable"],
            ["Address", addressLabel(inspected.assigned_ip)],
            ["Protocol", deviceProtocol(inspected.public_key)],
            ["Routing", deviceModeLabel(inspected.full_tunnel)],
            ["Last activity", inspected.status === "active" ? inspected.public_key ? lastSeen(inspected.last_handshake_at) : "liveness not reported" : "Not evaluated for " + inspected.status + " devices"],
            ["Received", inspected.rx_bytes === undefined ? "Not reported" : formatBytes(inspected.rx_bytes)],
            ["Sent", inspected.tx_bytes === undefined ? "Not reported" : formatBytes(inspected.tx_bytes)],
          ]} /></ResourceSummary>{inspected.status === "pending" && <p className="device-stage-note">Waiting for enrollment approval before connecting. <Link to="/devices/approvals">Review approvals</Link></p>}{inspected.status === "active" && inspected.needs_reexport && <p className="device-stage-warning">Re-export needed. The issued configuration no longer matches current network settings.</p>}{inspected.status === "active" && inspected.health_blocked && <p className="device-stage-warning">Access is blocked by posture checks.</p>}</>}
          {stage === "posture" && <><ResourceSummary title="Posture report"><DeviceFacts summary facts={[
            ["Evaluation", inspected.status !== "active" ? "Not evaluated for " + inspected.status + " devices" : !posturePlatformSupported(inspected.platform) ? "Not supported" : postureBadge(inspected)?.label ?? "No posture evaluation reported"],
            ["Last report", displayTime(inspected.health_reported_at)],
            ["Reported OS", inspected.health_os_version || "Not reported"],
            ["Disk encryption", diskFactLabel(inspected.health_disk_encrypted)],
          ]} /></ResourceSummary>{inspected.status === "active" && postureFailureSummary(inspected.health_failed_checks) && <p className="device-stage-warning">{postureFailureSummary(inspected.health_failed_checks)}</p>}<p className="device-stage-note">These checks use the device’s latest client report.</p></>}
          <footer className="device-detail-footer"><Button variant="ghost" onClick={() => setInspectedId(null)}>Back to devices</Button></footer>
        </section>
      </div>
    </section> : <section className="device-detail-missing"><h2>Device no longer listed</h2><p>This device is absent from the current inventory.</p><Button variant="ghost" onClick={() => setInspectedId(null)}>Back to devices</Button></section>)}

    {confirmation && <Modal placement="right" title={(confirmation.action === "revoke" ? "Revoke" : "Remove") + " device" + (confirmation.devices.length === 1 ? "?" : "s?")} danger onDismiss={() => { if (!busy) setConfirmation(null); }} actions={<><Button variant="ghost" disabled={busy} onClick={() => setConfirmation(null)}>Cancel</Button><Button variant="danger" disabled={busy || !ready.current} onClick={() => void decide()}>{busy ? "Applying…" : confirmation.action === "revoke" ? "Revoke device" : "Remove device"}</Button></>}>
      <div className="device-confirmation"><p>{confirmation.action === "revoke" ? "Disconnect these devices and invalidate their credentials. To connect again, enroll a new device." : "Remove these revoked devices from the inventory. Their credentials remain revoked."}</p><ul>{confirmation.devices.map(device => <li key={device.id}><strong>{device.name}</strong><span>{ownerEmail.get(device.user_id) ?? device.owner_email ?? "Owner record unavailable"} · {addressLabel(device.assigned_ip)}</span></li>)}</ul></div>
    </Modal>}

    {creating && <Modal title="Add device" placement="right" onDismiss={() => { if (!busy) setCreating(false); }} actions={<><Button variant="ghost" disabled={busy} onClick={() => setCreating(false)}>Cancel</Button><Button type="submit" form="add-device-form" disabled={busy || nodesLoading || Boolean(nodesError) || selectableNodes(nodes).length === 0 || (requiresGatewayChoice(nodes) && !nodeId)}>{busy ? "Creating…" : kind === "openvpn" ? "Export OpenVPN profile" : "Create device"}</Button></>}>
      <form id="add-device-form" onSubmit={create} className="device-enrollment">
        <fieldset disabled={busy} className="device-enrollment-fields">
        <p>Export a one-time configuration for this device.</p>
        <Field label="Device name"><Input value={name} onChange={event => setName(event.target.value)} required placeholder="my-laptop" /></Field>
        {ovpnEnabled ? <Field label="Protocol"><Select value={kind} onChange={event => setKind(event.target.value as ExportKind)}><option value="wireguard">WireGuard</option><option value="openvpn">OpenVPN</option></Select></Field> : <DeviceFacts facts={[["Protocol", "WireGuard"]]} />}
        {requiresGatewayChoice(nodes) ? <Field label="Gateway"><Select id="device-gateway" value={nodeId} onChange={event => setNodeId(event.target.value)}><option value="">Choose a gateway…</option>{selectableNodes(nodes).map(node => <option key={node.id} value={node.id}>{node.name}</option>)}</Select></Field> : defaultDeviceNode(nodes) ? <DeviceFacts facts={[["Gateway", defaultDeviceNode(nodes)!.name]]} /> : null}
        <label className="device-routing-choice"><input type="checkbox" checked={fullTunnel} onChange={event => setFullTunnel(event.target.checked)} /><span><strong>Route all traffic through Tunnex</strong><small>Leave off for private-network access only.</small></span></label>
        {selectableNodes(nodes).length === 0 && <p className="device-stage-warning">No active gateway is available. <Link to="/gateways">Manage gateways</Link></p>}
        <p className="device-stage-note">The exported configuration is bound to this gateway and is shown once.</p>
        </fieldset>
        <ErrorText>{createError}</ErrorText>
      </form>
    </Modal>}
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

  </div>;
}

function displayTime(value?: string) {
  if (!value || !Number.isFinite(Date.parse(value))) return "Not reported";
  return new Date(value).toLocaleString();
}

function DeviceFacts({ facts, summary = false }: { facts: Array<[string, string | undefined]>; summary?: boolean }) {
  return <dl className={summary ? "device-saved-facts tnx-resource-facts tnx-resource-facts-three" : "device-saved-facts"}>{facts.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value || "Not reported"}</dd></div>)}</dl>;
}
