import { useEffect, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api, loadOne } from "../lib/api";
import { Button, ErrorText, Field, Input, Modal } from "./ui";

type Connection = components["schemas"]["IPsecConnection"];
export function canRotateIPsecKeys(connection: Connection): boolean {
  return connection.desired_intent === "disabled" && !connection.finalized_at &&
    (connection.cleanup_state === "not_required" || connection.cleanup_state === "retained_guard") &&
    Number.isSafeInteger(connection.desired_revision) && connection.desired_revision > 0 && connection.desired_revision < Number.MAX_SAFE_INTEGER;
}

/** Parent session remounts on every user/org/authority change. No secret persistence. */
export function IPsecRotateKeys({ orgId, connection, onClose, onSaved }: {
  orgId: string; connection: Connection; onClose: () => void; onSaved: () => void;
}) {
  const alive = useRef(true);
  const submitting = useRef(false);
  const [tunnels, setTunnels] = useState<{ id: string; slot: number }[]>([]);
  const [keys, setKeys] = useState(["", ""]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [uncertain, setUncertain] = useState(false);
  useEffect(() => {
    alive.current = true;
    void Promise.all([
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}", { params: { path: { orgId, connectionId: connection.id } } })),
      loadOne(() => api.GET("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}/status", { params: { path: { orgId, connectionId: connection.id } } })),
    ]).then(([current, status]) => {
      if (!alive.current) return;
      if (!current.ok || !canRotateIPsecKeys(current.data) || current.data.id !== connection.id || current.data.desired_revision !== connection.desired_revision) {
        setError("Connection changed. Close and refresh before replacing keys."); return;
      }
      if (!status.ok || !Array.isArray(status.data.tunnels) || status.data.tunnels.length !== 2 || status.data.tunnels[0].slot !== 1 || status.data.tunnels[1].slot !== 2 || !status.data.tunnels[0].id || !status.data.tunnels[1].id || status.data.tunnels[0].id === status.data.tunnels[1].id) {
        setError("Could not load tunnel identities. Close and try again."); return;
      }
      setTunnels(status.data.tunnels.map(t => ({ id: t.id, slot: t.slot })));
    });
    return () => { alive.current = false; };
  }, [orgId, connection.id, connection.desired_revision]);
  function close() { setKeys(["", ""]); onClose(); }
  async function save() {
    if (submitting.current || uncertain || tunnels.length !== 2 || !keys.some(Boolean) || !canRotateIPsecKeys(connection)) return;
    submitting.current = true; setBusy(true); setError("");
    const body = { expected_desired_revision: connection.desired_revision, tunnels: tunnels.flatMap((t, i) => keys[i] ? [{ tunnel_id: t.id, psk: keys[i] }] : []) };
    setKeys(["", ""]);
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}/rotate-psks", { params: { path: { orgId, connectionId: connection.id } }, body });
      if (!alive.current) return;
      if (result.error || !result.data || result.data.id !== connection.id || result.data.desired_intent !== "disabled" || result.data.desired_revision !== connection.desired_revision + 1) {
        setUncertain(true); setError("Could not confirm the key change. Close and refresh before trying again."); return;
      }
      onSaved();
    } catch {
      if (alive.current) { setUncertain(true); setError("Could not confirm the key change. Close and refresh before trying again."); }
    } finally { submitting.current = false; if (alive.current) setBusy(false); }
  }
  return <Modal title="Rotate tunnel keys" onDismiss={close} actions={<><Button variant="ghost" onClick={close}>Close</Button><Button disabled={busy || uncertain || tunnels.length !== 2 || !keys.some(Boolean)} onClick={() => void save()}>Save new keys</Button></>}>
    <p className="font-medium text-ink-heading">{connection.name}</p>
    <p className="mt-2 text-sm text-ink-secondary">Connection stays disabled. Update the matching keys on your remote VPN before enabling.</p>
    <div className="mt-4 space-y-4">{tunnels.map((t, i) => <Field key={t.id} label={`Tunnel ${t.slot} new PSK`}><Input type="password" autoComplete="new-password" spellCheck={false} value={keys[i]} disabled={busy || uncertain} onChange={event => setKeys(old => old.map((v, index) => index === i ? event.target.value : v))} /></Field>)}</div>
    {tunnels.length === 2 && <p className="mt-2 text-xs text-ink-secondary">Leave a field blank to keep that tunnel’s key.</p>}
    {!tunnels.length && !error && <p role="status" className="mt-3 text-sm text-ink-secondary">Checking connection…</p>}
    <ErrorText>{error}</ErrorText>
  </Modal>;
}
