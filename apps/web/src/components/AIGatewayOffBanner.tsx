import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { api } from "../lib/api";
import { aiGatewayOffCopy, aiGatewayStatus, type AIGatewayOffReason, type AIGatewayStatus } from "../lib/aiGatewayPrerequisite";
import { AITransportSettings } from "./AITransportSettings";
import { Button, Modal } from "./ui";
import "./ai-gateway-off-banner.css";

type Settings = components["schemas"]["AIGatewaySettings"];
const settingsPath = "/api/v1/organizations/{orgId}/ai-gateway" as const;
const statusPath = "/api/v1/organizations/{orgId}/ai-gateway/status" as const;
const offReasons: readonly string[] = ["not_enabled", "transport_required", "no_provider", "engine_not_installed"];

export type AIGatewayState = {
  /** The saved settings, once read. Null while loading, after a failed read, or for a role that may not read them. */
  settings: Settings | null;
  loading: boolean;
  failed: boolean;
  status: AIGatewayStatus | null;
  /** True only when the gateway is known not to be usable. Unknown is not off. */
  off: boolean;
  reload: () => void;
  /** A page that was refused for a reason it can name supplies it when the settings themselves could not be read. */
  assume: (reason: AIGatewayOffReason | null) => void;
};

/** Reads why the gateway is not usable. Every AI Gateway page shows the same banner from this. */
export function useAIGatewayStatus(orgId: string): AIGatewayState {
  const [read, setRead] = useState<{ orgId: string; settings: Settings | null; failed: boolean; reason: AIGatewayOffReason | null } | null>(null);
  const [assumed, setAssumed] = useState<{ orgId: string; reason: AIGatewayOffReason } | null>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let live = true;
    void (async () => {
      let settings: Settings | null = null;
      try {
        const result = await api.GET(settingsPath, { params: { path: { orgId } } });
        const data = result?.data;
        if (data && typeof data.enabled === "boolean" && typeof data.available === "boolean") settings = data;
      } catch { /* an unreadable setting is unknown, never "off" */ }
      // A member may not read the settings. The status they may read says only whether the gateway works
      // and the one reason, which is all the banner needs to tell them whom to ask.
      let reason: AIGatewayOffReason | null = null;
      if (!settings) {
        try {
          const result = await api.GET(statusPath, { params: { path: { orgId } } });
          const data = result?.data;
          if (data && data.on === false && typeof data.reason === "string" && offReasons.includes(data.reason)) reason = data.reason;
        } catch { /* still unknown */ }
      }
      if (live) setRead({ orgId, settings, failed: !settings, reason });
    })();
    return () => { live = false; };
  }, [orgId, attempt]);
  const current = read?.orgId === orgId ? read : null;
  const settings = current?.settings ?? null;
  const fallback = (assumed?.orgId === orgId ? assumed.reason : null) ?? current?.reason ?? null;
  const status: AIGatewayStatus | null = settings ? aiGatewayStatus(settings) : fallback ? { on: false, reason: fallback } : null;
  const reload = useCallback(() => setAttempt(value => value + 1), []);
  const assume = useCallback((reason: AIGatewayOffReason | null) => setAssumed(reason ? { orgId, reason } : null), [orgId]);
  return { settings, loading: !current, failed: !!current?.failed, status, off: !!status && !status.on && !!status.reason, reload, assume };
}

const inApp = (href: string | null | undefined) => typeof href === "string" && /^\/[^/\\]/.test(href) ? href : null;

type BannerProps = {
  orgId: string; gateway: AIGatewayState;
  /** The reader may change this organization's AI Gateway. */
  canManage: boolean;
  /** The reader administers the server, so may choose the transport. */
  serverAdmin: boolean;
  /** Called after a fix was applied here, so the page can load again. */
  onChanged?: () => void;
  /** Opens the credential form in place, on a page that has one. */
  onAddProvider?: () => void;
};

/** One banner for every AI Gateway page: what is missing, and the control that fixes it or who can. */
export function AIGatewayOffBanner({ orgId, gateway, canManage, serverAdmin, onChanged, onAddProvider }: BannerProps) {
  const [busy, setBusy] = useState(false), [error, setError] = useState(""), [transportOpen, setTransportOpen] = useState(false);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const reason = gateway.off ? gateway.status?.reason ?? null : null;
  useEffect(() => setError(""), [reason, orgId]);
  if (!reason) return null;
  const copy = aiGatewayOffCopy(reason, { canManage, serverAdmin });
  const changed = () => { gateway.reload(); onChanged?.(); };
  async function turnOn() {
    if (busy) return;
    setBusy(true); setError("");
    try {
      const result = await api.PUT(settingsPath, { params: { path: { orgId } }, body: { enabled: true } });
      if (!alive.current) return;
      if (result?.error || !result?.data) {
        const message = (result?.error as { error?: { message?: string } } | undefined)?.error?.message;
        setError(message ? `AI Gateway could not be turned on: ${message}` : "AI Gateway could not be turned on. Try again.");
      }
      changed();
    } catch {
      if (alive.current) { setError("Could not reach the server, so AI Gateway may not be on yet. Try again."); gateway.reload(); }
    } finally { if (alive.current) setBusy(false); }
  }
  const credentialsHref = inApp(gateway.status?.fix?.href) ?? "/ai-gateway/credentials";
  const control = reason === "not_enabled" && canManage ? <Button disabled={busy} onClick={() => void turnOn()}>{busy ? "Turning on…" : "Turn on AI Gateway"}</Button>
    : reason === "transport_required" && serverAdmin ? <Button onClick={() => setTransportOpen(true)}>Choose transport</Button>
    : reason === "no_provider" && canManage ? onAddProvider ? <Button onClick={onAddProvider}>Add a provider credential</Button> : <Link className="ai-gateway-off-link" to={credentialsHref}>Add a provider credential</Link>
    : null;
  return <section className="ai-gateway-off-banner" role="status" aria-label="AI Gateway is not ready">
    <div className="ai-gateway-off-copy"><h3>{copy.title}</h3><p>{copy.body}</p>{error && <p role="alert" className="ai-gateway-off-error">{error}</p>}</div>
    {control && <div className="ai-gateway-off-actions">{control}</div>}
    {transportOpen && <Modal title="Choose how AI Gateway is reached" placement="right" size="enrollment" showClose onDismiss={() => { setTransportOpen(false); changed(); }} actions={<Button onClick={() => { setTransportOpen(false); changed(); }}>Done</Button>}>
      <AITransportSettings canEdit />
    </Modal>}
  </section>;
}
