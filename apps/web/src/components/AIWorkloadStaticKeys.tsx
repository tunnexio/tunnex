import { useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage, loadOne } from "../lib/api";
import { Badge, Button, Card, DataTable, Field, Input, Loading, Modal, type BadgeTone } from "./ui";
import { OneTimeSecretModal } from "./OneTimeSecret";
import { AICodeBlock } from "./AICodeBlock";
import { toast } from "./Toasts";
import AppAccessRowMenu from "./AppAccessRowMenu";
import AppAccessEmptyState from "./AppAccessEmptyState";

type S = components["schemas"];
export type StaticKey = S["AIWorkloadStaticKey"];
type Endpoint = S["AIInternalEndpoint"];
type Workload = S["AIWorkload"];
type Scope = S["AIWorkloadStaticKeyScope"];

const keysPath = "/api/v1/organizations/{orgId}/ai-gateway/workloads/{workloadId}/static-keys" as const;
const keyItemPath = "/api/v1/organizations/{orgId}/ai-gateway/workloads/{workloadId}/static-keys/{keyId}" as const;
export const internalEndpointsPath = "/api/v1/organizations/{orgId}/ai-gateway/internal-endpoints" as const;
export const staticKeySettingsPath = "/api/v1/organizations/{orgId}/ai-gateway/static-key-settings" as const;
const caPath = "/api/v1/organizations/{orgId}/ai-gateway/internal-endpoint-ca" as const;
/** The Settings tab section that sets up the internal AI endpoint and the public-key switch. */
export const internalEndpointSettingsLink = "/ai-gateway/settings#internal-ai-endpoint";

const DAY = 86400000;
/** Keys and certificates show "Expires soon" from this many days before expiry. */
export const SOON_DAYS = 14;
const MAX_DAYS = 90;
const date = (value: string) => new Date(value).toLocaleString();
const area = "min-h-20 w-full rounded-md border border-line bg-transparent px-3 py-2 font-mono text-xs text-ink-heading placeholder:text-ink-secondary disabled:opacity-50";

/** Split a list typed one per line, or separated by commas or spaces. */
export function parseList(text: string): string[] {
  return [...new Set(text.split(/[\s,]+/).map((v) => v.trim()).filter(Boolean))];
}
/** An IPv4 range in CIDR form, such as 10.20.0.0/16. The server checks private or public ranges and overlap. */
export function isIPv4CIDR(value: string): boolean {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(value);
  return !!match && match.slice(1, 5).every((n) => Number(n) <= 255) && Number(match[5]) <= 32;
}
export function isIPv4(value: string): boolean {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  return !!match && match.slice(1).every((n) => Number(n) <= 255);
}
export function daysLeft(iso: string, now = Date.now()): number {
  return (new Date(iso).getTime() - now) / DAY;
}
export function expiresSoon(iso: string | null | undefined, now = Date.now()): boolean {
  if (!iso) return false;
  const left = daysLeft(iso, now);
  return left > 0 && left <= SOON_DAYS;
}
function isActive(k: StaticKey) {
  return !k.revoked_at && k.status !== "revoked" && k.status !== "expired" && new Date(k.expires_at).getTime() > Date.now();
}
export function keyState(k: StaticKey): { label: string; tone: BadgeTone } {
  if (k.revoked_at || k.status === "revoked") return { label: "Revoked", tone: "neutral" };
  if (k.status === "expired" || new Date(k.expires_at).getTime() <= Date.now()) return { label: "Expired", tone: "neutral" };
  if (k.status === "error") return { label: "Setup failed", tone: "danger" };
  if (k.status === "pending") return { label: "Setting up", tone: "warn" };
  return { label: "Active", tone: "ok" };
}
const refusals: Record<string, string> = {
  wrong_ingress: "Used on the wrong endpoint",
  source_not_allowed: "Source address not allowed",
  public_keys_disabled: "Public keys are off",
  rate_limited: "Requests-per-minute limit reached",
  threshold_reached: "Daily limit reached",
  expired: "Key expired",
  revoked: "Key revoked",
  workload_disabled: "Workload is disabled",
  model_not_allowed: "Model not allowed for this workload",
  unavailable: "AI Gateway was unavailable",
};
export function refusalLabel(reason: string | null | undefined): string {
  return reason ? refusals[reason] ?? "Refused" : "Refused";
}
function where(ingress: "internal" | "public" | null | undefined, source: string | null | undefined, nodeId: string | null | undefined, endpoints: Endpoint[] | null) {
  const from = source ? ` from ${source}` : "";
  if (ingress === "public") return `public endpoint${from}`;
  if (ingress === "internal") {
    const gateway = nodeId ? endpoints?.find((e) => e.node_id === nodeId)?.node_name : undefined;
    return `internal endpoint${gateway ? ` via ${gateway}` : ""}${from}`;
  }
  return source ? `from ${source}` : "";
}
/** The listener origin, without a trailing /v1, whatever form the server reports. */
export function endpointRoot(url: string): string {
  return url.replace(/\/+$/, "").replace(/\/v1$/, "");
}
/** Gateways that serve, or are set to serve, the internal endpoint. */
export function servingEndpoints(endpoints: Endpoint[] | null | undefined): Endpoint[] {
  return (endpoints ?? []).filter((e) => e.supported && e.endpoint?.enabled);
}
/** Offer the organization's internal AI CA certificate as ca.pem. Returns an error to show, or "". */
export async function downloadInternalCA(orgId: string): Promise<string> {
  const result = await loadOne(() => api.GET(caPath, { params: { path: { orgId } } }));
  if (!result.ok || !result.data.certificate_pem) return "Could not download the CA certificate. Try again.";
  const url = URL.createObjectURL(new Blob([result.data.certificate_pem], { type: "application/x-pem-file" }));
  const link = document.createElement("a");
  link.href = url; link.download = "ca.pem";
  document.body.appendChild(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  return "";
}

type Expiry = { choice: "7" | "30" | "90" | "date"; date: string };
const isoDay = (ms: number) => { const d = new Date(ms); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`; };
/** The chosen expiry as an instant, or null when the date is missing or out of range (1 day to 90 days). */
export function expiryInstant(expiry: Expiry, now = Date.now()): string | null {
  if (expiry.choice !== "date") {
    // A few minutes short of the full period, so a slightly fast clock does not pass the 90-day limit.
    return new Date(now + Number(expiry.choice) * DAY - 10 * 60000).toISOString();
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(expiry.date)) return null;
  const at = new Date(`${expiry.date}T00:00:00`).getTime();
  if (!Number.isFinite(at) || at <= now + 3600000 || at > now + MAX_DAYS * DAY) return null;
  return new Date(at).toISOString();
}
function ExpiryChoice({ value, onChange, disabled, legend }: { value: Expiry; onChange: (v: Expiry) => void; disabled: boolean; legend: string }) {
  const name = useId();
  const now = Date.now();
  return <fieldset className="space-y-2"><legend className="mb-1 text-sm font-semibold">{legend}</legend>
    <div className="flex flex-wrap gap-4 text-sm">{(["7", "30", "90"] as const).map((d) => <label key={d} className="flex items-center gap-2"><input type="radio" name={name} checked={value.choice === d} disabled={disabled} onChange={() => onChange({ ...value, choice: d })} />{d} days</label>)}
      <label className="flex items-center gap-2"><input type="radio" name={name} checked={value.choice === "date"} disabled={disabled} onChange={() => onChange({ ...value, choice: "date" })} />A date</label></div>
    {value.choice === "date" && <Field label="Expiry date"><Input type="date" min={isoDay(now + DAY)} max={isoDay(now + MAX_DAYS * DAY)} value={value.date} disabled={disabled} onChange={(event) => onChange({ ...value, date: event.target.value })} /></Field>}
    <p className="text-xs text-ink-secondary">At most 90 days. You cannot extend a key; rotate it instead.</p>
  </fieldset>;
}

/** Turn an API refusal into one plain sentence. */
function keyError(result: { error?: unknown; response?: Response }, fallback: string): { message: string; conflict?: boolean } {
  const code = apiErrorCode(result.error), status = result.response?.status;
  if (code === "invalid_static_key") return { message: apiErrorMessage(result.error, "Check the key settings and try again.") };
  if (code === "static_key_capacity") return { message: "No room for another key. A workload can have 8 active keys, and the organization has an overall limit. Revoke a key you no longer use, then try again." };
  if (code === "public_static_keys_disabled") return { message: "Public keys are off for this organization. An AI Gateway administrator can turn them on in AI Gateway settings." };
  if (code === "static_key_inactive") return { message: "This key is revoked or expired, so it cannot be changed. The list was refreshed.", conflict: true };
  if (status === 409) return { message: "Someone else changed this key. The list was refreshed; review it and try again.", conflict: true };
  if (status === 403) return { message: "This workload is disabled, or your role cannot manage its keys." };
  return { message: fallback };
}

export function AIWorkloadStaticKeys({ orgId, workload, canManage, startCreate = false, onStartCreateHandled }: {
  orgId: string; workload: Workload; canManage: boolean; startCreate?: boolean; onStartCreateHandled?: () => void;
}) {
  const [keys, setKeys] = useState<StaticKey[] | null>(null), [cursor, setCursor] = useState<string | null>(null);
  const [endpoints, setEndpoints] = useState<Endpoint[] | null>(null);
  const [publicAllowed, setPublicAllowed] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true), [more, setMore] = useState(false), [error, setError] = useState("");
  const [editor, setEditor] = useState<StaticKey | "new" | null>(null);
  const [rotate, setRotate] = useState<StaticKey | null>(null), [revoke, setRevoke] = useState<StaticKey | null>(null);
  const [secret, setSecret] = useState<S["AIWorkloadStaticKeySecret"] | null>(null);
  const alive = useRef(true), generation = useRef(0);
  const path = { orgId, workloadId: workload.id };
  async function reload() {
    const n = ++generation.current; setLoading(true); setMore(false);
    const [k, e, s] = await Promise.all([
      loadOne(() => api.GET(keysPath, { params: { path, query: { limit: 50 } } })),
      loadOne(() => api.GET(internalEndpointsPath, { params: { path: { orgId } } })),
      loadOne(() => api.GET(staticKeySettingsPath, { params: { path: { orgId } } })),
    ]);
    if (!alive.current || n !== generation.current) return;
    setKeys(k.ok && Array.isArray(k.data.items) ? k.data.items : null); setCursor(k.ok ? k.data.next_cursor ?? null : null);
    setEndpoints(e.ok && Array.isArray(e.data.items) ? e.data.items : null);
    setPublicAllowed(s.ok && typeof s.data.public_static_keys_allowed === "boolean" ? s.data.public_static_keys_allowed : null);
    if (!k.ok) setError("Could not load API keys. Refresh to try again.");
    setLoading(false);
  }
  useEffect(() => { alive.current = true; void reload(); return () => { alive.current = false; generation.current++; }; }, [orgId, workload.id, workload.enabled]);
  useEffect(() => {
    if (startCreate && !loading) { if (canManage && workload.enabled) setEditor("new"); onStartCreateHandled?.(); }
  }, [startCreate, loading]);
  async function loadMore() {
    if (!cursor || more || loading) return;
    const after = cursor, n = generation.current; setMore(true);
    const result = await loadOne(() => api.GET(keysPath, { params: { path, query: { after, limit: 50 } } }));
    if (!alive.current || n !== generation.current) return;
    if (!result.ok || result.data.next_cursor === after) setError("Could not load more API keys. Try again.");
    else { setKeys((current) => [...new Map([...(current ?? []), ...result.data.items].map((k) => [k.id, k])).values()]); setCursor(result.data.next_cursor ?? null); }
    setMore(false);
  }
  const busy = loading || !!editor || !!rotate || !!revoke || !!secret;
  const serving = servingEndpoints(endpoints);
  return <Card>
    <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div><h3 className="font-semibold text-ink-heading">API keys</h3><p className="mt-1 text-sm text-ink-secondary">One key you paste into a tool that cannot run the Tunnex CLI. Each key expires; rotate it before then.</p></div>
      {canManage && <Button disabled={busy || !workload.enabled} onClick={() => setEditor("new")}>Create API key</Button>}
    </div>
    {!workload.enabled && <p className="ai-provider-notice">This workload is disabled, so its API keys are revoked. Re-enable it to create new keys.</p>}
    {error && <p role="alert" className="ai-provider-alert mb-3">{error}</p>}
    {loading ? <Loading label="Loading API keys…" /> : keys && <>
      <DataTable caption="API keys" rows={keys} rowKey={(k) => k.id} failed={false} filterable={false} pageSize={0}
        empty={<AppAccessEmptyState icon={null} title="No API keys yet" description="Create a key for a serverless function, a Windows service or a SaaS tool." />}
        columns={[
          { key: "name", header: "Name", cell: (k) => <><span className="font-medium text-ink-heading" title={k.id}>{k.name}</span>{(k.rate_limit_per_minute != null || k.daily_usd_threshold != null) && <span className="block text-xs text-ink-secondary">{[k.rate_limit_per_minute != null && `${k.rate_limit_per_minute} requests/min`, k.daily_usd_threshold != null && `$${k.daily_usd_threshold} a day`].filter(Boolean).join(" · ")}</span>}</> },
          { key: "scope", header: "Scope", cell: (k) => k.scope === "public" ? "Public" : "Internal" },
          { key: "sources", header: "Allowed sources", cell: (k) => (k.source_cidrs ?? []).length ? <span className="break-all font-mono text-xs">{k.source_cidrs.join(", ")}</span> : <span className="text-xs text-ink-secondary">{k.scope === "public" ? "Any address" : "Any address the endpoint allows"}</span> },
          { key: "hint", header: "Key", cell: (k) => <code className="text-xs">tnx_sk_…{k.hint}</code> },
          { key: "expires", header: "Expires", cell: (k) => <>{date(k.expires_at)}{isActive(k) && expiresSoon(k.expires_at) && <span className="mt-1 block"><Badge tone="warn">Expires soon</Badge></span>}</> },
          { key: "used", header: "Last used", cell: (k) => k.last_used_at ? <>{date(k.last_used_at)}<span className="block text-xs text-ink-secondary">{where(k.last_used_ingress, k.last_used_source, k.last_used_node_id, endpoints)}</span></> : <span className="text-ink-secondary">Never</span> },
          { key: "refused", header: "Last refused", cell: (k) => k.last_refused_at ? <>{refusalLabel(k.last_refused_reason)}<span className="block text-xs text-ink-secondary">{[date(k.last_refused_at), where(k.last_refused_ingress, k.last_refused_source, null, endpoints)].filter(Boolean).join(" · ")}</span></> : <span className="text-ink-secondary">None</span> },
          { key: "status", header: "Status", cell: (k) => { const s = keyState(k); return <Badge tone={s.tone}>{s.label}</Badge>; } },
          ...(canManage ? [{ key: "actions", header: "Actions", cell: (k: StaticKey) => isActive(k) ? <AppAccessRowMenu label={`Actions for API key ${k.name}`} actions={[
            { key: "edit", label: "Edit key", disabledReason: busy ? "Finish the current action first." : undefined, onSelect: () => setEditor(k) },
            { key: "rotate", label: "Rotate key", disabledReason: busy ? "Finish the current action first." : undefined, onSelect: () => setRotate(k) },
            { key: "revoke", label: "Revoke key", danger: true, disabledReason: busy ? "Finish the current action first." : undefined, onSelect: () => setRevoke(k) },
          ]} /> : null }] : []),
        ]} />
      {cursor && <Button className="mt-3" disabled={more} onClick={() => void loadMore()}>{more ? "Loading keys…" : "Load more keys"}</Button>}
    </>}
    <details className="mt-4 text-sm text-ink-secondary"><summary className="cursor-pointer text-ink-heading">How to use an API key</summary><div className="mt-3 space-y-4">
      <HowToUse orgId={orgId} workload={workload} scope="internal" endpoints={endpoints} />
      <HowToUse orgId={orgId} workload={workload} scope="public" endpoints={endpoints} />
    </div></details>
    {editor && canManage && <StaticKeyEditor orgId={orgId} workload={workload} existing={editor === "new" ? undefined : editor} endpoints={endpoints} serving={serving.length > 0} publicAllowed={publicAllowed}
      onDismiss={() => setEditor(null)}
      onConflict={(message) => { if (!alive.current) return; setEditor(null); setError(message); void reload(); }}
      onCreated={(value) => { if (!alive.current) return; setEditor(null); setSecret(value); void reload(); }}
      onSaved={() => { if (!alive.current) return; setEditor(null); setError(""); toast.success("API key saved"); void reload(); }} />}
    {rotate && canManage && <RotateDialog orgId={orgId} workloadId={workload.id} target={rotate} onDismiss={() => setRotate(null)}
      onConflict={(message) => { if (!alive.current) return; setRotate(null); setError(message); void reload(); }}
      onRotated={(value) => { if (!alive.current) return; setRotate(null); setSecret(value); void reload(); }} />}
    {revoke && canManage && <RevokeDialog orgId={orgId} workloadId={workload.id} target={revoke} onDismiss={() => setRevoke(null)}
      onRevoked={() => { if (!alive.current) return; setRevoke(null); setError(""); toast.success("API key revoked"); void reload(); }} />}
    {secret && canManage && <OneTimeSecretModal title="Save API key" caption="Shown once. Paste it into the tool or your secret store now. You cannot see it again." secret={secret.secret} copyLabel="Copy key" requireAck="I saved this key securely." onDismiss={() => setSecret(null)}>
      <div className="mt-3 max-h-72 space-y-3 overflow-y-auto text-xs text-slate-300">
        <p>{secret.key.name} · {secret.key.scope === "public" ? "Public" : "Internal"} · expires {date(secret.key.expires_at)}</p>
        {secret.previous && <p>The previous key keeps working until {date(secret.previous.expires_at)}. Replace it in the tool before then.</p>}
        <HowToUse orgId={orgId} workload={workload} scope={secret.key.scope} endpoints={endpoints} compact />
      </div>
    </OneTimeSecretModal>}
  </Card>;
}

/** Base URL, CA download and short samples for one scope. The samples read the key from an environment variable. */
function HowToUse({ orgId, workload, scope, endpoints, compact = false }: { orgId: string; workload: Workload; scope: Scope; endpoints: Endpoint[] | null; compact?: boolean }) {
  const [caError, setCaError] = useState(""), [caBusy, setCaBusy] = useState(false);
  const serving = servingEndpoints(endpoints).filter((e) => e.url);
  const root = scope === "public" ? `${window.location.origin}/ai` : serving[0]?.url ? endpointRoot(serving[0].url) : "";
  const usesTunnexCA = scope === "internal" && serving.some((e) => e.endpoint?.tls_mode === "tunnex_ca");
  const model = workload.models[0]?.model ?? "MODEL";
  const ca = usesTunnexCA ? " \\\n  --cacert ca.pem" : "";
  const body = JSON.stringify({ model, messages: [{ role: "user", content: "Hello" }] });
  const curl = `curl ${root}/v1/chat/completions${ca} \\\n  -H "Authorization: Bearer $TUNNEX_API_KEY" \\\n  -H "Content-Type: application/json" \\\n  -d '${body}'`;
  const python = `import os\nfrom openai import OpenAI\n\nclient = OpenAI(\n    base_url="${root}/v1",\n    api_key=os.environ["TUNNEX_API_KEY"],\n)\nresponse = client.chat.completions.create(\n    model="${model}",\n    messages=[{"role": "user", "content": "Hello"}],\n)\nprint(response.choices[0].message.content)`;
  const messages = `curl ${root}/anthropic/v1/messages${ca} \\\n  -H "x-api-key: $TUNNEX_API_KEY" \\\n  -H "Content-Type: application/json" \\\n  -d '${JSON.stringify({ model, max_tokens: 256, messages: [{ role: "user", content: "Hello" }] })}'`;
  async function ca_() {
    if (caBusy) return;
    setCaBusy(true); setCaError("");
    const message = await downloadInternalCA(orgId);
    setCaError(message); setCaBusy(false);
  }
  const heading: ReactNode = scope === "public" ? "Public key" : "Internal key";
  return <section aria-label={`How to use ${scope === "public" ? "a public" : "an internal"} key`} className="space-y-2">
    {!compact && <h4 className="font-semibold text-ink-heading">{heading}</h4>}
    {scope === "internal" && !serving.length ? <p>{endpoints === null ? "Could not check the internal AI endpoint." : "No gateway serves the internal AI endpoint yet."} <a className="underline" href={internalEndpointSettingsLink}>Set it up in AI Gateway settings</a>.</p> : <>
      <p>Base URL: {scope === "public" ? <code className="break-all">{root}/v1</code> : serving.map((e, i) => <span key={e.node_id}>{i > 0 && ", "}<code className="break-all">{endpointRoot(e.url!)}/v1</code> ({e.node_name})</span>)}</p>
      {scope === "public" && <p>Send requests over HTTPS only. Requests over plain HTTP are refused.</p>}
      {usesTunnexCA && <div className="space-y-2">
        <p>This endpoint uses your organization's Tunnex private CA. Download it and tell the tool to trust it.</p>
        <Button variant="ghost" disabled={caBusy} onClick={() => void ca_()}>{caBusy ? "Downloading…" : "Download CA certificate"}</Button>
        {caError && <p role="alert" className="text-danger">{caError}</p>}
        <ul className="list-disc space-y-1 pl-5">
          <li>Python with requests: <code>REQUESTS_CA_BUNDLE=/path/to/ca.pem</code></li>
          <li>Node.js: <code>NODE_EXTRA_CA_CERTS=/path/to/ca.pem</code></li>
          <li>Tools that use OpenSSL: <code>SSL_CERT_FILE=/path/to/ca.pem</code> (this replaces the system list for that tool)</li>
          <li>Windows: <code>certutil -addstore Root ca.pem</code> as an administrator</li>
          <li>Java: <code>keytool -importcert -alias tunnex-ai -file ca.pem -keystore truststore.jks</code>, then start Java with <code>-Djavax.net.ssl.trustStore=truststore.jks</code></li>
        </ul>
      </div>}
      <details><summary className="cursor-pointer text-ink-heading">Code samples</summary><div className="mt-2 space-y-2">
        <p>Put the key in the <code>TUNNEX_API_KEY</code> environment variable or your secret store. Never put it in code.</p>
        <AICodeBlock language="shell" source={curl} />
        <AICodeBlock language="python" source={python} />
        <p>Messages API, with the key in the <code>x-api-key</code> header:</p>
        <AICodeBlock language="shell" source={messages} />
      </div></details>
    </>}
    <p>Each key handles 4 requests at once per control-plane process. The requests-per-minute limit is the main control.</p>
  </section>;
}

function StaticKeyEditor({ orgId, workload, existing, endpoints, serving, publicAllowed, onDismiss, onCreated, onSaved, onConflict }: {
  orgId: string; workload: Workload; existing?: StaticKey; endpoints: Endpoint[] | null; serving: boolean; publicAllowed: boolean | null;
  onDismiss: () => void; onCreated: (v: S["AIWorkloadStaticKeySecret"]) => void; onSaved: () => void; onConflict: (message: string) => void;
}) {
  const formId = useId(), scopeName = useId();
  const [name, setName] = useState(existing?.name ?? "");
  const [scope, setScope] = useState<Scope>(existing?.scope ?? "internal");
  const [expiry, setExpiry] = useState<Expiry>({ choice: "30", date: "" });
  const [ranges, setRanges] = useState((existing?.source_cidrs ?? []).join("\n"));
  const [threshold, setThreshold] = useState(existing?.daily_usd_threshold?.toString() ?? "");
  const [rate, setRate] = useState(existing?.rate_limit_per_minute?.toString() ?? "");
  const [anySource, setAnySource] = useState(false);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const cidrs = parseList(ranges);
  const badRange = cidrs.find((c) => !isIPv4CIDR(c));
  const max = workload.daily_usd_threshold ?? 100000;
  const thresholdValid = threshold.trim() === "" || Number.isFinite(Number(threshold)) && Number(threshold) > 0 && Number(threshold) <= max;
  const rateValid = rate.trim() === "" || Number.isInteger(Number(rate)) && Number(rate) >= 1 && Number(rate) <= 60000;
  const expiresAt = existing ? existing.expires_at : expiryInstant(expiry);
  const needsAny = scope === "public" && cidrs.length === 0;
  const publicBlocked = !existing && publicAllowed !== true;
  const valid = !!name.trim() && name.trim().length <= 100 && !badRange && cidrs.length <= 32 && thresholdValid && rateValid && !!expiresAt && (!needsAny || anySource) && !(scope === "public" && publicBlocked);
  async function save(event: FormEvent) {
    event.preventDefault(); if (busy || !valid || !expiresAt) return;
    setBusy(true); setError("");
    const limits = { source_cidrs: cidrs, daily_usd_threshold: threshold.trim() === "" ? null : Number(threshold), rate_limit_per_minute: rate.trim() === "" ? null : Number(rate), ...(needsAny ? { allow_any_source: true } : {}) };
    try {
      if (existing) {
        const body: S["AIWorkloadStaticKeyUpdate"] = { name: name.trim(), ...limits, expected_updated_at: existing.updated_at };
        const result = await api.PUT(keyItemPath, { params: { path: { orgId, workloadId: workload.id, keyId: existing.id } }, body });
        if (!alive.current) return;
        if (result.error || !result.data) { const e = keyError(result, "Could not save the key. Refresh and try again."); if (e.conflict) onConflict(e.message); else setError(e.message); return; }
        onSaved();
      } else {
        const body: S["AIWorkloadStaticKeyInput"] = { name: name.trim(), scope, expires_at: expiresAt, ...limits };
        const result = await api.POST(keysPath, { params: { path: { orgId, workloadId: workload.id } }, body });
        if (!alive.current) return;
        if (result.error || !result.data) { setError(keyError(result, "Could not confirm the key was created. Refresh API keys before creating another.").message); return; }
        onCreated(result.data);
      }
    } catch { if (alive.current) setError("Could not confirm the change. Refresh API keys before retrying."); }
    finally { if (alive.current) setBusy(false); }
  }
  const publicReason = publicAllowed === null ? "Could not check whether public keys are allowed. Refresh to try again." : "Public keys are off for this organization. An AI Gateway administrator can turn on \"Allow public static keys\" in AI Gateway settings.";
  return <Modal title={existing ? "Edit API key" : "Create API key"} placement="right" showClose onDismiss={() => { if (!busy) onDismiss(); }} actions={<><Button type="button" disabled={busy} onClick={onDismiss}>Cancel</Button><Button type="submit" form={formId} disabled={busy || !valid}>{busy ? "Saving…" : existing ? "Save key" : "Create key"}</Button></>}>
    <form id={formId} onSubmit={(event) => void save(event)} className="ai-workload-key-editor space-y-5">
      <Field label="1. Key name"><Input autoFocus maxLength={100} required value={name} disabled={busy} placeholder="lambda-invoice-parser" onChange={(event) => setName(event.target.value)} /></Field>
      {existing ? <p className="text-sm">Where the tool runs: <strong>{existing.scope === "public" ? "Public internet" : "Inside your network"}</strong>. Expires {date(existing.expires_at)}. To change these, create a new key or rotate this one.</p> : <>
        <fieldset className="space-y-3"><legend className="mb-1 text-sm font-semibold">2. Where the tool runs</legend>
          <label className="flex items-start gap-2"><input className="mt-1" type="radio" name={scopeName} checked={scope === "internal"} disabled={busy} onChange={() => setScope("internal")} /><span><span className="block text-sm font-medium text-ink-heading">Inside your network (recommended)</span><span className="block text-xs text-ink-secondary">The key works only on your internal AI endpoint. It is refused on the internet.</span>
            {!serving && <span className="mt-1 block text-xs text-warn">{endpoints === null ? "Could not check the internal AI endpoint." : "No gateway serves the internal AI endpoint yet."} <a className="underline" href={internalEndpointSettingsLink}>Set it up in AI Gateway settings</a>. The key works once a gateway serves it.</span>}</span></label>
          <label className="flex items-start gap-2"><input className="mt-1" type="radio" name={scopeName} checked={scope === "public"} disabled={busy || publicBlocked} onChange={() => setScope("public")} /><span><span className="block text-sm font-medium text-ink-heading">Public internet</span><span className="block text-xs text-ink-secondary">For SaaS tools that cannot reach your network. Limit it to the tool's IP addresses.</span>
            {publicBlocked && <span className="mt-1 block text-xs text-warn">{publicReason}</span>}</span></label>
        </fieldset>
        <ExpiryChoice legend="3. Expires" value={expiry} disabled={busy} onChange={setExpiry} />
        {!expiresAt && expiry.choice === "date" && <p role="alert" className="text-sm text-danger">Choose a date between tomorrow and 90 days from now.</p>}
      </>}
      <fieldset className="space-y-3"><legend className="mb-1 text-sm font-semibold">{existing ? "Limits" : "4. Limits (optional)"}</legend>
        <Field label="Allowed source ranges"><textarea className={area} value={ranges} disabled={busy} placeholder={scope === "public" ? "203.0.113.0/24" : "10.20.0.0/16"} onChange={(event) => { setRanges(event.target.value); setAnySource(false); }} /></Field>
        <p className="text-xs text-ink-secondary">{scope === "public" ? "Public ranges only, one per line. Ask the tool's vendor for the addresses it calls from." : "Private ranges, one per line. Leave empty to allow every address the internal endpoint allows. If traffic passes source NAT, every caller behind it looks the same."}</p>
        {badRange && <p role="alert" className="text-sm text-danger">{badRange} is not a range. Use the form 10.20.0.0/16.</p>}
        {cidrs.length > 32 && <p role="alert" className="text-sm text-danger">Use at most 32 ranges.</p>}
        {needsAny && <label className="flex items-start gap-2 text-sm"><input className="mt-1" type="checkbox" checked={anySource} disabled={busy} onChange={(event) => setAnySource(event.target.checked)} /><span>Allow from any address<span className="block text-xs text-ink-secondary">Anyone on the internet who has this key can use it until it expires or you revoke it.</span></span></label>}
        <Field label="Daily limit in USD"><Input type="number" min="0.000000001" max={max} step="any" value={threshold} disabled={busy} placeholder={workload.daily_usd_threshold != null ? `Up to the workload's $${workload.daily_usd_threshold}` : "No limit"} onChange={(event) => setThreshold(event.target.value)} /></Field>
        {!thresholdValid && <p role="alert" className="text-sm text-danger">{workload.daily_usd_threshold != null ? `Enter a positive amount up to the workload's $${workload.daily_usd_threshold}, or leave it empty.` : "Enter a positive amount up to 100,000, or leave it empty."}</p>}
        <Field label="Requests per minute"><Input type="number" min={1} max={60000} step={1} value={rate} disabled={busy} placeholder="No limit" onChange={(event) => setRate(event.target.value)} /></Field>
        {!rateValid && <p role="alert" className="text-sm text-danger">Enter a whole number from 1 to 60,000, or leave it empty.</p>}
        <p className="text-xs text-ink-secondary">Each key handles 4 requests at once per control-plane process. The requests-per-minute limit is the main control.</p>
      </fieldset>
      {error && <p role="alert" className="text-sm text-danger">{error}</p>}
    </form>
  </Modal>;
}

function RotateDialog({ orgId, workloadId, target, onDismiss, onRotated, onConflict }: {
  orgId: string; workloadId: string; target: StaticKey; onDismiss: () => void; onRotated: (v: S["AIWorkloadStaticKeySecret"]) => void; onConflict: (message: string) => void;
}) {
  const formId = useId();
  const [overlap, setOverlap] = useState("24");
  const [expiry, setExpiry] = useState<Expiry>({ choice: "30", date: "" });
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  const hours = Number(overlap);
  const overlapValid = Number.isInteger(hours) && hours >= 1 && hours <= 168;
  const expiresAt = expiryInstant(expiry);
  async function submit(event: FormEvent) {
    event.preventDefault(); if (busy || !overlapValid || !expiresAt) return;
    setBusy(true); setError("");
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/ai-gateway/workloads/{workloadId}/static-keys/{keyId}/rotate", { params: { path: { orgId, workloadId, keyId: target.id } }, body: { overlap_hours: hours, expires_at: expiresAt } });
      if (!alive.current) return;
      if (result.error || !result.data) { const e = keyError(result, "Could not confirm the rotation. Refresh API keys before retrying."); if (e.conflict) onConflict(e.message); else setError(e.message); return; }
      onRotated(result.data);
    } catch { if (alive.current) setError("Could not confirm the rotation. Refresh API keys before retrying."); }
    finally { if (alive.current) setBusy(false); }
  }
  return <Modal title="Rotate API key" placement="right" showClose onDismiss={() => { if (!busy) onDismiss(); }} actions={<><Button type="button" disabled={busy} onClick={onDismiss}>Cancel</Button><Button type="submit" form={formId} disabled={busy || !overlapValid || !expiresAt}>{busy ? "Rotating…" : "Rotate key"}</Button></>}>
    <form id={formId} onSubmit={(event) => void submit(event)} className="ai-workload-key-editor space-y-5">
      <p className="text-sm">Rotating {target.name} creates a new key with the same settings and shows it once. The old key keeps working for the overlap, so you can update the tool first.</p>
      <Field label="Overlap in hours"><Input type="number" min={1} max={168} step={1} required value={overlap} disabled={busy} onChange={(event) => setOverlap(event.target.value)} /></Field>
      <p className="text-xs text-ink-secondary">1 to 168 hours (7 days). The old key stops at the end of the overlap, or at its own expiry if that is sooner.</p>
      {!overlapValid && <p role="alert" className="text-sm text-danger">Enter a whole number of hours from 1 to 168.</p>}
      <ExpiryChoice legend="New key expires" value={expiry} disabled={busy} onChange={setExpiry} />
      {!expiresAt && expiry.choice === "date" && <p role="alert" className="text-sm text-danger">Choose a date between tomorrow and 90 days from now.</p>}
      {error && <p role="alert" className="text-sm text-danger">{error}</p>}
    </form>
  </Modal>;
}

function RevokeDialog({ orgId, workloadId, target, onDismiss, onRevoked }: { orgId: string; workloadId: string; target: StaticKey; onDismiss: () => void; onRevoked: () => void }) {
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  async function confirm() {
    if (busy) return;
    setBusy(true); setError("");
    try {
      const result = await api.POST("/api/v1/organizations/{orgId}/ai-gateway/workloads/{workloadId}/static-keys/{keyId}/revoke", { params: { path: { orgId, workloadId, keyId: target.id } } });
      if (!alive.current) return;
      if (result.error || result.response?.status !== 204) { setError(keyError(result, "Could not confirm the key was revoked. Refresh API keys before retrying.").message); return; }
      onRevoked();
    } catch { if (alive.current) setError("Could not confirm the key was revoked. Refresh API keys before retrying."); }
    finally { if (alive.current) setBusy(false); }
  }
  return <Modal title="Revoke API key" danger onDismiss={() => { if (!busy) onDismiss(); }} actions={<><Button disabled={busy} onClick={onDismiss}>Cancel</Button><Button disabled={busy} onClick={() => void confirm()}>{busy ? "Revoking…" : "Revoke key"}</Button></>}>
    <p className="text-sm">Revoke {target.name} (<code>tnx_sk_…{target.hint}</code>)? The next request with this key is refused. You cannot undo this.</p>
    {error && <p role="alert" className="mt-3 text-sm text-danger">{error}</p>}
  </Modal>;
}
