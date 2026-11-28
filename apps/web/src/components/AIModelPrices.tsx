import { useEffect, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorMessage } from "../lib/api";
import { Button, Field, Input, Modal } from "./ui";
import { modelDisplayName } from "./HelpTooltip";
import { toast } from "./Toasts";

// AI-READY-1: operator model prices. People read prices per million tokens;
// the API stores USD per token.
type S = components["schemas"];
export type ModelPriceInfo = { effective?: S["AIEffectiveModelPrice"]; saved?: S["AIModelPrice"] };
const PER_MILLION = 1_000_000;

export function formatPerMillion(perToken: number | null | undefined): string {
  if (perToken == null) return "n/a";
  const v = perToken * PER_MILLION;
  // Two decimals as prices are quoted; more only for sub-cent rates.
  return `$${v >= 100 ? v.toFixed(0) : v >= 0.01 || v === 0 ? v.toFixed(2) : String(Number(v.toPrecision(2)))}`;
}

export function useModelPrices(orgId: string, models: string[]) {
  const [byModel, setByModel] = useState<Record<string, ModelPriceInfo>>({});
  const [failed, setFailed] = useState(false);
  const [version, setVersion] = useState(0);
  const serial = useRef(0);
  const key = [...new Set(models)].sort().slice(0, 1000).join("\n");
  useEffect(() => {
    const n = ++serial.current;
    const list = key ? key.split("\n") : [];
    if (!list.length) { setByModel({}); return; }
    void (async () => {
      try {
        // Small batches keep each request line well under proxy limits.
        const batches: string[][] = [];
        for (let i = 0; i < list.length; i += 40) batches.push(list.slice(i, i + 40));
        const results = await Promise.all(batches.map((model) => api.GET("/api/v1/organizations/{orgId}/ai-gateway/model-prices", { params: { path: { orgId }, query: { model } } })));
        if (n !== serial.current) return;
        if (results.some((r) => r.error || !r.data)) { setFailed(true); return; }
        const next: Record<string, ModelPriceInfo> = {};
        for (const r of results) for (const e of r.data!.effective) next[e.model] = { effective: e };
        for (const p of results[0].data!.prices) next[p.model] = { ...next[p.model], saved: p };
        setByModel(next); setFailed(false);
      } catch { if (n === serial.current) setFailed(true); }
    })();
  }, [orgId, key, version]);
  return { byModel, failed, reload: () => setVersion((v) => v + 1) };
}

export function ModelPriceCell({ info, failed }: { info?: ModelPriceInfo; failed: boolean }) {
  if (!info?.effective) return <span className="ai-gateway-muted">{failed ? "Unavailable" : "Loading"}</span>;
  const e = info.effective;
  const pending = info.saved && info.saved.status !== "applied";
  if (e.source === "unknown") return <span className="ai-price-cell"><span className="ai-gateway-state ai-gateway-state-pending" title="No price is known for this model. Under a daily limit it is refused unless AI Gateway settings allow models without a price.">Price unknown</span>{pending && <small>Custom price pending</small>}</span>;
  return <span className="ai-price-cell" title="Input / output, USD per million tokens">
    <span>{formatPerMillion(e.input_cost_per_token)} / {formatPerMillion(e.output_cost_per_token)}</span>
    <small>{e.source === "override" ? "Custom" : "Catalog"}{pending ? " · change pending" : ""}</small>
  </span>;
}

export function ModelPriceDialog({ orgId, model, mode, info, onClose, onSaved }: { orgId: string; model: string; mode: S["AIModelMode"]; info?: ModelPriceInfo; onClose: () => void; onSaved: () => void }) {
  const saved = info?.saved;
  const start = saved ?? (info?.effective?.source === "catalog" ? { input_cost_per_token: info.effective.input_cost_per_token, output_cost_per_token: info.effective.output_cost_per_token } : undefined);
  const asInput = (v: number | null | undefined) => v == null ? "" : String(Number((v * PER_MILLION).toPrecision(10)));
  const [input, setInput] = useState(asInput(start?.input_cost_per_token));
  const [output, setOutput] = useState(asInput(start?.output_cost_per_token));
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const embedding = mode === "embedding";
  const parse = (v: string) => v.trim() === "" ? NaN : Number(v);
  const inValue = parse(input), outValue = parse(output);
  const ok = (v: number) => Number.isFinite(v) && v >= 0 && v <= 10000;
  const valid = ok(inValue) && (embedding ? output.trim() === "" || ok(outValue) : ok(outValue));
  const unsupported = !["chat", "completion", "embedding"].includes(mode);
  async function save(remove: boolean) {
    setBusy(true); setError("");
    try {
      const r = remove && saved
        ? await api.DELETE("/api/v1/organizations/{orgId}/ai-gateway/model-prices", { params: { path: { orgId }, query: { model, expected_revision: saved.revision } } })
        : await api.PUT("/api/v1/organizations/{orgId}/ai-gateway/model-prices", { params: { path: { orgId } }, body: { model, input_cost_per_token: inValue / PER_MILLION, output_cost_per_token: output.trim() === "" ? null : outValue / PER_MILLION, expected_revision: saved?.revision ?? 0 } });
      if (r.error || !r.data) {
        setError(r.response?.status === 409 ? "Someone else changed this price. Close and reopen to load it." : apiErrorMessage(r.error, "Could not save the price."));
        return;
      }
      toast.success(remove ? "Custom price removed" : r.data.status === "applied" ? "Price saved" : "Price saved; applying to the gateway");
      onSaved();
    } catch { setError("Could not reach the API. Reload to check the saved price."); }
    finally { setBusy(false); }
  }
  return <Modal title={saved && !saved.removed ? "Edit price" : "Set price"} showClose onDismiss={() => !busy && onClose()} actions={<>
    <Button variant="ghost" disabled={busy} onClick={onClose}>Cancel</Button>
    {saved && !saved.removed && <Button variant="ghost" disabled={busy} onClick={() => void save(true)}>Remove price</Button>}
    <Button disabled={busy || !valid || unsupported} onClick={() => void save(false)}>{busy ? "Saving…" : "Save price"}</Button>
  </>}>
    <div className="grid gap-4">
      {error && <p role="alert" className="text-danger">{error}</p>}
      <p>Price for <strong>{modelDisplayName(model)}</strong> in this organization, in USD per million tokens. It is used for cost estimates and daily limits instead of the bundled catalog price.</p>
      {unsupported ? <p className="text-sm text-ink-tertiary">Prices can be set for chat, completion and embedding models. Daily limits do not price other modes.</p> : <>
        <Field label="Input (USD per 1M tokens)"><Input type="number" inputMode="decimal" min="0" max="10000" step="any" value={input} disabled={busy} onChange={(e) => setInput(e.target.value)} /></Field>
        <Field label={embedding ? "Output (USD per 1M tokens, optional)" : "Output (USD per 1M tokens)"}><Input type="number" inputMode="decimal" min="0" max="10000" step="any" value={output} disabled={busy} onChange={(e) => setOutput(e.target.value)} /></Field>
        {(input.trim() !== "" || output.trim() !== "") && !valid && <p className="text-sm text-danger">Enter amounts from 0 to 10000.</p>}
        <p className="text-sm text-ink-tertiary">Applies to new requests once the gateway confirms it. Earlier requests keep their recorded cost. A price of 0 means requests for this model cost nothing against daily limits.</p>
      </>}
    </div>
  </Modal>;
}
