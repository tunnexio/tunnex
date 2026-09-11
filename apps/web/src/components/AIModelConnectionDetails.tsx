import { useState } from "react";
import { getApiOrigin } from "@tunnex/shared";
import { useOrg } from "../lib/useOrg";
import { aiOperationExample } from "../lib/aiOperationExample";
import { Button } from "./ui";

export function AIModelConnectionDetails({ orgId, model, mode = "chat" }: { orgId: string; model: string; mode?: string }) {
  const { orgs, loading, failed } = useOrg();
  const organization = orgs.find((item) => item.id === orgId);
  const origin = getApiOrigin() ?? window.location.origin;
  const scopedBase = `${origin}/api/v1/organizations/${orgId}/ai-gateway/inference/v1`;
  const singleOrg = !loading && !failed && orgs.length === 1 && orgs[0].id === orgId;
  const base = singleOrg && mode === "chat" ? `${origin}/ai/v1` : scopedBase;
  const python = `from openai import OpenAI\n\nclient = OpenAI(\n    base_url=${JSON.stringify(base)},\n    api_key="unused",  # Identity comes from your Tunnex VPN connection\n)\n\nresponse = client.chat.completions.create(\n    model=${JSON.stringify(model)},\n    messages=[{"role": "user", "content": "Hello"}],\n    max_tokens=1024,\n)\nprint(response.choices[0].message.content)`;
  const operationExample = aiOperationExample(scopedBase, model, mode);
  const [notice, setNotice] = useState("");
  async function copy(label: string, value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setNotice(`${label} copied`);
    } catch {
      setNotice(`Could not copy ${label.toLowerCase()}. Select the text and copy it manually.`);
    }
  }
  return <section className="space-y-4 rounded-lg border border-white/20 p-5" aria-label={`Connection details for ${model}`}>
    <h3 className="text-xl font-semibold">Use this Base URL</h3>
    <code className="block break-all text-base">{base}</code>
    <Button onClick={() => void copy("Base URL", base)}>Copy Base URL</Button>
    <dl className="space-y-3">
      <div><dt className="font-semibold">Organization</dt><dd>{organization?.name ?? "Selected organization"}</dd></div>
      <div><dt className="font-semibold">Org ID</dt><dd className="break-all"><code>{orgId}</code></dd></div>
      <div><dt className="font-semibold">Model ID</dt><dd className="break-all"><code>{model}</code></dd></div>
    </dl>
    <div className="flex flex-wrap gap-2">
      <Button onClick={() => void copy("Org ID", orgId)}>Copy Org ID</Button>
      <Button onClick={() => void copy("Model ID", model)}>Copy Model ID</Button>
    </div>
    <p className="text-sm text-ink-tertiary">{singleOrg && mode === "chat" ? "You belong to one organization. Tunnex resolves it from your verified VPN identity." : "Use this organization-specific URL. Tunnex does not guess between your organizations."} Your user must have access to this model.</p>
    <p className="text-sm text-ink-tertiary">For VPN identity access, connect to this organization's gateway configured for AI ingress. A gateway in another organization cannot authorize this URL. Ask your administrator which gateway supports AI ingress if several are available.</p>
    {mode === "chat" ? <div className="space-y-3"><h4 className="font-semibold">OpenAI Python SDK over VPN</h4><p className="text-sm">Requires configured VPN AI ingress and a model grant. Install with <code>pip install openai</code>. A dummy key does not work on the public connection.</p><pre className="overflow-x-auto rounded-lg bg-ink-900 p-4 text-xs">{python}</pre><Button onClick={() => void copy("Python example", python)}>Copy Python example</Button></div> : <div className="space-y-3"><h4 className="font-semibold">Call this operation</h4><p className="text-sm">Set <code>TUNNEX_API_KEY</code> to your Tunnex login credential. This authenticated example needs a model grant; a provider key or dummy key will not work here.</p>{operationExample ? <><pre className="overflow-x-auto rounded-lg bg-ink-900 p-4 text-xs">{operationExample}</pre><Button onClick={() => void copy("Operation example", operationExample)}>Copy operation example</Button></> : <p>No example is available for this operation.</p>}{mode === "audio_speech" && <p className="text-sm">Replace the voice placeholder with a voice supported by your deployment.</p>}{mode === "audio_transcription" && <p className="text-sm">Use a local audio file up to 8 MiB.</p>}{mode === "video_generation" && <p className="text-sm">The response accepts a video job; it does not mean generation is complete. Reuse the same idempotency key when retrying the same job.</p>}</div>}
    {notice && <p role="status">{notice}</p>}
  </section>;
}
