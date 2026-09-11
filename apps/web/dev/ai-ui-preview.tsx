// Development-only fixture. No real accounts, credentials or network calls.
import React, { useState } from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import "@fontsource-variable/inter";
import "../../../packages/shared/generated/tokens.css";
import "../src/index.css";
const org = { id: "preview", name: "Demo", slug: "preview", agent_jit_access_enabled: true, agent_policy_templates_enabled: true };
const row = { id: "request", device_id: "agent", agent_name: "Build agent", destination_name: "Private database", destination_kind: "resource", destination_id: "resource", requested_by_user_id: "owner", reason: "Run deployment checks", state: "pending", requested_at: new Date().toISOString() };
let requests = [row];
window.fetch = async (input, init) => {
  const req = input instanceof Request ? input : new Request(new URL(String(input), window.location.origin), init);
  const url = new URL(req.url), path = url.pathname;
  const json = (data: unknown) => new Response(JSON.stringify(data), { headers: { "Content-Type": "application/json" } });
  if (path.endsWith("/auth/me")) return json({ id: "owner", email: "owner@example.test", email_verified: true });
  if (path === "/api/v1/organizations") return json([org]);
  if (path.endsWith("/members")) return json([{user_id: "owner", role: "owner"}]);
  if (path.endsWith("/license")) return json({ features: ["agent_jit_access"] });
  if (path.endsWith("/zero-trust-mode")) return json({ mode: "off" });
  if (path.endsWith("/agents")) return json({items: [{device_id: "agent", name: "Build agent"}]});
  if (path.endsWith("/agents/agent")) return json({device_id: "agent", name: "Build agent"});
  if (path.endsWith("/agent-access-destinations")) return json([{kind: "resource", id: "resource", name: "Private database"}]);
  if (path.endsWith("/agent-access-requests")) {
    if (req.method === "POST") requests = [{...row, id: crypto.randomUUID(), reason: (await req.json()).reason}, ...requests];
    const state = url.searchParams.get("state");
    return json(req.method === "POST" ? requests[0] : {items: requests.filter(r => !state || r.state === state)});
  }
  if (/\/(approve|reject|cancel|revoke)$/.test(path)) {
    const action = path.split("/").pop()!;
    requests = requests.map(r => r.id === path.split("/").at(-2) ? {...r, state: ({approve: "approved", reject: "rejected", cancel: "cancelled", revoke: "revoked"})[action]!} : r);
    return json(requests[0]);
  }
  if (path.includes("agent-access-requests/")) return json({request: requests[0], events: [{state: requests[0].state}]});
  return json([]);
};
const { AuthProvider } = await import("../src/lib/auth");
const { OrgProvider } = await import("../src/lib/useOrg");
const { LayoutCapabilityProvider } = await import("../src/components/ComposeGate");
const { AIModelResponse } = await import("../src/components/AIUserAccess");
const { AIModelConnectionDetails } = await import("../src/components/AIModelConnectionDetails");
const { AIUsageDashboard } = await import("../src/components/AIUsageDashboard");
const { default: Access } = await import("../src/pages/Access");
const { default: AgentsMCP } = await import("../src/pages/AgentsMCP");
function Preview() {
  const [view, setView] = useState("JIT");
  return <main className="mx-auto max-w-6xl p-6 text-ink-body"><p className="mb-3 text-sm text-amber-300">LOCAL PREVIEW · Simulated data only</p><nav className="mb-6 flex gap-4">{["JIT", "Model", "Usage", "MCP"].map(tab => <button className="rounded border border-white/20 px-4 py-2" key={tab} onClick={() => setView(tab)}>{tab}</button>)}</nav>
    {view === "JIT" ? <Access /> : view === "MCP" ? <AgentsMCP /> : view === "Usage" ? <AIUsageDashboard status="ready" totals={{requests: 12, tokens: 1408, inputTokens: 208, outputTokens: 1200, cost: 0, uncostedRequests: 12, successfulRequests: 12, failedRequests: 0}} models={[]} /> : <div className="space-y-5"><AIModelResponse output={JSON.stringify({choices:[{message:{content:"Your deployment checks passed. The private database is reachable and the model is ready to use."}}], usage:{total_tokens:88}})} /><AIModelConnectionDetails orgId="preview" model="custom-demo/embedding" mode="embedding" /></div>}
  </main>;
}
ReactDOM.createRoot(document.getElementById("root")!).render(<BrowserRouter><LayoutCapabilityProvider><AuthProvider><OrgProvider><Preview /></OrgProvider></AuthProvider></LayoutCapabilityProvider></BrowserRouter>);
