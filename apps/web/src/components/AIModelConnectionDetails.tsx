import { SiPython, SiJavascript, SiTypescript, SiGo, SiPhp, SiRuby, SiDotnet } from "react-icons/si";
import { DiJava } from "react-icons/di";
import { VscGlobe, VscTerminal } from "react-icons/vsc";
import type { IconType } from "react-icons";
import { useEffect, useId, useState } from "react";
import type { components } from "@tunnex/shared";
import { AICodeBlock } from "./AICodeBlock";
import { HelpTooltip } from "./HelpTooltip";
import { useOrg } from "../lib/useOrg";
import { useAuth } from "../lib/auth";
import { api, loadOne } from "../lib/api";
import { aiLanguageExamples } from "../lib/aiLanguageExamples";
import { Button } from "./ui";

const languageIcons: Record<string, IconType> = { python: SiPython, javascript: SiJavascript, typescript: SiTypescript, go: SiGo, php: SiPhp, ruby: SiRuby, shell: VscTerminal, csharp: SiDotnet, java: DiJava, http: VscGlobe };
type UserModel = components["schemas"]["AIUserModel"];
const unavailableMessages: Record<string, string> = {
  deployment_disabled: "VPN AI access is not enabled on this installation. Ask your administrator to update the gateway setup, then refresh.",
  http_disabled: "The gateway's VPN AI transport is disabled. Ask your installation administrator to enable it, then refresh.",
  transport_unavailable: "Could not verify the VPN AI transport. Refresh or ask your installation administrator to check it.",
  gateway_not_ready: "No ready VPN AI gateway is available for your device. Connect the Tunnex client and refresh; if this persists, ask your administrator to check the gateway.",
  operation_unsupported: "VPN connection examples currently support chat models only. This model's operation is not supported over VPN yet.",
};

export function AIModelConnectionDetails({ orgId, model, mode = "chat" }: { orgId: string; model: string; mode?: string }) {
  const { orgs } = useOrg();
  const { state } = useAuth();
  const userId = state.status === "authed" ? state.user.id : "";
  const organization = orgs.find((item) => item.id === orgId);
  const scope = JSON.stringify([orgId, userId, model, mode]);
  const [attempt, setAttempt] = useState(0);
  const [result, setResult] = useState<{ scope: string; models?: UserModel[]; failed?: boolean } | null>(null);
  useEffect(() => {
    let active = true;
    setResult(null);
    if (!userId || mode !== "chat") return;
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/ai-gateway/my-models", { params: { path: { orgId } } })).then((response) => {
      if (active) setResult(response.ok && Array.isArray(response.data) ? { scope, models: response.data } : { scope, failed: true });
    });
    return () => { active = false; };
  }, [scope, attempt]);
  // Also check the user's grant from administrator dialogs. Provider inventory alone
  // does not authorize inference, and a browser origin is never a VPN endpoint.
  const current = result?.scope === scope ? result : null;
  const granted = current?.models?.find((item) => item.model === model && item.mode === mode);
  const base = mode === "chat" ? granted?.vpn_base_url : undefined;
  const python = base ? `from openai import OpenAI\n\nclient = OpenAI(\n    base_url=${JSON.stringify(base)},\n    api_key="unused",  # Required by the SDK; access uses your Tunnex VPN identity\n)\n\nresponse = client.chat.completions.create(\n    model=${JSON.stringify(model)},\n    messages=[{"role": "user", "content": "Hello"}],\n    max_tokens=1024,\n)\nprint(response.choices[0].message.content)` : "";
  const restExamples = base ? aiLanguageExamples(base, model, mode) : [];
  const examples = [...restExamples.filter(item => item.language === "python"), ...restExamples.filter(item => item.language !== "python")];
  const [pythonStyle, setPythonStyle] = useState<"sdk" | "rest">("sdk");
  const tabsId = useId();
  const [exampleIndex, setExampleIndex] = useState(0);
  const selectedExample = examples[exampleIndex] ?? examples[0];
  const sdkSelected = selectedExample?.language === "python" && pythonStyle === "sdk";
  const example = sdkSelected ? { ...selectedExample, source: python } : selectedExample;
  const [notice, setNotice] = useState("");
  async function copy(label: string, value: string) {
    try {
      await navigator.clipboard.writeText(value);
      setNotice(`${label} copied`);
    } catch {
      setNotice(`Could not copy ${label.toLowerCase()}. Select the text and copy it manually.`);
    }
  }
  const unavailable = mode !== "chat" ? unavailableMessages.operation_unsupported
    : !userId ? "Sign in to check your model access and VPN endpoint."
    : current?.failed ? "Could not load your VPN endpoint. Refresh to try again."
    : current && !granted ? "Your user needs a model access grant before connection examples are available. Ask your administrator to grant this model to your user group."
    : granted ? unavailableMessages[granted.vpn_unavailable_reason ?? ""] ?? unavailableMessages.gateway_not_ready
    : "Checking your VPN endpoint…";
  return <section className="ai-connection-details space-y-4" aria-label={`Connection details for ${model}`}>
    <div className="ai-connect-context"><span>{organization?.name ?? "Selected organization"}</span><HelpTooltip label="Connection requirements">Connect your Tunnex client to this organization's gateway. Every example uses your VPN device identity and model access policy; no API key is needed. These endpoints are reachable only through the VPN.</HelpTooltip></div>
    {!base ? <div className="space-y-3"><p role={current?.failed ? "alert" : "status"}>{unavailable}</p>{mode === "chat" && userId && <Button disabled={!current} onClick={() => setAttempt(n => n + 1)}>Refresh VPN endpoint</Button>}</div> : <>
      <p className="text-sm text-ink-secondary">Connect your Tunnex client before running these examples. Access uses your VPN identity and model policy.</p>
      <div className="ai-connect-fields">{[["Base URL", base], ["Model ID", model], ["Org ID", orgId]].map(([label, value]) => <div className="ai-connect-field" key={label}><label>{label}</label><div><code title={value} tabIndex={0}>{value}</code><button type="button" aria-label={`Copy ${label}`} title={`Copy ${label}`} onClick={() => void copy(label, value)}><svg aria-hidden="true" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.7"><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M15 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h3"/></svg></button></div></div>)}</div>
      <div className="ai-connect-example">
        {example && <div className="ai-code-workbench"><div className="ai-code-tabbar"><div className="ai-code-tabs" role="tablist" aria-label="Example language">{examples.map((item, index) => <button type="button" role="tab" title={item.label} aria-label={item.label} id={`${tabsId}-tab-${index}`} aria-controls={`${tabsId}-panel`} aria-selected={exampleIndex === index} tabIndex={exampleIndex === index ? 0 : -1} key={item.label} onClick={() => setExampleIndex(index)} onKeyDown={event => {
          const next = event.key === "ArrowRight" ? (index + 1) % examples.length : event.key === "ArrowLeft" ? (index - 1 + examples.length) % examples.length : event.key === "Home" ? 0 : event.key === "End" ? examples.length - 1 : null;
          if (next !== null) { event.preventDefault(); setExampleIndex(next); document.getElementById(`${tabsId}-tab-${next}`)?.focus(); }
        }}><span aria-hidden="true" className={`ai-file-icon ai-file-${item.language}`}>{(() => { const LanguageIcon = languageIcons[item.language] ?? VscGlobe; return <LanguageIcon size={18} />; })()}</span><span className="ai-tab-language" aria-hidden="true">{item.label}</span></button>)}</div><HelpTooltip label="Example setup">{sdkSelected ? "Install openai. The SDK requires a placeholder key; your connected VPN device and model policy authorize the request." : "Run while connected to Tunnex. These REST examples need no API key. JavaScript and TypeScript run in Node.js."}</HelpTooltip></div><div role="tabpanel" id={`${tabsId}-panel`} aria-labelledby={`${tabsId}-tab-${exampleIndex}`}>{example.language === "python" && <div className="ai-python-style" role="group" aria-label="Python connection method"><button type="button" aria-pressed={pythonStyle === "sdk"} onClick={() => setPythonStyle("sdk")}>SDK over VPN</button><button type="button" aria-pressed={pythonStyle === "rest"} onClick={() => setPythonStyle("rest")}>REST over VPN</button></div>}<AICodeBlock source={example.source} language={example.language} showTitle={false} /></div><Button onClick={() => void copy(sdkSelected ? "Python example" : "Example", example.source)}>{sdkSelected ? "Copy Python example" : "Copy example"}</Button></div>}
      </div>
    </>}
    {notice && <p role="status">{notice}</p>}
  </section>;
}
