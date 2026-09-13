import { SiPython, SiJavascript, SiTypescript, SiGo, SiPhp, SiRuby, SiDotnet } from "react-icons/si";
import { DiJava } from "react-icons/di";
import { VscGlobe, VscTerminal } from "react-icons/vsc";
import type { IconType } from "react-icons";
import { AICodeBlock } from "./AICodeBlock";
import { HelpTooltip } from "./HelpTooltip";
import { useId, useState } from "react";
import { getApiOrigin } from "@tunnex/shared";
import { useOrg } from "../lib/useOrg";
import { aiLanguageExamples } from "../lib/aiLanguageExamples";
import { Button } from "./ui";

const languageIcons: Record<string, IconType> = { python: SiPython, javascript: SiJavascript, typescript: SiTypescript, go: SiGo, php: SiPhp, ruby: SiRuby, shell: VscTerminal, csharp: SiDotnet, java: DiJava, http: VscGlobe };

export function AIModelConnectionDetails({ orgId, model, mode = "chat" }: { orgId: string; model: string; mode?: string }) {
  const { orgs, loading, failed } = useOrg();
  const organization = orgs.find((item) => item.id === orgId);
  const origin = getApiOrigin() ?? window.location.origin;
  const scopedBase = `${origin}/api/v1/organizations/${orgId}/ai-gateway/inference/v1`;
  const singleOrg = !loading && !failed && orgs.length === 1 && orgs[0].id === orgId;
  const base = singleOrg && mode === "chat" ? `${origin}/ai/v1` : scopedBase;
  const python = `from openai import OpenAI\n\nclient = OpenAI(\n    base_url=${JSON.stringify(base)},\n    api_key="unused",  # Identity comes from your Tunnex VPN connection\n)\n\nresponse = client.chat.completions.create(\n    model=${JSON.stringify(model)},\n    messages=[{"role": "user", "content": "Hello"}],\n    max_tokens=1024,\n)\nprint(response.choices[0].message.content)`;
  const restExamples = aiLanguageExamples(scopedBase, model, mode);
  const examples = mode === "chat" ? [restExamples.find(item => item.language === "python")!, ...restExamples.filter(item => item.language !== "python")] : restExamples;
  const [pythonStyle, setPythonStyle] = useState<"sdk" | "rest">("sdk");
  const tabsId = useId();
  const [exampleIndex, setExampleIndex] = useState(0);
  const selectedExample = examples[exampleIndex] ?? examples[0];
  const sdkSelected = selectedExample?.language === "python" && mode === "chat" && pythonStyle === "sdk";
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
  return <section className="ai-connection-details space-y-4" aria-label={`Connection details for ${model}`}>
    <div className="ai-connect-context"><span>{organization?.name ?? "Selected organization"}</span><HelpTooltip label="Connection requirements">Use a model granted to your user. VPN identity access requires this organization's gateway with AI ingress configured. Public clients must authenticate with a Tunnex credential.</HelpTooltip></div>
    <div className="ai-connect-fields">{[["Base URL", base], ["Model ID", model], ["Org ID", orgId]].map(([label, value]) => <div className="ai-connect-field" key={label}><label>{label}</label><div><code title={value} tabIndex={0}>{value}</code><button type="button" aria-label={`Copy ${label}`} title={`Copy ${label}`} onClick={() => void copy(label, value)}><svg aria-hidden="true" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="1.7"><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M15 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h3"/></svg></button></div></div>)}</div>
    <div className="ai-connect-example">
    {example && <div className="ai-code-workbench"><div className="ai-code-tabbar"><div className="ai-code-tabs" role="tablist" aria-label="Example language">{examples.map((item, index) => <button type="button" role="tab" title={item.label} aria-label={item.label} id={`${tabsId}-tab-${index}`} aria-controls={`${tabsId}-panel`} aria-selected={exampleIndex === index} tabIndex={exampleIndex === index ? 0 : -1} key={item.label} onClick={() => setExampleIndex(index)} onKeyDown={event => {
      const next = event.key === "ArrowRight" ? (index + 1) % examples.length : event.key === "ArrowLeft" ? (index - 1 + examples.length) % examples.length : event.key === "Home" ? 0 : event.key === "End" ? examples.length - 1 : null;
      if (next !== null) { event.preventDefault(); setExampleIndex(next); document.getElementById(`${tabsId}-tab-${next}`)?.focus(); }
    }}><span aria-hidden="true" className={`ai-file-icon ai-file-${item.language}`}>{(() => { const LanguageIcon = languageIcons[item.language] ?? VscGlobe; return <LanguageIcon size={18} />; })()}</span><span className="ai-tab-language" aria-hidden="true">{item.label}</span></button>)}</div><HelpTooltip label="Example setup">{sdkSelected ? "Install openai. Requires configured VPN AI ingress and a model grant. The dummy key does not authorize public requests." : "Set TUNNEX_API_KEY to your Tunnex credential. These examples use authenticated REST calls and require a model grant. JavaScript and TypeScript run in Node.js; keep credentials out of browser code."} {mode === "video_generation" && "Replace the idempotency placeholder with one unique key per job and reuse it for retries."} {mode === "audio_transcription" && "Use a local audio file up to 8 MiB. This multipart operation is shown with cURL."}</HelpTooltip></div><div role="tabpanel" id={`${tabsId}-panel`} aria-labelledby={`${tabsId}-tab-${exampleIndex}`}>{example.language === "python" && mode === "chat" && <div className="ai-python-style" role="group" aria-label="Python connection method"><button type="button" aria-pressed={pythonStyle === "sdk"} onClick={() => setPythonStyle("sdk")}>SDK over VPN</button><button type="button" aria-pressed={pythonStyle === "rest"} onClick={() => setPythonStyle("rest")}>REST</button></div>}<AICodeBlock source={example.source} language={example.language} showTitle={false} /></div><Button onClick={() => void copy(sdkSelected ? "Python example" : "Example", example.source)}>{sdkSelected ? "Copy Python example" : "Copy example"}</Button></div>}
    </div>
    {notice && <p role="status">{notice}</p>}
  </section>;
}
