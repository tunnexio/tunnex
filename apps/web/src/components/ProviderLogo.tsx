import { VscAzure } from "react-icons/vsc";
import openai from "../assets/providers/openai.svg";
import anthropic from "../assets/providers/anthropic.svg";
import gemini from "../assets/providers/gemini.svg";
import openrouter from "../assets/providers/openrouter.svg";
import groq from "../assets/providers/groq.svg";
import mistral from "../assets/providers/mistral.svg";
import cerebras from "../assets/providers/cerebras.svg";
import xai from "../assets/providers/xai.svg";
import deepseek from "../assets/providers/deepseek.svg";
import sagemaker from "../assets/providers/sagemaker.svg";
const logos: Record<string, string> = { openai, anthropic, gemini, openrouter, groq, mistral, cerebras, xai, deepseek, sagemaker };
export function ProviderLogo({ provider }: { provider: string }) {
  if (provider === "azure_foundry") return <VscAzure aria-hidden="true" className="ai-provider-logo" style={{ color: "#0078d4" }} size={24} />;
  const src = logos[provider];
  return src ? <img src={src} alt="" aria-hidden="true" className="ai-provider-logo" width={24} height={24} /> : provider === "custom" ? <svg aria-hidden="true" className="ai-provider-logo ai-provider-logo-custom" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M9 5v5m6-5v5M7 10h10v3a5 5 0 0 1-10 0v-3Zm5 8v3" /><path d="M6 10h12" /></svg> : null;
}
