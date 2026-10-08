import { VscAzure } from "react-icons/vsc";
import openai from "../assets/providers/openai.svg";
import anthropic from "../assets/providers/anthropic.svg";
import gemini from "../assets/providers/gemini.svg";
import groq from "../assets/providers/groq.svg";
import mistral from "../assets/providers/mistral.svg";
import cerebras from "../assets/providers/cerebras.svg";
import xai from "../assets/providers/xai.svg";
import deepseek from "../assets/providers/deepseek.svg";
import sagemaker from "../assets/providers/sagemaker.svg";
const logos: Record<string, string> = { openai, anthropic, gemini, groq, mistral, cerebras, xai, deepseek, sagemaker };
export function ProviderLogo({ provider }: { provider: string }) {
  if (provider === "azure_foundry") return <VscAzure aria-hidden="true" className="ai-provider-logo" style={{ color: "#0078d4" }} size={24} />;
  if (provider === "openrouter") return <svg aria-hidden="true" className="ai-provider-logo ai-provider-logo-monochrome" viewBox="0 0 300 300" fill="currentColor" stroke="currentColor" strokeMiterlimit={2.3}>
    <path fill="none" strokeWidth={52.7} d="M1.8,145.9c8.8,0,42.8-7.6,60.4-17.5s17.6-10,53.9-35.7c46-32.6,78.5-21.7,131.8-21.7" />
    <path strokeWidth={0.6} d="M299.4,71.2l-90.1,52V19.2l90.1,52Z" />
    <path fill="none" strokeWidth={52.7} d="M0,145.9c8.8,0,42.8,7.6,60.4,17.5s17.6,10,53.9,35.7c46,32.6,78.5,21.7,131.8,21.7" />
    <path strokeWidth={0.6} d="M297.7,220.6l-90.1-52v104l90.1-52Z" />
  </svg>;
  const src = logos[provider];
  return src ? <img src={src} alt="" aria-hidden="true" className="ai-provider-logo" width={24} height={24} /> : provider === "custom" ? <svg aria-hidden="true" className="ai-provider-logo ai-provider-logo-custom" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M9 5v5m6-5v5M7 10h10v3a5 5 0 0 1-10 0v-3Zm5 8v3" /><path d="M6 10h12" /></svg> : null;
}
