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
  const src = logos[provider];
  return src ? <img src={src} alt="" aria-hidden="true" className="ai-provider-logo" width={24} height={24} /> : provider === "custom" ? <svg aria-hidden="true" className="ai-provider-logo" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="4" y="3" width="16" height="7" rx="2" /><rect x="4" y="14" width="16" height="7" rx="2" /><path d="M7 6h2m-2 11h2" /></svg> : null;
}
