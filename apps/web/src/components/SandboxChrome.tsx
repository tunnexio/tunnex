import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Logo } from "../brand";
import type { Sandbox, SandboxTemplate } from "../lib/api";
import { ImageProfileDetails } from "./SandboxImageProfiles";
import ubuntu from "../assets/sandbox/ubuntu.svg";
import openai from "../assets/providers/openai.svg";
import anthropic from "../assets/providers/anthropic.svg";
import "../sandbox-workspace.css";

export function SandboxHeader({ title, subtitle, actions, section = "workspaces" }: { title: string; subtitle: string; actions?: ReactNode; section?: "workspaces" | "skills" }) {
  return <>
    <header className="sb-header">
      <div><div className="sb-eyebrow"><Logo size={17} /> <span>/ DEVELOPER WORKSPACES</span></div><h1>{title}</h1><p>{subtitle}</p></div>
      <div className="sb-header-actions">{actions}</div>
    </header>
    <nav className="sb-tabs" aria-label="Sandbox navigation">
      <Link to="/sandboxes" aria-current={section === "workspaces" ? "page" : undefined}>Workspaces</Link>
      <Link to="/sandboxes/skills" aria-current={section === "skills" ? "page" : undefined}>Skills</Link>
      <span>PRIVATE WORKSPACE ACCESS</span>
    </nav>
  </>;
}

export function RuntimeMark({ template, large = false }: { template?: SandboxTemplate; large?: boolean }) {
  const isUbuntu = /\bubuntu\b/i.test(template?.name ?? "");
  return <span className={`sb-runtime-mark${large ? " sb-runtime-mark-large" : ""}`}>
    {isUbuntu ? <img src={ubuntu} alt="Ubuntu" /> : <Logo markOnly size={large ? 38 : 25} />}
  </span>;
}

export function RuntimeSpecs({ template, lifetime }: { template?: SandboxTemplate; lifetime?: string }) {
  return <><dl className="sb-specs">
    <div><dt>Memory</dt><dd>{template ? `${template.memory_mib} MiB` : "Not specified"}</dd></div>
    <div><dt>CPU / storage</dt><dd className="sb-unspecified">Not specified</dd></div>
    <div><dt>{lifetime ? "Lifetime" : "Max lifetime"}</dt><dd>{lifetime ?? (template ? `${Math.floor(template.max_ttl_seconds / 60)} min` : "Not specified")}</dd></div>
  </dl><ImageProfileDetails profile={template?.image_profile}/></>;
}

export function isConnectable(item: Sandbox, now = Date.now()) {
  return !!item.connection && item.observed_state === "ready" && item.desired_state === "started" && new Date(item.expires_at).getTime() > now;
}
export function remainingLifetime(expires: string, now = Date.now()) {
  const milliseconds = new Date(expires).getTime() - now;
  if (!Number.isFinite(milliseconds)) return "Expiry unavailable";
  if (milliseconds <= 0) return "Expired";
  const minutes = Math.ceil(milliseconds / 60000);
  return minutes >= 60 ? `${Math.floor(minutes / 60)}h ${minutes % 60}m left` : `${minutes}m left`;
}
export function SandboxStatus({ item, now }: { item: Sandbox; now?: number }) {
  const expired = new Date(item.expires_at).getTime() <= (now ?? Date.now());
  const state = expired ? "expired" : item.observed_state;
  return <span className="sb-status" data-state={state === "ready" && !isConnectable(item, now) ? "waiting" : state}><span aria-hidden />{state}</span>;
}

export function WorkflowNote() {
  return <div className="sb-workflow-note"><span>Local tools over private SSH</span><div><span className="sb-terminal-symbol" aria-hidden>&gt;_</span> Terminal <span className="sb-workflow-divider" /> <img src={openai} alt="" /> Codex <span className="sb-workflow-divider" /> <img src={anthropic} alt="" /> Claude</div><details><summary>Local tools</summary><p>Use your existing tools over SSH; none are installed here.</p></details></div>;
}

export function LaunchArtwork() {
  return <div className="sb-launch-art" aria-hidden>
    <div className="sb-art-grid" /><div className="sb-art-orbit" />
    <div className="sb-art-platform sb-art-platform-back" /><div className="sb-art-platform sb-art-platform-front" />
    <div className="sb-art-mark"><Logo markOnly size={76} /></div>
    <span className="sb-art-label">TUNNEX / SANDBOX</span><span className="sb-art-corner">PRIVATE SSH</span>
  </div>;
}
