import { useId } from "react";
import { Button, Field, Input } from "./ui";

const labelPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
export function appHostnamePrefix(hostname: string, domain: string): string {
  const suffix = `.${domain}`;
  return domain && hostname.endsWith(suffix) ? hostname.slice(0, -suffix.length) : hostname;
}
export function appHostnameFromInput(input: string, domain: string): string {
  const clean = input.trim().toLowerCase();
  if (!clean || !domain || clean === domain) return "";
  return `${appHostnamePrefix(clean, domain)}.${domain}`;
}
export function validAppHostname(hostname: string, domain: string): boolean {
  return !!domain && hostname.endsWith(`.${domain}`) && labelPattern.test(appHostnamePrefix(hostname, domain)) && hostname.length <= 253;
}

export default function AppAccessHostname({ value, domain, original, onChange }: { value: string; domain: string; original?: string; onChange: (value: string) => void }) {
  const legacy = !!original && value === original && !validAppHostname(value, domain);
  const descriptionId = useId();
  return <div className="space-y-2">
    {legacy ? <><p className="text-sm">Existing browser hostname: <span className="break-all font-mono">{value}</span></p><Button type="button" variant="ghost" disabled={!domain} onClick={() => onChange("")}>Change browser hostname</Button></> : <>
      <div className="flex min-w-0 flex-wrap items-end gap-2"><div className="min-w-0 flex-1"><Field label="Application subdomain"><Input required disabled={!domain} maxLength={253} pattern="[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?" title="Use one label of 1–63 letters, numbers or hyphens; start and end with a letter or number." placeholder="payroll" value={appHostnamePrefix(value, domain)} onChange={event => onChange(appHostnameFromInput(event.target.value, domain))} aria-describedby={descriptionId} /></Field></div><span className="min-h-9 break-all py-2 text-sm text-ink-secondary">{domain ? `.${domain}` : "Domain not configured"}</span></div>
      {value && !validAppHostname(value, domain) && <p role="alert" className="text-sm text-danger">Enter one subdomain label, such as payroll. Use 1–63 letters, numbers or hyphens.</p>}
    </>}
    <p id={descriptionId} className="break-all text-sm text-ink-secondary">{!domain ? "An operator must configure the Applications domain before choosing an address." : validAppHostname(value, domain) ? `Application address: https://${value}` : "The configured Applications domain is added automatically."}</p>
  </div>;
}
