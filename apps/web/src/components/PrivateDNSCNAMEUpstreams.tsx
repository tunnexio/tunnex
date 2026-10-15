import type { FQDNResolverEndpoint } from "../lib/api";
import { Button, Input, Select } from "./ui";

export const defaultCNAMEUpstreams = (): FQDNResolverEndpoint[] => ["1.1.1.1", "8.8.8.8"].map(address => ({ address, port: 53, transport: "udp" }));
export const validCNAMEUpstreams = (endpoints: FQDNResolverEndpoint[]) => endpoints.length <= 3
  && new Set(endpoints.map(endpoint => endpoint.address.trim())).size === endpoints.length
  && endpoints.every(endpoint =>
  endpoint.address.trim().split(".").length === 4 && endpoint.address.trim().split(".").every(part => /^(0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255)
  && endpoint.port === 53 && ["udp", "tcp"].includes(endpoint.transport));

export function PrivateDNSCNAMEUpstreams({ endpoints, onChange, profileIndex }: {
  endpoints: FQDNResolverEndpoint[];
  onChange: (endpoints: FQDNResolverEndpoint[]) => void;
  profileIndex: number;
}) {
  const label = `Profile ${profileIndex + 1}`;
  return <div className="space-y-2 rounded-inset border border-line p-3">
    <p className="text-sm text-ink-heading">CNAME target lookup</p>
    <p className="text-xs text-ink-tertiary">{endpoints.length ? `Normal DNS upstreams: ${endpoints.map(endpoint => endpoint.address || "not set").join(", ")}.` : "Alias only: external target addresses are not looked up by this profile."} These are ordinary DNS servers, not paid cloud resolver endpoints. A and AAAA records need no upstream.</p>
    <details><summary className="cursor-pointer text-xs font-medium text-ink-heading">Advanced target DNS settings</summary><div className="mt-3 space-y-2">
      <label className="flex items-center gap-2 text-sm"><input aria-label={`${label} resolve external CNAME targets`} type="checkbox" checked={endpoints.length > 0} onChange={event => onChange(event.target.checked ? defaultCNAMEUpstreams() : [])} />Resolve external CNAME targets</label>
      {endpoints.map((endpoint, index) => <div key={index} className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_100px_auto]">
        <Input aria-label={`${label} CNAME upstream ${index + 1} IP`} placeholder="1.1.1.1" value={endpoint.address} onChange={event => onChange(endpoints.map((item, i) => i === index ? { ...item, address: event.target.value } : item))} />
        <Select aria-label={`${label} CNAME upstream ${index + 1} transport`} value={endpoint.transport} onChange={event => onChange(endpoints.map((item, i) => i === index ? { ...item, transport: event.target.value as "udp" | "tcp" } : item))}><option value="udp">UDP</option><option value="tcp">TCP</option></Select>
        <Button size="sm" variant="ghost" aria-label={`Remove ${label.toLowerCase()} CNAME upstream ${index + 1}`} onClick={() => onChange(endpoints.filter((_, i) => i !== index))}>Remove</Button>
      </div>)}
      {endpoints.length > 0 && endpoints.length < 3 && <Button size="sm" variant="ghost" onClick={() => onChange([...endpoints, { address: "", port: 53, transport: "udp" }])}>Add target DNS server</Button>}
      <p className="text-xs text-ink-tertiary">Up to three public IPv4 DNS servers on port 53. The gateway must reach them on UDP and TCP. Only targets outside all configured private zones use these servers; private targets in another profile are refused. This does not change the office's default DNS or private-zone forwarding.</p>
    </div></details>
  </div>;
}
