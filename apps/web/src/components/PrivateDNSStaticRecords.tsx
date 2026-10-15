import type { components } from "@tunnex/shared";
import { Button, Field, Input, Select } from "./ui";

export type PrivateDNSStaticRecord = components["schemas"]["FQDNStaticRecord"];
export const emptyStaticRecord = (): PrivateDNSStaticRecord => ({ name: "", type: "A", value: "", ttl: 300 });

export function PrivateDNSStaticRecords({ records, onChange, onNameBlur, profileIndex }: {
  records: PrivateDNSStaticRecord[];
  onChange: (records: PrivateDNSStaticRecord[]) => void;
  onNameBlur?: (name: string) => void;
  profileIndex: number;
}) {
  const update = (index: number, value: Partial<PrivateDNSStaticRecord>) => onChange(records.map((record, i) => i === index ? { ...record, ...value } : record));
  return <div className="space-y-2">
    <p className="text-xs text-ink-tertiary">Enter a hostname and its private IP address, or choose CNAME for a load balancer hostname.</p>
    {records.map((record, index) => <div key={index} className="space-y-3 rounded-inset border border-line p-3"><div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_90px_minmax(0,1fr)]">
      <Field label="Hostname"><Input aria-label={`Profile ${profileIndex + 1} record ${index + 1} name`} placeholder="app.internal.example.com" value={record.name} onChange={event => update(index, { name: event.target.value })} onBlur={() => index === 0 && onNameBlur?.(record.name)} /></Field>
      <Field label="Type"><Select aria-label={`Profile ${profileIndex + 1} record ${index + 1} type`} value={record.type} onChange={event => update(index, { type: event.target.value as PrivateDNSStaticRecord["type"] })}><option value="A">A</option><option value="AAAA">AAAA</option><option value="CNAME">CNAME</option></Select></Field>
      <Field label={record.type === "CNAME" ? "Target hostname" : "IP address"}><Input aria-label={`Profile ${profileIndex + 1} record ${index + 1} value`} placeholder={record.type === "CNAME" ? "target.example.com" : record.type === "AAAA" ? "fd00::10" : "10.20.1.10"} value={record.value} onChange={event => update(index, { value: event.target.value })} /></Field>
      </div><div className="flex items-start justify-between gap-3 border-t border-line pt-2"><details className="text-xs text-ink-tertiary"><summary className="cursor-pointer">TTL: {record.ttl}s</summary><div className="mt-2 w-28"><Input aria-label={`Profile ${profileIndex + 1} record ${index + 1} TTL seconds`} type="number" min={30} max={86400} value={record.ttl} onChange={event => update(index, { ttl: Number(event.target.value) })} /></div></details>
      {records.length > 1 && <Button size="sm" variant="ghost" aria-label={`Remove profile ${profileIndex + 1} record ${index + 1}`} onClick={() => onChange(records.filter((_, i) => i !== index))}>Remove</Button>}
    </div></div>)}
    {records.length < 128 && <Button size="sm" variant="ghost" onClick={() => onChange([...records, emptyStaticRecord()])}>Add record</Button>}
    <details className="text-xs text-ink-tertiary"><summary className="cursor-pointer font-medium text-ink-heading">Record types and DNS behavior</summary><div className="mt-2 space-y-2"><p>A uses a private IPv4 address, AAAA a private IPv6 address, and CNAME another hostname. Record names must be inside this profile's DNS zones. TTL is in seconds (30–86400).</p><p>CNAME keeps the target hostname so load balancer address changes follow its DNS TTL. External targets use target lookup below; with it off, only the alias is returned. Same-profile targets use their local records. Targets in another private profile are not supported.</p><p>DNS answers do not grant application access. Allow the application IP or subnet separately.</p></div></details>
  </div>;
}
