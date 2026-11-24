import { suggestedOriginRange } from "../lib/appaccessorigin";
import { Button } from "./ui";

// AA-1: say before saving that the gateway will refuse a private origin outside the allowed ranges.
export function OriginRangeNotice({ originUrl, allowed, gatewayName, onAllow }: { originUrl: string; allowed: string[]; gatewayName?: string; onAllow?: (cidr: string) => void }) {
  let host = "";
  try { host = new URL(originUrl).hostname; } catch { return null; }
  const suggestion = suggestedOriginRange(originUrl, allowed);
  const gateway = gatewayName ? `The gateway ${gatewayName}` : "The selected gateway";
  if (suggestion && !suggestion.covered) return <div role="note" className="aa-editor-field-help space-y-2">
    <p>{gateway} will refuse {suggestion.address}: private origins need their range listed under Advanced connection settings → Allowed private destination ranges.</p>
    {onAllow && <Button variant="ghost" type="button" onClick={() => onAllow(suggestion.range)}>Allow {suggestion.range}</Button>}
  </div>;
  if (!suggestion && !/^[0-9.]+$/.test(host) && !host.startsWith("[")) return <p className="aa-editor-field-help">{gateway} resolves {host} when it connects. If it resolves to a private address, list that address's range under Advanced connection settings → Allowed private destination ranges.</p>;
  return null;
}
