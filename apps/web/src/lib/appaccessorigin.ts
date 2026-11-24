// Origin-policy guidance for App Access connection checks. The gateway refuses
// private destinations unless the saved policy lists their range; this only
// helps an admin find the exact single-host range for an origin written as a
// private IP literal. It never widens anything by itself: the suggestion is
// filled into the draft, which the admin must still save and re-check, and the
// server validates the range again.

const privateIPv4: Array<[number, number]> = [[0x0a000000, 8], [0xac100000, 12], [0xc0a80000, 16]];

function ipv4(value: string): number | null {
  const parts = value.split(".");
  if (parts.length !== 4 || parts.some(part => !/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255)) return null;
  return parts.reduce((sum, part) => sum * 256 + Number(part), 0);
}
function inIPv4(address: number, base: number, bits: number) {
  const size = 2 ** (32 - bits);
  return Math.floor(address / size) === Math.floor(base / size);
}
function coveredIPv4(address: number, allowed: string[]) {
  return allowed.some(value => {
    const [base, rawBits] = value.trim().split("/");
    const parsed = ipv4(base ?? ""), bits = Number(rawBits);
    return parsed !== null && Number.isInteger(bits) && bits >= 1 && bits <= 32 && inIPv4(address, parsed, bits);
  });
}

export type OriginRangeSuggestion = { address: string; range: string; covered: boolean };

/** The single-host range to allow for a private IP-literal origin, or null when none can be suggested. */
export function suggestedOriginRange(originUrl: string, allowed: string[] = []): OriginRangeSuggestion | null {
  let host: string;
  try { host = new URL(originUrl).hostname; } catch { return null; }
  const v4 = ipv4(host);
  if (v4 !== null) {
    if (!privateIPv4.some(([base, bits]) => inIPv4(v4, base, bits))) return null;
    return { address: host, range: `${host}/32`, covered: coveredIPv4(v4, allowed) };
  }
  // fc00::/7 unique-local only; other IPv6 literals are public or refused outright.
  const v6 = /^\[([0-9a-f:]+)\]$/i.exec(host)?.[1]?.toLowerCase();
  // fd00:ec2::254 (the EC2 metadata endpoint) is inside fc00::/7 but always refused by the server.
  if (!v6 || !/^f[cd][0-9a-f]{0,2}:/.test(v6) || v6 === "fd00:ec2::254") return null;
  const range = `${v6}/128`;
  return { address: v6, range, covered: allowed.some(value => value.trim().toLowerCase() === range) };
}
