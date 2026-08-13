import type { TunnelConfig } from "./helperclient";

// parseWgConf turns a WireGuard `.conf` (the one-time text the server returns at
// device creation — D2) into the helper's STRUCTURED TunnelConfig. Parsing happens
// in MAIN; the resulting private key never leaves main (→ safeStorage → helper).
//
// It is strict: unknown/malformed input throws rather than producing a partial
// config the root helper would then have to defend against. full_tunnel is set by
// the caller from the create INTENT, not guessed here (the helper enforces
// both-family completeness when it's true).
export function parseWgConf(text: string): Omit<TunnelConfig, "full_tunnel"> {
  const iface: Record<string, string> = {};
  const interfaceAddresses: string[] = [];
  const peer: Record<string, string> = {};
  let section: "interface" | "peer" | null = null;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (line === "") continue;
    const lower = line.toLowerCase();
    if (lower === "[interface]") {
      section = "interface";
      continue;
    }
    if (lower === "[peer]") {
      section = "peer";
      continue;
    }
    const eq = line.indexOf("=");
    if (eq < 0 || section === null) throw new Error(`malformed .conf line: ${rawLine}`);
    const key = line.slice(0, eq).trim().toLowerCase();
    const value = line.slice(eq + 1).trim();
    if (section === "interface" && key === "address") {
      interfaceAddresses.push(...value.split(",").map((s) => s.trim()).filter(Boolean));
    } else {
      (section === "interface" ? iface : peer)[key] = value;
    }
  }

  const need = (m: Record<string, string>, k: string, where: string): string => {
    const v = m[k];
    if (!v) throw new Error(`.conf missing ${where}.${k}`);
    return v;
  };

  const cfg: Omit<TunnelConfig, "full_tunnel"> = {
    private_key: need(iface, "privatekey", "Interface"),
    address: interfaceAddresses[0] ?? need(iface, "address", "Interface").split(",")[0].trim(),
    addresses: interfaceAddresses.length > 0 ? interfaceAddresses : undefined,
    peer_public_key: need(peer, "publickey", "Peer"),
    endpoint: need(peer, "endpoint", "Peer"),
    allowed_ips: need(peer, "allowedips", "Peer")
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s !== ""),
  };
  if (iface.dns) cfg.dns = iface.dns.split(",").map((s) => s.trim()).filter((s) => s !== "");
  if (iface.mtu) {
    const mtu = Number(iface.mtu);
    if (Number.isFinite(mtu)) cfg.mtu = mtu;
  }
  if (peer.persistentkeepalive) {
    const ka = Number(peer.persistentkeepalive);
    if (Number.isFinite(ka)) cfg.persistent_keepalive = ka;
  }
  return cfg;
}
