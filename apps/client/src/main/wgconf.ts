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
  const seenInterfaceKeys = new Set<string>();
  const seenPeerKeys = new Set<string>();
  const interfaceKeys = new Set(["privatekey", "address", "dns", "mtu"]);
  const peerKeys = new Set(["publickey", "endpoint", "allowedips", "persistentkeepalive"]);
  let sawInterface = false;
  let sawPeer = false;
  let section: "interface" | "peer" | null = null;

  for (const [index, rawLine] of text.split(/\r?\n/).entries()) {
    const lineNumber = index + 1;
    const line = rawLine.replace(/#.*$/, "").trim();
    if (line === "") continue;
    const lower = line.toLowerCase();
    if (lower === "[interface]") {
      if (sawInterface) throw new Error(`malformed .conf line ${lineNumber}: duplicate Interface section`);
      sawInterface = true;
      section = "interface";
      continue;
    }
    if (lower === "[peer]") {
      if (sawPeer) throw new Error(`malformed .conf line ${lineNumber}: duplicate Peer section`);
      sawPeer = true;
      section = "peer";
      continue;
    }
    if (line.startsWith("[") && line.endsWith("]")) {
      throw new Error(`malformed .conf line ${lineNumber}: unsupported section`);
    }
    const eq = line.indexOf("=");
    // A .conf can contain a one-time WireGuard private key. Never echo raw
    // parser input (or a value derived from it) through IPC/logging on failure.
    if (section === null) throw new Error(`malformed .conf line ${lineNumber}: setting outside a section`);
    if (eq < 0) throw new Error(`malformed .conf line ${lineNumber}: expected key = value`);
    const key = line.slice(0, eq).trim().toLowerCase();
    const value = line.slice(eq + 1).trim();
    const allowed = section === "interface" ? interfaceKeys : peerKeys;
    const seen = section === "interface" ? seenInterfaceKeys : seenPeerKeys;
    const sectionName = section === "interface" ? "Interface" : "Peer";
    if (!allowed.has(key)) {
      // The unknown key text itself is untrusted and could contain a secret.
      // Keep the diagnostic useful without echoing it or the raw line/value.
      throw new Error(`malformed .conf line ${lineNumber}: unsupported ${sectionName} directive`);
    }
    if (key !== "address" && seen.has(key)) {
      throw new Error(`malformed .conf line ${lineNumber}: duplicate ${sectionName}.${key}`);
    }
    seen.add(key);
    if (key === "mtu") {
      if (!/^\d+$/.test(value)) throw new Error(`malformed .conf line ${lineNumber}: invalid Interface.mtu`);
      const mtu = Number(value);
      if (!Number.isInteger(mtu) || (mtu !== 0 && (mtu < 1280 || mtu > 1500))) {
        throw new Error(`malformed .conf line ${lineNumber}: invalid Interface.mtu`);
      }
    }
    if (key === "persistentkeepalive") {
      if (!/^\d+$/.test(value)) throw new Error(`malformed .conf line ${lineNumber}: invalid Peer.persistentkeepalive`);
      const keepalive = Number(value);
      if (!Number.isInteger(keepalive) || keepalive < 0 || keepalive > 65535) {
        throw new Error(`malformed .conf line ${lineNumber}: invalid Peer.persistentkeepalive`);
      }
    }
    if (section === "interface" && key === "address") {
      const addresses = value.split(",").map((s) => s.trim()).filter(Boolean);
      if (addresses.length === 0) throw new Error(`malformed .conf line ${lineNumber}: invalid Interface.address`);
      interfaceAddresses.push(...addresses);
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
    cfg.mtu = Number(iface.mtu);
  }
  if (peer.persistentkeepalive) {
    cfg.persistent_keepalive = Number(peer.persistentkeepalive);
  }
  return cfg;
}
