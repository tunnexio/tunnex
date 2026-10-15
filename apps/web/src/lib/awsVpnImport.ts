import type { components } from "@tunnex/shared";

type Tunnel = components["schemas"]["IPsecConfigurationCheckInput"]["tunnels"][number];
export type AWSGenericImport = {
  name: string;
  mode: "ipv4-static" | "ipv4-bgp";
  customerOutsideAddress: string;
  tunnels: Tunnel[];
  bgp?: { localASN: number; remoteASN: number };
  cryptoMatches: boolean;
};
export const AWS_GENERIC_MAX_BYTES = 65536;
export const AWS_REQUIRED_CRYPTO = "IKEv2 with PSK; IKE and ESP AES256-CBC, SHA256, DH/PFS group 14 (MODP2048)";
// Only fixed messages leave the parser. Never include a supplied value in errors.
export class AWSImportError extends Error {}
function fail(message: string): never { throw new AWSImportError(message); }
const invalid = () => fail("AWS file was not imported. Use the AWS Generic IPv4 configuration with exactly two complete tunnel sections; XML and device scripts are not supported.");
const normalize = (value: string) => value.trim().toLowerCase().replace(/\s+/g, " ");
function ipv4(value: string): number {
  if (!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(value)) return invalid();
  const octets = value.split(".").map(Number);
  if (octets.some(octet => octet > 255)) return invalid();
  return octets.reduce((n, octet) => n * 256 + octet, 0);
}
const special = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"];
function publicIPv4(value: string): string {
  const address = ipv4(value);
  if (special.some(cidr => { const [base, bits] = cidr.split("/"); const size = 2 ** (32 - Number(bits)); return Math.floor(address / size) === Math.floor(ipv4(base) / size); })) fail("AWS file was not imported. Customer and AWS outside addresses must be public IPv4 addresses supported by Tunnex.");
  return value;
}
function inside(value: string): { address: string; network: string } {
  const [address, prefix, extra] = value.split("/");
  const n = ipv4(address);
  if (prefix !== "30" || extra !== undefined || !address.startsWith("169.254.") || (n % 4 !== 1 && n % 4 !== 2)) invalid();
  const network = `${address.substring(0, address.lastIndexOf(".") + 1)}${Math.floor(n % 256 / 4) * 4}/30`;
  if (["169.254.0.0/30", "169.254.1.0/30", "169.254.2.0/30", "169.254.3.0/30", "169.254.4.0/30", "169.254.5.0/30", "169.254.169.252/30"].includes(network)) fail("AWS file was not imported. A tunnel uses an AWS-reserved inside /30. Download a configuration with supported inside addresses.");
  return { address, network };
}
function asn(value: string, remote: boolean): number {
  const n = Number(value);
  if (!/^\d+$/.test(value) || !Number.isSafeInteger(n) || !((n >= 64512 && n <= 65534) || (n >= 4200000000 && n <= 4294967294) || (remote && n === 7224))) fail("AWS file was not imported. Tunnex requires private customer/AWS ASNs, or AWS legacy ASN 7224. Keep the actual ASN; do not substitute another value.");
  return n;
}
type Section = Map<string, string>;
function required(fields: Section | undefined, key: string): string { return fields?.get(key) ?? invalid(); }
function peer(fields: Section | undefined, suffix = ""): string {
  const values = ["virtual private gateway", "transit gateway"].map(label => fields?.get(label + suffix)).filter((value): value is string => value !== undefined);
  if (values.length !== 1) return invalid();
  return values[0];
}

/** Parse AWS Generic text in memory. The file supplies no site, access scope or attachment authority. */
export function parseAWSGeneric(text: string): AWSGenericImport {
  if (new TextEncoder().encode(text).length > AWS_GENERIC_MAX_BYTES || !text.trim() || /[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(text)) fail("AWS file was not imported. Choose a nonempty Generic text file no larger than 64 KiB.");
  const lines = text.replace(/^\uFEFF/, "").split(/\r?\n/);
  if (lines.length > 2048 || lines.some(line => line.length > 2048)) invalid();
  const blocks = new Map<number, Map<string, Section>>();
  let block: Map<string, Section> | undefined, section = "", addressSection = "";
  for (const raw of lines) {
    const line = raw.trim();
    const heading = /^IPSec Tunnel\s*#(\d+)\s*:?$/i.exec(line);
    if (heading) {
      const slot = Number(heading[1]);
      if ((slot !== 1 && slot !== 2) || blocks.has(slot)) invalid();
      block = new Map(); blocks.set(slot, block); section = ""; addressSection = ""; continue;
    }
    if (/^IPSec Tunnel\b/i.test(line)) invalid();
    if (!block) continue;
    const sectionHeading = /^#(\d+)\s*:\s*(.*?)\s*:?$/.exec(line);
    if (sectionHeading) {
      const title = normalize(sectionHeading[2]).replace(/:$/, "");
      const headings: Record<string, string> = { "internet key exchange configuration": "ike", "ipsec configuration": "esp", "tunnel interface configuration": "interface", "border gateway protocol (bgp) configuration": "bgp", "static routing configuration": "static" };
      section = headings[title];
      const expected = ["ike", "esp", "interface", "bgp", "static"].indexOf(section);
      if (!section || Number(sectionHeading[1]) !== (expected === 4 ? 4 : expected + 1) || block.has(section)) invalid();
      block.set(section, new Map()); addressSection = ""; continue;
    }
    if (/^(outside|inside) ip addresses\s*:?$/i.test(line)) {
      if (section !== "interface") invalid();
      addressSection = line.toLowerCase().startsWith("outside") ? "outside" : "inside";
      if (block.has(addressSection)) invalid();
      block.set(addressSection, new Map()); continue;
    }
    const field = /^-\s*([^:]+?)\s*:\s*(.*?)\s*$/.exec(line);
    if (!field || !section) continue;
    const fields = block.get(section === "interface" && addressSection ? addressSection : section)!;
    const key = normalize(field[1]);
    if (fields.has(key)) invalid();
    fields.set(key, field[2]);
  }
  if (blocks.size !== 2) invalid();
  let mode: AWSGenericImport["mode"] | undefined, customerOutsideAddress = "", bgp: AWSGenericImport["bgp"], cryptoMatches = true;
  const tunnels = [1, 2].map(slot => {
    const fields = blocks.get(slot)!;
    const ike = fields.get("ike"), esp = fields.get("esp");
    if (normalize(required(ike, "ike version")) !== "ikev2" || normalize(required(ike, "authentication method")) !== "pre-shared key") fail("AWS file was not imported. Tunnex requires IKEv2 with pre-shared keys; IKEv1 and certificate authentication are not supported.");
    if (normalize(required(esp, "protocol")) !== "esp" || normalize(required(esp, "mode")) !== "tunnel") fail("AWS file was not imported. Use an ESP tunnel-mode Generic configuration.");
    const checks: [Section | undefined, string, RegExp][] = [
      [ike, "authentication algorithm", /^(?:sha256|sha-256)$/], [ike, "encryption algorithm", /^aes-256-cbc$/], [ike, "diffie-hellman", /^group 14$/],
      [esp, "authentication algorithm", /^(?:hmac-sha256-128|hmac-sha-256-128|sha256|sha-256)$/], [esp, "encryption algorithm", /^aes-256-cbc$/], [esp, "perfect forward secrecy", /^(?:diffie-hellman )?group 14$/],
    ];
    for (const [values, key, pattern] of checks) if (!pattern.test(normalize(required(values, key)))) cryptoMatches = false;
    const psk = required(ike, "pre-shared key");
    if (!/^[A-Za-z1-9_.][A-Za-z0-9_.]{7,63}$/.test(psk)) fail("AWS file was not imported. Each tunnel needs its actual supported pre-shared key. Placeholder credentials are not accepted.");
    const outside = fields.get("outside"), insideFields = fields.get("inside");
    const customer = publicIPv4(required(outside, "customer gateway"));
    if (slot > 1 && customer !== customerOutsideAddress) invalid();
    customerOutsideAddress = customer;
    const cloudOutside = publicIPv4(peer(outside));
    const customerInside = inside(required(insideFields, "customer gateway")), cloudInside = inside(peer(insideFields));
    if (cloudOutside === customer || customerInside.network !== cloudInside.network || customerInside.address === cloudInside.address) invalid();
    if (fields.has("bgp") === fields.has("static")) invalid();
    const routing = fields.has("bgp") ? "ipv4-bgp" : "ipv4-static";
    if (mode && mode !== routing) invalid();
    mode = routing;
    if (routing === "ipv4-bgp") {
      const routingFields = fields.get("bgp");
      const next = { localASN: asn(required(routingFields, "customer gateway asn"), false), remoteASN: asn(peer(routingFields, " asn"), true) };
      if (next.localASN === next.remoteASN || (bgp && (bgp.localASN !== next.localASN || bgp.remoteASN !== next.remoteASN)) || required(routingFields, "neighbor ip address") !== cloudInside.address) invalid();
      bgp = next;
    }
    return { outside_address: cloudOutside, inside_cidr: customerInside.network, customer_inside_address: customerInside.address, cloud_inside_address: cloudInside.address, psk };
  });
  if (tunnels[0].outside_address === tunnels[1].outside_address || tunnels[0].inside_cidr === tunnels[1].inside_cidr) invalid();
  const ids = [...new Set([...text.matchAll(/^\s*(?:Your )?VPN Connection ID\s*:\s*(vpn-[a-f0-9]{8,17})\s*$/gim)].map(match => match[1]))];
  return { name: ids.length === 1 ? `AWS ${ids[0]}` : "AWS connection", mode: mode!, customerOutsideAddress, tunnels, ...(bgp ? { bgp } : {}), cryptoMatches };
}
