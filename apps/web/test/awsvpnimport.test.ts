import { expect, it } from "vitest";
import { AWS_GENERIC_MAX_BYTES, AWSImportError, parseAWSGeneric } from "../src/lib/awsVpnImport";
import { awsGeneric } from "./fixtures/awsGeneric";

it.each(["bgp", "static"] as const)("imports Generic %s without assigning any site, attachment or access ranges", mode => {
  const result = parseAWSGeneric(awsGeneric({ mode }));
  expect(result.mode).toBe(`ipv4-${mode}`);
  expect(result.name).toBe("AWS vpn-0123456789abcdef0");
  expect(result.customerOutsideAddress).toBe("9.9.9.9");
  expect(result.cryptoMatches).toBe(false);
  expect(result.tunnels).toEqual([1,2].map(slot => ({ outside_address: slot === 1 ? "8.8.8.8" : "1.1.1.1", inside_cidr: `169.254.${slot + 10}.0/30`, customer_inside_address: `169.254.${slot + 10}.2`, cloud_inside_address: `169.254.${slot + 10}.1`, psk: `Synthetic.PSK_${slot}` })));
  if (mode === "bgp") expect(result.bgp).toEqual({ localASN: 65010, remoteASN: 64512 }); else expect(result.bgp).toBeUndefined();
  expect(result).not.toHaveProperty("remote_prefixes"); expect(result).not.toHaveProperty("site_id"); expect(result).not.toHaveProperty("attachment");
});
it.each(["Virtual Private Gateway", "Transit Gateway"])("accepts %s labels without inferring attachment authority", peer => {
  for (const mode of ["bgp", "static"] as const) expect(parseAWSGeneric(awsGeneric({ peer, mode })).mode).toBe(`ipv4-${mode}`);
});
it.each([7224, 64512, 65534, 4200000000, 4294967294])("preserves supported AWS ASN %s", remoteASN => {
  expect(parseAWSGeneric(awsGeneric({ remoteASN })).bgp?.remoteASN).toBe(remoteASN);
});
it("supports private 32-bit customer ASNs and CRLF, BOM and label whitespace", () => {
  const text = "\uFEFF" + awsGeneric({ localASN: 4200000001 }).replace(/ : /g, "\t: \t").replace(/\n/g, "\r\n");
  expect(parseAWSGeneric(text).bgp?.localASN).toBe(4200000001);
});
it("reports exact profile declarations without claiming negotiated compatibility", () => {
  expect(parseAWSGeneric(awsGeneric({ matchingCrypto: true })).cryptoMatches).toBe(true);
  expect(parseAWSGeneric(awsGeneric({ matchingCrypto: true }).replace("Diffie-Hellman Group 14", "Diffie-Hellman Group 2")).cryptoMatches).toBe(false);
});
it.each(["exampleSecret123", "replace_Secret123", "your_psk_ActualKey"])("preserves valid PSKs without guessing from their prefix", psk => {
  expect(parseAWSGeneric(awsGeneric().replace("Synthetic.PSK_1", psk)).tunnels[0].psk).toBe(psk);
});
it("takes a name only from bounded VPN ID metadata, never credential text", () => {
  const input = awsGeneric().replace("Your VPN Connection ID : vpn-0123456789abcdef0", "").replace("Synthetic.PSK_1", "vpn.0123456789abcdef0");
  expect(parseAWSGeneric(input).name).toBe("AWS connection");
});
it.each([
  ["missing tunnel", (s: string) => s.slice(0, s.indexOf("IPSec Tunnel #2"))],
  ["duplicate tunnel", (s: string) => s.replace("IPSec Tunnel #2", "IPSec Tunnel #1")],
  ["third tunnel", (s: string) => `${s}\nIPSec Tunnel #3`],
  ["duplicate key", (s: string) => s.replace("- Pre-Shared Key : Synthetic.PSK_1", "- Pre-Shared Key : Synthetic.PSK_1\n- Pre-Shared Key : OtherSecret_1")],
  ["missing inside section", (s: string) => s.replace("Inside IP Addresses", "Unrecognized section")],
  ["extra peer label", (s: string) => s.replace("- Virtual Private Gateway : 8.8.8.8", "- Virtual Private Gateway : 8.8.8.8\n- Transit Gateway : 8.8.4.4")],
  ["IKEv1", (s: string) => s.replace("IKEv2", "IKEv1")],
  ["certificate", (s: string) => s.replace("Pre-Shared Key\n", "Certificate\n")],
  ["transport mode", (s: string) => s.replace("Mode : tunnel", "Mode : transport")],
  ["IPv6 outer", (s: string) => s.replace("8.8.8.8", "2001:db8::1")],
  ["private outer", (s: string) => s.replace("8.8.8.8", "10.1.1.1")],
  ["special outer", (s: string) => s.replace("8.8.8.8", "192.0.2.1")],
  ["duplicate outer", (s: string) => s.replace("1.1.1.1", "8.8.8.8")],
  ["different customer", (s: string) => s.replace("Customer Gateway : 9.9.9.9", "Customer Gateway : 9.9.9.10")],
  ["overlapping inside", (s: string) => s.replace(/169\.254\.12\./g, "169.254.11.")],
  ["reserved inside", (s: string) => s.replace(/169\.254\.11\./g, "169.254.0.")],
  ["bad host", (s: string) => s.replace("169.254.11.2/30", "169.254.11.0/30")],
  ["mismatched subnet", (s: string) => s.replace("169.254.11.2/30", "169.254.13.2/30")],
  ["wrong prefix", (s: string) => s.replace("169.254.11.2/30", "169.254.11.2/31")],
  ["neighbor mismatch", (s: string) => s.replace("Neighbor IP Address : 169.254.11.1", "Neighbor IP Address : 169.254.11.2")],
  ["ASN mismatch", (s: string) => s.replace("Customer Gateway ASN : 65010", "Customer Gateway ASN : 65011")],
  ["mixed routing", (s: string) => s.replace("#4: Border Gateway Protocol (BGP) Configuration:", "#4: Static Routing Configuration:")],
  ["placeholder", (s: string) => s.replace("Synthetic.PSK_1", "<your-secret>")],
  ["missing PSK", (s: string) => s.replace("- Pre-Shared Key : Synthetic.PSK_1", "")],
  ["binary", (s: string) => s + "\0"],
] as const)("rejects %s with redacted errors", (_, transform) => {
  try { parseAWSGeneric(transform(awsGeneric())); expect.fail("accepted malformed file"); }
  catch (error) { expect(error).toBeInstanceOf(AWSImportError); expect(String(error)).not.toMatch(/Synthetic|OtherSecret|your-secret|6501|8\.8/); }
});
it.each([65010, 65535, 4294967295, 12345])("rejects equal or unsupported AWS ASN %s", remoteASN => {
  expect(() => parseAWSGeneric(awsGeneric({ remoteASN }))).toThrow(AWSImportError);
});
it("bounds input and rejects XML and arbitrary text", () => {
  for (const text of ["", "x".repeat(AWS_GENERIC_MAX_BYTES + 1), "<vpn_connection>secret</vpn_connection>", "not an AWS Generic download"]) expect(() => parseAWSGeneric(text)).toThrow(AWSImportError);
});
