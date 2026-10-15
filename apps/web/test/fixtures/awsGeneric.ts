// Entirely synthetic AWS Generic-shaped input. Never replace with a real download.
export function awsGeneric({ mode = "bgp", peer = "Virtual Private Gateway", localASN = 65010, remoteASN = 64512, matchingCrypto = false }: { mode?: "bgp" | "static"; peer?: string; localASN?: number; remoteASN?: number; matchingCrypto?: boolean } = {}): string {
  return `AWS Site-to-Site VPN\nYour VPN Connection ID : vpn-0123456789abcdef0\n` + [1, 2].map(slot => `
IPSec Tunnel #${slot}
#1: Internet Key Exchange Configuration
The following configuration describes minimum requirements.
  - IKE version : IKEv2
  - Authentication Method : Pre-Shared Key
  - Pre-Shared Key : Synthetic.PSK_${slot}
  - Authentication Algorithm : ${matchingCrypto ? "sha256" : "sha1"}
  - Encryption Algorithm : ${matchingCrypto ? "aes-256-cbc" : "aes-128-cbc"}
  - Lifetime : 28800 seconds
  - Phase 1 Negotiation Mode : main
  - Diffie-Hellman : Group ${matchingCrypto ? 14 : 2}
#2: IPSec Configuration
  - Protocol : esp
  - Authentication Algorithm : ${matchingCrypto ? "hmac-sha256-128" : "hmac-sha1-96"}
  - Encryption Algorithm : ${matchingCrypto ? "aes-256-cbc" : "aes-128-cbc"}
  - Lifetime : 3600 seconds
  - Mode : tunnel
  - Perfect Forward Secrecy : Diffie-Hellman Group ${matchingCrypto ? 14 : 2}
#3: Tunnel Interface Configuration
Outside IP Addresses:
  - Customer Gateway : 9.9.9.9
  - ${peer} : ${slot === 1 ? "8.8.8.8" : "1.1.1.1"}
Inside IP Addresses
  - Customer Gateway : 169.254.${slot + 10}.2/30
  - ${peer} : 169.254.${slot + 10}.1/30
  - Tunnel interface MTU : 1436 bytes
${mode === "bgp" ? `#4: Border Gateway Protocol (BGP) Configuration:
  - Customer Gateway ASN : ${localASN}
  - ${peer.replace("Private Gateway", "Private  Gateway")} ASN : ${remoteASN}
  - Neighbor IP Address : 169.254.${slot + 10}.1
  - Neighbor Hold Time : 30` : `#4: Static Routing Configuration:
Sample default route 0.0.0.0/0 is not an authorized Tunnex remote range.`}
`).join("\n");
}
