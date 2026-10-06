import type { components } from "@tunnex/shared";
type Server = components["schemas"]["ServerAccessServer"];
export type BootstrapResult = { version: 1; org_id: string; server_id: string; ssh_port: number; accounts: string[]; host_fingerprint: string };
const marker = "BUNDLE = None  # Replaced only in the administrator-downloaded server bundle.";
function base64(bytes: Uint8Array) { return btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join("")); }
export async function bootstrapBundle(helper: string, publicKey: string, orgId: string, server: Server, fingerprint: string) {
 if (!server.private_ip || !server.ssh_port || server.ssh_port < 1024) throw new Error("Choose a dedicated SSH port of 1024 or higher for bootstrap.");
 if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(fingerprint)) throw new Error("The control plane must provide a verified public CA fingerprint. Refresh or update it before bootstrap.");
 if (!helper.includes(marker)) throw new Error("SSH helper version is incompatible. Refresh and retry.");
 const data = { version: 1, org_id: orgId, server_id: server.id, private_ip: server.private_ip, ssh_port: server.ssh_port, public_key: publicKey, ca_fingerprint: fingerprint };
 const encoded = base64(new TextEncoder().encode(JSON.stringify(data)));
 return helper.replace(marker, `BUNDLE = json.loads(base64.b64decode("${encoded}"))`);
}
export function parseBootstrapResult(text: string, orgId: string, server: Server): BootstrapResult {
 if (text.length > 65536) throw new Error("Bootstrap result is too large.");
 const r = JSON.parse(text) as BootstrapResult;
 if (!r || r.version !== 1 || r.org_id !== orgId || r.server_id !== server.id || r.ssh_port !== server.ssh_port) throw new Error("Result belongs to a different organization, server or SSH port.");
 if (!Array.isArray(r.accounts) || !r.accounts.length || r.accounts.length > 16 || new Set(r.accounts).size !== r.accounts.length || r.accounts.some(a => typeof a !== "string" || !/^[a-z_][a-z0-9_-]{0,31}$/.test(a) || a === "root")) throw new Error("Result must contain 1–16 unique non-root Linux account names.");
 if (typeof r.host_fingerprint !== "string" || !/^SHA256:[A-Za-z0-9+/]{43}$/.test(r.host_fingerprint)) throw new Error("Result has an invalid SSH host fingerprint.");
 return r;
}
