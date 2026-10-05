/** Normalize public keys before either sandbox or qualification-trial requests.
 * Private-key files and comments never enter these request bodies. The server
 * still validates the encoded key and current authorization. */
export function sandboxPublicKeys(value: string): { keys: string[]; error?: never } | { keys?: never; error: string } {
  const lines = value.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  if (!lines.length || lines.length > 7 || lines.some(line => line.length > 8192 || !/^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521))\s+[A-Za-z0-9+/]+={0,2}(?:\s+.*)?$/.test(line))) return { error: "Paste valid SSH public keys from your .pub files, one per line." };
  const keys = lines.map(line => line.split(/\s+/).slice(0, 2).join(" ")).sort();
  if (new Set(keys).size !== keys.length) return { error: "Each SSH public key must be different." };
  return { keys };
}
