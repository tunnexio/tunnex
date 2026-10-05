// One copy/paste command with the API's current host pin. A subshell owns its
// private temporary file; neither the caller's traps nor general known_hosts change.
export function sandboxConnectCommand(connection: {address:string;host_public_key:string}): string | null {
 const address=connection.address;
 const parts=address.split(".");
 const key=connection.host_public_key.trim();
 if(parts.length!==4||parts.some(part=>!/^\d{1,3}$/.test(part)||String(Number(part))!==part||Number(part)>255)||!/^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$/.test(key)||key.length>8192)return null;
 return [
  '(',
  '  sandbox_hosts=$(mktemp "${TMPDIR:-/tmp}/tunnex-sandbox-hosts.XXXXXX") &&',
  '  trap \'rm -f "$sandbox_hosts"\' EXIT HUP INT TERM &&',
  `  printf '%s\n' '${address} ${key}' > "$sandbox_hosts" &&`,
  '  ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$sandbox_hosts" -o GlobalKnownHostsFile=/dev/null -o UpdateHostKeys=no sandbox@'+address,
  ')',
 ].join("\n");
}
