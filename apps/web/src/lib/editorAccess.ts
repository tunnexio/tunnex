export function editorCallback(raw: string): URL | undefined {
 try {const u=new URL(raw);if(u.protocol!=="http:"||u.hostname!=="127.0.0.1"||!u.port||Number(u.port)<1||Number(u.port)>65535||u.pathname!=="/callback"||u.username||u.password||u.search||u.hash)return;return u;}catch{return;}
}
export function editorCommand(origin:string,org:string,server:string,account:string):string {
 const quote=(v:string)=>`'${v.replace(/'/g,`'"'"'`)}'`;
 const args=`--server ${quote(origin)} --org ${quote(org)} --target ${quote(server)} --account ${quote(account)}`;
 return `(
  set -eu
  umask 077
  t=$(mktemp)
  trap 'rm -f "$t"' EXIT HUP INT TERM
  curl --fail --silent --show-error --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 60 ${quote(origin+"/tunnex-editor.sh")} -o "$t"
  sh "$t" ${args}
)`;
}
