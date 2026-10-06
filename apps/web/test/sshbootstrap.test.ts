import { expect, it } from "vitest";
import type { components } from "@tunnex/shared";
import { bootstrapBundle, parseBootstrapResult } from "../src/lib/sshBootstrap";
const server={id:"server-1",private_ip:"172.31.48.32",ssh_port:2222} as components["schemas"]["ServerAccessServer"];
const fp="SHA256:"+"A".repeat(43);
const result={version:1,org_id:"org-1",server_id:server.id,ssh_port:2222,accounts:["ubuntu","deploy"],host_fingerprint:fp};
it("embeds actual public trust and server binding without a manual fingerprint placeholder",async()=>{
 const source=await bootstrapBundle("BUNDLE = None  # Replaced only in the administrator-downloaded server bundle.","ssh-ed25519 PUBLIC_CA","org-1",server,fp);
 const encoded=source.match(/b64decode\("([^"]+)"\)/)![1];
 expect(JSON.parse(atob(encoded))).toEqual({version:1,org_id:"org-1",server_id:"server-1",private_ip:"172.31.48.32",ssh_port:2222,public_key:"ssh-ed25519 PUBLIC_CA",ca_fingerprint:fp});
 expect(source).not.toContain("VERIFIED_CA_FINGERPRINT");
});
it("refuses incompatible helpers and missing CA fingerprint",async()=>{
 await expect(bootstrapBundle("wrong","key","org-1",server,fp)).rejects.toThrow(/incompatible/);
 await expect(bootstrapBundle("wrong","key","org-1",server,"")).rejects.toThrow(/verified public CA/);
});
it("accepts only matching bounded public result data",()=>{
 expect(parseBootstrapResult(JSON.stringify(result),"org-1",server).accounts).toEqual(["ubuntu","deploy"]);
 for(const change of [{org_id:"foreign"},{server_id:"foreign"},{ssh_port:22},{accounts:["root"]},{accounts:["ubuntu;id"]},{accounts:["ubuntu","ubuntu"]},{host_fingerprint:"invalid"},{version:2}]){
  expect(()=>parseBootstrapResult(JSON.stringify({...result,...change}),"org-1",server)).toThrow();
 }
 expect(()=>parseBootstrapResult(" ".repeat(65537),"org-1",server)).toThrow(/large/);
});
