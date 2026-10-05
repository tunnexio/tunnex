import {describe,expect,it} from "vitest";
import {mkdtempSync,readFileSync,writeFileSync,readdirSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {spawnSync} from "node:child_process";
import {sandboxConnectCommand} from "../src/lib/sandboxConnection";
const key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";
describe("sandbox connection command",()=>{
 it.each([0,37])("runs with exactly the API pin and cleans the temporary file after SSH exit%d",(status)=>{
  const dir=mkdtempSync(join(tmpdir(),"sandbox-connect-test-"));
  try{
   const general=join(dir,"known_hosts");writeFileSync(general,"existing unrelated host pin\n");
   const fakeSSH=`ssh() { printf '%s\n' "$@" > "$TMPDIR/args"; for arg do case "$arg" in UserKnownHostsFile=*) cat "\${arg#UserKnownHostsFile=}" > "$TMPDIR/pin";; esac; done; return ${status}; }\n`;
   const command=sandboxConnectCommand({address:"10.99.0.12",host_public_key:key+"\n"});expect(command).not.toBeNull();
   const result=spawnSync("/bin/sh",["-c",fakeSSH+command!],{env:{...process.env,PATH:dir+":"+process.env.PATH,TMPDIR:dir},encoding:"utf8"});
   expect(result.status).toBe(status);
   expect(readFileSync(join(dir,"pin"),"utf8")).toBe(`10.99.0.12 ${key}\n`);
   const args=readFileSync(join(dir,"args"),"utf8");expect(args).toContain("StrictHostKeyChecking=yes");expect(args).toContain("GlobalKnownHostsFile=/dev/null");expect(args).toContain("UpdateHostKeys=no");expect(args).toContain("sandbox@10.99.0.12");
   expect(readFileSync(general,"utf8")).toBe("existing unrelated host pin\n");
   expect(readdirSync(dir).some(name=>name.startsWith("tunnex-sandbox-hosts."))).toBe(false);
  }finally{rmSync(dir,{recursive:true,force:true})}
 });
 it("rejects malformed or executable host metadata",()=>{
  for(const address of ["10.99.0.12;touch /tmp/pwn","10.99.0.12\n*","256.99.0.12","10.099.0.12","host.invalid"]){expect(sandboxConnectCommand({address,host_public_key:key})).toBeNull()}
  for(const host_public_key of [key+"\n* "+key,"$(touch /tmp/pwn)",key+"';touch /tmp/pwn",""]){expect(sandboxConnectCommand({address:"10.99.0.12",host_public_key})).toBeNull()}
 });
});
