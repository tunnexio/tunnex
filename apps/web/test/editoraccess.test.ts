import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { editorCallback, editorCommand } from "../src/lib/editorAccess";
describe("editor browser handoff",()=>{
 it("accepts only a clean numeric loopback callback",()=>{
  expect(editorCallback("http://127.0.0.1:12345/callback")?.port).toBe("12345");
  for(const raw of ["https://example.com/callback","http://127.0.0.1.evil:123/callback","http://user@127.0.0.1:123/callback","http://127.0.0.1:123/callback?next=evil","http://127.0.0.1:123/callback#x","http://localhost:123/callback","http://127.0.0.1:0/callback","http://127.0.0.1:123/other"])expect(editorCallback(raw)).toBeUndefined();
 });
 it("quotes CLI values without carrying credentials or private target addresses",()=>{
  const command=editorCommand("https://console.example","org","server","developer");
  expect(command).toContain("https://console.example/tunnex-editor.sh");
  expect(command).toContain("--server");
  expect(command).toContain("-o");
  expect(command).not.toContain("--insecure");
  expect(editorCommand("https://console.example","org","server","a'b")).not.toContain("--insecure");
 });
});

it("executes the copied command with literal arguments, including shell metacharacters",()=>{
 const dir=mkdtempSync(join(tmpdir(),"tunnex-command-"));
 try {
  const curl=join(dir,"curl");
  writeFileSync(curl,`#!/bin/sh
while [ "$#" -gt 0 ]; do if [ "$1" = -o ]; then printf '%s\\n' '#!/bin/sh' 'printf "%s\\n" "$@"' > "$2"; exit 0; fi; shift; done
exit 1
`);
  chmodSync(curl,0o700);
  const account="a'b; $(printf INJECTION)";
  const output=execFileSync("sh",["-c",editorCommand("https://console.example","org","server",account)],{env:{...process.env,PATH:`${dir}:/usr/bin:/bin`},encoding:"utf8"});
  expect(output.trim().split("\n")).toEqual(["--server","https://console.example","--org","org","--target","server","--account",account]);
 } finally {rmSync(dir,{recursive:true,force:true});}
});
