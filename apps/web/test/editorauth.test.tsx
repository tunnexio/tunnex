import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import EditorAuth from "../src/pages/EditorAuth";
const state=vi.hoisted(()=>({posts:[] as string[],verified:false,enabled:true}));
vi.mock("../src/components/HealthStatus",()=>({HealthStatus:()=>null}));
vi.mock("../src/components/MfaSettings",()=>({MfaSettings:()=>null}));
vi.mock("../src/lib/api", async () => {
 const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
 return {...actual, api: {
  GET: vi.fn(async () => ({data:{mfa_freshness_seconds:900,servers:[{id:"target",name:"Build host",accounts:["ubuntu"],enabled:true,ready_accounts:["ubuntu"],developer_access_enabled:state.enabled}]}})),
  POST: vi.fn(async (path:string) => {
   state.posts.push(path);
   if(path.endsWith("step-up")){state.verified=true;return {data:{ok:true}}}
   return {error:{error:{code:state.verified?"account_not_granted":"mfa_required",message:state.verified?"Grant expired":"Verify MFA"}}};
  }),
 }};
});
function mount(callback="http://127.0.0.1:4567/callback"){const q=new URLSearchParams({org:"org",server:"target",account:"ubuntu",public_key:"ssh-ed25519 public",code_challenge:"a".repeat(43),state:"b".repeat(43),redirect_uri:callback});render(<MemoryRouter initialEntries={[`/editor-auth?${q}`]}><EditorAuth/></MemoryRouter>)}
beforeEach(()=>{state.posts=[];state.verified=false;state.enabled=true});afterEach(cleanup);
it("requires explicit approval, labels recording off, and reuses inline MFA",async()=>{mount();await screen.findByText("Build host · ubuntu");expect(state.posts).toEqual([]);expect(screen.getByText("Tunnex CLI · Recording off")).toBeTruthy();fireEvent.click(screen.getByRole("button",{name:"Approve editor access"}));await screen.findByRole("region",{name:"MFA for Open Build host in VS Code"});fireEvent.change(screen.getByLabelText("Authenticator or recovery code"),{target:{value:"123456"}});fireEvent.click(screen.getByRole("button",{name:"Verify and continue"}));await screen.findByText("Grant expired");await waitFor(()=>expect(state.posts.filter(p=>p.endsWith("sessions/editor"))).toHaveLength(2))});
it("refuses an external callback without minting a capability",()=>{mount("http://evil.example:4567/callback");expect(screen.getByText(/Invalid editor request/)).toBeTruthy();expect(state.posts).toEqual([])});
it("does not offer approval for a disabled developer policy",async()=>{state.enabled=false;mount();await screen.findByText(/Ask your admin/);expect((screen.getByRole("button",{name:"Approve editor access"})as HTMLButtonElement).disabled).toBe(true)});
