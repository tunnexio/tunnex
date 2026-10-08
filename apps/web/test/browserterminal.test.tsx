import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { StrictMode } from "react";
import { MemoryRouter } from "react-router-dom";
import BrowserTerminal from "../src/pages/BrowserTerminal";
const state=vi.hoisted(()=>({terminal:null as any,pasted:[] as string[],selected:"",selectionChanged:null as any,multi:false,empty:false,serverCount:1,accountCount:1,developer:false,admin:false,recording:false,failed:false,connect:false,ready:true,sshPort:22,orgEnabled:true,serverEnabled:true,checkError:false,verified:false,requests:[] as string[],bodies:[] as unknown[]}));
vi.mock("../src/lib/useOrg",()=>({useOrg:()=>({org:{id:"org-1"},failed:false})}));
vi.mock("../src/components/MfaSettings",()=>({MfaSettings:()=> <div>Existing account MFA setup</div>}));
vi.mock("@xterm/xterm",()=>({Terminal:class{rows=24;cols=80;constructor(){state.terminal=this}onSelectionChange(cb:any){state.selectionChanged=cb;return {dispose(){}}}getSelection(){return state.selected}paste(text:string){state.pasted.push(text);this.data?.(text)}data:any;loadAddon(){}open(){}focus(){}write(){}dispose(){}onData(cb:any){this.data=cb;return {dispose(){}}}}}));
vi.mock("@xterm/addon-fit",()=>({FitAddon:class{fit(){}}}));
vi.mock("../src/lib/api",async()=>{
 const actual=await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
 return {...actual,api:{
  GET:vi.fn(async(path:string)=>{
   state.requests.push(path);
   if(path.endsWith("/server-access")){
    if(state.failed)return {error:{error:{message:"Workspace unavailable"}}};
    const workspace={data:{enabled:state.orgEnabled,can_manage:state.admin,can_grant:state.admin,can_manage_sessions:state.admin,grants:[],sessions:state.checkError?[{id:"check-1",kind:"check",server_id:"server-1",account:"fixture",status:"failed",reason:"ssh_authentication_failed"}]:[],mfa_freshness_seconds:900,recording_retention_days:7,recording_max_session_bytes:4194304,recording_max_org_bytes:67108864,limitations:["Recording-required servers refuse Connect until capture is implemented."],servers:[{id:"server-1",name:"Build host",gateway_id:"gateway-1",private_ip:state.admin?"10.2.3.4":undefined,ssh_port:22,host_fingerprint:"SHA256:fixture",accounts:["fixture"],ready_accounts:state.ready?["fixture"]:[],revision:1,enabled:state.serverEnabled,recording_enabled:state.recording,developer_access_enabled:state.developer,idle_timeout_seconds:300,max_session_seconds:900},...(state.multi?[{id:"server-2",name:"Database host",gateway_id:"gateway-1",accounts:["ubuntu"],ready_accounts:["ubuntu"],revision:1,enabled:true,recording_enabled:false,idle_timeout_seconds:300,max_session_seconds:900}]:[])]}};
    workspace.data.servers[0].ssh_port=state.sshPort;
    if(state.serverCount>1)workspace.data.servers=Array.from({length:state.serverCount},(_,index)=>({...workspace.data.servers[0],id:`server-${index}`,name:`Host ${index}`}));
    if(state.accountCount>1){const accounts=Array.from({length:state.accountCount},(_,index)=>`account-${index}`);workspace.data.servers[0]={...workspace.data.servers[0],accounts,ready_accounts:accounts}}
    if(state.empty)workspace.data.servers=[];
    return workspace;
   }
   if(path.endsWith("/enrollment"))return {response:{status:404},error:{error:{message:"No setup job"}}};
   return {data:[]};
  }),
  POST:vi.fn(async(path:string,options:unknown)=>{
   state.requests.push(path);state.bodies.push(options);
   if(path.endsWith("/mfa/step-up")){state.verified=true;return {data:{ok:true}}}
   if(state.verified&&path.endsWith("/check"))return {data:{id:"check-2",status:"pending"}};
   if(state.connect&&path.endsWith("/sessions")){const body=(options as {body:{server_id:string;account:string}}).body;return {data:{id:body.server_id==="server-2"?"session-2":"session-1",server_id:body.server_id,user_id:"user-1",account:body.account,status:"pending",reason:"",kind:"terminal",expires_at:new Date(Date.now()+60000).toISOString(),recording_enabled:false}}};
   return {error:{error:{code:"mfa_required",message:"Recent MFA required"}}};
  }),
  PUT:vi.fn(async()=>({data:{status:"updated"}})),
  DELETE:vi.fn(async()=>({error:{error:{message:"Termination unconfirmed"}}}))
 }};
});
beforeEach(()=>{state.developer=false;state.terminal=null;state.pasted=[];state.selected="";state.selectionChanged=null;state.multi=false;state.empty=false;state.serverCount=1;state.accountCount=1;state.admin=false;state.recording=false;state.failed=false;state.connect=false;state.ready=true;state.sshPort=22;state.orgEnabled=true;state.serverEnabled=true;state.checkError=false;state.verified=false;state.requests=[];state.bodies=[]});afterEach(cleanup);
function mount(){render(<MemoryRouter><BrowserTerminal/></MemoryRouter>)}
async function openServer(name="Build host"){fireEvent.click(await screen.findByRole("button",{name}))}
async function rowAction(label:string,action:string){const trigger=await screen.findByRole("button",{name:label});if(trigger.getAttribute("aria-expanded")!=="true")fireEvent.click(trigger);return within(screen.getByRole("menu",{name:label})).getByRole("menuitem",{name:action})}
const serverAction=(action:string)=>rowAction("Actions for Build host",action);
const accountAction=(action:string)=>rowAction("Account actions for fixture",action);
function serverStep(name:string){fireEvent.click(within(screen.getByRole("navigation",{name:"Server setup steps"})).getByRole("button",{name:new RegExp(`${name}$`)}))}
function manualStep(name:string){fireEvent.click(within(screen.getByRole("navigation",{name:"Manual SSH setup steps"})).getByRole("button",{name}))}
it("member catalog does not request privileged topology and MFA refusal cannot open a terminal",async()=>{mount();await openServer();await screen.findByRole("button",{name:"Connect as fixture"});expect(state.requests).toEqual(["/api/v1/organizations/{orgId}/server-access"]);expect(screen.queryByText("10.2.3.4:22")).toBeNull();fireEvent.click(screen.getByRole("button",{name:"Connect as fixture"}));await screen.findByRole("heading",{name:"Verify your identity"});expect(state.bodies[0]).toMatchObject({params:{path:{orgId:"org-1"}},body:{server_id:"server-1",account:"fixture"}});expect(screen.queryByLabelText("SSH terminal for fixture")).toBeNull()});
it("recording-enabled servers allow admission when capture is implemented",async()=>{state.recording=true;mount();await openServer();const button=await screen.findByRole("button",{name:"Connect as fixture"});expect((button as HTMLButtonElement).disabled).toBe(false);fireEvent.click(screen.getByText("Session options",{selector:"summary"}));expect(screen.getByText(/Recording on/)).toBeTruthy()});
it("failed workspace reads show an error instead of an empty granted catalog",async()=>{state.failed=true;mount();await screen.findByText("Workspace unavailable");expect(screen.queryByText("No servers are available for your account.")).toBeNull()});
it("clears a failed workspace read when a manual refresh restores the healthy catalog",async()=>{state.failed=true;mount();await screen.findByText("Workspace unavailable");state.failed=false;fireEvent.click(screen.getByRole("button",{name:"Refresh servers"}));await screen.findByRole("button",{name:"Build host"});expect(screen.queryByText("Workspace unavailable")).toBeNull();expect(state.bodies).toHaveLength(0)});
it("admin configuration reads are explicitly scoped to the selected organization",async()=>{state.admin=true;mount();fireEvent.click(await screen.findByRole("button",{name:"Register server"}));await screen.findByRole("dialog",{name:"Register server"});await waitFor(()=>expect(state.requests).toContain("/api/v1/organizations/{orgId}/nodes"));expect(state.requests).toContain("/api/v1/organizations/{orgId}/members");expect(state.requests).toContain("/api/v1/organizations/{orgId}/groups")});

it("a failed End request keeps the live terminal visible without claiming termination",async()=>{
 state.connect=true;
 class Socket{static OPEN=1;readyState=1;onopen:unknown;onmessage:unknown;onclose:unknown;onerror:unknown;send(){}close(){}}
 vi.stubGlobal("WebSocket",Socket);vi.stubGlobal("ResizeObserver",class{observe(){}disconnect(){}});
 try{mount();await openServer();fireEvent.click(await screen.findByRole("button",{name:"Connect as fixture"}));await screen.findByLabelText("SSH terminal for fixture");fireEvent.click(screen.getByRole("button",{name:"End terminal"}));await screen.findByText(/Termination unconfirmed/);expect(screen.getByLabelText("SSH terminal for fixture")).toBeTruthy();expect(screen.queryByRole("button",{name:"Close terminal"})).toBeNull()}finally{cleanup();vi.unstubAllGlobals()}
});

it("Strict Mode opens one websocket and does not revoke the initial single-use admission",async()=>{
 state.connect=true;let sockets=0;const deletes=vi.mocked((await import("../src/lib/api")).api.DELETE);deletes.mockClear();
 class Socket{static OPEN=1;readyState=1;onopen:unknown;onmessage:unknown;onclose:unknown;onerror:unknown;constructor(){sockets++}send(){}close(){}}
 vi.stubGlobal("WebSocket",Socket);vi.stubGlobal("ResizeObserver",class{observe(){}disconnect(){}});
 try{render(<StrictMode><MemoryRouter><BrowserTerminal/></MemoryRouter></StrictMode>);await openServer();fireEvent.click(await screen.findByRole("button",{name:"Connect as fixture"}));await screen.findByLabelText("SSH terminal for fixture");await waitFor(()=>expect(sockets).toBe(1));expect(deletes).not.toHaveBeenCalled();cleanup();expect(deletes).toHaveBeenCalledTimes(1)}finally{cleanup();vi.unstubAllGlobals()}
});

it("members cannot reveal session details through the direct Sessions URL",async()=>{
 render(<MemoryRouter initialEntries={["/browser-access/terminal?view=sessions"]}><BrowserTerminal/></MemoryRouter>);
 await openServer();await screen.findByRole("button",{name:"Connect as fixture"});
 expect(screen.queryByRole("link",{name:"Sessions"})).toBeNull();
 expect(screen.queryByRole("heading",{name:"Sessions"})).toBeNull();
 expect(screen.queryByRole("button",{name:"Import recording"})).toBeNull();
 expect(screen.queryByRole("table",{name:"Terminal sessions"})).toBeNull();
 expect(screen.queryByRole("link",{name:"View session evidence in Audit Log"})).toBeNull();
});
it("administrators retain session review and recording import",async()=>{
 state.admin=true;render(<MemoryRouter initialEntries={["/browser-access/terminal?view=sessions"]}><BrowserTerminal/></MemoryRouter>);
 await screen.findByRole("heading",{name:"Server sessions"});
 fireEvent.click(screen.getByText("Import recording",{selector:"summary"}));
 expect(screen.getByRole("button",{name:"Import recording"})).toBeTruthy();
 fireEvent.click(screen.getByText("Connection requirements",{selector:"summary"}));
 expect(screen.getByRole("link",{name:"View session evidence in Audit Log"})).toBeTruthy();
});

it("admin sees target SSH prerequisites when a granted account is not ready",async()=>{
 state.admin=true;state.ready=false;mount();await openServer();
 expect(await screen.findByRole("button",{name:"Check SSH for fixture"})).toHaveProperty("disabled",false);expect(screen.queryByRole("button",{name:"Connect as fixture"})).toBeNull();
 const requirements=screen.getByText("SSH setup requirements",{selector:"summary"});expect(requirements.closest("details")).toHaveProperty("open",false);fireEvent.click(requirements);expect(screen.getByText("Trusted CA")).toBeTruthy();expect(screen.getByText("Account principal")).toBeTruthy();
 expect(await accountAction("Check fixture")).toBeTruthy();
 fireEvent.click(await accountAction("SSH setup for fixture"));
 expect(screen.getByRole("dialog",{name:"SSH setup · fixture"})).toBeTruthy();manualStep("Account");
 expect(screen.getByText(/AuthorizedPrincipalsFile/)).toBeTruthy();
});
it("member sees an administrator action instead of privileged SSH setup details",async()=>{
 state.ready=false;mount();await openServer();const connect=await screen.findByRole("button",{name:"Connect as fixture"});expect(connect).toHaveProperty("disabled",true);fireEvent.click(connect);expect(state.bodies).toHaveLength(0);
 expect(screen.getByText("Waiting for administrator check")).toBeTruthy();
 expect(screen.queryByText("SSH setup for fixture")).toBeNull();
 expect(screen.queryByText(/AuthorizedPrincipalsFile/)).toBeNull();
 expect(screen.queryByRole("button",{name:"Check SSH for fixture"})).toBeNull();expect(screen.queryByRole("button",{name:"Account actions for fixture"})).toBeNull();expect(state.requests).toEqual(["/api/v1/organizations/{orgId}/server-access"]);
});

it("checks an unready disabled Linux server through the primary admin action without admitting a terminal",async()=>{
 state.admin=true;state.ready=false;state.serverEnabled=false;mount();await openServer();const check=screen.getByRole("button",{name:"Check SSH for fixture"});expect(check).toHaveProperty("disabled",false);fireEvent.click(check);
 await screen.findByRole("heading",{name:"Verify your identity"});expect(state.requests.filter(path=>path.endsWith("/check"))).toHaveLength(1);expect(state.requests.filter(path=>path.endsWith("/sessions"))).toHaveLength(0);
 expect(state.bodies).toEqual([{params:{path:{orgId:"org-1",serverId:"server-1"}},body:{server_id:"server-1",account:"fixture"}}]);expect(screen.queryByLabelText("SSH terminal for fixture")).toBeNull();
});

it("blocks the primary SSH check while Server Access is disabled",async()=>{
 state.admin=true;state.ready=false;state.orgEnabled=false;mount();await openServer();const check=screen.getByRole("button",{name:"Check SSH for fixture"});expect(check).toHaveProperty("disabled",true);fireEvent.click(check);expect(state.bodies).toHaveLength(0);expect(screen.queryByRole("heading",{name:"Verify your identity"})).toBeNull();expect(screen.queryByLabelText("SSH terminal for fixture")).toBeNull();
});

it("submits a primary SSH check only once while its protected request is pending",async()=>{
 state.admin=true;state.ready=false;const {api}=await import("../src/lib/api");vi.mocked(api.POST).mockClear();vi.mocked(api.POST).mockImplementationOnce(()=>new Promise(()=>{}));mount();await openServer();const check=screen.getByRole("button",{name:"Check SSH for fixture"});fireEvent.click(check);fireEvent.click(check);
 expect(api.POST).toHaveBeenCalledTimes(1);expect(api.POST).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/server-access/servers/{serverId}/check",{params:{path:{orgId:"org-1",serverId:"server-1"}},body:{server_id:"server-1",account:"fixture"}});expect(check).toHaveProperty("disabled",true);expect(screen.queryByLabelText("SSH terminal for fixture")).toBeNull();
});

it("failed account checks give administrators actionable certificate authentication guidance",async()=>{
 state.admin=true;state.ready=false;state.checkError=true;mount();await openServer();
 expect(await screen.findByText(/SSH authentication failed. Verify that the target SSH listener/)).toBeTruthy();
});

it("admin gets a downloadable reusable helper and account-only repeat command",async()=>{
 state.admin=true;state.sshPort=2222;mount();await openServer();
 fireEvent.click(await accountAction("SSH setup for fixture"));
 expect(screen.getByRole("link",{name:"Download SSH setup helper"}).getAttribute("href")).toBe("/tunnex-browser-ssh.py");
 expect(screen.getByRole("radio",{name:"First server setup"})).toHaveProperty("checked",true);manualStep("Account");
 expect(screen.getByLabelText("SSH setup command").textContent).toBe("sudo tunnex-browser-ssh init --ca ./ca.pub --ca-fingerprint 'SHA256:VERIFIED_CA_FINGERPRINT' --org 'org-1' --server 'server-1' --account 'fixture' --port 2222");
 expect(screen.queryByText("sudo tunnex-browser-ssh add-account --account 'fixture'")).toBeNull();
 fireEvent.click(screen.getByText("Account principal",{selector:"summary"}));expect(screen.getByText("tunnex:org-1:server-1:fixture")).toBeTruthy();
 manualStep("Prepare target");fireEvent.click(screen.getByRole("radio",{name:"Already configured target"}));manualStep("SSH trust");expect(screen.getByText(/Reuse the existing CA trust only after confirming it matches this organization's public SSH CA/)).toBeTruthy();manualStep("Account");
 expect(screen.getByLabelText("SSH setup command").textContent).toBe("sudo tunnex-browser-ssh add-account --account 'fixture'");expect(screen.queryByText(/sudo tunnex-browser-ssh init/)).toBeNull();expect(state.bodies).toHaveLength(0);
});

it("navigates manual setup without changing authority and sends only the final protected account check",async()=>{
 state.admin=true;state.ready=false;state.serverEnabled=false;state.sshPort=2222;mount();await openServer();fireEvent.click(await accountAction("SSH setup for fixture"));
 const dialog=screen.getByRole("dialog",{name:"SSH setup · fixture"});const guide=within(dialog);const steps=guide.getByRole("navigation",{name:"Manual SSH setup steps"});
 expect(within(steps).getByRole("button",{name:"Prepare target"}).getAttribute("aria-current")).toBe("step");expect(guide.queryByLabelText("SSH setup command")).toBeNull();
 fireEvent.click(guide.getByRole("button",{name:"Continue"}));expect(guide.getByRole("heading",{name:"SSH trust"})).toBeTruthy();expect(dialog.textContent).toContain("this organization's public SSH CA");
 fireEvent.click(guide.getByRole("button",{name:"Continue"}));expect(guide.getByRole("heading",{name:"Account"})).toBeTruthy();expect(guide.getByLabelText("SSH setup command")).toBeTruthy();
 fireEvent.click(guide.getByRole("button",{name:"Back"}));expect(guide.getByRole("heading",{name:"SSH trust"})).toBeTruthy();expect(guide.queryByLabelText("SSH setup command")).toBeNull();fireEvent.click(guide.getByRole("button",{name:"Continue"}));fireEvent.click(guide.getByRole("button",{name:"Continue"}));
 expect(guide.getByRole("heading",{name:"Check"})).toBeTruthy();expect(state.bodies).toHaveLength(0);expect(screen.queryByText("Connection checked")).toBeNull();const check=guide.getByRole("button",{name:"Check SSH for fixture"});expect(check).toHaveProperty("disabled",false);fireEvent.click(check);
 await screen.findByRole("region",{name:"MFA for Access fixture on Build host"});expect(screen.queryByRole("dialog",{name:"SSH setup · fixture"})).toBeNull();
 expect(state.requests.filter(path=>path.endsWith("/check"))).toHaveLength(1);expect(state.requests.filter(path=>path.endsWith("/grants")||path.endsWith("/sessions"))).toHaveLength(0);expect(state.bodies).toEqual([{params:{path:{orgId:"org-1",serverId:"server-1"}},body:{server_id:"server-1",account:"fixture"}}]);expect(screen.queryByLabelText("SSH terminal for fixture")).toBeNull();expect(screen.queryByText("Connection checked")).toBeNull();
 fireEvent.click(screen.getByRole("button",{name:"Cancel verification"}));expect(state.bodies).toHaveLength(1);expect(screen.queryByRole("region",{name:"MFA for Access fixture on Build host"})).toBeNull();
});

it("loads and downloads only the explicitly requested organization public CA without verifying target trust",async()=>{
 const {api}=await import("../src/lib/api");vi.mocked(api.GET).mockClear();vi.mocked(api.POST).mockClear();vi.mocked(api.DELETE).mockClear();
 const publicKey="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA org-1-ca\n";const fingerprint=`SHA256:${"B".repeat(43)}`;let completeRead!:()=>void;
 state.admin=true;state.ready=false;state.sshPort=2222;mount();await openServer();fireEvent.click(await accountAction("SSH setup for fixture"));manualStep("SSH trust");manualStep("Account");manualStep("SSH trust");
 const guide=within(screen.getByRole("dialog",{name:"SSH setup · fixture"}));const initialReads=vi.mocked(api.GET).mock.calls.length;expect(api.GET).not.toHaveBeenCalledWith("/api/v1/organizations/{orgId}/server-access/trust",expect.anything());
 vi.mocked(api.GET).mockImplementationOnce(()=>new Promise(resolve=>{completeRead=()=>resolve({data:{public_key:publicKey,ca_fingerprint:fingerprint,instructions:[]}} as never)}));const load=guide.getByRole("button",{name:"Load public CA"});fireEvent.click(load);fireEvent.click(load);
 expect(guide.getByRole("button",{name:"Loading public CA…"})).toHaveProperty("disabled",true);expect(guide.queryByRole("link",{name:"Download ca.pub"})).toBeNull();expect(api.GET).toHaveBeenCalledTimes(initialReads+1);expect(api.GET).toHaveBeenLastCalledWith("/api/v1/organizations/{orgId}/server-access/trust",{params:{path:{orgId:"org-1"}}});
 await act(async()=>completeRead());const download=guide.getByRole("link",{name:"Download ca.pub"});expect(download.getAttribute("download")).toBe("ca.pub");const href=download.getAttribute("href")!;expect(href.startsWith("data:text/plain;charset=utf-8,")).toBe(true);expect(decodeURIComponent(href.slice(href.indexOf(",")+1))).toBe(publicKey);expect(guide.getByText(fingerprint)).toBeTruthy();
 const key=guide.getByText("Public CA key",{selector:"summary"});fireEvent.click(key);expect(key.closest("details")?.textContent).toContain(publicKey);
 manualStep("Account");const command=screen.getByLabelText("SSH setup command").textContent!;expect(command).toContain("--ca-fingerprint 'SHA256:VERIFIED_CA_FINGERPRINT'");expect(command).not.toContain(fingerprint);expect(state.bodies).toHaveLength(0);expect(api.POST).not.toHaveBeenCalled();expect(api.DELETE).not.toHaveBeenCalled();expect(screen.queryByText("Connection checked")).toBeNull();expect(screen.queryByLabelText("SSH terminal for fixture")).toBeNull();
});

it.each(["api","transport"])("clears stale public CA data on a failed reload and retries locally (%s)",async(failure)=>{
 const {api}=await import("../src/lib/api");vi.mocked(api.GET).mockClear();vi.mocked(api.POST).mockClear();const oldKey="ssh-ed25519 OLD_PUBLIC_KEY org-1-ca\n";const freshKey="ssh-ed25519 FRESH_PUBLIC_KEY org-1-ca\n";const oldFingerprint=`SHA256:${"C".repeat(43)}`;
 state.admin=true;state.ready=false;mount();await openServer();fireEvent.click(await accountAction("SSH setup for fixture"));manualStep("SSH trust");const guide=within(screen.getByRole("dialog",{name:"SSH setup · fixture"}));
 vi.mocked(api.GET).mockResolvedValueOnce({data:{public_key:oldKey,ca_fingerprint:oldFingerprint,instructions:[]}} as never);fireEvent.click(guide.getByRole("button",{name:"Load public CA"}));await guide.findByRole("link",{name:"Download ca.pub"});expect(guide.getByText(oldFingerprint)).toBeTruthy();
 if(failure==="api")vi.mocked(api.GET).mockResolvedValueOnce({error:{error:{message:"Public CA unavailable"}}} as never);else vi.mocked(api.GET).mockRejectedValueOnce(new Error("Connection lost"));fireEvent.click(guide.getByRole("button",{name:"Reload public CA"}));await guide.findByText(failure==="api"?"Public CA unavailable":"Could not load the public SSH CA. Try again.");
 expect(guide.queryByRole("link",{name:"Download ca.pub"})).toBeNull();expect(guide.queryByText(oldFingerprint)).toBeNull();expect(guide.queryByText("Public CA key",{selector:"summary"})).toBeNull();expect(guide.getByRole("heading",{name:"SSH trust"})).toBeTruthy();
 vi.mocked(api.GET).mockResolvedValueOnce({data:{public_key:freshKey,instructions:[]}} as never);fireEvent.click(guide.getByRole("button",{name:"Retry public CA"}));const download=await guide.findByRole("link",{name:"Download ca.pub"});const href=download.getAttribute("href")!;expect(decodeURIComponent(href.slice(href.indexOf(",")+1))).toBe(freshKey);expect(guide.queryByText("CA fingerprint")).toBeNull();expect(guide.getByText("This response did not include a fingerprint. Verify the public key independently before using it.")).toBeTruthy();expect(guide.queryByText("Public CA unavailable")).toBeNull();expect(guide.queryByText("Could not load the public SSH CA. Try again.")).toBeNull();
 expect(api.GET).toHaveBeenLastCalledWith("/api/v1/organizations/{orgId}/server-access/trust",{params:{path:{orgId:"org-1"}}});expect(api.POST).not.toHaveBeenCalled();expect(state.bodies).toHaveLength(0);expect(screen.queryByText("Connection checked")).toBeNull();expect(screen.queryByLabelText("SSH terminal for fixture")).toBeNull();
});

it("withholds an unsupported initial setup command while retaining explicit account-only setup",async()=>{
 state.admin=true;state.ready=false;mount();await openServer();fireEvent.click(await accountAction("SSH setup for fixture"));manualStep("Account");
 expect(screen.getByText(/Choose a dedicated SSH port between 1024 and 65535.*The saved port is 22/)).toBeTruthy();expect(screen.queryByLabelText("SSH setup command")).toBeNull();expect(screen.queryByRole("button",{name:"Copy SSH setup command"})).toBeNull();
 manualStep("Prepare target");fireEvent.click(screen.getByRole("radio",{name:"Already configured target"}));manualStep("Account");expect(screen.getByLabelText("SSH setup command").textContent).toBe("sudo tunnex-browser-ssh add-account --account 'fixture'");expect(screen.queryByText(/sudo tunnex-browser-ssh init/)).toBeNull();expect(state.bodies).toHaveLength(0);
});

it("keeps the wizard's final account check disabled when Server Access is unavailable",async()=>{
 state.admin=true;state.ready=false;state.orgEnabled=false;mount();await openServer();fireEvent.click(await accountAction("SSH setup for fixture"));manualStep("Check");const dialog=within(screen.getByRole("dialog",{name:"SSH setup · fixture"}));const check=dialog.getByRole("button",{name:"Check SSH for fixture"});expect(check).toHaveProperty("disabled",true);fireEvent.click(check);expect(state.bodies).toHaveLength(0);expect(dialog.getByText(/Checking is unavailable while another action is running or Server Access is disabled/)).toBeTruthy();expect(screen.queryByRole("heading",{name:"Verify your identity"})).toBeNull();
});

it.each([true,false])("reports local setup-command clipboard success without changing server authority (success=%s)",async(success)=>{
 const previous=Object.getOwnPropertyDescriptor(navigator,"clipboard");const writeText=vi.fn();if(success)writeText.mockResolvedValue(undefined);else writeText.mockRejectedValue(new Error("Clipboard unavailable"));Object.defineProperty(navigator,"clipboard",{configurable:true,value:{writeText}});
 try{state.admin=true;mount();await openServer();fireEvent.click(await accountAction("SSH setup for fixture"));fireEvent.click(screen.getByRole("radio",{name:"Already configured target"}));manualStep("Account");fireEvent.click(screen.getByRole("button",{name:"Copy SSH setup command"}));await waitFor(()=>expect(writeText).toHaveBeenCalledWith("sudo tunnex-browser-ssh add-account --account 'fixture'"));await screen.findByText(success?"Command copied.":"Could not copy. Select and copy the command manually.");if(!success)expect(screen.queryByText("Command copied.")).toBeNull();expect(state.bodies).toHaveLength(0);expect(screen.queryByLabelText("SSH terminal for fixture")).toBeNull();}finally{cleanup();if(previous)Object.defineProperty(navigator,"clipboard",previous);else Reflect.deleteProperty(navigator,"clipboard")}
});

it("server removal requires explicit confirmation and members cannot see the action",async()=>{
 mount();await openServer();await screen.findByRole("button",{name:"Connect as fixture"});expect(screen.queryByRole("button",{name:"Remove server"})).toBeNull();cleanup();
 state.admin=true;mount();fireEvent.click(await serverAction("Remove server"));
 expect(await screen.findByText(/Remove this server from admin and member lists/)).toBeTruthy();
 expect(state.bodies).toHaveLength(0);fireEvent.click(screen.getByRole("button",{name:"Cancel"}));
 expect(screen.queryByRole("button",{name:"Confirm server removal"})).toBeNull();
});

it("quick bootstrap is admin-only and registration remains disabled with pending host trust",async()=>{
 mount();await openServer();await screen.findByRole("button",{name:"Connect as fixture"});expect(screen.queryByText("Quick SSH bootstrap")).toBeNull();cleanup();
 state.admin=true;mount();await openServer();serverStep("Connection");expect(screen.getByText("Quick SSH bootstrap")).toBeTruthy();
 fireEvent.click(screen.getByRole("button",{name:"Back to servers"}));
 fireEvent.click(screen.getByRole("button",{name:"Register server"}));
 expect(await screen.findByText(/Host trust is pending bootstrap/)).toBeTruthy();
 expect(screen.getByRole("button",{name:"Register disabled server"})).toBeTruthy();
 expect(screen.queryByLabelText("Independently verified SHA256 host fingerprint")).toBeNull();
});

it("inline MFA resumes the refused account check and subsequent checks reuse verification",async()=>{
 state.admin=true;mount();await openServer();
 fireEvent.click(await accountAction("Check fixture"));
 await screen.findByRole("region",{name:"MFA for Access fixture on Build host"});
 fireEvent.change(screen.getByLabelText("Authenticator or recovery code"),{target:{value:"123456"}});
 fireEvent.click(screen.getByRole("button",{name:"Verify and continue"}));
 await waitFor(()=>expect(state.requests.filter(p=>p.endsWith("/check"))).toHaveLength(2));
 await waitFor(()=>expect(screen.queryByRole("heading",{name:"Verify your identity"})).toBeNull());
 fireEvent.click(await accountAction("Check fixture"));
 await waitFor(()=>expect(state.requests.filter(p=>p.endsWith("/check"))).toHaveLength(3));
 expect(state.requests.filter(p=>p.endsWith("/mfa/step-up"))).toHaveLength(1);
});
it("Windows registration requests RDP fields and hides Linux bootstrap and recording controls",async()=>{
 state.admin=true;mount();fireEvent.click(await screen.findByRole("button",{name:"Register server"}));
 fireEvent.change(screen.getByLabelText("Operating system"),{target:{value:"windows"}});
 expect((screen.getByLabelText("RDP port") as HTMLInputElement).value).toBe("3389");
 expect(screen.getByLabelText("Windows accounts (comma separated)")).toBeTruthy();
 fireEvent.click(screen.getByText("Session and client options",{selector:"summary"}));
 expect(screen.getByLabelText("Windows domain (optional)")).toBeTruthy();
 expect(screen.getByLabelText("Verified SHA256 RDP certificate fingerprint")).toBeTruthy();
 expect(screen.queryByRole("switch",{name:"Discover accounts during setup"})).toBeNull();
 expect(screen.queryByRole("switch",{name:"Record new sessions"})).toBeNull();
});

it("opens grants from the selected server without a server picker",async()=>{state.admin=true;mount();fireEvent.click(await serverAction("Manage access"));expect(screen.getByRole("dialog")).toBeTruthy();expect(screen.queryByLabelText("Grant server")).toBeNull();expect(screen.getByLabelText("Server account")).toHaveProperty("value","fixture");});
it("access overview does not show the new grant form",async()=>{state.admin=true;render(<MemoryRouter initialEntries={["/browser-access/terminal?view=access"]}><BrowserTerminal/></MemoryRouter>);await screen.findByText("Account grants");expect(screen.queryByRole("button",{name:"Create account grant"})).toBeNull();});

it("disabling from inventory requires confirmation and cancellation performs no update",async()=>{state.admin=true;mount();fireEvent.click(await serverAction("Disable server"));expect(screen.getByRole("dialog",{name:"Disable Build host?"})).toBeTruthy();expect(state.requests.filter(p=>p.endsWith("/servers/{serverId}"))).toHaveLength(0);fireEvent.click(screen.getByRole("button",{name:"Cancel"}));expect(screen.queryByRole("dialog")).toBeNull();await openServer();expect(await serverAction("Disable server")).toBeTruthy();expect(screen.getAllByRole("menuitem",{name:"Disable server"})).toHaveLength(1);});

it("keeps both server sockets alive while switching tabs and closes only the selected session",async()=>{
 state.multi=true;state.connect=true;const sockets:{url:string;closed:boolean}[]=[];
 const deletes=vi.mocked((await import("../src/lib/api")).api.DELETE);deletes.mockClear();
 class Socket{static OPEN=1;readyState=1;constructor(public url:string){sockets.push(this)}closed=false;send(){}close(){this.closed=true}}
 vi.stubGlobal("WebSocket",Socket);vi.stubGlobal("ResizeObserver",class{observe(){}disconnect(){}});
 try{mount();await openServer();fireEvent.click(await screen.findByRole("button",{name:"Connect as fixture"}));await screen.findByLabelText("SSH terminal for fixture");
 fireEvent.click(within(screen.getByRole("navigation",{name:"Servers workspace"})).getByRole("link",{name:"My servers"}));await openServer("Database host");
 const second=screen.getByRole("button",{name:"Connect as ubuntu"});expect((second as HTMLButtonElement).disabled).toBe(false);fireEvent.click(second);await screen.findByLabelText("SSH terminal for ubuntu");
 expect(screen.getAllByRole("tab")).toHaveLength(2);await waitFor(()=>expect(sockets).toHaveLength(2));expect(sockets.every(s=>!s.closed)).toBe(true);
 fireEvent.click(screen.getByRole("tab",{name:"Build host · fixture"}));expect(screen.getByRole("tabpanel").getAttribute("aria-labelledby")).toBe("connection-tab-session-1");
 fireEvent.click(screen.getByRole("tab",{name:"Database host · ubuntu"}));expect(sockets).toHaveLength(2);expect(deletes).not.toHaveBeenCalled();
 deletes.mockResolvedValueOnce({data:{}} as never);fireEvent.click(screen.getByRole("button",{name:"End terminal"}));await waitFor(()=>expect(screen.getAllByRole("tab")).toHaveLength(1));
 expect(sockets[1].closed).toBe(true);expect(sockets[0].closed).toBe(false);expect(screen.getByRole("tab",{name:"Build host · fixture"}).getAttribute("aria-selected")).toBe("true");
 }finally{cleanup();vi.unstubAllGlobals()}
});


it("copies selected Linux text and pastes through xterm into the SSH input channel",async()=>{
 state.connect=true;let socket:any;const sent:any[]=[];const writeText=vi.fn(async()=>{});
 vi.stubGlobal("WebSocket",class {static OPEN=1;readyState=1;constructor(){socket=this}onmessage:any;send(text:string){sent.push(JSON.parse(text))}close(){}});vi.stubGlobal("ResizeObserver",class{observe(){}disconnect(){}});
 Object.defineProperty(navigator,"clipboard",{configurable:true,value:{writeText,readText:vi.fn(async()=>"echo café")}});
 try{mount();await openServer();fireEvent.click(await screen.findByRole("button",{name:"Connect as fixture"}));await screen.findByLabelText("SSH terminal for fixture");await waitFor(()=>expect(socket).toBeTruthy());
 act(()=>socket.onmessage({data:JSON.stringify({type:"output",data:btoa("ready")})}));
 act(()=>{state.selected="Linux output";state.selectionChanged()});fireEvent.click(screen.getByRole("button",{name:"Copy selection"}));await waitFor(()=>expect(writeText).toHaveBeenCalledWith("Linux output"));
 fireEvent.click(screen.getByRole("button",{name:"Paste text"}));await waitFor(()=>expect((screen.getByLabelText("Text to paste into terminal") as HTMLTextAreaElement).value).toBe("echo café"));fireEvent.click(screen.getByRole("button",{name:"Paste into terminal"}));expect(state.pasted).toEqual(["echo café"]);expect(sent.filter(f=>f.type==="input").map(f=>new TextDecoder().decode(Uint8Array.from(atob(f.data),c=>c.charCodeAt(0))))).toEqual(["echo café"]);
 fireEvent.click(screen.getByRole("button",{name:"Paste text"}));fireEvent.change(await screen.findByLabelText("Text to paste into terminal"),{target:{value:"x".repeat(8193)}});fireEvent.click(screen.getByRole("button",{name:"Paste into terminal"}));expect(state.pasted).toHaveLength(1);expect(screen.getByText("Enter text up to 8 KB, without null characters.")).toBeTruthy();
 }finally{cleanup();vi.unstubAllGlobals();Object.defineProperty(navigator,"clipboard",{configurable:true,value:undefined})}
});

it("only offers VS Code for explicitly enabled developer access",async()=>{mount();await openServer();await screen.findByRole("button",{name:"Connect as fixture"});expect(screen.queryByRole("button",{name:"Local VS Code · Requires CLI"})).toBeNull();cleanup();state.developer=true;mount();await openServer();fireEvent.click(await accountAction("Local VS Code · Requires CLI"));expect(await screen.findByRole("dialog")).toBeTruthy();expect(screen.getByText(/tunnex-editor\.sh/).textContent).toContain("--account 'fixture'");expect(state.bodies).toHaveLength(0)});

it("opens one server with a breadcrumb and moves through connection, accounts and access without saving",async()=>{
 state.admin=true;mount();await openServer();
 const breadcrumb=screen.getByRole("navigation",{name:"Server breadcrumb"});
 expect(within(breadcrumb).getByText("Build host").getAttribute("aria-current")).toBe("page");
 expect(screen.getByRole("table",{name:"Server accounts"})).toBeTruthy();
 expect(screen.queryByText("10.2.3.4:22")).toBeNull();
 serverStep("Connection");expect(screen.getByText("10.2.3.4:22")).toBeTruthy();
 expect(screen.queryByRole("table",{name:"Server accounts"})).toBeNull();
 fireEvent.click(screen.getByRole("button",{name:"Continue to accounts"}));
 expect(screen.getByRole("button",{name:"Connect as fixture"})).toBeTruthy();
 fireEvent.click(screen.getByRole("button",{name:"Continue to access"}));
 expect(screen.getByRole("button",{name:"Grant account access"})).toBeTruthy();
 expect(screen.queryByRole("button",{name:"Connect as fixture"})).toBeNull();
 fireEvent.click(screen.getByRole("button",{name:"Grant account access"}));
 expect(screen.getByLabelText("Server account")).toHaveProperty("value","fixture");
 expect(state.bodies).toHaveLength(0);
});

it.each([false,true])("returns to the server inventory through the same-URL workspace link (admin=%s)",async(admin)=>{
 state.admin=admin;mount();await openServer();expect(screen.getByRole("navigation",{name:"Server setup steps"})).toBeTruthy();
 fireEvent.click(within(screen.getByRole("navigation",{name:"Servers workspace"})).getByRole("link",{name:admin?"Servers":"My servers"}));
 expect(await screen.findByRole("table",{name:"Servers"})).toBeTruthy();expect(screen.queryByRole("navigation",{name:"Server setup steps"})).toBeNull();expect(screen.queryByRole("navigation",{name:"Server breadcrumb"})).toBeNull();expect(state.bodies).toHaveLength(0);
});

it("shows loaded empty server guidance without a table, pagination or privileged reads",async()=>{
 state.empty=true;mount();await screen.findByRole("heading",{name:"No servers available"});
 expect(screen.queryByRole("table",{name:"Servers"})).toBeNull();expect(screen.queryByRole("columnheader")).toBeNull();
 expect(screen.queryByRole("navigation",{name:"Table pagination"})).toBeNull();expect(screen.queryByRole("combobox",{name:"Rows per page"})).toBeNull();
 expect(screen.queryByRole("button",{name:"Previous servers"})).toBeNull();expect(screen.queryByRole("button",{name:"Next servers"})).toBeNull();
 expect(state.requests).toEqual(["/api/v1/organizations/{orgId}/server-access"]);
});

it("pages the complete permitted server catalog at the chosen size and resets after search or size changes",async()=>{
 state.serverCount=55;mount();await screen.findByRole("button",{name:"Host 0"});
 fireEvent.change(screen.getByRole("combobox",{name:"Rows per page"}),{target:{value:"10"}});expect(screen.getAllByRole("row")).toHaveLength(11);
 fireEvent.click(screen.getByRole("button",{name:"Next servers"}));expect(screen.getByRole("button",{name:"Host 10"})).toBeTruthy();expect(screen.queryByRole("button",{name:"Host 0"})).toBeNull();
 fireEvent.change(screen.getByRole("combobox",{name:"Rows per page"}),{target:{value:"50"}});expect(screen.getAllByRole("row")).toHaveLength(51);expect(screen.getByRole("button",{name:"Previous servers"})).toHaveProperty("disabled",true);
 fireEvent.click(screen.getByRole("button",{name:"Next servers"}));expect(screen.getByRole("button",{name:"Host 50"})).toBeTruthy();
 fireEvent.change(screen.getByRole("textbox",{name:"Search servers"}),{target:{value:"Host 0"}});expect(screen.getByRole("button",{name:"Host 0"})).toBeTruthy();expect(screen.getAllByRole("row")).toHaveLength(2);
 expect(screen.queryByRole("navigation",{name:"Table pagination"})).toBeNull();expect(screen.queryByRole("button",{name:"Previous servers"})).toBeNull();
 expect(state.requests).toEqual(["/api/v1/organizations/{orgId}/server-access"]);expect(state.bodies).toHaveLength(0);
});

it("keeps a single permitted account usable without pagination controls",async()=>{
 mount();await openServer();expect(screen.getByRole("table",{name:"Server accounts"})).toBeTruthy();expect(screen.getAllByRole("row")).toHaveLength(2);expect(screen.getByRole("button",{name:"Connect as fixture"})).toHaveProperty("disabled",false);expect(screen.queryByRole("navigation",{name:"Table pagination"})).toBeNull();expect(screen.queryByRole("combobox",{name:"Rows per page"})).toBeNull();expect(screen.queryByRole("button",{name:"Previous accounts"})).toBeNull();expect(screen.queryByRole("button",{name:"Next accounts"})).toBeNull();expect(state.requests).toEqual(["/api/v1/organizations/{orgId}/server-access"]);expect(state.bodies).toHaveLength(0);
});

it("pages authoritative accounts at the chosen size without requesting topology or admitting a session",async()=>{
 state.accountCount=55;mount();await openServer();
 fireEvent.change(screen.getByRole("combobox",{name:"Rows per page"}),{target:{value:"10"}});expect(screen.getAllByRole("row")).toHaveLength(11);
 fireEvent.click(screen.getByRole("button",{name:"Next accounts"}));expect(screen.getByRole("button",{name:"Connect as account-10"})).toBeTruthy();expect(screen.queryByRole("button",{name:"Connect as account-0"})).toBeNull();
 fireEvent.change(screen.getByRole("combobox",{name:"Rows per page"}),{target:{value:"50"}});expect(screen.getAllByRole("row")).toHaveLength(51);expect(screen.getByRole("button",{name:"Previous accounts"})).toHaveProperty("disabled",true);
 fireEvent.click(screen.getByRole("button",{name:"Next accounts"}));expect(screen.getAllByRole("row")).toHaveLength(6);expect(screen.getByRole("button",{name:"Connect as account-50"})).toBeTruthy();expect(screen.getByRole("button",{name:"Previous accounts"})).toHaveProperty("disabled",false);expect(screen.getByRole("button",{name:"Next accounts"})).toHaveProperty("disabled",true);fireEvent.click(screen.getByRole("button",{name:"Previous accounts"}));expect(screen.getByRole("button",{name:"Connect as account-0"})).toBeTruthy();expect(screen.getAllByRole("row")).toHaveLength(51);
 expect(state.requests).toEqual(["/api/v1/organizations/{orgId}/server-access"]);expect(state.bodies).toHaveLength(0);
});

it("submits a pending connection only once and keeps account admission blocked until it settles",async()=>{
 const {api}=await import("../src/lib/api");
 vi.mocked(api.POST).mockClear();
 vi.mocked(api.POST).mockImplementationOnce(()=>new Promise(()=>{}));
 mount();await openServer();const connect=screen.getByRole("button",{name:"Connect as fixture"});
 fireEvent.click(connect);fireEvent.click(connect);
 expect(api.POST).toHaveBeenCalledTimes(1);expect(api.POST).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/server-access/sessions",expect.objectContaining({body:{server_id:"server-1",account:"fixture"}}));
 expect(connect).toHaveProperty("disabled",true);expect(screen.queryByLabelText("SSH terminal for fixture")).toBeNull();
});


it("preserves freshly disabled organization activation when saving a previously opened recording policy",async()=>{
 const {api}=await import("../src/lib/api");const put=vi.mocked(api.PUT);put.mockClear();state.admin=true;
 render(<MemoryRouter initialEntries={["/browser-access/terminal?view=settings"]}><BrowserTerminal/></MemoryRouter>);
 fireEvent.click(await screen.findByText("Security and retention policy",{selector:"summary"}));
 fireEvent.change(screen.getByRole("spinbutton",{name:"Recording retention (days)"}),{target:{value:"19"}});
 state.orgEnabled=false;
 fireEvent.click(screen.getByRole("button",{name:"Save recording policy"}));
 await waitFor(()=>expect(put).toHaveBeenCalledExactlyOnceWith("/api/v1/organizations/{orgId}/server-access",{params:{path:{orgId:"org-1"}},body:{enabled:false,recording_retention_days:19,mfa_freshness_seconds:900,recording_max_session_bytes:4194304,recording_max_org_bytes:67108864}}));
 await screen.findByText("Server access is disabled.");
 expect(screen.queryByRole("button",{name:"Save recording policy"})).toBeNull();
 expect(screen.getByRole("link",{name:"Manage feature"}).getAttribute("href")).toBe("/settings?section=features&feature=server-access");
});

it("refuses an operational recording save when the fresh setting withdraws management authority",async()=>{
 const {api}=await import("../src/lib/api");const put=vi.mocked(api.PUT);put.mockClear();state.admin=true;
 render(<MemoryRouter initialEntries={["/browser-access/terminal?view=settings"]}><BrowserTerminal/></MemoryRouter>);
 fireEvent.click(await screen.findByText("Security and retention policy",{selector:"summary"}));
 state.admin=false;fireEvent.click(screen.getByRole("button",{name:"Save recording policy"}));
 await screen.findByText("The request could not be completed.");expect(put).not.toHaveBeenCalled();
});
