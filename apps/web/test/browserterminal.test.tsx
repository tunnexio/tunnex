import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { StrictMode } from "react";
import { MemoryRouter } from "react-router-dom";
import BrowserTerminal from "../src/pages/BrowserTerminal";
const state=vi.hoisted(()=>({terminal:null as any,pasted:[] as string[],selected:"",selectionChanged:null as any,multi:false,developer:false,admin:false,recording:false,failed:false,connect:false,ready:true,checkError:false,verified:false,requests:[] as string[],bodies:[] as unknown[]}));
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
    return {data:{enabled:true,can_manage:state.admin,can_grant:state.admin,can_manage_sessions:state.admin,grants:[],sessions:state.checkError?[{id:"check-1",kind:"check",server_id:"server-1",account:"fixture",status:"failed",reason:"ssh_authentication_failed"}]:[],mfa_freshness_seconds:900,recording_retention_days:7,recording_max_session_bytes:4194304,recording_max_org_bytes:67108864,limitations:["Recording-required servers refuse Connect until capture is implemented."],servers:[{id:"server-1",name:"Build host",gateway_id:"gateway-1",private_ip:state.admin?"10.2.3.4":undefined,ssh_port:22,host_fingerprint:"SHA256:fixture",accounts:["fixture"],ready_accounts:state.ready?["fixture"]:[],revision:1,enabled:true,recording_enabled:state.recording,developer_access_enabled:state.developer,idle_timeout_seconds:300,max_session_seconds:900},...(state.multi?[{id:"server-2",name:"Database host",gateway_id:"gateway-1",accounts:["ubuntu"],ready_accounts:["ubuntu"],revision:1,enabled:true,recording_enabled:false,idle_timeout_seconds:300,max_session_seconds:900}]:[])]}};
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
  DELETE:vi.fn(async()=>({error:{error:{message:"Termination unconfirmed"}}}))
 }};
});
beforeEach(()=>{state.developer=false;state.terminal=null;state.pasted=[];state.selected="";state.selectionChanged=null;state.multi=false;state.admin=false;state.recording=false;state.failed=false;state.connect=false;state.ready=true;state.checkError=false;state.verified=false;state.requests=[];state.bodies=[]});afterEach(cleanup);
function mount(){render(<MemoryRouter><BrowserTerminal/></MemoryRouter>)}
it("member catalog does not request privileged topology and MFA refusal cannot open a terminal",async()=>{mount();await screen.findByRole("button",{name:"Connect as fixture"});expect(state.requests).toEqual(["/api/v1/organizations/{orgId}/server-access"]);expect(screen.queryByText("10.2.3.4:22")).toBeNull();fireEvent.click(screen.getByRole("button",{name:"Connect as fixture"}));await screen.findByRole("heading",{name:"Verify MFA for Terminal"});expect(state.bodies[0]).toMatchObject({params:{path:{orgId:"org-1"}},body:{server_id:"server-1",account:"fixture"}});expect(screen.queryByLabelText("SSH terminal for fixture")).toBeNull()});
it("recording-enabled servers allow admission when capture is implemented",async()=>{state.recording=true;mount();const button=await screen.findByRole("button",{name:"Connect as fixture"});expect((button as HTMLButtonElement).disabled).toBe(false);expect(screen.getByText(/Recording on/)).toBeTruthy()});
it("failed workspace reads show an error instead of an empty granted catalog",async()=>{state.failed=true;mount();await screen.findByText("Workspace unavailable");expect(screen.queryByText("No servers are available for your account.")).toBeNull()});
it("admin configuration reads are explicitly scoped to the selected organization",async()=>{state.admin=true;mount();fireEvent.click(await screen.findByRole("button",{name:"Register server"}));await screen.findByRole("heading",{name:"Register a server"});await waitFor(()=>expect(state.requests).toContain("/api/v1/organizations/{orgId}/nodes"));expect(state.requests).toContain("/api/v1/organizations/{orgId}/members");expect(state.requests).toContain("/api/v1/organizations/{orgId}/groups")});

it("a failed End request keeps the live terminal visible without claiming termination",async()=>{
 state.connect=true;
 class Socket{static OPEN=1;readyState=1;onopen:unknown;onmessage:unknown;onclose:unknown;onerror:unknown;send(){}close(){}}
 vi.stubGlobal("WebSocket",Socket);vi.stubGlobal("ResizeObserver",class{observe(){}disconnect(){}});
 try{mount();fireEvent.click(await screen.findByRole("button",{name:"Connect as fixture"}));await screen.findByLabelText("SSH terminal for fixture");fireEvent.click(screen.getByRole("button",{name:"End terminal"}));await screen.findByText(/Termination unconfirmed/);expect(screen.getByLabelText("SSH terminal for fixture")).toBeTruthy();expect(screen.queryByRole("button",{name:"Close terminal"})).toBeNull()}finally{cleanup();vi.unstubAllGlobals()}
});

it("Strict Mode opens one websocket and does not revoke the initial single-use admission",async()=>{
 state.connect=true;let sockets=0;const deletes=vi.mocked((await import("../src/lib/api")).api.DELETE);deletes.mockClear();
 class Socket{static OPEN=1;readyState=1;onopen:unknown;onmessage:unknown;onclose:unknown;onerror:unknown;constructor(){sockets++}send(){}close(){}}
 vi.stubGlobal("WebSocket",Socket);vi.stubGlobal("ResizeObserver",class{observe(){}disconnect(){}});
 try{render(<StrictMode><MemoryRouter><BrowserTerminal/></MemoryRouter></StrictMode>);fireEvent.click(await screen.findByRole("button",{name:"Connect as fixture"}));await screen.findByLabelText("SSH terminal for fixture");await waitFor(()=>expect(sockets).toBe(1));expect(deletes).not.toHaveBeenCalled();cleanup();expect(deletes).toHaveBeenCalledTimes(1)}finally{cleanup();vi.unstubAllGlobals()}
});

it("members cannot reveal session details through the direct Sessions URL",async()=>{
 render(<MemoryRouter initialEntries={["/browser-access/terminal?view=sessions"]}><BrowserTerminal/></MemoryRouter>);
 await screen.findByRole("button",{name:"Connect as fixture"});
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
 expect(screen.getByRole("link",{name:"View session evidence in Audit Log"})).toBeTruthy();
});

it("admin sees target SSH prerequisites when a granted account is not ready",async()=>{
 state.admin=true;state.ready=false;mount();fireEvent.click(await screen.findByRole("button",{name:"Build host"}));
 const connect=await screen.findByRole("button",{name:"Connect as fixture"});expect((connect as HTMLButtonElement).disabled).toBe(true);
 expect(screen.getByText(/An access grant alone does not configure SSH/)).toBeTruthy();
 expect(screen.getByText("SSH setup for fixture")).toBeTruthy();
 expect(screen.getByText(/AuthorizedPrincipalsFile/)).toBeTruthy();
 expect(screen.getByRole("button",{name:"Check fixture"})).toBeTruthy();
});
it("member sees an administrator action instead of privileged SSH setup details",async()=>{
 state.ready=false;mount();await screen.findByRole("button",{name:"Connect as fixture"});
 expect(screen.getByText("Waiting for administrator check")).toBeTruthy();
 expect(screen.queryByText("SSH setup for fixture")).toBeNull();
 expect(screen.queryByText(/AuthorizedPrincipalsFile/)).toBeNull();
});

it("failed account checks give administrators actionable certificate authentication guidance",async()=>{
 state.admin=true;state.ready=false;state.checkError=true;mount();fireEvent.click(await screen.findByRole("button",{name:"Build host"}));
 expect(await screen.findByText(/SSH authentication failed. Verify that the target SSH listener/)).toBeTruthy();
});

it("admin gets a downloadable reusable helper and account-only repeat command",async()=>{
 state.admin=true;mount();fireEvent.click(await screen.findByRole("button",{name:"Build host"}));
 expect(screen.getByRole("link",{name:"Download SSH setup helper"}).getAttribute("href")).toBe("/tunnex-browser-ssh.py");
 expect(screen.getByText("sudo tunnex-browser-ssh add-account --account 'fixture'")).toBeTruthy();
 expect(screen.getByText(/sudo tunnex-browser-ssh init/).textContent).toContain("--server 'server-1'");
});

it("server removal requires explicit confirmation and members cannot see the action",async()=>{
 mount();await screen.findByRole("button",{name:"Connect as fixture"});expect(screen.queryByRole("button",{name:"Remove server"})).toBeNull();cleanup();
 state.admin=true;mount();fireEvent.click(await screen.findByRole("button",{name:"Remove server"}));
 expect(await screen.findByText(/Remove this server from admin and member lists/)).toBeTruthy();
 expect(state.bodies).toHaveLength(0);fireEvent.click(screen.getByRole("button",{name:"Cancel"}));
 expect(screen.queryByRole("button",{name:"Confirm server removal"})).toBeNull();
});

it("quick bootstrap is admin-only and registration remains disabled with pending host trust",async()=>{
 mount();await screen.findByRole("button",{name:"Connect as fixture"});expect(screen.queryByText("Quick SSH bootstrap")).toBeNull();cleanup();
 state.admin=true;mount();fireEvent.click(await screen.findByRole("button",{name:"Build host"}));expect(screen.getByText("Quick SSH bootstrap")).toBeTruthy();
 fireEvent.click(screen.getByRole("button",{name:"Register server"}));
 expect(await screen.findByText(/Host trust is pending bootstrap/)).toBeTruthy();
 expect(screen.getByRole("button",{name:"Register disabled server"})).toBeTruthy();
 expect(screen.queryByLabelText("Independently verified SHA256 host fingerprint")).toBeNull();
});

it("inline MFA resumes the refused account check and subsequent checks reuse verification",async()=>{
 state.admin=true;mount();fireEvent.click(await screen.findByRole("button",{name:"Build host"}));
 fireEvent.click(await screen.findByRole("button",{name:"Check fixture"}));
 await screen.findByRole("region",{name:"MFA for Access fixture on Build host"});
 fireEvent.change(screen.getByLabelText("Authenticator or recovery code"),{target:{value:"123456"}});
 fireEvent.click(screen.getByRole("button",{name:"Verify and continue"}));
 await waitFor(()=>expect(state.requests.filter(p=>p.endsWith("/check"))).toHaveLength(2));
 await waitFor(()=>expect(screen.queryByRole("heading",{name:"Verify MFA for Terminal"})).toBeNull());
 fireEvent.click(screen.getByRole("button",{name:"Check fixture"}));
 await waitFor(()=>expect(state.requests.filter(p=>p.endsWith("/check"))).toHaveLength(3));
 expect(state.requests.filter(p=>p.endsWith("/mfa/step-up"))).toHaveLength(1);
});
it("Windows registration requests RDP fields and hides Linux bootstrap and recording controls",async()=>{
 state.admin=true;mount();fireEvent.click(await screen.findByRole("button",{name:"Register server"}));
 fireEvent.change(screen.getByLabelText("Operating system"),{target:{value:"windows"}});
 expect((screen.getByLabelText("RDP port") as HTMLInputElement).value).toBe("3389");
 expect(screen.getByLabelText("Windows accounts (comma separated)")).toBeTruthy();
 expect(screen.getByLabelText("Windows domain (optional)")).toBeTruthy();
 expect(screen.getByLabelText("Verified SHA256 RDP certificate fingerprint")).toBeTruthy();
 expect(screen.queryByRole("switch",{name:"Discover accounts during setup"})).toBeNull();
 expect(screen.queryByRole("switch",{name:"Record new sessions"})).toBeNull();
});

it("opens grants from the selected server without a server picker",async()=>{state.admin=true;mount();fireEvent.click(await screen.findByRole("button",{name:"Access"}));expect(screen.getByRole("dialog")).toBeTruthy();expect(screen.queryByLabelText("Grant server")).toBeNull();expect(screen.getByLabelText("Server account")).toHaveProperty("value","fixture");});
it("access overview does not show the new grant form",async()=>{state.admin=true;render(<MemoryRouter initialEntries={["/browser-access/terminal?view=access"]}><BrowserTerminal/></MemoryRouter>);await screen.findByText("Account grants");expect(screen.queryByRole("button",{name:"Create account grant"})).toBeNull();});

it("disabling from inventory requires confirmation and cancellation performs no update",async()=>{state.admin=true;mount();fireEvent.click(await screen.findByRole("button",{name:"Disable server"}));expect(screen.getByRole("dialog",{name:"Disable Build host?"})).toBeTruthy();expect(state.requests.filter(p=>p.endsWith("/servers/{serverId}"))).toHaveLength(0);fireEvent.click(screen.getByRole("button",{name:"Cancel"}));expect(screen.queryByRole("dialog")).toBeNull();fireEvent.click(screen.getByRole("button",{name:"Build host"}));expect(screen.getAllByRole("button",{name:"Disable server"})).toHaveLength(1);});

it("keeps both server sockets alive while switching tabs and closes only the selected session",async()=>{
 state.multi=true;state.connect=true;const sockets:{url:string;closed:boolean}[]=[];
 const deletes=vi.mocked((await import("../src/lib/api")).api.DELETE);deletes.mockClear();
 class Socket{static OPEN=1;readyState=1;constructor(public url:string){sockets.push(this)}closed=false;send(){}close(){this.closed=true}}
 vi.stubGlobal("WebSocket",Socket);vi.stubGlobal("ResizeObserver",class{observe(){}disconnect(){}});
 try{mount();fireEvent.click(await screen.findByRole("button",{name:"Connect as fixture"}));await screen.findByLabelText("SSH terminal for fixture");
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
 try{mount();fireEvent.click(await screen.findByRole("button",{name:"Connect as fixture"}));await screen.findByLabelText("SSH terminal for fixture");await waitFor(()=>expect(socket).toBeTruthy());
 act(()=>socket.onmessage({data:JSON.stringify({type:"output",data:btoa("ready")})}));
 act(()=>{state.selected="Linux output";state.selectionChanged()});fireEvent.click(screen.getByRole("button",{name:"Copy selection"}));await waitFor(()=>expect(writeText).toHaveBeenCalledWith("Linux output"));
 fireEvent.click(screen.getByRole("button",{name:"Paste text"}));await waitFor(()=>expect((screen.getByLabelText("Text to paste into terminal") as HTMLTextAreaElement).value).toBe("echo café"));fireEvent.click(screen.getByRole("button",{name:"Paste into terminal"}));expect(state.pasted).toEqual(["echo café"]);expect(sent.filter(f=>f.type==="input").map(f=>new TextDecoder().decode(Uint8Array.from(atob(f.data),c=>c.charCodeAt(0))))).toEqual(["echo café"]);
 fireEvent.click(screen.getByRole("button",{name:"Paste text"}));fireEvent.change(await screen.findByLabelText("Text to paste into terminal"),{target:{value:"x".repeat(8193)}});fireEvent.click(screen.getByRole("button",{name:"Paste into terminal"}));expect(state.pasted).toHaveLength(1);expect(screen.getByText("Enter text up to 8 KB, without null characters.")).toBeTruthy();
 }finally{cleanup();vi.unstubAllGlobals();Object.defineProperty(navigator,"clipboard",{configurable:true,value:undefined})}
});

it("only offers VS Code for explicitly enabled developer access",async()=>{mount();await screen.findByRole("button",{name:"Connect as fixture"});expect(screen.queryByRole("button",{name:"Local VS Code · Requires CLI"})).toBeNull();cleanup();state.developer=true;mount();fireEvent.click(await screen.findByRole("button",{name:"Local VS Code · Requires CLI"}));expect(await screen.findByRole("dialog")).toBeTruthy();expect(screen.getByText(/tunnex-editor\.sh/).textContent).toContain("--account 'fixture'");expect(state.bodies).toHaveLength(0)});
