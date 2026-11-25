import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { AutomaticSSHSetup } from "../src/components/AutomaticSSHSetup";
const mocks=vi.hoisted(()=>({GET:vi.fn(),POST:vi.fn(),DELETE:vi.fn()}));
vi.mock("../src/lib/api",()=>({api:mocks,apiErrorMessage:(e:{error?:{message?:string}},fallback:string)=>e?.error?.message??fallback}));
const authState=vi.hoisted(()=>({value:undefined as undefined|{state:{status:string;user:{recovery_codes_remaining?:number|null}}}}));
vi.mock("../src/lib/auth",async original=>({...(await original<typeof import("../src/lib/auth")>()),useOptionalAuth:()=>authState.value}));
afterEach(()=>{cleanup();vi.resetAllMocks();authState.value=undefined});
const server={id:"server",name:"Host",gateway_id:"gateway",private_ip:"10.2.3.4",ssh_port:2222,host_fingerprint:"SHA256:"+"A".repeat(43),accounts:[],ready_accounts:[],revision:1,enabled:false,recording_enabled:false,idle_timeout_seconds:300,max_session_seconds:900};
const job={id:"job",server_id:"server",state:"awaiting_authorization",expires_at:new Date(Date.now()+60000).toISOString(),authorization_command:"sudo reviewed-authorization",message:"Authorize target"};
const fingerprintField=()=>screen.getByLabelText("Verified management SSH fingerprint (optional)");
it("prepares without a pasted fingerprint: the host key is verified from the one-time authorization (SA-UX-2 item 2)",async()=>{
 mocks.GET.mockResolvedValue({response:{status:404}});mocks.POST.mockResolvedValue({data:job});
 render(<AutomaticSSHSetup orgId="org" server={server} disabled={false} onComplete={()=>{}} onMfa={()=>{}}/>);
 expect(screen.getByText(/Server identity is verified automatically/)).toBeTruthy();
 expect(screen.getByText("Advanced: verify the host key independently").closest("details")?.open).toBe(false);
 const prepare=screen.getByRole("button",{name:"Prepare automatic setup"});expect((prepare as HTMLButtonElement).disabled).toBe(false);
 fireEvent.click(prepare);
 await screen.findByRole("button",{name:"Configure automatically"});
 expect(mocks.POST).toHaveBeenCalledWith(expect.stringContaining("/enrollment"),expect.objectContaining({body:{management_account:"ubuntu",management_port:22,accounts:[]}}));
});
it("refuses a malformed independent fingerprint but sends a valid one to be pinned",async()=>{
 mocks.GET.mockResolvedValue({response:{status:404}});mocks.POST.mockResolvedValue({data:job});
 render(<AutomaticSSHSetup orgId="org" server={server} disabled={false} onComplete={()=>{}} onMfa={()=>{}}/>);
 const prepare=screen.getByRole("button",{name:"Prepare automatic setup"});
 fireEvent.change(fingerprintField(),{target:{value:"SHA256:short"}});expect((prepare as HTMLButtonElement).disabled).toBe(true);
 fireEvent.change(fingerprintField(),{target:{value:"SHA256:"+"B".repeat(43)}});fireEvent.click(prepare);
 await screen.findByRole("button",{name:"Configure automatically"});
 expect(mocks.POST).toHaveBeenCalledWith(expect.stringContaining("/enrollment"),expect.objectContaining({body:{management_account:"ubuntu",management_port:22,management_fingerprint:"SHA256:"+"B".repeat(43),accounts:[]}}));
 expect(mocks.POST.mock.calls.every(c=>!c[0].includes("/grants"))).toBe(true);
 expect((screen.getByLabelText("One-time SSH authorization command") as HTMLTextAreaElement).value).toBe("sudo reviewed-authorization");
});
it("restores a running setup after refresh",async()=>{
 mocks.GET.mockResolvedValue({data:{...job,state:"running",authorization_command:"",message:"Configuring target"}});
 render(<AutomaticSSHSetup orgId="org" server={server} disabled={false} onComplete={()=>{}} onMfa={()=>{}}/>);
 await screen.findByText("Configuring target");
 expect(screen.queryByRole("button",{name:"Prepare automatic setup"})).toBeNull();expect(screen.getByRole("button",{name:"Cancel setup"})).toBeTruthy();
});
it("MFA refusal requests step-up without claiming setup success",async()=>{
 mocks.GET.mockResolvedValue({response:{status:404}});mocks.POST.mockResolvedValue({error:{error:{code:"mfa_required",message:"Recent MFA required"}}});const mfa=vi.fn();
 render(<AutomaticSSHSetup orgId="org" server={server} disabled={false} onComplete={()=>{}} onMfa={mfa}/>);
 fireEvent.click(screen.getByRole("button",{name:"Prepare automatic setup"}));
 await waitFor(()=>expect(mfa).toHaveBeenCalled());expect(screen.queryByRole("button",{name:"Configure automatically"})).toBeNull();
});
it("syncs discovered users through fresh authorization without granting access",async()=>{
 mocks.GET.mockResolvedValue({response:{status:404}});mocks.POST.mockResolvedValue({data:job});
 render(<AutomaticSSHSetup orgId="org" server={{...server,accounts:["ubuntu"]}} disabled={false} onComplete={()=>{}} onMfa={()=>{}}/>);
 expect(screen.getByRole("heading",{name:"Sync Linux accounts"})).toBeTruthy();
 fireEvent.click(screen.getByRole("button",{name:"Sync accounts"}));
 await screen.findByRole("button",{name:"Run account sync"});
 expect(mocks.POST).toHaveBeenCalledWith(expect.stringContaining("/enrollment"),expect.objectContaining({body:expect.objectContaining({accounts:[]})}));
 expect(mocks.POST.mock.calls.every(c=>!c[0].includes("/grants"))).toBe(true);
});
it("allows account sync on an enabled enrolled server",()=>{
 mocks.GET.mockResolvedValue({response:{status:404}});
 render(<AutomaticSSHSetup orgId="org" server={{...server,accounts:["ubuntu"],enabled:true}} disabled={false} onComplete={()=>{}} onMfa={()=>{}}/>);
 
 expect((screen.getByRole("button",{name:"Sync accounts"}) as HTMLButtonElement).disabled).toBe(false);expect(mocks.POST).not.toHaveBeenCalled();
});
it("explains why preparation is unavailable",()=>{
 mocks.GET.mockResolvedValue({response:{status:404}});
 render(<AutomaticSSHSetup orgId="org" server={{...server,enabled:true}} disabled={false} onComplete={()=>{}} onMfa={()=>{}}/>);
 expect(screen.getByText("Disable this server before initial SSH setup.")).toBeTruthy();
 expect(screen.getByRole("list",{name:"SSH setup steps"})).toBeTruthy();
});
it("states the network requirement with the gateway address and firewall examples before setup (SA-UX-2 item 1)",()=>{
 mocks.GET.mockResolvedValue({response:{status:404}});
 render(<AutomaticSSHSetup orgId="org" server={server} gateway={{id:"gateway",name:"gcp-gw",endpoint:"34.1.2.3:51820"} as never} disabled={false} onComplete={()=>{}} onMfa={()=>{}}/>);
 expect(screen.getByText(/must reach 10\.2\.3\.4 on TCP 22 \(management SSH, for setup\) and on TCP 2222/)).toBeTruthy();
 expect(screen.getByText(/aws ec2 authorize-security-group-ingress .*--port 2222 --cidr GATEWAY_PRIVATE_IP\/32/)).toBeTruthy();
 expect(screen.getByText(/35\.235\.240\.0\/20/)).toBeTruthy();
 expect(screen.getAllByText("ip -4 route get 10.2.3.4").length).toBeGreaterThan(0);
});
it("shows the two-factor requirement up front and offers setup when none is enrolled (SA-UX-2 item 3)",()=>{
 mocks.GET.mockResolvedValue({response:{status:404}});
 authState.value={state:{status:"authed",user:{recovery_codes_remaining:null}}};
 const {unmount}=render(<AutomaticSSHSetup orgId="org" server={server} disabled={false} onComplete={()=>{}} onMfa={()=>{}}/>);
 expect(screen.getByText(/your account has none yet/)).toBeTruthy();
 expect(screen.getByText("Set up two-factor verification")).toBeTruthy();
 expect((screen.getByRole("button",{name:"Prepare automatic setup"}) as HTMLButtonElement).disabled).toBe(true);
 unmount();
 authState.value={state:{status:"authed",user:{recovery_codes_remaining:8}}};
 render(<AutomaticSSHSetup orgId="org" server={server} disabled={false} onComplete={()=>{}} onMfa={()=>{}}/>);
 expect(screen.getByText(/you will confirm a code from your authenticator app/)).toBeTruthy();
 expect((screen.getByRole("button",{name:"Prepare automatic setup"}) as HTMLButtonElement).disabled).toBe(false);
});
