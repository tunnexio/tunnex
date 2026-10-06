import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { AutomaticSSHSetup } from "../src/components/AutomaticSSHSetup";
const mocks=vi.hoisted(()=>({GET:vi.fn(),POST:vi.fn(),DELETE:vi.fn()}));
vi.mock("../src/lib/api",()=>({api:mocks,apiErrorMessage:(e:{error?:{message?:string}},fallback:string)=>e?.error?.message??fallback}));
afterEach(()=>{cleanup();vi.resetAllMocks()});
const server={id:"server",name:"Host",gateway_id:"gateway",private_ip:"10.2.3.4",ssh_port:2222,host_fingerprint:"SHA256:"+"A".repeat(43),accounts:[],ready_accounts:[],revision:1,enabled:false,recording_enabled:false,idle_timeout_seconds:300,max_session_seconds:900};
const job={id:"job",server_id:"server",state:"awaiting_authorization",expires_at:new Date(Date.now()+60000).toISOString(),authorization_command:"sudo reviewed-authorization",message:"Authorize target"};
it("requires management trust and requests discovery without granting access",async()=>{
 mocks.GET.mockResolvedValue({response:{status:404}});mocks.POST.mockResolvedValue({data:job});
 render(<AutomaticSSHSetup orgId="org" server={server} disabled={false} onComplete={()=>{}} onMfa={()=>{}}/>);
 const prepare=screen.getByRole("button",{name:"Prepare automatic setup"});expect((prepare as HTMLButtonElement).disabled).toBe(true);
 fireEvent.change(screen.getByLabelText("Verified management SSH fingerprint"),{target:{value:"SHA256:"+"B".repeat(43)}});fireEvent.click(prepare);
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
 fireEvent.change(screen.getByLabelText("Verified management SSH fingerprint"),{target:{value:"SHA256:"+"B".repeat(43)}});fireEvent.click(screen.getByRole("button",{name:"Prepare automatic setup"}));
 await waitFor(()=>expect(mfa).toHaveBeenCalled());expect(screen.queryByRole("button",{name:"Configure automatically"})).toBeNull();
});
it("syncs discovered users through fresh authorization without granting access",async()=>{
 mocks.GET.mockResolvedValue({response:{status:404}});mocks.POST.mockResolvedValue({data:job});
 render(<AutomaticSSHSetup orgId="org" server={{...server,accounts:["ubuntu"]}} disabled={false} onComplete={()=>{}} onMfa={()=>{}}/>);
 expect(screen.getByRole("heading",{name:"Sync Linux accounts"})).toBeTruthy();
 fireEvent.change(screen.getByLabelText("Verified management SSH fingerprint"),{target:{value:"SHA256:"+"B".repeat(43)}});fireEvent.click(screen.getByRole("button",{name:"Sync accounts"}));
 await screen.findByRole("button",{name:"Run account sync"});
 expect(mocks.POST).toHaveBeenCalledWith(expect.stringContaining("/enrollment"),expect.objectContaining({body:expect.objectContaining({accounts:[]})}));
 expect(mocks.POST.mock.calls.every(c=>!c[0].includes("/grants"))).toBe(true);
});
it("allows account sync on an enabled enrolled server",()=>{
 mocks.GET.mockResolvedValue({response:{status:404}});
 render(<AutomaticSSHSetup orgId="org" server={{...server,accounts:["ubuntu"],enabled:true}} disabled={false} onComplete={()=>{}} onMfa={()=>{}}/>);
 fireEvent.change(screen.getByLabelText("Verified management SSH fingerprint"),{target:{value:"SHA256:"+"B".repeat(43)}});
 expect((screen.getByRole("button",{name:"Sync accounts"}) as HTMLButtonElement).disabled).toBe(false);expect(mocks.POST).not.toHaveBeenCalled();
});
it("explains why preparation is unavailable and keeps fingerprint instructions expandable",()=>{
 mocks.GET.mockResolvedValue({response:{status:404}});
 render(<AutomaticSSHSetup orgId="org" server={server} disabled={false} onComplete={()=>{}} onMfa={()=>{}}/>);
 expect(screen.getByText("Enter the verified management SSH fingerprint to continue.")).toBeTruthy();
 expect(screen.getByText("How to get the fingerprint").closest("details")?.open).toBe(false);
 expect(screen.getByRole("list",{name:"SSH setup steps"})).toBeTruthy();
});
