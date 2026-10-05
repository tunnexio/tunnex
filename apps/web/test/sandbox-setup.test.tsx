import {afterEach,beforeEach,expect,it,vi} from "vitest";
import {act,cleanup,render,screen,fireEvent,waitFor} from "@testing-library/react";
import {MemoryRouter} from "react-router-dom";
const mocks=vi.hoisted(()=>({get:vi.fn(),put:vi.fn()}));
vi.mock("../src/lib/useOrg",()=>({useOrg:()=>({org:{id:"org-a"},loading:false,failed:false})}));
vi.mock("../src/lib/api",()=>({api:{GET:mocks.get,PUT:mocks.put},apiErrorMessage:(_:unknown,fallback:string)=>fallback,loadOne:async(call:()=>Promise<{data?:unknown,error?:unknown}>)=>{try{const result=await call();return result.error||result.data===undefined?{ok:false,error:"Could not load."}:{ok:true,data:result.data}}catch{return {ok:false,error:"Could not reach the API."}}}}));
import {SandboxSetupPage} from "../src/pages/SandboxSetup";
const template={id:"profile-a",name:"Ubuntu terminal",image_digest:"sha256:fixture",maximum_scope:[],memory_mib:128,max_ttl_seconds:3600,allowed_skill_revision_ids:[]};
const setup={settings:{enabled:false,max_per_user:2,max_total:20},policy_mode:"enforcing",creation_status:{can_admin:true,can_manage_catalog:true,runtime_ready:false,blocked_reasons:["runtime_not_ready","organization_disabled"]},catalog:[{template,enabled:false,runtime_compatible:true}]};
function mockSetup(value:unknown){mocks.get.mockImplementation(async(path:string)=>({data:path.endsWith("/sandbox-runner-enrollments")?{profiles:[],enrollments:[],blocked_reasons:[]}:value}))}
beforeEach(()=>{mocks.get.mockReset();mocks.put.mockReset();mockSetup(setup);mocks.put.mockResolvedValue({data:setup})});afterEach(cleanup);
function page(){render(<MemoryRouter><SandboxSetupPage/></MemoryRouter>)}
it("keeps activation unavailable without a qualified runtime while saving limits through real CAS API",async()=>{
 page();const enable=await screen.findByRole("checkbox",{name:"Enable sandbox creation"});expect((enable as HTMLInputElement).disabled).toBe(true);
 expect(screen.getByText(/No qualified runtime is currently connected/)).toBeTruthy();
 fireEvent.change(screen.getByLabelText("Retained sandboxes per user"),{target:{value:"3"}});fireEvent.click(screen.getByRole("button",{name:"Save settings"}));
 await waitFor(()=>expect(mocks.put).toHaveBeenCalledTimes(1));
 expect(mocks.put.mock.calls[0][0]).toBe("/api/v1/organizations/{orgId}/sandbox-setup");expect(mocks.put.mock.calls[0][1]).toMatchObject({params:{path:{orgId:"org-a"}},body:{expected:setup.settings,settings:{enabled:false,max_per_user:3,max_total:20}}});
});
it("publishes an existing catalog entry separately from activation",async()=>{
 page();fireEvent.click(await screen.findByRole("button",{name:"Publish configuration"}));
 await waitFor(()=>expect(mocks.put).toHaveBeenCalledTimes(1));expect(mocks.put.mock.calls[0][0]).toBe("/api/v1/organizations/{orgId}/sandbox-catalog/{templateId}");expect(mocks.put.mock.calls[0][1]).toMatchObject({params:{path:{orgId:"org-a",templateId:"profile-a"}},body:{expected_enabled:false,enabled:true}});
 expect((screen.getByRole("checkbox",{name:"Enable sandbox creation"}) as HTMLInputElement).checked).toBe(false);
});
it("permits activation only with readiness, enforcing policy and published compatibility",async()=>{
 mockSetup({...setup,creation_status:{...setup.creation_status,runtime_ready:true},catalog:[{...setup.catalog[0],enabled:true}]});page();const enable=await screen.findByRole("checkbox",{name:"Enable sandbox creation"});await waitFor(()=>expect((enable as HTMLInputElement).disabled).toBe(false));fireEvent.click(enable);fireEvent.click(screen.getByRole("button",{name:"Save settings"}));await waitFor(()=>expect(mocks.put).toHaveBeenCalled());expect(mocks.put.mock.calls[0][1].body.settings.enabled).toBe(true);
});
it.each([undefined,false])("preserves fresh qualified legacy runtime setup without an enrollment service (%s)",async(required)=>{
 const ready={...setup,creation_status:{...setup.creation_status,runtime_ready:true,runner_enrollment_required:required},catalog:[{...setup.catalog[0],enabled:true}]};
 mocks.get.mockImplementation(async(path:string)=>path.endsWith("/sandbox-runner-enrollments")?{error:{code:"unavailable"}}:{data:ready});page();
 const enable=await screen.findByRole("checkbox",{name:"Enable sandbox creation"});await waitFor(()=>expect((enable as HTMLInputElement).disabled).toBe(false));
 expect(screen.getByText(/Runtime: Qualified and connected/)).toBeTruthy();expect(screen.queryByRole("button",{name:"Add sandbox runner"})).toBeNull();
 expect(mocks.get.mock.calls.some(([path])=>path.endsWith("/sandbox-runner-enrollments"))).toBe(false);
});
it.each(["unavailable","offline"])("requires fresh Ready enrollment in configured mode when metadata is %s",async(state)=>{
 const ready={...setup,creation_status:{...setup.creation_status,runtime_ready:true,runner_enrollment_required:true},catalog:[{...setup.catalog[0],enabled:true}]};
 mocks.get.mockImplementation(async(path:string)=>path.endsWith("/sandbox-runner-enrollments")?state==="unavailable"?{error:{code:"unavailable"}}:{data:{profiles:[],enrollments:[{id:"runner-a",name:"Offline runner",state:"offline",blocked_reasons:["runner_offline"]}],blocked_reasons:[]}}:{data:ready});page();
 await screen.findByRole("button",{name:"Add sandbox runner"});await waitFor(()=>expect(mocks.get.mock.calls.some(([path])=>path.endsWith("/sandbox-runner-enrollments"))).toBe(true));
 expect((screen.getByRole("checkbox",{name:"Enable sandbox creation"}) as HTMLInputElement).disabled).toBe(true);expect(screen.getByText(/Runtime: Readiness unconfirmed/)).toBeTruthy();
});
it("retains the runner modal when a Ready transition reloads canonical setup",async()=>{
 const ready={...setup,creation_status:{...setup.creation_status,runtime_ready:true,runner_enrollment_required:true},catalog:[{...setup.catalog[0],enabled:true}]};
 const runners={profiles:[],enrollments:[{id:"runner-a",name:"Team runner",state:"awaiting_connection",blocked_reasons:[]}],blocked_reasons:[]};
 mocks.get.mockImplementation(async(path:string)=>({data:path.endsWith("/sandbox-runner-enrollments")?runners:{...ready,creation_status:{...ready.creation_status,runtime_ready:false}}}));page();
 const enable=await screen.findByRole("checkbox",{name:"Enable sandbox creation"});fireEvent.click(await screen.findByRole("button",{name:"View Team runner"}));
 await waitFor(()=>expect((screen.getByRole("button",{name:"Refresh status"}) as HTMLButtonElement).disabled).toBe(false));
 let resolve!:(value:unknown)=>void;mocks.get.mockImplementation(async(path:string)=>path.endsWith("/sandbox-runner-enrollments")?{data:{...runners,enrollments:[{...runners.enrollments[0],state:"ready"}]}}:new Promise(done=>{resolve=done}));
 fireEvent.click(screen.getByRole("button",{name:"Refresh status"}));await waitFor(()=>expect(typeof resolve).toBe("function"));
 expect(screen.getByRole("dialog",{name:"Runner: Team runner"})).toBeTruthy();
 expect((enable as HTMLInputElement).disabled).toBe(true);await act(async()=>resolve({data:ready}));
 expect(screen.getByRole("dialog",{name:"Runner: Team runner"})).toBeTruthy();expect(screen.getByRole("link",{name:/Review Sandbox setup/})).toBeTruthy();expect((enable as HTMLInputElement).disabled).toBe(false);
});
it("keeps setup visible but invalidates canonical readiness while refreshing and after a failed read",async()=>{
 const ready={...setup,creation_status:{...setup.creation_status,runtime_ready:true,runner_enrollment_required:true},catalog:[{...setup.catalog[0],enabled:true}]};
 const runners={profiles:[],enrollments:[{id:"runner-a",name:"Team runner",state:"ready",blocked_reasons:[]}],blocked_reasons:[]};
 mocks.get.mockImplementation(async(path:string)=>({data:path.endsWith("/sandbox-runner-enrollments")?runners:ready}));page();
 const enable=await screen.findByRole("checkbox",{name:"Enable sandbox creation"});await waitFor(()=>expect((enable as HTMLInputElement).disabled).toBe(false));
 let resolve!:(value:unknown)=>void;mocks.get.mockImplementation(async(path:string)=>path.endsWith("/sandbox-runner-enrollments")?{data:runners}:new Promise(done=>{resolve=done}));
 fireEvent.click(screen.getByRole("button",{name:"Refresh"}));await waitFor(()=>expect((enable as HTMLInputElement).disabled).toBe(true));
 expect(screen.getByRole("button",{name:"View Team runner"})).toBeTruthy();await act(async()=>resolve({error:{error:{message:"Synthetic canonical setup failure"}}}));
 expect(screen.getByRole("button",{name:"View Team runner"})).toBeTruthy();expect((enable as HTMLInputElement).disabled).toBe(true);
});
it("separates permission or server failure from empty setup",async()=>{
 mocks.get.mockResolvedValue({error:{code:"forbidden"}});page();expect(await screen.findByText(/requires administrator permission and server support/)).toBeTruthy();expect(screen.queryByRole("button",{name:"Save settings"})).toBeNull();
});
it("retains draft and reports an unconfirmed settings request",async()=>{
 mocks.put.mockRejectedValue(new Error("lost response"));page();await screen.findByRole("button",{name:"Save settings"});fireEvent.change(screen.getByLabelText("Retained sandboxes per user"),{target:{value:"4"}});fireEvent.click(screen.getByRole("button",{name:"Save settings"}));expect(await screen.findByText(/Settings could not be confirmed/)).toBeTruthy();expect((screen.getByLabelText("Retained sandboxes per user") as HTMLInputElement).value).toBe("4");
});
it("distinguishes a connected runtime from a configuration mismatch",async()=>{
 mockSetup({...setup,creation_status:{...setup.creation_status,runtime_ready:true},catalog:[{...setup.catalog[0],runtime_compatible:false}]});page();
 expect(await screen.findByText(/Unpublished · Runtime mismatch/)).toBeTruthy();
 expect((screen.getByRole('checkbox',{name:'Enable sandbox creation'}) as HTMLInputElement).disabled).toBe(true);
});

it("distinguishes a held historical reservation from one reusable workload and closes activation on drift",async()=>{
 const withReservation={...setup,runtime_limits:{max_retained:2,max_workloads:1,retained:1,workloads:0,reservation_id:"historical-fixture",reservation_state:"pending"},creation_status:{...setup.creation_status,runtime_ready:true,blocked_reasons:["organization_disabled"]},catalog:[{...setup.catalog[0],enabled:true}]};
 mockSetup(withReservation);page();
 expect(await screen.findByText(/Runtime limit: 1 retained workload; 0 occupied/)).toBeTruthy();
 expect(screen.getByText(/Overall retained limit: 2; 1 occupied/)).toBeTruthy();
 expect(screen.getByText(/Its position never becomes reusable workload capacity/)).toBeTruthy();
 await waitFor(()=>expect((screen.getByRole("checkbox",{name:"Enable sandbox creation"}) as HTMLInputElement).disabled).toBe(false));
 cleanup();mockSetup({...withReservation,runtime_limits:{...withReservation.runtime_limits,reservation_state:"invalid"},creation_status:{...withReservation.creation_status,blocked_reasons:["historical_reservation_invalid"]}});page();
 expect(await screen.findByText(/historical reservation no longer matches/)).toBeTruthy();
 expect((screen.getByRole("checkbox",{name:"Enable sandbox creation"}) as HTMLInputElement).disabled).toBe(true);
});
