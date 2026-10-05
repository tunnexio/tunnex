import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), org: { id: "org-a" }, available: false, skillsEnabled: false }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "owner" } } }) }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: mocks.org, loading: false, failed: false }) }));
vi.mock("../src/lib/api", () => ({ api: { GET: mocks.get, POST: mocks.post }, apiErrorMessage: (_: unknown, fallback: string) => fallback }));
import { SandboxCreatePage, SandboxesPage, SandboxDetailPage } from "../src/pages/Sandboxes";
const template = { id: "template", name: "Minimal terminal", image_digest: "sha256:digest", maximum_scope: [{ cidr: "10.1.0.0/16", protocol: "tcp", port_low: 22, port_high: 22 }], memory_mib: 256, max_ttl_seconds: 3600, allowed_skill_revision_ids: ["skill"] };
const publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f";
const connection = { address:"10.254.242.2",username:"sandbox",port:22,host_public_key:publicKey,host_key_fingerprint:"SHA256:fixture-public-pin" };
beforeEach(() => { mocks.org = { id: "org-a" };mocks.available = false;mocks.skillsEnabled = false;mocks.get.mockReset();mocks.post.mockReset();mocks.get.mockImplementation(async (path: string) => {
 if (path.endsWith("/sandbox-templates")) return { data: { items: [template] } };
 if (path.endsWith("/sandbox-skills")) return { data: { items: mocks.skillsEnabled ? [{ id: "skill", name: "Fixture guide", description: "Approved instructions", version: "1", digest: "digest", required_scope: [], fields: [{ key: "format", label: "Format", required: true, choices: ["short", "long"] }] }] : [], configuration_available: mocks.skillsEnabled } };
 return { data: { items: [], create_available: mocks.available } };
}); });
afterEach(cleanup);
async function wizard() {
 render(<MemoryRouter initialEntries={["/sandboxes/new"]}><Routes><Route path="/sandboxes/new" element={<SandboxCreatePage />} /><Route path="/sandboxes" element={<SandboxesPage />} /></Routes></MemoryRouter>);
 return within(await screen.findByRole("dialog",{name:"Create sandbox"}));
}
async function environment() {
 const modal=await wizard();
 fireEvent.change(modal.getByLabelText("Sandbox name"),{target:{value:"work"}});
 fireEvent.change(modal.getByLabelText("Runtime configuration"),{target:{value:"template"}});
 fireEvent.click(modal.getByRole("button",{name:/^Next/}));
 return modal;
}
async function access() {
 const modal=await environment();
 fireEvent.change(modal.getByLabelText("SSH public keys"),{target:{value:publicKey+" local-comment"}});
 fireEvent.click(modal.getByRole("checkbox"));
 fireEvent.click(modal.getByRole("button",{name:/^Next/}));
 return modal;
}
it("shows real inventory, approved runtime limits and clear unavailability",async()=>{
 render(<MemoryRouter><SandboxesPage /></MemoryRouter>);
 expect(await screen.findByText(/No sandboxes yet/)).toBeTruthy();
 expect(screen.getByText("Creation unavailable")).toBeTruthy();
 expect(screen.getByText(/does not provide setup details/)).toBeTruthy();
 expect(screen.getByText("256 MiB")).toBeTruthy();
 expect(screen.getByRole("link",{name:"Skills"}).getAttribute("href")).toBe("/sandboxes/skills");
 expect(screen.getAllByRole("button",{name:/^Create sandbox/}).every(button=>(button as HTMLButtonElement).disabled)).toBe(true);
 expect(mocks.get.mock.calls.every(([path])=>!path.includes("/agents"))).toBe(true);
});
it("keeps a deep-linked wizard gated when the runtime is unavailable",async()=>{
 const modal=await wizard();
 fireEvent.change(modal.getByLabelText("Sandbox name"),{target:{value:"work"}});
 fireEvent.change(modal.getByLabelText("Runtime configuration"),{target:{value:"template"}});
 expect((modal.getByRole("button",{name:/^Next/}) as HTMLButtonElement).disabled).toBe(true);
 expect(mocks.post).not.toHaveBeenCalled();
});
it("creates only from review and preserves idempotency on uncertain retry",async()=>{
 mocks.available=true;mocks.post.mockRejectedValue(new Error("lost response"));
 const modal=await access();expect(mocks.post).not.toHaveBeenCalled();
 fireEvent.click(modal.getByRole("button",{name:/^Next/}));expect(mocks.post).not.toHaveBeenCalled();
 fireEvent.click(modal.getByRole("button",{name:/^Create sandbox/}));
 await modal.findByText("Sandbox creation could not be confirmed. Retry with the same configuration.");
 fireEvent.click(modal.getByRole("button",{name:/^Create sandbox/}));
 await waitFor(()=>expect(mocks.post).toHaveBeenCalledTimes(2));
 const first=mocks.post.mock.calls[0][1], second=mocks.post.mock.calls[1][1];
 expect(first.params.header["Idempotency-Key"]).toBe(second.params.header["Idempotency-Key"]);
 expect(first.body.requested_scope).toEqual(template.maximum_scope);expect(first.body.ssh_public_keys).toEqual([publicKey]);expect(first.body).not.toHaveProperty("creator_id");
});
it("preserves skill selections and configuration between wizard steps",async()=>{
 mocks.available=true;mocks.skillsEnabled=true;mocks.post.mockRejectedValue(new Error("lost response"));
 const modal=await access();
 fireEvent.click(modal.getByRole("checkbox",{name:/Fixture guide/}));
 fireEvent.change(modal.getByLabelText("Fixture guide: Format"),{target:{value:"short"}});
 fireEvent.click(modal.getByRole("button",{name:/^Next/}));fireEvent.click(modal.getByRole("button",{name:"Back"}));
 expect((modal.getByRole("checkbox",{name:/Fixture guide/}) as HTMLInputElement).checked).toBe(true);
 expect((modal.getByLabelText("Fixture guide: Format") as HTMLSelectElement).value).toBe("short");
 fireEvent.click(modal.getByRole("button",{name:/^Next/}));fireEvent.click(modal.getByRole("button",{name:/^Create sandbox/}));
 await waitFor(()=>expect(mocks.post).toHaveBeenCalledTimes(1));
 expect(mocks.post.mock.calls[0][1].body.selected_skills).toEqual([{revision_id:"skill",configuration:{format:"short"}}]);
});
it("rejects private key text before advancing past access",async()=>{
 mocks.available=true;const modal=await environment();
 fireEvent.change(modal.getByLabelText("SSH public keys"),{target:{value:"-----BEGIN OPENSSH PRIVATE KEY-----\nfixture-only"}});
 fireEvent.click(modal.getByRole("button",{name:/^Next/}));
 expect(await modal.findByText("Paste valid SSH public keys from your .pub files, one per line.")).toBeTruthy();expect(mocks.post).not.toHaveBeenCalled();
});
it("returns to the inventory on Cancel without creating",async()=>{
 mocks.available=true;const modal=await wizard();fireEvent.click(modal.getByRole("button",{name:"Cancel"}));
 await waitFor(()=>expect(screen.queryByRole("dialog")).toBeNull());expect(mocks.post).not.toHaveBeenCalled();
});
it("suppresses concurrent creation while the final request is unresolved",async()=>{
 mocks.available=true;mocks.post.mockImplementation(()=>new Promise(()=>{}));const modal=await access();fireEvent.click(modal.getByRole("button",{name:/^Next/}));
 fireEvent.click(modal.getByRole("button",{name:/^Create sandbox/}));fireEvent.click(modal.getByRole("button",{name:/^Creating/}));
 expect(mocks.post).toHaveBeenCalledTimes(1);
});
function mockDetail(state:string,expires="2030-01-01T00:00:00Z"){
 const previous=mocks.get.getMockImplementation();mocks.get.mockImplementation(async(path:string,...args:unknown[])=>path.endsWith("/sandboxes/{sandboxId}")?{data:{id:"box",name:"Terminal",requested_scope:[],desired_state:"started",observed_state:state,generation:1,expires_at:expires,connection}}:previous?.(path,...args));
 render(<MemoryRouter initialEntries={["/sandboxes/box"]}><Routes><Route path="/sandboxes/:sandboxId" element={<SandboxDetailPage/>}/></Routes></MemoryRouter>);
}
it("delivers pinned public SSH instructions and copy feedback only when ready",async()=>{
 const writeText=vi.fn().mockResolvedValue(undefined);Object.defineProperty(navigator,"clipboard",{configurable:true,value:{writeText}});
 mockDetail("ready");await screen.findByText("Connect");expect(screen.getByText(`10.254.242.2 ${publicKey}`)).toBeTruthy();
 fireEvent.click(screen.getByRole("button",{name:"Copy SSH command"}));await screen.findByText("Copied SSH command.");const copied=writeText.mock.calls[0][0];expect(copied).toContain("StrictHostKeyChecking=yes");expect(copied).toContain('UserKnownHostsFile="$sandbox_hosts"');expect(copied).toContain(`10.254.242.2 ${publicKey}`);expect(copied).toContain("sandbox@10.254.242.2");expect(copied).not.toContain("~/.ssh/known_hosts");expect(screen.getByText("02 / HOST KEY DATA (NOT A COMMAND)")).toBeTruthy();
});
it("withholds connection instructions for starting and expired responses",async()=>{
 mockDetail("starting");await screen.findByText("Waiting for private access");expect(screen.queryByRole("button",{name:"Copy SSH command"})).toBeNull();cleanup();
 mockDetail("ready","2020-01-01T00:00:00Z");await screen.findByText("Workspace lifetime ended");expect(screen.queryByRole("button",{name:"Copy SSH command"})).toBeNull();
});
it("distinguishes a failed inventory from an empty inventory",async()=>{
 mocks.get.mockResolvedValue({error:{message:"forbidden"}});render(<MemoryRouter><SandboxesPage /></MemoryRouter>);await screen.findByRole("alert");expect(screen.queryByText(/No sandboxes yet/)).toBeNull();expect(screen.getByRole("button",{name:"Retry"})).toBeTruthy();
});
it("offers creation only with an approved available environment",async()=>{
 mocks.available=true;render(<MemoryRouter><SandboxesPage /></MemoryRouter>);expect((await screen.findAllByRole("link",{name:/^Create sandbox/}))[0].getAttribute("href")).toBe("/sandboxes/new");
});
it("does not expose stale private connection metadata in the inventory",async()=>{
 const previous=mocks.get.getMockImplementation();mocks.get.mockImplementation(async(path:string,...args:unknown[])=>path.endsWith("/sandboxes")?{data:{items:[{id:"box",name:"Terminal",desired_state:"stopped",observed_state:"ready",expires_at:"2030-01-01T00:00:00Z",connection}],create_available:false}}:previous?.(path,...args));
 render(<MemoryRouter><SandboxesPage /></MemoryRouter>);await screen.findByRole("link",{name:"Open Terminal"});expect(screen.queryByText(/10.254.242.2/)).toBeNull();expect(screen.getByText("Private SSH · not connected")).toBeTruthy();
});
it("explains missing approved runtimes rather than offering an unusable launch",async()=>{
 mocks.available=true;const previous=mocks.get.getMockImplementation();mocks.get.mockImplementation(async(path:string,...args:unknown[])=>path.endsWith("/sandbox-templates")?{data:{items:[]}}:previous?.(path,...args));
 render(<MemoryRouter><SandboxesPage /></MemoryRouter>);await screen.findAllByText("No approved environments");expect(screen.getAllByRole("button",{name:/^Create sandbox/}).every(button=>(button as HTMLButtonElement).disabled)).toBe(true);
});

it("allows authenticated stop and delete when creation is closed, while resume stays gated", async () => {
 mocks.available=false;
 mocks.post.mockResolvedValue({data:{id:"box",name:"Terminal",requested_scope:[],desired_state:"stopped",observed_state:"stopping",generation:2,expires_at:"2030-01-01T00:00:00Z"}});
 mockDetail("starting");
 const stop=await screen.findByRole("button",{name:"Stop"});
 expect((stop as HTMLButtonElement).disabled).toBe(false);
 expect((screen.getByRole("button",{name:"Delete"}) as HTMLButtonElement).disabled).toBe(false);
 fireEvent.click(stop);
 const resume=await screen.findByRole("button",{name:"Resume"});
 expect((resume as HTMLButtonElement).disabled).toBe(true);
 expect(mocks.post.mock.calls[0][1].body).toEqual({generation:1,desired_state:"stopped"});
 const confirm=vi.spyOn(window,"confirm").mockReturnValue(true);
 fireEvent.click(screen.getByRole("button",{name:"Delete"}));
 await waitFor(()=>expect(mocks.post).toHaveBeenCalledTimes(2));
 expect(mocks.post.mock.calls[1][1].body).toEqual({generation:2,desired_state:"deleted"});
 confirm.mockRestore();
});

it("gives administrators real setup navigation and members specific blocked reasons",async()=>{
 const previous=mocks.get.getMockImplementation();mocks.get.mockImplementation(async(path:string,...args:unknown[])=>path.endsWith("/sandboxes")?{data:{items:[],create_available:false,creation_status:{can_admin:true,can_manage_catalog:true,runtime_ready:false,blocked_reasons:["organization_disabled","runtime_not_ready"]}}}:previous?.(path,...args));
 render(<MemoryRouter><SandboxesPage/></MemoryRouter>);
 expect(await screen.findByRole("link",{name:"Sandbox setup"})).toHaveProperty("href",expect.stringContaining("/sandboxes/setup"));
 expect(screen.getByText(/No qualified runtime is currently connected/)).toBeTruthy();
 expect(screen.queryByText(/contact an administrator/)).toBeNull();
 cleanup();
 mocks.get.mockImplementation(async(path:string,...args:unknown[])=>path.endsWith("/sandboxes")?{data:{items:[],create_available:false,creation_status:{can_admin:false,can_manage_catalog:false,runtime_ready:false,blocked_reasons:["user_quota_reached"]}}}:previous?.(path,...args));
 render(<MemoryRouter><SandboxesPage/></MemoryRouter>);
 expect(await screen.findByText(/Your active sandbox limit/)).toBeTruthy();
 expect(screen.queryByRole("link",{name:"Sandbox setup"})).toBeNull();
});

it("never includes candidate metadata in the create selector",async()=>{
 mocks.available=true;const previous=mocks.get.getMockImplementation();mocks.get.mockImplementation(async(path:string,...args:unknown[])=>path.endsWith("/sandbox-templates")?{data:{items:[template],candidate_profiles:[{name:"Candidate-only Python",architecture:"amd64",qualification:"candidate",included_tools:[],excluded_tools:[],compressed_image_bytes:1,unpacked_image_bytes:2,idle_memory_bytes:1,measurement_memory_cap_bytes:1,measurement_workspace_cap_bytes:1}]}}:previous?.(path,...args));
 const modal=await wizard();expect(modal.getByRole("option",{name:/Minimal terminal/})).toBeTruthy();expect(modal.queryByRole("option",{name:/Candidate-only/})).toBeNull();expect(screen.getByText("Candidate-only Python")).toBeTruthy();
});

it("puts workspace rows before a collapsed environment catalog",async()=>{
 const prior=mocks.get.getMockImplementation();mocks.get.mockImplementation(async(path:string,...args:unknown[])=>path.endsWith('/sandboxes')?{data:{items:[{id:'box',name:'Dense workspace',template_id:'template',desired_state:'started',observed_state:'ready',generation:1,expires_at:'2030-01-01T00:00:00Z',connection,requested_scope:[]}],create_available:true}}:prior?.(path,...args));
 render(<MemoryRouter><SandboxesPage/></MemoryRouter>);
 const inventory=await screen.findByRole('table',{name:'Workspace inventory'});
 expect(within(inventory).getAllByRole('row')).toHaveLength(2);
 expect(within(inventory).getByRole('link',{name:'Open Dense workspace'})).toBeTruthy();
 const catalog=screen.getByLabelText('Runtime environments') as HTMLDetailsElement;
 expect(catalog.open).toBe(false);
 expect(inventory.compareDocumentPosition(catalog)&Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
 expect(document.querySelector('.sb-launch')).toBeNull();
});

it("keeps blocked reasons accessible without an expanded instruction panel",async()=>{
 const prior=mocks.get.getMockImplementation();mocks.get.mockImplementation(async(path:string,...args:unknown[])=>path.endsWith('/sandboxes')?{data:{items:[],create_available:false,creation_status:{can_admin:true,can_manage_catalog:true,runtime_ready:false,blocked_reasons:['runtime_not_ready']}}}:prior?.(path,...args));
 render(<MemoryRouter><SandboxesPage/></MemoryRouter>);
 await screen.findByText('Creation unavailable');
 expect((document.querySelector('.sb-notice details') as HTMLDetailsElement).open).toBe(false);
 expect(screen.getByText(/No qualified runtime is currently connected/)).toBeTruthy();
 expect(screen.getByRole('link',{name:'Sandbox setup'}).getAttribute('href')).toBe('/sandboxes/setup');
});

it("defaults the only approved environment without inventing a scope or skipping review",async()=>{
 mocks.available=true;const modal=await wizard();
 expect((modal.getByLabelText('Runtime configuration') as HTMLSelectElement).value).toBe('template');
 fireEvent.change(modal.getByLabelText('Sandbox name'),{target:{value:'Default environment'}});
 fireEvent.click(modal.getByRole('button',{name:/^Next/}));
 expect((modal.getByRole('checkbox') as HTMLInputElement).checked).toBe(false);
 expect(mocks.post).not.toHaveBeenCalled();
});


it.each([
 ["full quota", "stopped", "2030-01-01T00:00:00Z", ["runtime_workload_quota_reached", "user_quota_reached", "organization_quota_reached"], false],
 ["expired", "stopped", "2000-01-01T00:00:00Z", ["user_quota_reached"], true],
 ["disabled organization", "stopped", "2030-01-01T00:00:00Z", ["organization_disabled"], true],
 ["policy disabled", "stopped", "2030-01-01T00:00:00Z", ["policy_not_enforcing"], true],
 ["still stopping", "stopping", "2030-01-01T00:00:00Z", ["user_quota_reached"], true],
])("Resume lifecycle eligibility: %s", async (_label, observed, expires, reasons, disabled) => {
 const prior=mocks.get.getMockImplementation();
 mocks.get.mockImplementation(async(path:string,...args:unknown[]) => {
  if(path.endsWith("/sandboxes")) return {data:{items:[],create_available:false,creation_status:{can_admin:false,can_manage_catalog:false,runtime_ready:true,blocked_reasons:reasons}}};
  if(path.endsWith("/sandboxes/{sandboxId}")) return {data:{id:"box",name:"Terminal",requested_scope:[],desired_state:"stopped",observed_state:observed,generation:3,expires_at:expires}};
  return prior?.(path,...args);
 });
 mocks.post.mockResolvedValue({error:{message:"Current policy no longer permits this action."}});
 render(<MemoryRouter initialEntries={["/sandboxes/box"]}><Routes><Route path="/sandboxes/:sandboxId" element={<SandboxDetailPage/>}/></Routes></MemoryRouter>);
 const resume=await screen.findByRole("button",{name:"Resume"});
 expect((resume as HTMLButtonElement).disabled).toBe(disabled);
 expect(Boolean(screen.queryByText("Resume is currently unavailable."))).toBe(disabled);
 fireEvent.click(resume);
 if(disabled) expect(mocks.post).not.toHaveBeenCalled();
 else {
  await waitFor(()=>expect(mocks.post).toHaveBeenCalledTimes(1));
  expect(mocks.post.mock.calls[0][1].body).toEqual({generation:3,desired_state:"started"});
  expect(await screen.findByText("Sandbox request failed.")).toBeTruthy();
 }
});

it("requires an owned terminal selection and includes it in idempotent organization requests",async()=>{
 mocks.available=true;mocks.skillsEnabled=true;mocks.post.mockRejectedValue(new Error("lost response"));
 const previous=mocks.get.getMockImplementation();
 mocks.get.mockImplementation(async(path:string,...args:unknown[])=>{
  if(path.endsWith("/devices"))return {data:[{id:"terminal-a",name:"My terminal",user_id:"owner",node_id:"gateway",kind:"human",status:"active"},{id:"terminal-b",name:"Second terminal",user_id:"owner",node_id:"gateway",kind:"human",status:"active"}]};
  const result=await previous?.(path,...args);
  if(path.endsWith("/sandboxes"))return {data:{...result?.data,creation_status:{requires_terminal_device:true,terminal_gateway_id:"gateway"}}};
  return result;
 });
 const modal=await environment();
 await modal.findByRole("option",{name:"My terminal"});
 fireEvent.change(modal.getByLabelText("SSH public keys"),{target:{value:publicKey}});
 fireEvent.submit(modal.getByRole("button",{name:/^Next/}).closest("form")!);
 await modal.findByText("Choose your terminal device before continuing.");
 expect(mocks.post).not.toHaveBeenCalled();
 fireEvent.change(modal.getByLabelText("Your terminal device"),{target:{value:"terminal-a"}});
 fireEvent.click(modal.getByRole("button",{name:/^Next/}));
 fireEvent.click(modal.getByRole("checkbox",{name:/Fixture guide/}));
 fireEvent.change(modal.getByLabelText("Fixture guide: Format"),{target:{value:"short"}});
 fireEvent.click(modal.getByRole("button",{name:/^Next/}));
 expect(modal.getByText("My terminal")).toBeTruthy();
 fireEvent.click(modal.getByRole("button",{name:/^Create sandbox/}));
 await modal.findByText("Sandbox creation could not be confirmed. Retry with the same configuration.");
 fireEvent.click(modal.getByRole("button",{name:/^Create sandbox/}));
 await waitFor(()=>expect(mocks.post).toHaveBeenCalledTimes(2));
 const first=mocks.post.mock.calls[0][1];
 expect(first.body.terminal_device_id).toBe("terminal-a");
 expect(first.body.selected_skills).toEqual([{revision_id:"skill",configuration:{format:"short"}}]);
 expect(mocks.post.mock.calls[1][1].params.header["Idempotency-Key"]).toBe(first.params.header["Idempotency-Key"]);
 fireEvent.click(modal.getByRole("button",{name:/Access$/}));
 await modal.findByRole("option",{name:"Second terminal"});
 fireEvent.change(modal.getByLabelText("Your terminal device"),{target:{value:"terminal-b"}});
 fireEvent.click(modal.getByRole("button",{name:/^Next/}));
 fireEvent.click(modal.getByRole("button",{name:/^Next/}));
 fireEvent.click(modal.getByRole("button",{name:/^Create sandbox/}));
 await waitFor(()=>expect(mocks.post).toHaveBeenCalledTimes(3));
 expect(mocks.post.mock.calls[2][1].body.terminal_device_id).toBe("terminal-b");
 expect(mocks.post.mock.calls[2][1].params.header["Idempotency-Key"]).not.toBe(first.params.header["Idempotency-Key"]);
});
