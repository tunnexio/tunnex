import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
const mocks = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), remove: vi.fn() }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: { id: "org-a" }, loading: false, failed: false }) }));
vi.mock("../src/lib/api", () => ({ api: { GET: mocks.get, POST: mocks.post, PUT: mocks.put, DELETE: mocks.remove }, apiErrorMessage: (_: unknown, fallback: string) => fallback }));
import SandboxCustomSkillsPage from "../src/pages/SandboxCustomSkills";
const document = "---\nname: my-guide\ndescription: Review my work\n---\n\nInstructions\n";
const skill = { id: "private-skill", revision_id: "revision-one", generation: 1, name: "my-guide", description: "Review my work", digest: "digest", document, created_at: "2026-10-02T00:00:00Z", deleted: false };
beforeEach(() => { mocks.get.mockReset(); mocks.post.mockReset(); mocks.put.mockReset(); mocks.remove.mockReset(); mocks.get.mockImplementation(async (path: string) => path.endsWith("/{skillId}") ? { data: skill } : { data: { items: [] } }); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
function page(path = "/sandboxes/skills") { return render(<MemoryRouter initialEntries={[path]}><Routes><Route path="/sandboxes/skills" element={<SandboxCustomSkillsPage />} /><Route path="/sandboxes/skills/:skillId" element={<SandboxCustomSkillsPage />} /></Routes></MemoryRouter>); }
it("adds private skill text and preserves the request on uncertain retry", async () => {
 mocks.post.mockRejectedValue(new Error("lost reply")); page(); await screen.findByText("No custom skills yet."); fireEvent.click(screen.getAllByRole("button",{name:/^Add custom skill/})[0]); await screen.findByRole("dialog");
 fireEvent.change(screen.getByLabelText("SKILL.md document"), { target: { value: document } });
 fireEvent.click(screen.getByRole("button", { name: "Add private skill" })); await screen.findByText("Add could not be confirmed. Retry the same document to preserve the request.");
 fireEvent.click(screen.getByRole("button", { name: "Add private skill" })); await waitFor(() => expect(mocks.post).toHaveBeenCalledTimes(2));
 expect(mocks.post.mock.calls[0][1].body).toEqual({ document });
 expect(mocks.post.mock.calls[0][1].params.header["Idempotency-Key"]).toEqual(mocks.post.mock.calls[1][1].params.header["Idempotency-Key"]);
 expect(mocks.post.mock.calls[0][1].body).not.toHaveProperty("owner_id");
});
it("saves a new revision with the loaded generation", async () => {
 mocks.put.mockResolvedValue({ error: {} }); page("/sandboxes/skills/private-skill"); await screen.findByText(/Revision 1. Saving creates/);
 fireEvent.change(screen.getByLabelText("SKILL.md document"), { target: { value: document + "new text" } });
 fireEvent.click(screen.getByRole("button", { name: "Save new revision" })); await waitFor(() => expect(mocks.put).toHaveBeenCalledTimes(1));
 expect(mocks.put.mock.calls[0][1].body).toEqual({ document: document + "new text", generation: 1 });
 expect(mocks.post).not.toHaveBeenCalled();
});
it("confirms deletion and sends the current generation", async () => {
 const confirmation = vi.spyOn(window, "confirm").mockReturnValue(true); mocks.remove.mockResolvedValue({ error: {} }); page("/sandboxes/skills/private-skill"); await screen.findByText(/Revision 1. Saving creates/);
 fireEvent.click(screen.getByRole("button", { name: "Delete private skill" })); await waitFor(() => expect(mocks.remove).toHaveBeenCalledTimes(1));
 expect(confirmation.mock.calls[0][0]).toContain("disables all its revisions"); expect(mocks.remove.mock.calls[0][1].params.query).toEqual({ generation: 1 });
});
it("rejects an oversized import without uploading it", async () => {
 page(); await screen.findByText("No custom skills yet."); fireEvent.click(screen.getAllByRole("button",{name:/^Add custom skill/})[0]); await screen.findByRole("dialog"); const file = new File(["x".repeat(32769)], "SKILL.md", { type: "text/markdown" });
 fireEvent.change(screen.getByLabelText("Import SKILL.md"), { target: { files: [file] } }); await screen.findByText("Choose one UTF-8 .md file up to 32 KiB.");
 expect(mocks.post).not.toHaveBeenCalled();
});

it("searches actual skill metadata and distinguishes no matches from an empty library",async()=>{
 mocks.get.mockResolvedValue({data:{items:[skill,{...skill,id:"two",name:"deploy-guide",description:"Release checklist",generation:3}]}});
 page();await screen.findByRole("link",{name:"Edit my-guide"});
 fireEvent.change(screen.getByRole("textbox",{name:"Search private skills"}),{target:{value:"Release"}});
 expect(screen.queryByRole("link",{name:"Edit my-guide"})).toBeNull();expect(screen.getByRole("link",{name:"Edit deploy-guide"})).toBeTruthy();
 fireEvent.change(screen.getByRole("textbox",{name:"Search private skills"}),{target:{value:"unknown"}});
 expect(screen.getByText("No skills match your search")).toBeTruthy();expect(screen.queryByText("No custom skills yet.")).toBeNull();
 fireEvent.click(screen.getByRole("button",{name:"Clear search"}));expect(screen.getByRole("link",{name:"Edit my-guide"})).toBeTruthy();
});
it("shows a retry error instead of pretending the skill library is empty",async()=>{
 mocks.get.mockResolvedValue({error:{}});page();await screen.findByRole("alert");expect(screen.queryByText("No custom skills yet.")).toBeNull();expect(screen.getByRole("button",{name:"Retry"})).toBeTruthy();
});
it("validates malformed documents without sending a save",async()=>{
 page();await screen.findByText("No custom skills yet.");fireEvent.click(screen.getAllByRole("button",{name:/^Add custom skill/})[0]);
 fireEvent.change(screen.getByLabelText("SKILL.md document"),{target:{value:"invalid front matter"}});fireEvent.click(screen.getByRole("button",{name:"Add private skill"}));
 await screen.findByRole("alert");expect(mocks.post).not.toHaveBeenCalled();
});
it("previews instructions without executing raw HTML or loading external images",async()=>{
 page();await screen.findByText("No custom skills yet.");fireEvent.click(screen.getAllByRole("button",{name:/^Add custom skill/})[0]);
 fireEvent.change(screen.getByLabelText("SKILL.md document"),{target:{value:document+"\n## Review code\n<script>alert('bad')</script>\n![untrusted](https://example.test/image.png)"}});
 fireEvent.click(screen.getByRole("tab",{name:"Preview"}));const preview=screen.getByRole("tabpanel");
 expect(within(preview).getByRole("heading",{name:"Review code"})).toBeTruthy();expect(preview.querySelector("script")).toBeNull();expect(preview.querySelector("img")).toBeNull();
});
it("cancels an unsaved draft without mutation and retains it when reopened",async()=>{
 page();await screen.findByText("No custom skills yet.");fireEvent.click(screen.getAllByRole("button",{name:/^Add custom skill/})[0]);
 fireEvent.change(screen.getByLabelText("SKILL.md document"),{target:{value:document}});fireEvent.click(screen.getByRole("button",{name:"Cancel"}));
 expect(screen.queryByRole("dialog")).toBeNull();expect(mocks.post).not.toHaveBeenCalled();fireEvent.click(screen.getAllByRole("button",{name:/^Add custom skill/})[0]);
 expect((screen.getByLabelText("SKILL.md document") as HTMLTextAreaElement).value).toBe(document);
});
it("imports valid UTF-8 Markdown locally and exposes revision identity without inventing history",async()=>{
 page("/sandboxes/skills/private-skill");await screen.findByText(/Revision 1. Saving creates/);
 const file=new File([document+"new local instructions"],"SKILL.md",{type:"text/markdown"});fireEvent.change(screen.getByLabelText("Import SKILL.md"),{target:{files:[file]}});
 await waitFor(()=>expect((screen.getByLabelText("SKILL.md document") as HTMLTextAreaElement).value).toContain("new local instructions"));
 fireEvent.click(screen.getByText("Revision identity"));expect(screen.getByText("revision-one")).toBeTruthy();expect(screen.getByText("Earlier revision documents are not available in this view.")).toBeTruthy();expect(mocks.put).not.toHaveBeenCalled();
});
it("does not delete when the existing destructive confirmation is canceled",async()=>{
 vi.spyOn(window,"confirm").mockReturnValue(false);page("/sandboxes/skills/private-skill");await screen.findByText(/Revision 1. Saving creates/);fireEvent.click(screen.getByRole("button",{name:"Delete private skill"}));expect(mocks.remove).not.toHaveBeenCalled();
});
