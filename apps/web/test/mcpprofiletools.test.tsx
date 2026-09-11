import { afterEach, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { MCPProfileTools } from "../src/components/MCPProfileTools";
vi.mock("../src/lib/api", () => ({ api: { GET: vi.fn() }, loadOne: async () => ({ ok: true, data: { observed_at: "2026-09-11T14:00:00Z", snapshot: { servers: [
  { endpoint: "http://fixture/mcp", server_name: "Fixture", status: "healthy", tools: [{name: "echo", description: "Returns a message"}] },
  { endpoint: "http://other/mcp", tools: [{name: "wrong-server-tool"}] }
] } } }) }));
afterEach(cleanup);
it("shows observed tools only from the selected server with source and permission link", async () => {
 render(<MemoryRouter><MCPProfileTools orgId="org" endpoint="http://fixture/mcp" members={[{device_id:"agent",name:"Test agent",status:"active",node_id:"node",added_at:"now"}]} /></MemoryRouter>);
 expect(await screen.findByText("echo")).toBeTruthy();
 expect(screen.queryByText("wrong-server-tool")).toBeNull();
 expect(screen.getByText(/Last observed:/).textContent).toContain("2026-09-11");
 expect(screen.getByRole("link",{name:/Manage this agent/}).getAttribute("href")).toBe("/agents/agent?tab=mcp");
});
it("explains discovery prerequisites when no agents are assigned", () => {
 render(<MemoryRouter><MCPProfileTools orgId="org" endpoint="http://fixture/mcp" members={[]} /></MemoryRouter>);
 expect(screen.getByText(/Add an agent to this group/)).toBeTruthy();
 expect(screen.queryByText("Loading observed tools…")).toBeNull();
});
