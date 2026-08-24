import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

let mode: "denied" | "ready" = "denied";
let assignmentMode: "none" | "same" | "different" = "none";
let memberCount = 1;
let archiveBlocked = false;
const profileA = { id: "profile-a", org_id: "org-a", name: "Jira", endpoint: "https://mcp.example/jira", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z", archived_at: null };
const profileB = { id: "profile-b", org_id: "org-a", name: "GitHub", endpoint: "https://mcp.example/github", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z", archived_at: null };

vi.mock("../src/lib/useOrg", () => ({
  useOrg: () => ({ org: { id: "org-a", name: "Org A", agent_policy_templates_enabled: true } }),
}));

vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    api: {
      GET: vi.fn(async (path: string) => {
        if (path.endsWith("/agent-mcp-profiles")) return mode === "denied"
          ? { error: { error: { code: "permission_denied", message: "MCP profiles require permission." } } }
          : { data: [profileA, profileB] };
        if (path.endsWith("/agent-mcp-assignments")) return { data: assignmentMode === "none" ? [] : [{ id: "assignment-a", group_id: "group-a", group_name: "Production", profile_id: assignmentMode === "same" ? "profile-a" : "profile-b", profile_name: assignmentMode === "same" ? "Jira" : "GitHub", state: "active", assigned_at: "2026-01-01T00:00:00Z", ended_at: null, quarantine_reason: null }] };
        if (path.endsWith("/agent-groups")) return { data: mode === "ready" ? [{ id: "group-a", name: "Production", description: "", member_count: 1, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" }] : [] };
        if (path.endsWith("/members")) return { data: Array.from({ length: memberCount }, (_, index) => ({ id: `member-${index}`, device_id: `device-${index}`, group_id: "group-a" })) };
        return { data: [] };
      }),
      POST: vi.fn(async (path: string) => path.endsWith("/archive") && archiveBlocked
        ? { error: { code: "mcp_profile_in_use", active_group_count: 2, affected_agent_count: 3 } }
        : { data: profileA }), PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn(),
    },
  };
});

import AgentsMCP from "../src/pages/AgentsMCP";

afterEach(() => { cleanup(); mode = "denied"; assignmentMode = "none"; memberCount = 1; archiveBlocked = false; });

async function assignmentImpactText() {
  const heading = await screen.findByRole("heading", { name: "Shared assignment impact" });
  return heading.parentElement?.parentElement?.textContent ?? "";
}

async function findParagraphContaining(text: string) {
  return screen.findByText((_, element) => element?.tagName === "P" && Boolean(element.textContent?.includes(text)));
}

describe("Agents MCP permission boundary", () => {
  it("renders forbidden inventory as permission denied, never as an empty or failed inventory", async () => {
    render(<MemoryRouter><AgentsMCP /></MemoryRouter>);
    await screen.findByRole("heading", { name: "You do not have permission to view MCP profiles" });
    expect(screen.queryByText("MCP profiles could not be loaded")).toBeNull();
    expect(screen.queryByText("Create a reusable MCP profile")).toBeNull();
  });

  it("uses the generated group-owned lifecycle contract from the profile workspace", async () => {
    mode = "ready";
    render(<MemoryRouter><AgentsMCP /></MemoryRouter>);
    await screen.findByRole("button", { name: "Preview assignment" });
    expect(screen.getByRole("link", { name: "Manage agent groups" }).getAttribute("href")).toBe("/access/groups?type=agents");
    expect(await assignmentImpactText()).toContain("Preview the exact shared impact before the first assignment.");
  });

  it("tells the operator that a same active profile affects no agents when the selected group is empty", async () => {
    mode = "ready"; assignmentMode = "same"; memberCount = 0;
    render(<MemoryRouter initialEntries={["/agents/mcp?profile=profile-a&group=group-a"]}><AgentsMCP /></MemoryRouter>);
    expect(await assignmentImpactText()).toContain("Jira is already active for Production.");
    expect(screen.getByText("No agents are currently affected by this group.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Preview replacement" })).toBeNull();
    expect(screen.getByRole("button", { name: "Preview unassign" })).toBeTruthy();
  });

  it("describes same active profile inheritance for groups with members", async () => {
    mode = "ready"; assignmentMode = "same"; memberCount = 2;
    render(<MemoryRouter initialEntries={["/agents/mcp?profile=profile-a&group=group-a"]}><AgentsMCP /></MemoryRouter>);
    expect(await findParagraphContaining("2 agents currently inherit through this group.")).toBeTruthy();
    expect(screen.getByText("This profile is already active for the group.")).toBeTruthy();
  });

  it("keeps a different active profile on the explicit replacement path", async () => {
    mode = "ready"; assignmentMode = "different";
    render(<MemoryRouter initialEntries={["/agents/mcp?profile=profile-a&group=group-a"]}><AgentsMCP /></MemoryRouter>);
    expect(await assignmentImpactText()).toContain("Jira can replace GitHub for Production.");
    expect(screen.getByRole("button", { name: "Preview replacement" })).toBeTruthy();
  });

  it("keeps a group without an active profile on the distinct first-assignment path", async () => {
    mode = "ready"; assignmentMode = "none";
    render(<MemoryRouter initialEntries={["/agents/mcp?profile=profile-a&group=group-a"]}><AgentsMCP /></MemoryRouter>);
    expect(await assignmentImpactText()).toContain("Jira can be assigned to Production.");
    expect(screen.getByRole("button", { name: "Preview assignment" })).toBeTruthy();
  });

  it("uses server-authoritative archive conflict counts instead of a stale local assumption", async () => {
    mode = "ready"; archiveBlocked = true;
    render(<MemoryRouter initialEntries={["/agents/mcp?profile=profile-a&group=group-a"]}><AgentsMCP /></MemoryRouter>);
    fireEvent.click(await screen.findByRole("button", { name: "Archive" }));
    fireEvent.click(screen.getByRole("button", { name: "Archive profile" }));
    expect(await screen.findByText("Archive is blocked by 2 active groups affecting 3 distinct agents. Unassign the profile from those groups, then retry.")).toBeTruthy();
  });
});
