import { createElement, type ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";

const get = vi.fn();
const org = { id: "org-1", name: "Test org" };

vi.mock("../src/lib/useOrg", () => ({
  useOrg: () => ({ org }),
}));

vi.mock("../src/lib/auth", () => ({
  useAuth: () => ({ state: { status: "authed", user: { id: "member-1", email: "member@example.com", email_verified: true } } }),
}));

vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: get, POST: vi.fn(), DELETE: vi.fn() } };
});

vi.mock("react-router-dom", () => ({
  Link: ({ children, ...props }: { children: ReactNode; [key: string]: unknown }) =>
    createElement("a", props, children),
}));

vi.mock("../src/components/ui", () => {
  const primitive = (tag: string) =>
    ({ children, ...props }: { children?: ReactNode; [key: string]: unknown }) =>
      createElement(tag, props, children);
  return {
    // The page header is a real component now, not markup each page hand-rolls. Mocked to an h1 so the
    // route's heading stays assertable — a `primitive("header")` would spread `title` onto the DOM node
    // and the text would vanish from the tree.
    PageHeader: ({
      title,
      subtitle,
      actions,
    }: {
      title: string;
      subtitle?: ReactNode;
      actions?: ReactNode;
    }) =>
      createElement(
        "header",
        null,
        createElement("h1", null, title),
        subtitle ?? null,
        actions ?? null,
      ),
    Badge: primitive("span"),
    Button: primitive("button"),
    Card: primitive("section"),
    DataTable: () => null,
    Field: primitive("label"),
    Input: primitive("input"),
    Select: primitive("select"),
    StatusDot: () => null,
  };
});

vi.mock("../src/components/OneTimeSecret", () => ({
  OneTimeSecretModal: () => null,
}));

vi.mock("../src/lib/agentview", () => ({
  AGENT_PREREQ: "",
  NO_AGENTS: "No agents yet.",
  agentBootstrapCommand: () => "",
  attributionNote: () => null,
  sortAgents: (rows: unknown[]) => rows,
  livenessLabel: () => ({ label: "never connected", detail: "never", tone: "warn" }),
  agentLiveness: () => "never",
  formatTraffic: () => null,
}));

afterEach(() => {
  cleanup();
  get.mockReset();
});

describe("released /agents route absence boundary", () => {
  it("does not render profile metadata or lifecycle controls for a plain-member route", async () => {
    get.mockImplementation(async (path: string) => {
      if (path.endsWith("/nodes")) return { data: [], error: undefined };
      if (path.endsWith("/agents")) return { data: [], error: undefined, response: { status: 200 } };
      if (path.endsWith("/members")) return { data: [{ user_id: "member-1", role: "member" }], response: { status: 200 } };
      return { data: undefined, error: { error: { code: "not_found" } }, response: { status: 404 } };
    });

    const { default: Agents } = await import("../src/pages/Agents");
    render(createElement(Agents));

    expect(await screen.findByText("No agents yet.")).toBeTruthy();
    expect(screen.queryByText("Environment")).toBeNull();
    expect(screen.queryByText("Runtime")).toBeNull();
    expect(screen.queryByRole("button", { name: "Suspend" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Resume" })).toBeNull();
  });
});
