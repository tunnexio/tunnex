import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

let resources: Array<Record<string, unknown>> = [];
let role = "admin";
let emailVerified = true;

vi.mock("../src/lib/useOrg", () => ({
  useOrg: () => ({ org: { id: "org-a", name: "Org A" } }),
}));
vi.mock("../src/lib/auth", () => ({
  useAuth: () => ({ state: { status: "authed", user: { id: "user-a", email_verified: emailVerified } } }),
}));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    api: {
      GET: vi.fn(async (path: string) => {
        if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role }] };
        if (path.endsWith("/resources")) return { data: resources };
        return { data: [] };
      }),
      POST: vi.fn(async () => ({ data: {} })),
      PATCH: vi.fn(async () => ({ data: {} })),
      PUT: vi.fn(async () => ({ data: {} })),
      DELETE: vi.fn(async () => ({ data: {} })),
    },
  };
});

import { api } from "../src/lib/api";
import AccessResources from "../src/pages/AccessResources";

function renderPage() {
  return render(<MemoryRouter><AccessResources /></MemoryRouter>);
}
async function openCreate() {
  await screen.findByRole("button", { name: "Create resource" });
  // The action is available as soon as permission resolves, but the CIDR form
  // deliberately stays behind the inventory's loading state.  Wait for that
  // state to settle before opening the chooser so this test exercises the
  // port contract rather than racing the independent list request.
  await screen.findByLabelText("Search resources");
  fireEvent.click(screen.getAllByRole("button", { name: "Create resource" })[0]);
  fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: /^Create CIDR resource/ }));
  fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Jira" } });
  fireEvent.change(screen.getByLabelText("CIDR"), { target: { value: "10.0.0.4/32" } });
}
function submitCreate() {
  fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Create resource" }));
}

beforeEach(() => { resources = []; role = "admin"; emailVerified = true; vi.mocked(api.POST).mockClear(); vi.mocked(api.PATCH).mockClear(); });
afterEach(() => cleanup());

describe("Access Resources port scope", () => {
  it("withdraws a CIDR draft when the same actor loses email verification while retaining authorized reads", async () => {
    resources = [{ id: "saved", name: "Saved resource", cidr: "10.1.0.0/24", protocol: "tcp", port_low: 443, port_high: null }];
    const rendered = renderPage();
    await openCreate();
    expect(screen.getByRole("dialog")).toBeTruthy();
    emailVerified = false;
    rendered.rerender(<MemoryRouter><AccessResources /></MemoryRouter>);
    expect(screen.queryByRole("dialog")).toBeNull();
    await screen.findByText("Saved resource");
    expect(screen.queryByRole("button", { name: "Create resource" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Saved resource" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Actions for Saved resource" })).toBeNull();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.PATCH).not.toHaveBeenCalled();
  });

  it("pages the loaded CIDR inventory with real size choices and resets search without another read", async () => {
    resources = Array.from({ length: 55 }, (_, index) => ({ id: `res-${index + 1}`, name: `Resource ${String(index + 1).padStart(2, "0")}`, cidr: `10.0.${index + 1}.0/24`, protocol: "tcp", port_low: 443, port_high: null }));
    renderPage();
    await screen.findByRole("button", { name: "Resource 01" });
    expect(screen.getByRole("button", { name: "Resource 20" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Resource 21" })).toBeNull();
    const reads = vi.mocked(api.GET).mock.calls.length;
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    expect(screen.getByRole("button", { name: "Resource 55" })).toBeTruthy();
    expect((screen.getByRole("button", { name: "Previous page" }) as HTMLButtonElement).disabled).toBe(false);
    expect((screen.getByRole("button", { name: "Next page" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "10" } });
    expect(screen.getByRole("button", { name: "Resource 10" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Resource 11" })).toBeNull();
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "50" } });
    expect(screen.getByRole("button", { name: "Resource 50" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Search resources" }), { target: { value: "Resource 55" } });
    expect(screen.getByRole("button", { name: "Resource 55" })).toBeTruthy();
    expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
    expect(vi.mocked(api.GET).mock.calls).toHaveLength(reads);
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.PATCH).not.toHaveBeenCalled();
  });

  it("sends explicit null bounds for Any and TCP/UDP All ports", async () => {
    renderPage();
    await openCreate();
    submitCreate();
    await waitFor(() => expect(vi.mocked(api.POST)).toHaveBeenCalled());
    expect(vi.mocked(api.POST).mock.calls[0][1]).toMatchObject({ body: { protocol: "any", port_low: null, port_high: null } });

    cleanup(); renderPage(); await openCreate();
    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "tcp" } });
    expect((screen.getByLabelText("Port scope") as HTMLSelectElement).value).toBe("all");
    submitCreate();
    await waitFor(() => expect(vi.mocked(api.POST)).toHaveBeenCalledTimes(2));
    expect(vi.mocked(api.POST).mock.calls[1][1]).toMatchObject({ body: { protocol: "tcp", port_low: null, port_high: null } });
  });

  it("round-trips single and range bounds without fabricating a high bound", async () => {
    renderPage(); await openCreate();
    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "udp" } });
    fireEvent.change(screen.getByLabelText("Port scope"), { target: { value: "single" } });
    fireEvent.change(screen.getByLabelText("Port"), { target: { value: "53" } });
    submitCreate();
    await waitFor(() => expect(vi.mocked(api.POST)).toHaveBeenCalled());
    expect(vi.mocked(api.POST).mock.calls[0][1]).toMatchObject({ body: { protocol: "udp", port_low: 53, port_high: 53 } });

    cleanup(); renderPage(); await openCreate();
    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "tcp" } });
    fireEvent.change(screen.getByLabelText("Port scope"), { target: { value: "range" } });
    fireEvent.change(screen.getByLabelText("Port"), { target: { value: "443" } });
    fireEvent.change(screen.getByLabelText("Through"), { target: { value: "445" } });
    submitCreate();
    await waitFor(() => expect(vi.mocked(api.POST)).toHaveBeenCalledTimes(2));
    expect(vi.mocked(api.POST).mock.calls[1][1]).toMatchObject({ body: { protocol: "tcp", port_low: 443, port_high: 445 } });
  });

  it("prefills All, Single, and Range exactly, delays port validation until touch, and omits empty description filler", async () => {
    resources = [
      { id: "all", name: "All", cidr: "10.0.0.0/24", protocol: "tcp", port_low: null, port_high: null, label: null },
      { id: "one", name: "One", cidr: "10.0.1.0/24", protocol: "udp", port_low: 53, port_high: null, label: "DNS" },
      { id: "range", name: "Range", cidr: "10.0.2.0/24", protocol: "tcp", port_low: 443, port_high: 445, label: "" },
    ];
    renderPage();
    await screen.findByRole("button", { name: "All" });
    expect(screen.queryByText("No description")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "All" }));
    expect((screen.getByLabelText("Port scope") as HTMLSelectElement).value).toBe("all");
    expect(screen.queryByText(/Use whole ports/)).toBeNull();
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }));
    fireEvent.click(screen.getByRole("button", { name: "One" }));
    expect((screen.getByLabelText("Port scope") as HTMLSelectElement).value).toBe("single");
    expect((screen.getByLabelText("Port") as HTMLInputElement).value).toBe("53");
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }));
    fireEvent.click(screen.getByRole("button", { name: "Range" }));
    expect((screen.getByLabelText("Port scope") as HTMLSelectElement).value).toBe("range");
    expect((screen.getByLabelText("Port") as HTMLInputElement).value).toBe("443");
    expect((screen.getByLabelText("Through") as HTMLInputElement).value).toBe("445");
    fireEvent.change(screen.getByLabelText("Through"), { target: { value: "442" } });
    expect(await screen.findByText(/range must end at or above/)).toBeTruthy();
  });

  it("clears existing bounds with an exact PATCH payload and rejects boundary ports after touch", async () => {
    resources = [{ id: "range", name: "Range", cidr: "10.0.2.0/24", protocol: "tcp", port_low: 443, port_high: 445, label: "TLS" }];
    renderPage();
    await screen.findByRole("button", { name: "Range" });
    fireEvent.click(screen.getByRole("button", { name: "Range" }));
    fireEvent.change(screen.getByLabelText("Port scope"), { target: { value: "all" } });
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Save resource" }));
    await waitFor(() => expect(vi.mocked(api.PATCH)).toHaveBeenCalled());
    expect(vi.mocked(api.PATCH).mock.calls[0][1]).toMatchObject({ body: { protocol: "tcp", port_low: null, port_high: null } });

    cleanup(); renderPage(); await openCreate();
    fireEvent.change(screen.getByLabelText("Protocol"), { target: { value: "udp" } });
    fireEvent.change(screen.getByLabelText("Port scope"), { target: { value: "single" } });
    fireEvent.change(screen.getByLabelText("Port"), { target: { value: "0" } });
    expect(await screen.findByText(/Use whole ports/)).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Port"), { target: { value: "65536" } });
    expect(screen.getByText(/Use whole ports/)).toBeTruthy();
  });

  it("keeps the permission-denied state explicit without rendering resource mutations", async () => {
    role = "member";
    resources = [{ id: "r1", name: "Private", cidr: "10.0.0.0/24", protocol: "any", port_low: null, port_high: null }];
    renderPage();
    expect(await screen.findByText("You do not have permission to manage CIDR resources.")).toBeTruthy();
    expect(screen.queryByText(/FQDN resources are unavailable because your role lacks/)).toBeNull();
    expect(screen.queryByRole("button", { name: "Create resource" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Edit" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete" })).toBeNull();
  });
});
