import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
const mocks = vi.hoisted(() => ({ get: vi.fn(), userId: "owner" }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: mocks.userId } } }) }));
vi.mock("../src/lib/api", () => ({ api: { GET: mocks.get }, apiErrorMessage: (_: unknown, fallback: string) => fallback }));
import { SandboxTerminalPicker, type SandboxTerminalSelection } from "../src/components/SandboxTerminalPicker";
const own = { id: "own", name: "My terminal", user_id: "owner", node_id: "gateway", kind: "human", status: "active", health_blocked: false };
function Picker({ orgId = "org", initial = "" }: { orgId?: string; initial?: string }) {
  const [selected, setSelected] = useState<SandboxTerminalSelection | null>(initial ? { id: initial, name: initial } : null);
  return <><SandboxTerminalPicker orgId={orgId} gatewayId="gateway" value={selected?.id ?? ""} onChange={setSelected} /><output>{selected?.id ?? "none"}</output></>;
}
afterEach(() => { cleanup(); mocks.get.mockReset(); });
it("offers only the caller's healthy active human devices on the pinned gateway", async () => {
  mocks.get.mockResolvedValue({ data: [own, { ...own, id: "other", user_id: "someone" }, { ...own, id: "agent", kind: "agent" }, { ...own, id: "blocked", health_blocked: true }, { ...own, id: "revoked", status: "revoked" }, { ...own, id: "wrong-gateway", node_id: "other-gateway" }] });
  render(<Picker />);
  await screen.findByRole("option", { name: "My terminal" });
  expect(screen.getAllByRole("option")).toHaveLength(2);
  fireEvent.change(screen.getByLabelText("Your terminal device"), { target: { value: "own" } });
  expect(screen.getByRole("status").textContent).toBe("own");
  expect(mocks.get.mock.calls[0][1]).toEqual({ params: { path: { orgId: "org" } } });
});
it("clears a previously selected device when refreshed ownership or health is invalid", async () => {
  mocks.get.mockResolvedValue({ data: [{ ...own, user_id: "someone" }] });
  render(<Picker initial="own" />);
  await screen.findByText(/No eligible terminal device/);
  expect(screen.getByRole("status").textContent).toBe("none");
});
it("ignores an old organization's response and clears selection on load failure", async () => {
  let resolveOld!: (value: unknown) => void;
  mocks.get.mockImplementationOnce(() => new Promise(resolve => { resolveOld = resolve; })).mockResolvedValueOnce({ error: { message: "unavailable" } });
  const view = render(<Picker initial="own" />);
  view.rerender(<Picker orgId="next" initial="own" />);
  await screen.findByText(/Terminal devices could not be loaded/);
  resolveOld({ data: [own] });
  await waitFor(() => expect(screen.queryByRole("option", { name: "My terminal" })).toBeNull());
  expect(screen.getByRole("status").textContent).toBe("none");
});
