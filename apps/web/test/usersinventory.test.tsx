import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import type { Member } from "../src/lib/api";
import UsersInventory, { type UsersInventoryProps } from "../src/components/UsersInventory";

const member = (index: number, values: Partial<Member> = {}): Member => ({ user_id: `member-${index}`, name: `Person ${index}`, email: `person${index}@example.test`, role: "member", status: "active", email_verified: true, joined_at: "2026-10-08T08:00:00Z", ...values });
function mount(members: Member[], options: Partial<UsersInventoryProps> = {}) {
  const props: UsersInventoryProps = { members, devices: [], actorId: "member-1", actorRole: "owner", emailVerified: true, busy: false, view: "users", ownerCount: 1, onInspect: vi.fn(), onRequestAction: vi.fn(), ...options };
  const ui = (next = props) => <MemoryRouter><UsersInventory {...next} /></MemoryRouter>;
  return { ...render(ui()), props, ui };
}
const names = () => within(screen.getByRole("table", { name: "Members" })).getAllByRole("row").slice(1).map(row => within(row).getByRole("button", { name: /^Person \d+$/ }).textContent);
function menu(email: string) {
  fireEvent.click(screen.getByRole("button", { name: `User actions for ${email}` }));
  return within(screen.getByRole("menu", { name: `User actions for ${email}` }));
}
afterEach(cleanup);

describe("UsersInventory roster and account targets", () => {
  it("pages 55 loaded people and retains a short last page while size and role searches reset to the start", () => {
    const members = Array.from({ length: 55 }, (_, index) => member(index + 1, index === 40 ? { role: "ai-admin", status: "deactivated" } : {}));
    mount(members);
    expect(names()).toHaveLength(20);
    fireEvent.click(screen.getByRole("button", { name: "Next members page" }));
    expect(names()[0]).toBe("Person 21");
    fireEvent.click(screen.getByRole("button", { name: "Next members page" }));
    expect(names()).toEqual(Array.from({ length: 15 }, (_, index) => `Person ${index + 41}`));
    expect(screen.getByRole("button", { name: "Next members page" })).toHaveProperty("disabled", true);
    fireEvent.change(screen.getByRole("searchbox", { name: "Filter Members" }), { target: { value: "ai-admin deactivated" } });
    expect(names()).toEqual(["Person 41"]);
    expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
    fireEvent.change(screen.getByRole("searchbox", { name: "Filter Members" }), { target: { value: "" } });
    expect(names()[0]).toBe("Person 1");
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "50" } });
    expect(names()).toHaveLength(50);
    fireEvent.click(screen.getByRole("button", { name: "Next members page" }));
    expect(names()).toEqual(["Person 51", "Person 52", "Person 53", "Person 54", "Person 55"]);
    expect(screen.getByRole("button", { name: "Previous members page" })).toHaveProperty("disabled", false);
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "10" } });
    expect(names()).toHaveLength(10);
    expect(names()[0]).toBe("Person 1");
  });

  it("keeps cross-page selection but sends only eligible account states and requires a single 2FA target", () => {
    const members = Array.from({ length: 45 }, (_, index) => member(index + 1, index === 40 ? { status: "deactivated" } : {}));
    const view = mount(members);
    fireEvent.click(screen.getByRole("checkbox", { name: "Select person1@example.test" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Select person2@example.test" }));
    fireEvent.click(screen.getByRole("button", { name: "Next members page" }));
    fireEvent.change(screen.getByRole("searchbox", { name: "Filter Members" }), { target: { value: "person41@example.test" } });
    fireEvent.click(screen.getByRole("checkbox", { name: "Select person41@example.test" }));
    const selection = within(screen.getByRole("group", { name: "Selected member actions" }));
    expect(selection.getByText("3 selected")).toBeTruthy();
    expect(selection.getByText("2 outside this page")).toBeTruthy();
    expect(selection.getAllByText("1 of 3")).toHaveLength(2);
    expect(selection.getByRole("button", { name: "Reset 2FA" })).toHaveProperty("disabled", true);
    fireEvent.click(selection.getByRole("button", { name: "Deactivate" }));
    expect(view.props.onRequestAction).toHaveBeenLastCalledWith("deactivate", [members[1]]);
    fireEvent.click(selection.getByRole("button", { name: "Reactivate" }));
    expect(view.props.onRequestAction).toHaveBeenLastCalledWith("reactivate", [members[40]]);
    fireEvent.change(screen.getByRole("searchbox", { name: "Filter Members" }), { target: { value: "" } });
    expect(screen.getByRole("checkbox", { name: "Select person2@example.test" })).toHaveProperty("checked", true);
    view.rerender(view.ui({ ...view.props, members: members.filter(value => value.user_id !== "member-2") }));
    expect(screen.getByText("2 selected")).toBeTruthy();
  });

  it("distinguishes page selection from an explicit full roster selection and excludes self from deactivation", () => {
    const members = Array.from({ length: 45 }, (_, index) => member(index + 1));
    const view = mount(members);
    fireEvent.click(screen.getByRole("checkbox", { name: "Select all 20 on this page" }));
    expect(screen.getByText("20 selected")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Deactivate" }));
    expect(view.props.onRequestAction).toHaveBeenLastCalledWith("deactivate", members.slice(1, 20));
    fireEvent.click(screen.getByRole("button", { name: "Select all 45 matching" }));
    expect(screen.getByText("45 selected")).toBeTruthy();
    expect(screen.getByText("25 outside this page")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Deactivate" }));
    expect(view.props.onRequestAction).toHaveBeenLastCalledWith("deactivate", members.slice(1));
  });

  it("offers self role editing while protecting own account deactivation and 2FA reset", () => {
    const self = member(1, { role: "owner" });
    const view = mount([self]);
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Person 1" }));
    expect(view.props.onInspect).toHaveBeenLastCalledWith("member-1", "overview");
    const actions = menu(self.email);
    expect(actions.queryByRole("menuitem", { name: "Deactivate" })).toBeNull();
    expect(actions.queryByRole("menuitem", { name: "Reset 2FA" })).toBeNull();
    fireEvent.click(actions.getByRole("menuitem", { name: "Edit roles" }));
    expect(view.props.onInspect).toHaveBeenLastCalledWith("member-1", "roles");
    expect(view.props.onRequestAction).not.toHaveBeenCalled();
  });

  it("withholds management columns and private device counts for a member", () => {
    const members = [member(1), member(2, { role: "owner" })];
    const view = mount(members, { actorRole: "member", devices: null });
    const table = screen.getByRole("table", { name: "Members" });
    expect(within(table).queryByRole("columnheader", { name: "Devices" })).toBeNull();
    expect(within(table).queryByRole("columnheader", { name: "Actions" })).toBeNull();
    expect(within(table).queryByRole("checkbox")).toBeNull();
    expect(screen.queryByText("could not load")).toBeNull();
    expect(screen.queryByText("0")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Person 2" }));
    expect(view.props.onInspect).toHaveBeenCalledWith("member-2", "overview");
    expect(view.props.onRequestAction).not.toHaveBeenCalled();
  });

  it("withdraws selected account authority when the actor loses verification and does not restore it later", () => {
    const view = mount([member(1), member(2)]);
    fireEvent.click(screen.getByRole("checkbox", { name: "Select person2@example.test" }));
    expect(screen.getByRole("group", { name: "Selected member actions" })).toBeTruthy();
    view.rerender(view.ui({ ...view.props, emailVerified: false }));
    expect(screen.queryByRole("group", { name: "Selected member actions" })).toBeNull();
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(screen.queryByRole("button", { name: /^User actions for/ })).toBeNull();
    view.rerender(view.ui());
    expect(screen.queryByRole("group", { name: "Selected member actions" })).toBeNull();
    expect(screen.getByRole("checkbox", { name: "Select person2@example.test" })).toHaveProperty("checked", false);
    expect(view.props.onRequestAction).not.toHaveBeenCalled();
  });

  it("keeps an unavailable fleet distinct from a real zero and preserves all assigned roles", () => {
    const members = [member(1, { roles: ["owner", "ai-admin"] }), member(2)];
    const view = mount(members, { devices: null });
    const row = screen.getByRole("button", { name: "Person 1" }).closest("tr")!;
    expect(within(row).getByText("owner + ai-admin")).toBeTruthy();
    expect(within(row).getByText("could not load")).toBeTruthy();
    expect(within(row).queryByText("0")).toBeNull();
    view.rerender(view.ui({ ...view.props, devices: [] }));
    expect(within(row).getByText("0")).toBeTruthy();
    expect(within(row).queryByText("could not load")).toBeNull();
  });
});
