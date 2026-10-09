import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import AppAccessRowMenu from "../src/components/AppAccessRowMenu";

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it("navigates enabled actions by keyboard and returns focus on Escape without acting", () => {
  const selected = vi.fn();
  render(<MemoryRouter><AppAccessRowMenu label="Actions for Build host" actions={[
    { key: "edit", label: "Edit server", disabledReason: "Management is unavailable.", onSelect: selected },
    { key: "connect", label: "Connect", onSelect: selected },
    { key: "events", label: "Session events", href: "/audit" },
  ]} /></MemoryRouter>);
  const trigger = screen.getByRole("button", { name: "Actions for Build host" });
  trigger.focus();
  fireEvent.keyDown(trigger, { key: "ArrowDown" });
  const menu = screen.getByRole("menu", { name: "Actions for Build host" });
  const disabled = within(menu).getByRole("menuitem", { name: "Edit server" });
  expect(disabled).toHaveProperty("disabled", true);
  expect(document.getElementById(disabled.getAttribute("aria-describedby")!)?.textContent).toBe("Management is unavailable.");
  expect(document.activeElement).toBe(within(menu).getByRole("menuitem", { name: "Connect" }));
  fireEvent.keyDown(menu, { key: "End" });
  expect(document.activeElement).toBe(within(menu).getByRole("menuitem", { name: "Session events" }));
  fireEvent.keyDown(menu, { key: "ArrowDown" });
  expect(document.activeElement).toBe(within(menu).getByRole("menuitem", { name: "Connect" }));
  fireEvent.keyDown(menu, { key: "Escape" });
  expect(screen.queryByRole("menu")).toBeNull();
  expect(document.activeElement).toBe(trigger);
  expect(selected).not.toHaveBeenCalled();
});

it("opens outside a clipped table container within the viewport and dismisses on outside scroll", () => {
  vi.stubGlobal("innerWidth", 320);
  vi.stubGlobal("innerHeight", 240);
  vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(function (this: HTMLElement) {
    return this.getAttribute("role") === "menu"
      ? { x: 0, y: 0, top: 0, bottom: 100, left: 0, right: 200, width: 200, height: 100, toJSON: () => ({}) }
      : { x: 291, y: 200, top: 200, bottom: 224, left: 291, right: 315, width: 24, height: 24, toJSON: () => ({}) };
  });
  render(<MemoryRouter><div data-testid="clipped-table" style={{ overflow: "hidden" }}><AppAccessRowMenu label="Actions for Local preview" actions={[
    { key: "details", label: "View details", href: "/beam/shares/sample" },
  ]} /></div></MemoryRouter>);
  fireEvent.click(screen.getByRole("button", { name: "Actions for Local preview" }));
  const menu = screen.getByRole("menu", { name: "Actions for Local preview" });
  expect(screen.getByTestId("clipped-table").contains(menu)).toBe(false);
  expect(menu.parentElement).toBe(document.body);
  const left = Number.parseFloat(menu.style.left); const top = Number.parseFloat(menu.style.top);
  expect(left).toBeGreaterThanOrEqual(8); expect(left + 200).toBeLessThanOrEqual(320);
  expect(top).toBeGreaterThanOrEqual(8); expect(top + 100).toBeLessThanOrEqual(240);
  fireEvent.scroll(menu);
  expect(screen.getByRole("menu")).toBe(menu);
  fireEvent.scroll(document);
  expect(screen.queryByRole("menu")).toBeNull();
});
