import { describe, expect, it, afterEach } from "vitest";
import {
  render,
  screen,
  cleanup,
  fireEvent,
  within,
  act,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { OrgProvider } from "../src/lib/useOrg";
import { CommandPalette } from "../src/components/CommandPalette";
import { NAV_DESTINATIONS } from "../src/components/AppShell";
import { MotionProvider } from "../src/components/MotionProvider";

// S14.3 SLICE B — the palette. NAVIGATION ONLY, and reading the SAME source the sidebar renders.

afterEach(cleanup);

const open = () => {
  render(
    <MemoryRouter>
      <OrgProvider>
        <MotionProvider value={true}>
          <CommandPalette />
        </MotionProvider>
      </OrgProvider>
    </MemoryRouter>,
  );
  act(() => {
    fireEvent.keyDown(window, { key: "k", metaKey: true });
  });
};

describe("the palette is a named dialog with a combobox and a listbox", () => {
  it("⌘K opens it", () => {
    open();
    expect(
      screen.getByRole("dialog", { name: "Command palette" }),
    ).toBeTruthy();
    expect(screen.getByRole("combobox", { name: "Go to" })).toBeTruthy();
    expect(screen.getByRole("listbox", { name: "Destinations" })).toBeTruthy();
  });

  it("is CLOSED until asked for — it must not be in the DOM unprompted", () => {
    render(
      <MemoryRouter>
        <OrgProvider>
          <MotionProvider value={true}>
            <CommandPalette />
          </MotionProvider>
        </OrgProvider>
      </MemoryRouter>,
    );
    expect(
      screen.queryByRole("dialog", { name: "Command palette" }),
    ).toBeNull();
  });
});

describe("⛔ THE PALETTE MAY RANK AND FILTER — IT MAY NEVER BE THE ONLY ROUTE", () => {
  it("its unfiltered destination set is EXACTLY the nav's", () => {
    // S14.2's rule, applied one surface over. A destination reachable only by typing is hidden from everyone
    // who does not already know it exists. Reading NAV_DESTINATIONS rather than a second list is what makes
    // that structural: a private list would drift, and BOTH surfaces would still look fine.
    open();
    const list = screen.getByRole("listbox", { name: "Destinations" });
    const labels = within(list)
      .getAllByRole("option")
      .map((o) => o.textContent);
    expect(labels.sort()).toEqual(NAV_DESTINATIONS.map((d) => d.label).sort());
  });

  it("the set is non-trivial — parity over an empty list would hold vacuously", () => {
    expect(NAV_DESTINATIONS.length).toBeGreaterThanOrEqual(8);
  });
});

describe("it offers NO ACTIONS in this slice, and that is the measured ruling", () => {
  it("every option is a navigation destination — nothing that mutates", () => {
    // An action in a palette is a mutation two keystrokes from a typo, and lib/undo.ts measured that MOST of
    // this product's mutations are NOT reversible. "Revoke device" behind a fuzzy match with no undo behind it
    // would be the worst affordance in the product.
    open();
    const list = screen.getByRole("listbox", { name: "Destinations" });
    const labels = within(list)
      .getAllByRole("option")
      .map((o) => (o.textContent ?? "").toLowerCase());
    for (const l of labels) {
      expect(l, `"${l}" reads like an action`).not.toMatch(
        /revoke|delete|remove|disable|reset|create/,
      );
    }
  });
});

describe("filtering narrows, and says so when nothing matches", () => {
  it("typing filters the list", () => {
    open();
    fireEvent.change(screen.getByRole("combobox", { name: "Go to" }), {
      target: { value: "site" },
    });
    const list = screen.getByRole("listbox", { name: "Destinations" });
    const labels = within(list)
      .getAllByRole("option")
      .map((o) => o.textContent);
    expect(labels).toEqual(["Sites"]);
  });

  it("an unmatched query says NO MATCH rather than rendering an empty box", () => {
    open();
    fireEvent.change(screen.getByRole("combobox", { name: "Go to" }), {
      target: { value: "zzzz" },
    });
    expect(screen.getByText("No destination matches.")).toBeTruthy();
    expect(screen.queryAllByRole("option")).toHaveLength(0);
  });
});
