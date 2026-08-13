import { describe, expect, it, afterEach, vi } from "vitest";
import {
  render,
  screen,
  cleanup,
  fireEvent,
  act,
  waitFor,
} from "@testing-library/react";
import { ToastProvider, useToast } from "../src/components/Toasts";

// S14.3 SLICE B — the three properties of the undo, each asserted.

afterEach(cleanup);

function Harness({
  action,
  undo,
}: {
  action?: string;
  undo?: () => Promise<void>;
}) {
  const { show } = useToast();
  return (
    <button onClick={() => show({ message: "Rule disabled.", action, undo })}>
      fire
    </button>
  );
}

const fire = (props: Parameters<typeof Harness>[0]) => {
  render(
    <ToastProvider>
      <Harness {...props} />
    </ToastProvider>,
  );
  act(() => fireEvent.click(screen.getByRole("button", { name: "fire" })));
};

describe("PROPERTY 1 — undo is offered ONLY where the criterion allows it", () => {
  it("an undoable action gets an Undo control", () => {
    fire({ action: "policy.rule_disabled", undo: async () => {} });
    expect(screen.getByRole("button", { name: "Undo" })).toBeTruthy();
  });

  it("a NON-undoable action gets NO Undo control, even though one was offered in code", () => {
    // The offer is DROPPED, not honoured. An undo control on an act the server cannot reverse is a lie told
    // by a button — worse than no button, because the user relies on it.
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    fire({ action: "device.revoked", undo: async () => {} });
    expect(screen.queryByRole("button", { name: "Undo" })).toBeNull();
    expect(screen.getByText("Rule disabled.")).toBeTruthy(); // the toast itself still shows
    err.mockRestore();
  });

  it("a toast with no action at all gets no Undo", () => {
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    fire({ undo: async () => {} });
    expect(screen.queryByRole("button", { name: "Undo" })).toBeNull();
    err.mockRestore();
  });
});

describe("PROPERTY 2 — undo can FAIL, and its failure is LOUD", () => {
  it("a successful undo dismisses the toast", async () => {
    fire({ action: "policy.rule_disabled", undo: async () => {} });
    fireEvent.click(screen.getByRole("button", { name: "Undo" }));
    await waitFor(() =>
      expect(screen.queryByText("Rule disabled.")).toBeNull(),
    );
  });

  it("A FAILED UNDO DOES NOT DISMISS, SAYS SO, AND OFFERS A RETRY", async () => {
    // The property that matters most. A silent failure would leave the user believing they reversed something
    // they did not — STRICTLY WORSE THAN THE ORIGINAL MISTAKE, because they have stopped worrying about it.
    fire({
      action: "policy.rule_disabled",
      undo: async () => {
        throw new Error("network");
      },
    });
    fireEvent.click(screen.getByRole("button", { name: "Undo" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Retry undo" })).toBeTruthy(),
    );
    expect(screen.getByText(/Couldn't undo/)).toBeTruthy();
  });
});

describe("PROPERTY 3 — a toast is ANNOUNCED, because a message only sighted users receive is not a message", () => {
  it("toasts render in a live region with role=status", () => {
    fire({ action: "policy.rule_disabled", undo: async () => {} });
    expect(screen.getAllByRole("status").length).toBeGreaterThan(0);
  });

  it("is dismissible by an explicitly named control", () => {
    fire({});
    fireEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByText("Rule disabled.")).toBeNull();
  });
});
