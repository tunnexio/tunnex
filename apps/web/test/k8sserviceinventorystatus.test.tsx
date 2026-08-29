import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { K8sServiceInventoryStatus } from "../src/components/K8sServiceInventoryStatus";

afterEach(cleanup);

describe("connected-agent Kubernetes inventory status", () => {
  it("keeps unavailable distinct from an authenticated empty result", () => {
    const { rerender } = render(<K8sServiceInventoryStatus state={{ kind: "unavailable" }} />);
    expect(screen.getByText(/dropdowns are unavailable/i)).toBeTruthy();
    expect(screen.getByText(/No cluster objects or zero counts are inferred/i)).toBeTruthy();

    rerender(<K8sServiceInventoryStatus state={{ kind: "empty" }} />);
    expect(screen.getByText(/reported an empty Kubernetes inventory/i)).toBeTruthy();
  });

  it("names loading, stale, and error without rendering verified content", () => {
    const { rerender } = render(<K8sServiceInventoryStatus state={{ kind: "loading" }} />);
    expect(screen.getByText(/Loading authenticated connected-agent inventory/i)).toBeTruthy();

    rerender(<K8sServiceInventoryStatus state={{ kind: "stale" }} />);
    expect(screen.getByText(/inventory is stale/i)).toBeTruthy();

    rerender(<K8sServiceInventoryStatus state={{ kind: "error", message: "Inventory read failed." }} />);
    expect(screen.getByRole("alert").textContent).toContain("Inventory read failed.");
    expect(screen.queryByText("VERIFIED REPORT")).toBeNull();
  });

  it("shows verified content only for the ready arm", () => {
    render(
      <K8sServiceInventoryStatus
        state={{ kind: "ready", content: <label>Namespace<select><option>payments</option></select></label> }}
      />,
    );
    expect(screen.getByText("VERIFIED REPORT")).toBeTruthy();
    expect(screen.getByRole("combobox", { name: "Namespace" })).toBeTruthy();
  });
});
