import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { LoadRetry } from "../src/components/LoadRetry";

afterEach(cleanup);

describe("LoadRetry", () => {
  it("announces a failed load and provides its explicit retry action", () => {
    const retry = vi.fn();
    render(<LoadRetry error="Could not load gateways." onRetry={retry} />);

    expect(screen.getByRole("alert").textContent).toContain(
      "Could not load gateways.",
    );
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(retry).toHaveBeenCalledTimes(1);
  });
});
