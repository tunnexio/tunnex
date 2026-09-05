import { afterEach, expect, it } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  within,
} from "@testing-library/react";
import { AddressBlockExplorer } from "../src/components/AddressBlockExplorer";
import { mapAddressSpace } from "../src/lib/routedrangesview";
afterEach(cleanup);
it("bounds the visible map and drills down to pending allocations", () => {
  const map = mapAddressSpace([
    { cidr: "10.40.0.0/16", kind: "pending", label: "Office" },
  ]).blocks[0];
  render(<AddressBlockExplorer map={map} complete />);
  expect(screen.getAllByRole("button")).toHaveLength(32);
  fireEvent.click(
    screen.getByRole("button", { name: "10.40.0.0/16, 1 allocations" }),
  );
  expect(screen.getByText("Pending approval")).toBeTruthy();
  expect(screen.getByText("Office")).toBeTruthy();
});
it("pages dense blocks without dropping allocations", () => {
  const map = mapAddressSpace(
    Array.from({ length: 20 }, (_, i) => ({
      cidr: `10.0.${i}.0/24`,
      kind: "approved" as const,
      label: `Site ${i}`,
    })),
  ).blocks[0];
  render(<AddressBlockExplorer map={map} complete />);
  fireEvent.click(
    screen.getByRole("button", { name: "10.0.0.0/16, 20 allocations" }),
  );
  const details = screen.getByRole("region", {
    name: "Allocations in 10.0.0.0/16",
  });
  expect(within(details).getAllByRole("listitem")).toHaveLength(8);
  fireEvent.click(screen.getByRole("button", { name: "Next" }));
  fireEvent.click(screen.getByRole("button", { name: "Next" }));
  expect(within(details).getAllByRole("listitem")).toHaveLength(4);
  expect(screen.getByText("Site 19")).toBeTruthy();
  expect(
    (screen.getByRole("button", { name: "Next" }) as HTMLButtonElement)
      .disabled,
  ).toBe(true);
});
it("does not report an unverified block as free", () => {
  const map = mapAddressSpace([
    { cidr: "10.0.0.0/24", kind: "approved", label: "Office" },
  ]).blocks[0];
  render(<AddressBlockExplorer map={map} complete={false} />);
  fireEvent.click(
    screen.getByRole("button", { name: "10.1.0.0/16, Not verified" }),
  );
  expect(screen.getByText(/This block is not confirmed free/)).toBeTruthy();
});
