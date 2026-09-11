import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AIModelConnectionDetails } from "../src/components/AIModelConnectionDetails";
const state = vi.hoisted(() => ({ orgs: [{ id: "one", name: "First" }], loading: false, failed: false }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => state }));
vi.mock("@tunnex/shared", () => ({ getApiOrigin: () => "https://internal.test" }));
const copy = vi.fn().mockResolvedValue(undefined);
beforeEach(() => {
  state.orgs = [{ id: "one", name: "First" }]; state.loading = false; state.failed = false;
  copy.mockClear(); Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: copy } });
});
afterEach(cleanup);
it("copies the single-org base and exact model ID into the VPN SDK example", async () => {
  render(<AIModelConnectionDetails orgId="one" model="custom-connection/gpt-5" />);
  fireEvent.click(screen.getByRole("button", { name: "Copy Base URL" }));
  await waitFor(() => expect(copy).toHaveBeenCalledWith("https://internal.test/ai/v1"));
  fireEvent.click(screen.getByRole("button", { name: "Copy Python example" }));
  expect(copy).toHaveBeenLastCalledWith(expect.stringContaining('api_key="unused"'));
  expect(copy).toHaveBeenLastCalledWith(expect.stringContaining('model="custom-connection/gpt-5"'));
});
it.each(["multiple", "loading", "failed"])("never recommends an unscoped URL when organization state is %s", async (kind) => {
  if (kind === "multiple") state.orgs.push({ id: "two", name: "Second" });
  if (kind === "loading") state.loading = true;
  if (kind === "failed") state.failed = true;
  render(<AIModelConnectionDetails orgId="one" model="model" />);
  fireEvent.click(screen.getByRole("button", { name: "Copy Base URL" }));
  await waitFor(() => expect(copy).toHaveBeenCalledWith("https://internal.test/api/v1/organizations/one/ai-gateway/inference/v1"));
});
it("does not promise dummy-key support for unsupported modes", () => {
  render(<AIModelConnectionDetails orgId="one" model="embedding" mode="embedding" />);
  expect(screen.queryByRole("button", { name: "Copy Python example" })).toBeNull();
});
