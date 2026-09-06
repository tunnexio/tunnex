import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
const mock = vi.hoisted(() => ({ post: vi.fn(), role: "owner" }));
vi.mock("../src/lib/api", () => ({
  api: { POST: mock.post },
  apiErrorMessage: () => "The private range overlaps an existing network.",
}));
vi.mock("../src/lib/auth", () => ({
  useAuth: () => ({
    state: { status: "authed", user: { email_verified: true } },
  }),
}));
vi.mock("../src/lib/useGatewayInventory", () => ({
  useGatewayInventory: () => ({
    org: { id: "org-a", name: "Acme" },
    state: {
      kind: "ready",
      role: mock.role,
      nodes: [
        {
          id: "gw-a",
          name: "Sydney",
          enrolled_kind: "gateway",
          status: "active",
        },
        {
          id: "gw-b",
          name: "Assigned",
          enrolled_kind: "gateway",
          status: "active",
          site_id: "s1",
        },
        {
          id: "gw-c",
          name: "Revoked",
          enrolled_kind: "gateway",
          status: "revoked",
        },
      ],
    },
    reload: vi.fn(),
    canEnroll: true,
  }),
}));
vi.mock("../src/components/Gateways", () => ({ Gateways: () => null }));
import NetworkSetup from "../src/pages/NetworkSetup";
afterEach(cleanup);
beforeEach(() => {
  mock.post.mockReset();
  mock.role = "owner";
});
function show() {
  render(
    <MemoryRouter>
      <NetworkSetup />
    </MemoryRouter>,
  );
}
function review() {
  fireEvent.click(screen.getByRole("button", { name: /Sydney/ }));
  fireEvent.click(screen.getByRole("button", { name: /Continue/ }));
  fireEvent.change(screen.getByLabelText("Network name"), {
    target: { value: "Office" },
  });
  fireEvent.change(screen.getByLabelText("Private range (CIDR)"), {
    target: { value: "10.20.0.0/24" },
  });
  fireEvent.click(screen.getByRole("button", { name: /Continue/ }));
}
describe("Network setup", () => {
  it("writes only after review and excludes assigned or revoked gateways", async () => {
    mock.post.mockResolvedValue({ data: {} });
    show();
    expect(
      screen.queryByRole("button", { name: /Assigned|Revoked/ }),
    ).toBeNull();
    review();
    expect(mock.post).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Create network" }));
    await screen.findByText("Network created");
    expect(mock.post).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/routed-lans",
      {
        params: { path: { orgId: "org-a" } },
        body: { node_id: "gw-a", cidr: "10.20.0.0/24", name: "Office" },
      },
    );
    expect(
      screen
        .getByRole("link", { name: /Configure access/ })
        .getAttribute("href"),
    ).toBe("/access");
  });
  it("keeps the review available after a server refusal", async () => {
    mock.post.mockResolvedValue({ error: {} });
    show();
    review();
    fireEvent.click(screen.getByRole("button", { name: "Create network" }));
    await screen.findByText("The private range overlaps an existing network.");
    expect(screen.queryByText("Network created")).toBeNull();
  });
  it("prevents blind retries when the save outcome is unknown", async () => {
    mock.post.mockRejectedValue(new Error("Network interrupted"));
    show();
    review();
    fireEvent.click(screen.getByRole("button", { name: "Create network" }));
    await screen.findByRole("link", { name: /Check Sites/ });
    await waitFor(() =>
      expect(
        (
          screen.getByRole("button", {
            name: "Create network",
          }) as HTMLButtonElement
        ).disabled,
      ).toBe(true),
    );
  });
  it("does not offer setup to members without permission", () => {
    mock.role = "member";
    show();
    expect(screen.queryByRole("button", { name: /Continue/ })).toBeNull();
    expect(mock.post).not.toHaveBeenCalled();
  });
});
