import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
type SubnetFixture = { cidr: string; status: string };
const mock = vi.hoisted(() => ({
  post: vi.fn(),
  put: vi.fn(),
  // SSI-9: the highest artifact version the Sydney gateway reports; 15 is the first that can translate.
  sydneyMaxPolicy: undefined as number | undefined,
  role: "owner",
  // SSI-4: what the Review step reads to say what a new range will be linked to.
  mode: "enforcing" as string | null,
  sites: [] as Array<{ id: string; name: string }> | null,
  subnets: {} as Record<string, SubnetFixture[]>,
}));
vi.mock("../src/lib/api", () => ({
  api: {
    POST: mock.post,
    PUT: mock.put,
    GET: async (path: string, options: { params: { path: { siteId?: string } } }) => {
      if (path.endsWith("/zero-trust-mode")) return mock.mode === null ? { error: {} } : { data: { mode: mock.mode } };
      if (path.endsWith("/sites")) return mock.sites === null ? { error: {} } : { data: mock.sites };
      if (path.endsWith("/subnets")) return { data: mock.subnets[options.params.path.siteId ?? ""] ?? [] };
      return { error: {} };
    },
  },
  apiErrorMessage: () => "The private range overlaps an existing network.",
  loadOne: async (call: () => Promise<{ data?: unknown; error?: unknown }>) => {
    const { data, error } = await call();
    return error || data === undefined ? { ok: false, error: "Could not load." } : { ok: true, data };
  },
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
          get max_policy_version() { return mock.sydneyMaxPolicy; },
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
  mock.put.mockReset();
  mock.sydneyMaxPolicy = undefined;
  mock.role = "owner";
  mock.mode = "enforcing";
  mock.sites = [];
  mock.subnets = {};
});
// create waits for Review to finish reading what the range will be linked to; Create network is disabled
// until then (SSI-4).
async function create() {
  const button = screen.getByRole("button", { name: "Create network" }) as HTMLButtonElement;
  await waitFor(() => expect(button.disabled).toBe(false));
  fireEvent.click(button);
}
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
  it("writes only after review and excludes revoked gateways", async () => {
    mock.post.mockResolvedValue({ data: {} });
    show();
    expect(
      screen.queryByRole("button", { name: /Revoked/ }),
    ).toBeNull();
    review();
    expect(mock.post).not.toHaveBeenCalled();
    await create();
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
  it("uses an assigned gateway without creating or renaming its site", async () => {
    mock.post.mockResolvedValue({ data: {} });
    show();
    fireEvent.click(screen.getByRole("button", { name: /Assigned/ }));
    fireEvent.click(screen.getByRole("button", { name: /Continue/ }));
    expect((screen.getByLabelText("Existing site") as HTMLInputElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText("Private range (CIDR)"), { target: { value: "10.30.0.0/24" } });
    fireEvent.click(screen.getByRole("button", { name: /Continue/ }));
    expect(mock.post).not.toHaveBeenCalled();
    await create();
    await screen.findByText("Network created");
    expect(mock.post.mock.calls[0][1].body.node_id).toBe("gw-b");
  });
  it("keeps the review available after a server refusal", async () => {
    mock.post.mockResolvedValue({ error: {} });
    show();
    review();
    await create();
    await screen.findByText("The private range overlaps an existing network.");
    expect(screen.queryByText("Network created")).toBeNull();
  });
  it("prevents blind retries when the save outcome is unknown", async () => {
    mock.post.mockRejectedValue(new Error("Network interrupted"));
    show();
    review();
    await create();
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

it("embedded connection setup creates a distinct location and returns to the wizard", async () => {
  mock.post.mockResolvedValue({ data: {} });
  const onComplete = vi.fn();
  render(<MemoryRouter><NetworkSetup embedded onComplete={onComplete} /></MemoryRouter>);
  expect(screen.queryByRole("button", { name: /Assigned/ })).toBeNull();
  expect(screen.queryByRole("link", { name: /Back to Sites/ })).toBeNull();
  review();
  expect(mock.post).not.toHaveBeenCalled();
  await create();
  fireEvent.click(await screen.findByRole("button", { name: "Continue connection setup" }));
  expect(onComplete).toHaveBeenCalledOnce();
  expect(mock.post).toHaveBeenCalledOnce();
  expect(screen.queryByRole("link", { name: /Configure access|View network/ })).toBeNull();
});

it("embedded setup reports uncertain writes so its parent cannot silently discard them", async () => {
  mock.post.mockRejectedValue(new Error("network interrupted"));
  const onBusyChange = vi.fn();
  render(<MemoryRouter><NetworkSetup embedded onBusyChange={onBusyChange} /></MemoryRouter>);
  review();
  await create();
  await screen.findByText(/response was interrupted/);
  expect(onBusyChange).toHaveBeenLastCalledWith(true);
  expect((screen.getByRole("button", { name: "Back to locations" }) as HTMLButtonElement).disabled).toBe(true);
});

// SSI-4 (finding F2): the wizard says what a new range will be linked to, and when the link is open it will
// not create the network until the operator acknowledges it.
describe("Network setup — what the range will be linked to", () => {
  beforeEach(() => {
    mock.sites = [{ id: "s1", name: "Head office" }, { id: "s2", name: "Warehouse" }];
    mock.subnets = {
      s1: [{ cidr: "172.31.0.0/16", status: "approved" }],
      s2: [{ cidr: "10.40.0.0/24", status: "approved" }, { cidr: "10.41.0.0/24", status: "pending" }],
    };
  });

  it("with enforcement off, lists what opens and blocks Create until acknowledged", async () => {
    mock.mode = "off";
    mock.post.mockResolvedValue({ data: {} });
    show();
    review();
    const notice = await screen.findByTestId("site-link-exposure");
    expect(notice.textContent).toContain("This opens 10.20.0.0/24 to 2 other networks");
    expect(notice.textContent).toContain("172.31.0.0/16");
    expect(notice.textContent).toContain("10.40.0.0/24");
    expect(notice.textContent).not.toContain("10.41.0.0/24"); // a pending range is routed nowhere
    const button = screen.getByRole("button", { name: "Create network" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.click(button);
    expect(mock.post).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("checkbox", { name: "I understand this link is open in both directions" }));
    expect(button.disabled).toBe(false);
    fireEvent.click(button);
    await screen.findByText("Network created");
    expect(mock.post).toHaveBeenCalledOnce();
  });

  it("with enforcement on, says nothing crosses without a rule and asks for nothing", async () => {
    mock.post.mockResolvedValue({ data: {} });
    show();
    review();
    const notice = await screen.findByTestId("site-link-exposure");
    expect(notice.textContent).toContain("nothing crosses the link until an access rule allows it");
    expect(screen.queryByRole("checkbox")).toBeNull();
    await create();
    await screen.findByText("Network created");
  });

  it("says nothing about linking for the first network", async () => {
    mock.mode = "off";
    mock.sites = [];
    show();
    review();
    await waitFor(() => expect((screen.getByRole("button", { name: "Create network" }) as HTMLButtonElement).disabled).toBe(false));
    expect(screen.queryByTestId("site-link-exposure")).toBeNull();
    expect(screen.queryByRole("checkbox")).toBeNull();
  });

  it("does not read an unlisted set of networks as an empty one", async () => {
    mock.mode = "off";
    mock.sites = null;
    show();
    review();
    await screen.findByText(/could not be listed, so Tunnex cannot say/);
    const button = screen.getByRole("button", { name: "Create network" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: "I understand this may link to networks that could not be listed" }));
    expect(button.disabled).toBe(false);
  });

  it("does not guess the safe mode when enforcement could not be read", async () => {
    mock.mode = null;
    show();
    review();
    const notice = await screen.findByTestId("site-link-exposure");
    expect(notice.textContent).toContain("The enforcement mode could not be read");
    expect((screen.getByRole("button", { name: "Create network" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("leaves the gateway's own site out of what it is being linked to", async () => {
    mock.mode = "off";
    show();
    fireEvent.click(screen.getByRole("button", { name: /Assigned/ })); // bound to site s1
    fireEvent.click(screen.getByRole("button", { name: /Continue/ }));
    fireEvent.change(screen.getByLabelText("Private range (CIDR)"), { target: { value: "10.30.0.0/24" } });
    fireEvent.click(screen.getByRole("button", { name: /Continue/ }));
    const notice = await screen.findByTestId("site-link-exposure");
    expect(notice.textContent).toContain("to 1 other network");
    expect(notice.textContent).not.toContain("172.31.0.0/16");
  });
});

// SSI-9: the wizard offers how the new network sees traffic from other networks, defaults to the mode that
// needs no cloud route, and says afterwards which mode is actually in force.
describe("Network setup — how the new network sees other networks", () => {
  beforeEach(() => {
    mock.sites = [{ id: "s1", name: "Head office" }];
    mock.subnets = { s1: [{ cidr: "172.31.0.0/16", status: "approved" }] };
    mock.post.mockResolvedValue({ data: { id: "site-new" } });
    mock.put.mockResolvedValue({ data: { lan_egress: "gateway_address" } });
    mock.sydneyMaxPolicy = 15;
  });
  const egressPut = ["/api/v1/organizations/{orgId}/sites/{siteId}/lan-egress", {
    params: { path: { orgId: "org-a", siteId: "site-new" } },
    body: { lan_egress: "gateway_address" },
  }];

  it("defaults to the gateway address and applies it after the network is created", async () => {
    show();
    review();
    await screen.findByTestId("site-link-exposure");
    expect((screen.getByRole("radio", { name: /Gateway address/ }) as HTMLInputElement).checked).toBe(true);
    await create();
    await screen.findByText("Network created");
    expect(mock.put).toHaveBeenCalledWith(...egressPut);
    expect(screen.getByTestId("lan-egress-result").textContent).toContain("nothing needs setting up in this network's cloud for traffic that arrives here");
  });

  it("with the original address chosen, sends nothing more and lists the cloud steps", async () => {
    show();
    review();
    await screen.findByTestId("site-link-exposure");
    fireEvent.click(screen.getByRole("radio", { name: /Original address/ }));
    await create();
    await screen.findByText("Network created");
    expect(mock.put).not.toHaveBeenCalled();
    const result = screen.getByTestId("lan-egress-result").textContent ?? "";
    expect(result).toContain("Route each other network's range to this gateway");
    expect(result).toContain("source/destination check");
  });

  it("does not offer a mode the gateway cannot apply, and says what that costs", async () => {
    mock.sydneyMaxPolicy = 14;
    show();
    review();
    await screen.findByTestId("site-link-exposure");
    expect(screen.queryByRole("radio")).toBeNull();
    expect(screen.getByTestId("lan-egress-unavailable").textContent).toContain("Upgrade the gateway");
    await create();
    await screen.findByText("Network created");
    expect(mock.put).not.toHaveBeenCalled();
    expect(screen.getByTestId("lan-egress-result").textContent).toContain("Route each other network's range");
  });

  it("keeps the network and tells the truth when the mode could not be set", async () => {
    mock.put.mockResolvedValue({ error: {} });
    show();
    review();
    await screen.findByTestId("site-link-exposure");
    await create();
    await screen.findByText("Network created");
    expect(screen.getByText(/Servers on this network will see the original address/)).toBeTruthy();
    expect(screen.getByTestId("lan-egress-result").textContent).toContain("Route each other network's range");
  });

  it("offers nothing for the first network", async () => {
    mock.sites = [];
    show();
    review();
    await create();
    await screen.findByText("Network created");
    expect(mock.put).not.toHaveBeenCalled();
    expect(screen.queryByTestId("lan-egress-result")).toBeNull();
  });
});
