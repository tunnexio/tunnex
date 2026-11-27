import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

vi.mock("../src/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/lib/api")>();
  return { ...actual, api: { ...actual.api, GET: vi.fn(), PUT: vi.fn() } };
});

import { K8sApiAccessPanel } from "../src/components/K8sApiAccess";
import { api, type Role } from "../src/lib/api";
import rbacPolicy from "../src/lib/rbac-policy.json";
import {
  K8S_API_ACCESS_PATH,
  k8sApiChangeNotice,
  k8sApiGate,
  kubeconfigLines,
  type K8sApiAccess,
} from "../src/lib/k8sapiaccess";

const get = vi.mocked(api.GET);
const put = vi.mocked(api.PUT);

const CLUSTER = { id: "cluster", name: "prod" };
const FQDN = "kubernetes.default.svc.prod.k8s.example.internal";
const OFF: K8sApiAccess = { cluster_id: "cluster", enabled: false, fqdn: FQDN, port: 443, vip: null, rule_count: 0, ordinary_exposure: false, enabled_at: null };
const ON: K8sApiAccess = { ...OFF, enabled: true, vip: "100.66.0.9", enabled_at: "2026-11-23T06:00:00Z" };
// The one role that holds k8s:manage without k8s_api:manage. It is a machine role, so it is not in the
// human Role union; the gate reads the same grant table for it.
const K8S_MANAGE_ONLY = "operator" as unknown as Role;
// The string Tunnex never prints, spelled in pieces so this file is not itself a hit for a search.
const FORBIDDEN = ["insecure", "skip", "tls", "verify"].join("-");

let served: unknown = OFF;
let mode: unknown = { mode: "enforcing" };

function panel(role: Parameters<typeof k8sApiGate>[0]["role"] = "admin", emailVerified = true) {
  return render(<MemoryRouter><K8sApiAccessPanel orgId="org" cluster={CLUSTER} gate={k8sApiGate({ role, emailVerified })} /></MemoryRouter>);
}

afterEach(cleanup);
beforeEach(() => {
  vi.clearAllMocks();
  served = OFF;
  mode = { mode: "enforcing" };
  get.mockImplementation((async (path: string) => {
    if (path === K8S_API_ACCESS_PATH) return { data: served };
    if (path.endsWith("/zero-trust-mode")) return mode === null ? { error: { error: { message: "mode unavailable" } } } : { data: mode };
    return { data: [] };
  }) as never);
});

describe("API access on a cluster's page (K8N-3 stage 1)", () => {
  it("is off by default and reads the cluster's own endpoint", async () => {
    panel();
    const section = await screen.findByRole("region", { name: "API access" });
    expect(await within(section).findByText("Off")).toBeTruthy();
    expect(section.textContent).toMatch(/The cluster's Kubernetes API has no address in the tunnel/);
    expect(get).toHaveBeenCalledWith(K8S_API_ACCESS_PATH, { params: { path: { orgId: "org", clusterId: "cluster" } } });
    // Off shows no kubeconfig lines: there is nothing to point a kubeconfig at yet.
    expect(screen.queryByLabelText("kubeconfig lines to change")).toBeNull();
    expect(put).not.toHaveBeenCalled();
  });

  it("states the consequences and needs an explicit tick before turning it on", async () => {
    put.mockResolvedValue({ data: ON } as never);
    panel();
    fireEvent.click(await screen.findByRole("button", { name: "Turn on API access…" }));
    const dialog = screen.getByRole("dialog", { name: "Turn on API access for prod" });
    const impact = within(dialog).getByLabelText("What turning on API access does");

    expect(impact.textContent).toMatch(/A network path only\./);
    expect(impact.textContent).toMatch(/Each person's own cluster credential still decides what they may do\./);
    expect(impact.textContent).toMatch(/Tunnex holds no cluster credential\./);
    expect(impact.textContent).toMatch(/Nobody can reach it until an access rule grants a person or a group\./);
    expect(impact.textContent).toMatch(/people and groups only, on TCP 443/);
    expect(impact.textContent).toMatch(/Everyone granted reaches whatever the API server answers without signing in\./);
    expect(impact.textContent).toMatch(/All Tunnex users appear to the cluster as the gateway node's address\./);
    expect(impact.textContent).toMatch(/If the cluster's gateway is down, kubectl through Tunnex is down\./);
    expect(impact.textContent).toMatch(/Keep a way into the cluster that does not use Tunnex\./);
    // No rule names this cluster's API yet, so nothing is said to take effect again.
    expect(impact.textContent).not.toMatch(/take effect again|takes effect again/);

    const confirm = within(dialog).getByRole("button", { name: "Turn on API access" });
    expect(confirm).toHaveProperty("disabled", true);
    fireEvent.click(confirm);
    expect(put).not.toHaveBeenCalled();

    fireEvent.click(within(dialog).getByRole("checkbox", { name: /Open a network path to the Kubernetes API of prod/ }));
    expect(confirm).toHaveProperty("disabled", false);
    fireEvent.click(confirm);

    await waitFor(() => expect(put).toHaveBeenCalledWith(
      K8S_API_ACCESS_PATH,
      { params: { path: { orgId: "org", clusterId: "cluster" } }, body: { enabled: true } },
    ));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    // The operator is told what happened, and that enabling granted nothing.
    expect(screen.getByText("API access is on for prod. Nobody can reach it until an access rule grants a person or a group.")).toBeTruthy();
    expect(screen.getByText("On")).toBeTruthy();
  });

  it("says how many existing rules take effect again", async () => {
    served = { ...OFF, rule_count: 3 };
    panel();
    expect(await screen.findByText(/3 rules name this cluster's API\. They are kept and allow nothing while API access is off\./)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Turn on API access…" }));
    const impact = screen.getByLabelText("What turning on API access does");
    expect(impact.textContent).toMatch(/3 rules take effect again\./);
    expect(impact.textContent).toMatch(/3 existing rules name this cluster's API and allow access as soon as this is on\./);
  });

  it("warns that every connected device reaches the API only when enforcement is off", async () => {
    panel();
    fireEvent.click(await screen.findByRole("button", { name: "Turn on API access…" }));
    let dialog = screen.getByRole("dialog");
    expect(within(dialog).queryByText(/Zero Trust enforcement is off/)).toBeNull();
    expect(dialog.textContent).not.toMatch(/Every connected device/i);
    expect(within(dialog).queryByRole("alert")).toBeNull();
    cleanup();

    mode = { mode: "off" };
    panel();
    fireEvent.click(await screen.findByRole("button", { name: "Turn on API access…" }));
    dialog = screen.getByRole("dialog");
    const warning = within(dialog).getByRole("alert");
    expect(warning.textContent).toMatch(/Zero Trust enforcement is off\./);
    expect(warning.textContent).toMatch(/Every connected device will be able to reach this cluster's API address as soon as this is on/);
    // With an open mesh the dialog does not promise that nobody gains access.
    expect(dialog.textContent).not.toMatch(/Nobody gains access yet/);
    expect(dialog.textContent).toMatch(/Access rules do not limit it while enforcement is off\./);
  });

  it("does not claim a mode it could not read", async () => {
    mode = null;
    panel();
    fireEvent.click(await screen.findByRole("button", { name: "Turn on API access…" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).queryByRole("alert")).toBeNull();
    expect(dialog.textContent).toMatch(/The enforcement mode could not be read\. If Zero Trust enforcement is off, every connected device/);
  });

  it("is read-only without k8s_api:manage, and k8s:manage alone is not enough", async () => {
    served = ON;
    // The premise, read from the generated grant table rather than assumed.
    const grants = rbacPolicy as Record<string, string[]>;
    expect(grants.operator).toContain("k8s:manage");
    expect(grants.operator).not.toContain("k8s_api:manage");
    panel(K8S_MANAGE_ONLY);
    expect(await screen.findByText("On")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Turn o(n|ff) API access/ })).toBeNull();
    expect(screen.getByText("Only owners, admins and network admins can turn API access on or off.")).toBeTruthy();
    // Without the control, the mode that only decides a dialog warning is not read.
    expect((get.mock.calls as unknown as Array<[string]>).some(([path]) => path.endsWith("/zero-trust-mode"))).toBe(false);
    // Everyone still sees the lines they need to use it.
    expect(screen.getByLabelText("kubeconfig lines to change")).toBeTruthy();
    cleanup();

    served = OFF;
    panel("member");
    expect(await screen.findByText("Off")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Turn on API access/ })).toBeNull();
    cleanup();

    // The server also needs a verified email; the control is withheld and the line says why.
    panel("owner", false);
    expect(await screen.findByText("Off")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Turn on API access/ })).toBeNull();
    expect(screen.getByText("Verify your email address to turn API access on or off.")).toBeTruthy();
  });

  it("cannot be turned on while default/kubernetes is exposed as an ordinary Service", async () => {
    served = { ...OFF, ordinary_exposure: true };
    panel();
    const note = await screen.findByText(/default\/kubernetes is already exposed as an ordinary Service in this cluster\./);
    expect(note.textContent).toMatch(/It is left in place\./);
    expect(note.textContent).toMatch(/Unexpose it under Services before API access can be turned on\./);
    const turnOn = screen.getByRole("button", { name: "Turn on API access…" });
    expect(turnOn).toHaveProperty("disabled", true);
    fireEvent.click(turnOn);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(put).not.toHaveBeenCalled();
  });

  it("confirms turning it off and names the rules that are kept", async () => {
    served = { ...ON, rule_count: 2 };
    put.mockResolvedValue({ data: { ...OFF, rule_count: 2 } } as never);
    panel();
    fireEvent.click(await screen.findByRole("button", { name: "Turn off API access…" }));
    const dialog = screen.getByRole("dialog", { name: "Turn off API access for prod" });
    expect(dialog.textContent).toMatch(/kubectl through Tunnex stops for everyone\./);
    expect(dialog.textContent).toMatch(/The 2 rules that name this cluster's API are kept and allow nothing until API access is turned on again\./);
    expect(put).not.toHaveBeenCalled();

    fireEvent.click(within(dialog).getByRole("button", { name: "Turn off API access" }));
    await waitFor(() => expect(put).toHaveBeenCalledWith(
      K8S_API_ACCESS_PATH,
      { params: { path: { orgId: "org", clusterId: "cluster" } }, body: { enabled: false } },
    ));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    // After the destructive verb the operator is told what happened.
    expect(screen.getByText("API access is off for prod. kubectl through Tunnex has stopped for everyone. 2 rules that name this cluster's API are kept and allow nothing until API access is turned on again.")).toBeTruthy();
    expect(screen.queryByLabelText("kubeconfig lines to change")).toBeNull();
  });

  it.each([
    ["forbidden", "forbidden"],
    ["k8s_api_ordinary_exposure_exists", "default/kubernetes is already exposed as an ordinary Service in this cluster. Unexpose it first, then turn on API access"],
    ["k8s_api_connector_pool_unsupported", "API access is not available for a cluster served by a connector pool"],
    ["vip_range_exhausted", "the cluster's address range 100.66.0.0/24 is full"],
  ])("shows the server's own message for %s and stays off", async (code, message) => {
    put.mockResolvedValue({ error: { error: { code, message } } } as never);
    panel();
    fireEvent.click(await screen.findByRole("button", { name: "Turn on API access…" }));
    const dialog = screen.getByRole("dialog");
    fireEvent.click(within(dialog).getByRole("checkbox"));
    fireEvent.click(within(dialog).getByRole("button", { name: "Turn on API access" }));
    expect(await within(dialog).findByText(message)).toBeTruthy();
    // The dialog stays open and nothing claims the change was made.
    expect(screen.getByRole("dialog")).toBeTruthy();
    expect(screen.queryByText(/API access is on for prod/)).toBeNull();
    expect(screen.queryByText("On")).toBeNull();
  });

  it("does not show a state it could not read", async () => {
    get.mockImplementation((async (path: string) => path === K8S_API_ACCESS_PATH ? { data: [] } : { data: { mode: "enforcing" } }) as never);
    panel();
    expect(await screen.findByText("Could not read API access for this cluster.")).toBeTruthy();
    expect(screen.queryByText("Off")).toBeNull();
    expect(screen.queryByRole("button", { name: /Turn on API access/ })).toBeNull();
    served = OFF;
    get.mockImplementation((async (path: string) => path === K8S_API_ACCESS_PATH ? { data: OFF } : { data: { mode: "enforcing" } }) as never);
    fireEvent.click(screen.getByRole("button", { name: "Retry reading API access" }));
    expect(await screen.findByText("Off")).toBeTruthy();
  });

  it("shows exactly the two kubeconfig lines when on, with the address and the credential sentence", async () => {
    served = { ...ON, rule_count: 1 };
    panel();
    const block = await screen.findByLabelText("kubeconfig lines to change");
    const pre = block.querySelector("pre");
    expect(pre?.textContent).toBe(`server: https://${FQDN}\ntls-server-name: <host from your original server line>`);
    // Two lines, and nothing that looks like a whole kubeconfig.
    expect(pre?.textContent?.split("\n")).toHaveLength(2);
    for (const key of ["apiVersion", "clusters:", "users:", "contexts:", "certificate-authority", "token", "client-certificate"]) {
      expect(document.body.textContent).not.toContain(key);
    }
    expect(block.textContent).toMatch(/tls-server-name must be the host from your kubeconfig's original server: line\./);
    expect(block.textContent).toMatch(/The API server's certificate covers that name, not the Tunnex name\./);
    expect(block.textContent).toMatch(/Certificate checking stays on\./);
    expect(block.textContent).toMatch(/A cloud CLI that regenerates the kubeconfig overwrites these two lines\./);
    expect(within(block).getByText("Your own cluster credential still decides what you may do.")).toBeTruthy();
    expect(within(block).getByText("A Tunnex refusal looks like a timeout. A 401 or 403 is the cluster's answer.")).toBeTruthy();

    const section = screen.getByRole("region", { name: "API access" });
    expect(within(section).getByText("100.66.0.9")).toBeTruthy();
    expect(within(section).getByText(FQDN)).toBeTruthy();
    expect(within(section).getByText("TCP 443")).toBeTruthy();
    // Enabling grants nothing: the way to the rule is on the same screen.
    expect(section.textContent).toMatch(/Turning this on grants nothing\./);
    expect(within(section).getByRole("link", { name: "Create a rule in Access Policies" }).getAttribute("href")).toBe("/access");
  });

  it("copies the two lines and nothing else", async () => {
    served = ON;
    const writeText = vi.fn(async () => {});
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    panel();
    fireEvent.click(await screen.findByRole("button", { name: "Copy the two lines" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(`server: https://${FQDN}\ntls-server-name: <host from your original server line>`));
    expect(await screen.findByText("Copied")).toBeTruthy();
  });

  it("never renders the option that turns certificate checking off, in any state", async () => {
    const seen: string[] = [];
    const snapshot = () => seen.push(document.body.innerHTML);

    // Off, with the turn-on dialog open under an open mesh and existing rules.
    served = { ...OFF, rule_count: 2 };
    mode = { mode: "off" };
    panel();
    fireEvent.click(await screen.findByRole("button", { name: "Turn on API access…" }));
    snapshot();
    cleanup();

    // Off and blocked by an ordinary exposure.
    served = { ...OFF, ordinary_exposure: true };
    panel();
    await screen.findByText(/default\/kubernetes is already exposed/);
    snapshot();
    cleanup();

    // On, with the kubeconfig lines and the turn-off dialog open.
    served = { ...ON, rule_count: 2 };
    panel();
    await screen.findByLabelText("kubeconfig lines to change");
    snapshot();
    fireEvent.click(screen.getByRole("button", { name: "Turn off API access…" }));
    snapshot();
    cleanup();

    // Read-only.
    panel("member");
    await screen.findByLabelText("kubeconfig lines to change");
    snapshot();

    expect(seen).toHaveLength(5);
    for (const html of seen) {
      expect(html.toLowerCase()).not.toContain(FORBIDDEN);
      expect(html.toLowerCase()).not.toContain("skip-tls");
    }
  });
});

describe("API access view logic", () => {
  it("builds the two lines from the served name and never anything else", () => {
    const lines = kubeconfigLines(FQDN);
    expect(lines).toEqual([`server: https://${FQDN}`, "tls-server-name: <host from your original server line>"]);
    expect(lines.join("\n")).not.toContain(FORBIDDEN);
  });

  it("gates the control on k8s_api:manage and a verified email", () => {
    expect(k8sApiGate({ role: "owner", emailVerified: true })).toEqual({ canManage: true, whoCan: null });
    expect(k8sApiGate({ role: "admin", emailVerified: true }).canManage).toBe(true);
    expect(k8sApiGate({ role: K8S_MANAGE_ONLY, emailVerified: true }).canManage).toBe(false);
    expect(k8sApiGate({ role: "member", emailVerified: true }).canManage).toBe(false);
    expect(k8sApiGate({ role: undefined, emailVerified: true }).canManage).toBe(false);
    expect(k8sApiGate({ role: "admin", emailVerified: false }).canManage).toBe(false);
  });

  it("tells the operator what the change did, from the state the server returned", () => {
    expect(k8sApiChangeNotice({ enabled: true, rule_count: 1 }, "prod", "enforcing")).toBe("API access is on for prod. 1 rule for this cluster's API is in effect again.");
    expect(k8sApiChangeNotice({ enabled: true, rule_count: 0 }, "prod", "off")).toBe("API access is on for prod. Zero Trust enforcement is off, so every connected device can reach the cluster's API address now.");
    expect(k8sApiChangeNotice({ enabled: false, rule_count: 1 }, "prod", "enforcing")).toBe("API access is off for prod. kubectl through Tunnex has stopped for everyone. 1 rule that names this cluster's API is kept and allows nothing until API access is turned on again.");
    expect(k8sApiChangeNotice({ enabled: false, rule_count: 0 }, "prod", "enforcing")).toBe("API access is off for prod. kubectl through Tunnex has stopped for everyone. No access rule names this cluster's API.");
  });
});
