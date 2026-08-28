import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import {
  ProviderFirstEnrollmentModal,
  ProviderMetadataCorrectionModal,
} from "../src/components/K8sEnrollment";
import type { Node, Site } from "../src/lib/api";
import type { EnrollmentDraft } from "../src/lib/k8senrollment";

afterEach(cleanup);

const SITE = { id: "site-1", name: "Production VPC" } as Site;
const CONNECTOR = {
  id: "node-1",
  name: "prod-k8s-connector",
  status: "active",
  site_id: SITE.id,
  endpoint: "connector.internal:51820",
} as Node;

const renderModal = (overrides: Partial<React.ComponentProps<typeof ProviderFirstEnrollmentModal>> = {}) => {
  const props: React.ComponentProps<typeof ProviderFirstEnrollmentModal> = {
    sites: [SITE],
    nodes: [CONNECTOR],
    onDismiss: () => {},
    onSubmit: async () => ({ ok: true }),
    onDone: () => {},
    ...overrides,
  };
  return render(<ProviderFirstEnrollmentModal {...props} />);
};

describe("ProviderFirstEnrollmentModal", () => {
  it("renders provider-hosted cloud marks locally without runtime hotlinks", () => {
    renderModal();
    expect(screen.getAllByRole("radio")).toHaveLength(4);
    expect(screen.getByRole("radio", { name: /Amazon Web Services/i })).toBeTruthy();
    expect(document.querySelectorAll("svg[data-provider-mark]")).toHaveLength(4);
    const officialMarks = document.querySelectorAll(
      'svg[data-provider-mark-origin]:not([data-provider-mark-origin="local-neutral"])',
    );
    expect(officialMarks).toHaveLength(3);
    for (const mark of officialMarks) {
      expect(mark.querySelector("image")?.getAttribute("href")).toMatch(/^data:image\//);
      expect(mark.querySelector("image")?.getAttribute("href")).not.toContain("https://");
    }
    expect(document.querySelector("img")).toBeNull();
  });

  it("does not default network facts and resets dependent choices when provider changes", () => {
    renderModal({
      initialAdvancedOpen: true,
      initialDraft: {
        provider: "aws",
        platform: "eks",
        siteId: SITE.id,
        connectorNodeId: CONNECTOR.id,
        name: "prod",
      },
    });

    expect((screen.getByLabelText("Kubernetes Service CIDR") as HTMLInputElement).value).toBe("");
    fireEvent.click(screen.getByRole("radio", { name: /Microsoft Azure/i }));
    expect((screen.getByLabelText("Kubernetes service") as HTMLSelectElement).value).toBe("");
    expect((screen.getByLabelText("Fronting Site") as HTMLSelectElement).value).toBe("");
    expect((screen.getByLabelText("In-cluster connector") as HTMLSelectElement).value).toBe("");
    expect((screen.getByLabelText("Cluster name") as HTMLInputElement).value).toBe("");
  });

  it("keeps provider services specific while the eligible connector stays provider-neutral", () => {
    renderModal();
    const cases = [
      [/Amazon Web Services/i, "eks", "Amazon Elastic Kubernetes Service (EKS)"],
      [/Microsoft Azure/i, "aks", "Azure Kubernetes Service (AKS)"],
      [/Google Cloud/i, "gke_standard", "Google Kubernetes Engine (GKE Standard)"],
      [/Self-managed/i, "kubernetes", "Kubernetes"],
    ] as const;

    for (const [provider, platform, service] of cases) {
      fireEvent.click(screen.getByRole("radio", { name: provider }));
      const serviceSelect = screen.getByLabelText("Kubernetes service") as HTMLSelectElement;
      expect(Array.from(serviceSelect.options).map((option) => option.text)).toContain(service);
      fireEvent.change(serviceSelect, { target: { value: platform } });
      fireEvent.change(screen.getByLabelText("Fronting Site"), { target: { value: SITE.id } });
      const connectorSelect = screen.getByLabelText("In-cluster connector") as HTMLSelectElement;
      expect(Array.from(connectorSelect.options).map((option) => option.text)).toContain("prod-k8s-connector");
    }
  });

  it("submits the complete explicit draft and makes no readiness claim", async () => {
    const submit = vi.fn(async (_draft: EnrollmentDraft) => ({ ok: true as const }));
    renderModal({
      initialAdvancedOpen: true,
      initialDraft: {
        provider: "aws",
        platform: "eks",
        siteId: SITE.id,
        connectorNodeId: CONNECTOR.id,
        name: "prod-eks",
        vipRange: "100.64.32.0/20",
        serviceCidr: "10.96.0.0/12",
        dnsZone: "k8s.example.test",
      },
      onSubmit: submit,
    });

    expect(screen.getByText(/Registration records control-plane intent/i)).toBeTruthy();
    expect(screen.queryByText(/^Active$/i)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Enroll cluster" }));
    await waitFor(() => expect(submit).toHaveBeenCalledTimes(1));
    expect(submit.mock.calls[0][0]).toMatchObject({ provider: "aws", platform: "eks" });
  });

  it("exposes accessible DNS validation and blocks malformed enrollment", () => {
    renderModal({
      initialAdvancedOpen: true,
      initialDraft: {
        provider: "aws", platform: "eks", siteId: SITE.id,
        connectorNodeId: CONNECTOR.id, name: "Prod EKS",
        vipRange: "100.64.32.0/20", serviceCidr: "10.96.0.0/12",
        dnsZone: "K8S Example",
      },
    });
    expect(screen.getByLabelText("Cluster name").getAttribute("aria-invalid")).toBe("true");
    expect(screen.getByLabelText("DNS zone").getAttribute("aria-invalid")).toBe("true");
    expect(screen.getAllByRole("alert").map((node) => node.textContent).join(" ")).toMatch(/lowercase DNS/);
    expect((screen.getByRole("button", { name: "Enroll cluster" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("does not collapse failed Site and Node reads into empty inventories", () => {
    renderModal({ sites: null, nodes: null, sitesError: "sites failed", nodesError: "nodes failed", initialDraft: { provider: "aws", platform: "eks" } });
    expect(screen.getByText(/Site inventory could not be loaded/)).toBeTruthy();
    expect(screen.getByText(/Node inventory could not be loaded/)).toBeTruthy();
    expect(screen.queryByText(/No active endpoint-bearing connector/)).toBeNull();
  });

  it("ignores Escape dismissal while enrollment is in flight", async () => {
    let finish!: (value: { ok: true }) => void;
    const dismiss = vi.fn();
    renderModal({
      initialAdvancedOpen: true,
      initialDraft: { provider: "aws", platform: "eks", siteId: SITE.id, connectorNodeId: CONNECTOR.id, name: "prod", vipRange: "100.64.0.0/24", serviceCidr: "10.96.0.0/12", dnsZone: "k8s.example" },
      onDismiss: dismiss,
      onSubmit: () => new Promise((resolve) => { finish = resolve; }),
    });
    fireEvent.click(screen.getByRole("button", { name: "Enroll cluster" }));
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    expect(dismiss).not.toHaveBeenCalled();
    finish({ ok: true });
  });
});

describe("ProviderMetadataCorrectionModal", () => {
  it("does not infer unknown legacy metadata and saves only an exact supported pair", async () => {
    const submit = vi.fn(async () => ({ ok: true as const }));
    render(
      <ProviderMetadataCorrectionModal
        clusterName="legacy-prod"
        initialProvider="unknown"
        initialPlatform="unknown"
        onDismiss={() => {}}
        onSubmit={submit}
        onDone={() => {}}
      />,
    );

    expect(screen.getByText(/No provider or platform was inferred/i)).toBeTruthy();
    const save = screen.getByRole("button", { name: "Save provider metadata" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.click(screen.getByRole("radio", { name: /Microsoft Azure/i }));
    expect((screen.getByLabelText("Kubernetes service") as HTMLSelectElement).value).toBe("");
    fireEvent.change(screen.getByLabelText("Kubernetes service"), { target: { value: "aks" } });
    fireEvent.click(save);
    await waitFor(() => expect(submit).toHaveBeenCalledWith("azure", "aks"));
  });
});
