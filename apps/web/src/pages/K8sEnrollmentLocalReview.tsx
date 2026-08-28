import { useState } from "react";
import {
  ProviderFirstEnrollmentModal,
  ProviderMetadataCorrectionModal,
} from "../components/K8sEnrollment";
import { Badge, Button, Card } from "../components/ui";
import type { Node, Site } from "../lib/api";
import { ExposeServiceModal } from "./Kubernetes";

const REVIEW_SITE = {
  id: "11111111-1111-4111-8111-111111111111",
  name: "Production VPC",
} as Site;

const REVIEW_CONNECTOR = {
  id: "22222222-2222-4222-8222-222222222222",
  name: "prod-k8s-connector",
  status: "active",
  site_id: REVIEW_SITE.id,
  endpoint: "connector.internal:51820",
} as Node;

/** Build-flagged, fixture-only visual review. It performs no API read or mutation. */
export default function K8sEnrollmentLocalReview() {
  const [open, setOpen] = useState<"enrollment" | "metadata" | "exposure" | null>("enrollment");
  const [exposureNotice, setExposureNotice] = useState("");

  return (
    <main className="tnx-page min-h-dvh p-4 sm:p-6" data-k8s-enrollment-local-review>
      <div className="mx-auto max-w-4xl space-y-4">
        <Badge tone="warn">LOCAL FIXTURE — NO CLOUD OR CLUSTER API</Badge>
        <h1 className="text-[22px] font-semibold text-ink-heading">Provider-first Kubernetes enrollment preview</h1>
        <p className="text-cell text-ink-tertiary">
          Production component with deterministic local Site and connector facts. Saving changes only in-memory preview state.
        </p>
        <Card>
          <div className="flex flex-wrap gap-2">
            <Button onClick={() => setOpen("enrollment")}>Open enrollment preview</Button>
            <Button variant="ghost" onClick={() => setOpen("metadata")}>Open metadata correction preview</Button>
            <Button variant="ghost" onClick={() => setOpen("exposure")}>Open verified inventory exposure</Button>
          </div>
        </Card>
      </div>

      {open === "enrollment" && (
        <ProviderFirstEnrollmentModal
          sites={[REVIEW_SITE]}
          nodes={[REVIEW_CONNECTOR]}
          initialAdvancedOpen
          initialDraft={{
            provider: "aws",
            platform: "eks",
            siteId: REVIEW_SITE.id,
            connectorNodeId: REVIEW_CONNECTOR.id,
            name: "prod-eks",
            vipRange: "100.64.32.0/20",
            serviceCidr: "10.96.0.0/12",
            dnsZone: "k8s.acme.internal",
          }}
          onDismiss={() => setOpen(null)}
          onSubmit={async () => ({
            ok: true,
            notice: "Local preview only — no cluster was registered.",
          })}
          onDone={() => {}}
        />
      )}
      {open === "metadata" && (
        <ProviderMetadataCorrectionModal
          clusterName="legacy-prod"
          initialProvider="unknown"
          initialPlatform="unknown"
          onDismiss={() => setOpen(null)}
          onSubmit={async () => ({
            ok: true,
            notice: "Local preview only — metadata was not saved.",
          })}
          onDone={() => setOpen(null)}
        />
      )}
      {open === "exposure" && (
        <ExposeServiceModal
          orgId="33333333-3333-4333-8333-333333333333"
          clusterId="44444444-4444-4444-8444-444444444444"
          fixtureInventory={{
            observed_at: "2026-08-28T13:30:00Z",
            fresh_until: "2026-08-28T23:55:00Z",
            next_cursor: null,
            items: [
              { inventory_ref: "55555555-5555-4555-8555-555555555551", namespace: "payments", service: "checkout-api", ports: [
                { port_ref: "66666666-6666-4666-8666-666666666661", name: "https", protocol: "tcp", service_port: 443 },
                { port_ref: "66666666-6666-4666-8666-666666666662", name: "metrics", protocol: "tcp", service_port: 9090 },
              ] },
              { inventory_ref: "55555555-5555-4555-8555-555555555552", namespace: "platform", service: "grafana", ports: [
                { port_ref: "66666666-6666-4666-8666-666666666663", name: "web", protocol: "tcp", service_port: 3000 },
              ] },
            ],
          }}
          onFixtureExpose={async (_inventoryRef, portRefs) => setExposureNotice(`Local preview only — ${portRefs.length} exact ports selected; no Service was exposed.`)}
          onClose={() => setOpen(null)}
          onDone={() => {}}
        />
      )}
      {exposureNotice && <p role="status" className="fixed bottom-4 left-4 z-[60] rounded-md border border-accent-400/40 bg-ink-900 px-3 py-2 text-sm text-ink-heading">{exposureNotice}</p>}
    </main>
  );
}
