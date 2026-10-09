import type { BeamShare, BeamShareFilters } from "./beam";

const localFixtureOrg = "01900000-0000-7000-8000-000000000001";
// Imported only by the development preview chunk. Both an explicit Vite opt-in and
// the local seeded organization are required; no sample grants or serving access exist.
export const beamUIFixturesEnabled = import.meta.env.DEV && import.meta.env.VITE_BEAM_UI_FIXTURES === "1";
const started = Date.now();
export function beamUIFixtures(orgId: string): BeamShare[] {
  if (!beamUIFixturesEnabled || orgId !== localFixtureOrg) return [];
  return ([
    ["Dashboard redesign", "active", "online", 5173],
    ["Customer onboarding", "paused", "online", 3000],
    ["API documentation", "active", "offline", 8080],
    ["Checkout experiment", "active", "origin_unavailable", 4000],
  ] as const).map(([name, state, connectivity, port], index) => ({
    id: `01900000-0000-7000-8000-0000000fd00${index + 1}`,
    org_id: orgId, publisher_id: "01900000-0000-7000-8000-000000000002",
    publisher_name: "Demo Owner", name,
    hostname: `preview-${index + 1}.sharing.example.test`, url: `https://preview-${index + 1}.sharing.example.test`,
    state, connectivity, version: 1, authority_version: 1,
    created_at: new Date(started - (index + 1) * 3600000).toISOString(),
    expires_at: new Date(started + (index + 2) * 3600000).toISOString(),
    target: { protocol: "http", address: "127.0.0.1", port },
    can_manage: false, can_open: false,
  }));
}
export function filterBeamUIFixtures(orgId: string, q: string | undefined, filters: BeamShareFilters) {
  if (filters.scope === "history") return [];
  return beamUIFixtures(orgId).filter(share =>
    (!q || `${share.name} ${share.hostname}`.toLowerCase().includes(q.toLowerCase())) &&
    (!filters.state || share.state === filters.state) &&
    (!filters.connectivity || share.connectivity === filters.connectivity));
}
