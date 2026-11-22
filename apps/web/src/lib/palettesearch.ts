// What the command palette can find besides pages: the organisation's own gateways, devices, people and
// clusters, by name. Reading only — a result opens the place where that thing is managed.

export type PaletteEntity = { key: string; kind: "Gateway" | "Device" | "Person" | "Cluster"; label: string; detail?: string; to: string };

export type PaletteInventory = {
  gateways?: Array<{ id: string; name?: string | null; endpoint?: string | null }>;
  devices?: Array<{ id: string; name?: string | null; owner_email?: string | null; assigned_ip?: string | null }>;
  people?: Array<{ user_id: string; name?: string | null; email?: string | null }>;
  clusters?: Array<{ id: string; name?: string | null }>;
};

const PER_KIND = 5;

/** Entities whose name (or address / e-mail) contains the query. Empty below two characters. */
export function entityResults(query: string, inventory: PaletteInventory): PaletteEntity[] {
  const q = query.trim().toLowerCase();
  if (q.length < 2) return [];
  const has = (...values: Array<string | null | undefined>) => values.some(value => !!value && value.toLowerCase().includes(q));
  const out: PaletteEntity[] = [];
  const take = <T,>(rows: T[] | undefined, match: (row: T) => boolean, map: (row: T) => PaletteEntity) =>
    out.push(...(rows ?? []).filter(match).slice(0, PER_KIND).map(map));
  take(inventory.gateways, g => has(g.name, g.endpoint),
    g => ({ key: `g:${g.id}`, kind: "Gateway", label: g.name || g.id.slice(0, 8), detail: g.endpoint ?? undefined, to: `/gateways/${g.id}` }));
  take(inventory.devices, d => has(d.name, d.owner_email, d.assigned_ip),
    d => ({ key: `d:${d.id}`, kind: "Device", label: d.name || d.id.slice(0, 8), detail: d.owner_email ?? undefined, to: `/devices?q=${encodeURIComponent(d.name || "")}` }));
  take(inventory.people, m => has(m.name, m.email),
    m => ({ key: `p:${m.user_id}`, kind: "Person", label: m.name || m.email || m.user_id.slice(0, 8), detail: m.name ? m.email ?? undefined : undefined, to: `/users?q=${encodeURIComponent(m.email || m.name || "")}` }));
  take(inventory.clusters, c => has(c.name),
    c => ({ key: `c:${c.id}`, kind: "Cluster", label: c.name || c.id.slice(0, 8), to: `/kubernetes?cluster=${c.id}` }));
  return out;
}
