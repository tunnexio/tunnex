import type { CloudVpnLink, GatewayRole, NetworkStatus, SiteCard } from "./sitesview";
import { networkStatus } from "./sitesview";

// ── SSI-13 D5/D6 — the map as BOXES ─────────────────────────────────────────────────────────────────────
//
// The old map drew gateways as circles in the middle and networks as circles around them. A standby floated
// beside its primary, a network was a ring with a number in it, and the picture shrank as networks were
// added. Here a network is a box with its gateways inside it, links join networks, and above
// MAP_DIAGRAM_MAX the map changes FORM (a paged grid of tiles, problems first) instead of shrinking.
//
// PURE and deterministic: same inputs, same geometry. No grouping by cloud or region: the product does not
// record where a network runs, and deriving it from names would be a guess presented as a fact.

export const MAP_DIAGRAM_MAX = 12;
export const MAP_BOX_WIDTH = 250;
const COLUMN_GAP = 170;
const ROW_GAP = 18;

export interface MapGateway { id: string; name: string; role: GatewayRole | null }
export interface MapNetwork {
  id: string;
  name: string;
  ranges: string[];
  gateways: MapGateway[];
  vpns: CloudVpnLink[];
  status: NetworkStatus;
}
export interface MapBox { x: number; y: number; width: number; height: number }
export interface MapLink { from: string; to: string; tone: "linked" | "degraded" | "down" }
export interface MapLayout {
  mode: "empty" | "diagram" | "grid";
  /** Problems first, then by name. The order tiles and the text list are read in. */
  networks: MapNetwork[];
  hubId: string | null;
  boxes: Map<string, MapBox>;
  links: MapLink[];
  width: number;
  height: number;
}

/** Height of a network's box: title, ranges, one row per gateway (or one "no gateway" row), one per cloud VPN, status. */
export function mapBoxHeight(network: Pick<MapNetwork, "gateways" | "vpns">): number {
  return 58 + Math.max(1, network.gateways.length) * 26 + network.vpns.length * 22 + 26;
}

export function networkMapLayout(cards: SiteCard[], roles: Map<string, GatewayRole>, vpns: Map<string, CloudVpnLink[]>, nowMs: number = Date.now()): MapLayout {
  const networks: MapNetwork[] = cards
    .map((card) => ({
      id: card.id,
      name: card.name,
      ranges: card.subnets.filter((subnet) => subnet.status === "approved").map((subnet) => subnet.cidr),
      gateways: card.gateways.filter((gateway) => gateway.status === "active").map((gateway) => ({ id: gateway.id, name: gateway.name, role: roles.get(gateway.id) ?? null })),
      vpns: vpns.get(card.id) ?? [],
      status: networkStatus(card, roles, nowMs),
    }))
    .sort((a, b) => Number(b.status.attention) - Number(a.status.attention) || a.name.localeCompare(b.name));
  const empty: MapLayout = { mode: "empty", networks, hubId: null, boxes: new Map(), links: [], width: 0, height: 0 };
  if (networks.length === 0) return empty;
  if (networks.length > MAP_DIAGRAM_MAX) return { ...empty, mode: "grid" };

  // The hub network: the one whose gateway is the acting primary; else the one the backend elected; else
  // none (no links are drawn: a link nobody carries is not a link).
  // A primary that has stopped answering and has not been passed over yet is STILL where the links go:
  // dropping the hub the moment it falls silent would erase every line exactly when they should turn red.
  const hub =
    networks.find((network) => network.gateways.some((gateway) => gateway.role === "primary")) ??
    networks.find((network) => network.gateways.some((gateway) => gateway.role === "not_answering")) ??
    networks.find((network) => cards.find((card) => card.id === network.id)?.gateways.some((gateway) => gateway.status === "active" && gateway.isHub)) ??
    null;
  const others = networks.filter((network) => network.id !== hub?.id);
  // Up to four others sit in one column to the right of the hub; more than that go on both sides so no
  // link has to cross a box.
  const both = hub != null && others.length > 4;
  const right = both ? others.filter((_, index) => index % 2 === 0) : others;
  const left = both ? others.filter((_, index) => index % 2 === 1) : [];
  const columnHeight = (column: MapNetwork[]) => column.reduce((sum, network) => sum + mapBoxHeight(network), 0) + Math.max(0, column.length - 1) * ROW_GAP;
  const height = Math.max(hub ? mapBoxHeight(hub) : 0, columnHeight(right), columnHeight(left));
  const boxes = new Map<string, MapBox>();
  const place = (column: MapNetwork[], x: number) => {
    let y = (height - columnHeight(column)) / 2;
    for (const network of column) {
      const h = mapBoxHeight(network);
      boxes.set(network.id, { x, y, width: MAP_BOX_WIDTH, height: h });
      y += h + ROW_GAP;
    }
  };
  const step = MAP_BOX_WIDTH + COLUMN_GAP;
  const hubX = both ? step : 0;
  if (hub) boxes.set(hub.id, { x: hubX, y: (height - mapBoxHeight(hub)) / 2, width: MAP_BOX_WIDTH, height: mapBoxHeight(hub) });
  place(left, 0);
  place(right, hub ? hubX + step : 0);
  const links: MapLink[] = hub
    ? others
        .filter((network) => network.gateways.length > 0 && hub.gateways.length > 0)
        .map((network) => ({
          from: hub.id,
          to: network.id,
          tone: hub.status.tone === "danger" || network.status.tone === "danger" ? "down" : network.status.attention ? "degraded" : "linked",
        }))
    : [];
  const columns = (hub ? 1 : 0) + (right.length ? 1 : 0) + (left.length ? 1 : 0);
  return { mode: "diagram", networks, hubId: hub?.id ?? null, boxes, links, width: columns * MAP_BOX_WIDTH + Math.max(0, columns - 1) * COLUMN_GAP, height };
}

/** clip shortens a label to fit a box, with an ellipsis. */
export function clip(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}
