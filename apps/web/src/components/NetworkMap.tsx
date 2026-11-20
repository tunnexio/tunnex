import { useMemo, useState } from "react";
import { LINK_DASH, LINK_STROKE } from "./viz";
import { Badge } from "./ui";
import AppAccessPagination from "./AppAccessPagination";
import { clip, networkMapLayout, type MapNetwork } from "../lib/networkmapview";
import type { CloudVpnLink, GatewayRole, SiteCard } from "../lib/sitesview";

const TONE_STROKE = { ok: "#3A3A3A", neutral: "#3A3A3A", warn: "#C39A4E", danger: "#D06A6A" } as const;
const TONE_TEXT = { ok: "#8E8E8A", neutral: "#8E8E8A", warn: "#C39A4E", danger: "#D06A6A" } as const;
const ROLE_LABEL: Record<GatewayRole, string> = { primary: "PRIMARY", standby: "STANDBY", not_answering: "NOT ANSWERING" };
const TILES_PER_PAGE = 24;

function describe(network: MapNetwork): string {
  const gateways = network.gateways.length
    ? network.gateways.map((gateway) => `${gateway.name}${gateway.role ? ` ${ROLE_LABEL[gateway.role].toLowerCase()}` : ""}`).join(", ")
    : "no gateway";
  const cloud = network.vpns.length ? `. Cloud VPN: ${network.vpns.map((vpn) => vpn.name).join(", ")}` : "";
  return `${network.name}: ${network.status.label}. Gateways: ${gateways}${cloud}`;
}

/**
 * SSI-13 D5/D6 — the Site-to-site map. Up to twelve networks it is a diagram of boxes and links; above
 * that it is a paged grid of tiles, problems first. Every box and tile is a real button with its state in
 * words, so nothing is carried by colour or position alone.
 */
export function NetworkMap({ cards, roles, vpns, selectedId, onSelect }: {
  cards: SiteCard[]; roles: Map<string, GatewayRole>; vpns: Map<string, CloudVpnLink[]>;
  selectedId: string | null; onSelect: (id: string | null) => void;
}) {
  const layout = useMemo(() => networkMapLayout(cards, roles, vpns), [cards, roles, vpns]);
  const [page, setPage] = useState(1);
  if (layout.mode === "empty") return <div className="s2s-empty-state" role="status"><h3>No networks yet</h3><p>Add a network to draw it here.</p></div>;

  if (layout.mode === "grid") {
    const tiles = layout.networks.slice((page - 1) * TILES_PER_PAGE, page * TILES_PER_PAGE);
    const attention = layout.networks.filter((network) => network.status.attention).length;
    return <section aria-label="Network map">
      <p className="mb-2 text-micro text-ink-tertiary">{layout.networks.length} networks, {attention} needing attention. Shown as tiles, problems first.</p>
      <ul className="m-0 grid list-none grid-cols-2 gap-2 p-0 sm:grid-cols-3 lg:grid-cols-4">
        {tiles.map((network) => <li key={network.id}>
          <button type="button" aria-pressed={network.id === selectedId} aria-label={describe(network)} onClick={() => onSelect(network.id === selectedId ? null : network.id)}
            className="flex w-full flex-col gap-1 rounded-lg border bg-ink-800 px-3 py-2 text-left" style={{ borderColor: TONE_STROKE[network.status.tone] }}>
            <span className="truncate text-cell font-semibold text-ink-heading">{network.name}</span>
            <span className="text-micro text-ink-tertiary">{network.gateways.length} gateway{network.gateways.length === 1 ? "" : "s"}{network.vpns.length ? ` · ${network.vpns.length} cloud VPN` : ""}</span>
            <Badge tone={network.status.tone}>{network.status.label}</Badge>
          </button>
        </li>)}
      </ul>
      <AppAccessPagination maxOffset={null} page={page} pageSize={TILES_PER_PAGE} count={tiles.length} hasNext={page * TILES_PER_PAGE < layout.networks.length} onPageChange={setPage} onPageSizeChange={() => {}} previousLabel="Previous networks" nextLabel="Next networks" />
    </section>;
  }

  const pad = 16;
  return <section aria-label="Network map">
    <div className="overflow-x-auto">
      <svg viewBox={`${-pad} ${-pad} ${layout.width + pad * 2} ${layout.height + pad * 2}`} width={layout.width + pad * 2} style={{ maxWidth: "100%", height: "auto", minWidth: Math.min(560, layout.width) }} role="group" aria-label="Networks and the links between them">
        {layout.links.map((link) => {
          const a = layout.boxes.get(link.from)!; const b = layout.boxes.get(link.to)!;
          const toRight = b.x > a.x;
          const x1 = toRight ? a.x + a.width : a.x; const x2 = toRight ? b.x : b.x + b.width;
          const y1 = a.y + a.height / 2; const y2 = b.y + b.height / 2;
          const mid = (x1 + x2) / 2;
          return <path key={`${link.from}-${link.to}`} data-edge={`${link.from}:${link.to}`} d={`M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`} fill="none" stroke={LINK_STROKE[link.tone]} strokeDasharray={LINK_DASH[link.tone]} strokeWidth="2" strokeLinecap="round" />;
        })}
        {layout.networks.map((network) => {
          const box = layout.boxes.get(network.id);
          if (!box) return null;
          const selected = network.id === selectedId;
          let y = box.y + 78;
          return <g key={network.id} data-network-id={network.id} role="button" tabIndex={0} aria-pressed={selected} aria-label={describe(network)} className="cursor-pointer outline-none"
            onClick={() => onSelect(selected ? null : network.id)}
            onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); onSelect(selected ? null : network.id); } }}>
            <title>{describe(network)}</title>
            <rect x={box.x} y={box.y} width={box.width} height={box.height} rx="12" fill="#131313" stroke={selected ? "var(--tnx-text-heading)" : TONE_STROKE[network.status.tone]} strokeWidth={selected ? 2 : 1.4} />
            <text x={box.x + 14} y={box.y + 26} fill="var(--tnx-text-heading)" fontSize="14" fontWeight="600">{clip(network.name, 28)}</text>
            <text x={box.x + 14} y={box.y + 44} fill="var(--tnx-text-secondary)" fontSize="10.5" fontFamily="JetBrains Mono, monospace">{network.ranges.length ? clip(network.ranges.join(" · "), 36) : "no approved range"}</text>
            {network.gateways.length === 0 && <text x={box.x + 14} y={box.y + 78} fill="#8E8E8A" fontSize="12">No gateway assigned</text>}
            {network.gateways.map((gateway) => {
              const rowY = y; y += 26;
              const silent = gateway.role === "not_answering";
              return <g key={gateway.id}>
                <rect x={box.x + 10} y={rowY - 16} width={box.width - 20} height="22" rx="6" fill={gateway.role === "primary" ? "#1F1F1F" : "#171717"} stroke={silent ? "#D06A6A" : gateway.role === "primary" ? "#C9C9C4" : "#2E2E2E"} strokeDasharray={silent ? "4 3" : undefined} />
                <circle cx={box.x + 22} cy={rowY - 5} r="3.5" fill={silent ? "#D06A6A" : "#4EC98A"} />
                <text x={box.x + 32} y={rowY - 1} fill="var(--tnx-text-primary)" fontSize="11.5" fontWeight="600">{clip(gateway.name, gateway.role ? 18 : 30)}</text>
                {gateway.role && <text x={box.x + box.width - 16} y={rowY - 1} textAnchor="end" fill={silent ? "#D06A6A" : "#A3A39E"} fontSize="9" fontFamily="JetBrains Mono, monospace">{ROLE_LABEL[gateway.role]}</text>}
              </g>;
            })}
            {network.gateways.length === 0 && (y += 26, null)}
            {network.vpns.map((vpn) => { const rowY = y; y += 22; return <text key={vpn.id} x={box.x + 14} y={rowY - 2} fill="#8CC0FF" fontSize="11">{clip(`Cloud VPN · ${vpn.name}${vpn.state !== "applied" ? ` · ${vpn.state}` : ""}`, 38)}</text>; })}
            <text x={box.x + 14} y={box.y + box.height - 12} fill={TONE_TEXT[network.status.tone]} fontSize="11">{clip(network.status.detail ? `${network.status.label} · ${network.status.detail}` : network.status.label, 46)}</text>
          </g>;
        })}
      </svg>
    </div>
    <div className="mt-2 flex flex-wrap items-center gap-4 font-mono text-micro text-ink-tertiary">
      {(["linked", "degraded", "down"] as const).map((tone) => <span key={tone} className="flex items-center gap-1.5"><svg aria-hidden width="20" height="6" viewBox="0 0 20 6"><path d="M 0 3 L 20 3" fill="none" stroke={LINK_STROKE[tone]} strokeWidth="2" strokeDasharray={LINK_DASH[tone]} strokeLinecap="round" /></svg>{tone}</span>)}
      <span className="text-ink-faint">Click a network to open it</span>
    </div>
    <ul className="sr-only">{layout.links.map((link) => <li key={`${link.from}-${link.to}`}>{layout.networks.find((network) => network.id === link.from)?.name} to {layout.networks.find((network) => network.id === link.to)?.name}: {link.tone}</li>)}</ul>
  </section>;
}
