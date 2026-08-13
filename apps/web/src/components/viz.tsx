import { useId, type ReactNode } from "react";
import { EmptyState } from "./ui";
import {
  allocationLabel,
  utilisationLabel,
  KIND_LABEL,
  type AllocKind,
  type Block,
  type BlockMap,
  type Cell,
} from "../lib/routedrangesview";

// S14.3 SLICE C — DATA VISUALIZATION. THREE PRIMITIVES, HAND-ROLLED SVG, NO CHARTING LIBRARY.
//
// WHY HAND-ROLLED, measured rather than preferred: of the ten visualization types named across the 17 screens,
// a general charting library covers at most three (donut, histogram, bar) and NONE of the force-directed
// network map, the bipartite access-flow, the address-space heatmap or the radial device fabric. A library
// would be added for three and the other seven hand-rolled anyway — which is exactly how "a design system
// acquires four charting libraries." Against a 352 kB bundle that is a large fraction for a minority of need.
//
// AND THE SURVIVORS REDUCE TO THREE SHAPES, not ten: a PROPORTION, a BINNED COUNT over discrete events, and a
// NODE-LINK graph. The heatmap is a proportion on a grid.

/**
 * ⛔ EVERY CHART NAMES ITS SOURCE, AND THE COMPILER ENFORCES IT.
 *
 * The render-floor rule used to be prose — *"every panel names its endpoint or is marked roadmap"* — and prose
 * is a convention. As a REQUIRED prop it is a mechanism: **a chart with no source does not typecheck.**
 *
 * ⚠ AND THE AUDIT READS THE SPEC'S SEMANTICS, NOT MERELY ENDPOINT EXISTENCE. That is the harder case and the
 * one that would otherwise pass. `openapi.yaml` describes `rx_bytes`/`tx_bytes` as:
 *
 *     "Raw gauge since the last handshake (display only, never summed as monotonic)."
 *
 * The endpoint EXISTS. The field EXISTS. The spec FORBIDS the use. An audit that only asks "does an endpoint
 * supply this?" answers YES and lets a throughput chart through — which is why both known render-floor
 * violations in this repo are charts. `endpoint` is therefore a claim about a PERMITTED reading, not about a
 * URL being reachable.
 */
export type VizSource =
  | { endpoint: string; roadmap?: never }
  | { roadmap: true; why: string; endpoint?: never };

/** Shared frame: accessible name, the source contract, and the failed/empty discipline in ONE place. */
interface VizFrameProps {
  /** The chart's accessible name. Required — an unnamed graphic is unqueryable and unannounced. */
  label: string;
  source: VizSource;
  /**
   * REQUIRED, same reasoning as `DataTable`: an empty dataset means either "there are none" or "we never found
   * out", and drawing the second as the first is the reassuring-empty defect with an axis on it. A default
   * would pick the dangerous answer silently.
   */
  failed: boolean;
  children: ReactNode;
  /** Rendered instead of the graphic when there is genuinely nothing to draw. */
  empty: ReactNode;
  isEmpty: boolean;
}

/**
 * The frame every visualization renders through.
 *
 * ⛔ A FAILED LOAD RENDERS NOTHING — never an empty axis, never a flat line at zero. A chart is the easiest
 * place in a UI to assert a fact nobody measured: a zero baseline LOOKS like data, and "no traffic" and "we
 * could not read the traffic" are opposite claims that draw identically.
 */
export function VizFrame({
  label,
  source,
  failed,
  isEmpty,
  empty,
  children,
}: VizFrameProps) {
  if (failed) return null;
  if (source.roadmap) {
    // NOT a plausible drawing. A roadmap chart renders its honest state — a picture with no data behind it is
    // the render-floor violation itself, and a greyed-out sample is still a picture.
    return (
      <p
        role="note"
        className="rounded-md border border-white/5 bg-ink-800 px-3 py-2 text-xs text-slate-400"
      >
        {label} isn&rsquo;t available yet. {source.why}
      </p>
    );
  }
  if (isEmpty) return <EmptyState>{empty}</EmptyState>;
  return <figure aria-label={label}>{children}</figure>;
}

// ── PRIMITIVE 1 — PROPORTION ────────────────────────────────────────────────────────────────────────────────

export interface Slice {
  label: string;
  value: number;
  tone: "ok" | "warn" | "danger" | "neutral";
}

const TONE_VAR: Record<Slice["tone"], string> = {
  ok: "var(--tnx-ok)",
  warn: "var(--tnx-warn)",
  danger: "var(--tnx-danger)",
  neutral: "var(--tnx-neutral)",
};

/**
 * A proportion of a CURRENT-STATE total — peers online, devices by posture, members by role.
 *
 * ⛔ THE NUMBERS ARE RENDERED AS TEXT BESIDE THE ARC, NOT ONLY AS GEOMETRY. An SVG arc is unreadable to a
 * screen reader, unqueryable by the tier, and ambiguous to anyone who cannot distinguish the colours — three
 * failures with one cause, the same one `Badge` avoids by carrying its status as text.
 */
export function Donut({
  label,
  source,
  failed,
  slices,
  empty = "Nothing to show yet.",
  centreLabel,
  animate = false,
}: {
  label: string;
  source: VizSource;
  failed: boolean;
  slices: Slice[];
  empty?: ReactNode;
  /** The word under the centre total ("devices", "gateways"). Absent when the total needs no unit. */
  centreLabel?: string;
  /**
   * Sweep the arcs on. OPT-IN and defaulted OFF so every existing Donut renders byte-identically.
   *
   * ⛔ SMIL, NOT GSAP. The founder asked for "gsap animation"; gsap is NOT a dependency of this repo
   * (`grep -c gsap package.json` -> 0) and the wireframe's own animations were ported to SMIL in S14.7 for
   * that reason. Adding a 70KB animation runtime to sweep one ring is not the trade, and SMIL gives the same
   * draw-on with no bundle cost.
   *
   * The caller passes the MOTION DECISION, it is not read here: `matchMedia` is touched in exactly one place
   * in this product (`readsReducedMotionPreference`), so a component asking the platform would be the second.
   */
  animate?: boolean;
}) {
  const total = slices.reduce((t, s) => t + s.value, 0);
  const titleId = useId();
  let offset = 25; // 25% = 12 o'clock, so the first arc starts at the top rather than at 3 o'clock
  return (
    <VizFrame
      label={label}
      source={source}
      failed={failed}
      isEmpty={total === 0}
      empty={empty}
    >
      <div className="flex items-center gap-4">
        <div className="relative h-[120px] w-[120px] shrink-0">
          <svg
            viewBox="0 0 42 42"
            className="h-full w-full -rotate-90"
            role="presentation"
            aria-labelledby={titleId}
          >
            <title id={titleId}>{label}</title>
            {/* The track. Without it a partial ring reads as a broken ring rather than as a proportion. */}
            <circle
              cx="21"
              cy="21"
              r="15.9"
              fill="transparent"
              stroke="var(--tnx-badge-bg)"
              strokeWidth="4"
            />
            {slices.map((s, i) => {
              const pct = (s.value / total) * 100;
              const el = (
                <circle
                  key={s.label}
                  className="tnx-arc"
                  cx="21"
                  cy="21"
                  r="15.9"
                  fill="transparent"
                  stroke={TONE_VAR[s.tone]}
                  strokeWidth="4"
                  // The arc's length IS its dash, so sweeping it on means growing the dash from 0 to `pct`
                  // while the gap shrinks — the ring draws clockwise from twelve o'clock, in slice order.
                  strokeDasharray={animate ? `0 100` : `${pct} ${100 - pct}`}
                  strokeDashoffset={String(offset)}
                >
                  {animate && (
                    <animate
                      attributeName="stroke-dasharray"
                      from="0 100"
                      to={`${pct} ${100 - pct}`}
                      dur="0.7s"
                      begin={`${0.1 + i * 0.12}s`}
                      calcMode="spline"
                      keyTimes="0;1"
                      keySplines="0.22 1 0.36 1"
                      fill="freeze"
                    />
                  )}
                </circle>
              );
              offset -= pct;
              return el;
            })}
          </svg>
          {/* THE TOTAL IN THE CENTRE, as the design has it — and as TEXT, so it is readable, queryable and
              announced. The ring is the accelerant; the number is the content. */}
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-[26px] font-bold leading-none text-ink-heading">
              {total}
            </span>
            {centreLabel && (
              <span className="mt-1 text-[9px] text-ink-tertiary">
                {centreLabel}
              </span>
            )}
          </div>
        </div>
        {/* The legend. This is what the tier queries and what a screen reader announces. */}
        <ul className="min-w-0 flex-1 space-y-1.5 text-[11px]">
          {slices.map((s) => (
            <li key={s.label} className="flex items-center gap-2 text-ink-body">
              <span
                aria-hidden
                className="h-[7px] w-[7px] shrink-0 rounded-full"
                style={{ background: TONE_VAR[s.tone] }}
              />
              <span className="truncate">{s.label}</span>
              <span className="ml-auto shrink-0 text-ink-primary">
                {s.value}
                {total > 0 && (
                  <span className="ml-1 text-ink-tertiary">
                    ({Math.round((s.value / total) * 100)}%)
                  </span>
                )}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </VizFrame>
  );
}

// ── PRIMITIVE 2 — BINNED COUNT OVER DISCRETE EVENTS ─────────────────────────────────────────────────────────

export interface Bin {
  /** Bucket label — an hour, a day, a provider. */
  label: string;
  value: number;
  /**
   * ⛔ NO DATA FOR THIS BUCKET — DISTINCT FROM ZERO, and the distinction is the reason this primitive is honest
   * enough to ship. `AccessEvent.decision` carries `gap` as a first-class enum value precisely because the
   * agent can know it did not observe a window. A chart that draws absent data as a zero-height bar is the
   * reassuring-empty defect with an axis on it: "no denials" and "we did not see" look identical.
   */
  gap?: boolean;
}

/**
 * A count of DISCRETE EVENTS per bucket — never a sampled rate.
 *
 * That distinction is what makes this chart permissible when a throughput series is not: binning events the
 * API actually returns (`/access-events`, with `occurred_at`) is honest; drawing a rate from a gauge the spec
 * calls "display only, never summed as monotonic" is not.
 */
export function Histogram({
  label,
  source,
  failed,
  bins,
  empty = "No events in this window.",
}: {
  label: string;
  source: VizSource;
  failed: boolean;
  bins: Bin[];
  empty?: ReactNode;
}) {
  const max = Math.max(1, ...bins.filter((b) => !b.gap).map((b) => b.value));
  return (
    <VizFrame
      label={label}
      source={source}
      failed={failed}
      isEmpty={bins.length === 0}
      empty={empty}
    >
      <ol className="flex h-24 items-end gap-1">
        {bins.map((b) => (
          <li key={b.label} className="flex h-full flex-1 flex-col justify-end">
            {b.gap ? (
              // A GAP IS DRAWN AS A GAP: a hatched placeholder with its own label, never a zero-height bar.
              <span
                aria-label={`${b.label}: no data`}
                title={`${b.label}: no data`}
                className="block w-full border-b-2 border-dashed border-slate-600"
                style={{ height: "100%" }}
              />
            ) : (
              <span
                aria-label={`${b.label}: ${b.value}`}
                title={`${b.label}: ${b.value}`}
                className="tnx-rise block w-full rounded-sm bg-accent-500"
                style={{ height: `${(b.value / max) * 100}%` }}
              />
            )}
          </li>
        ))}
      </ol>
    </VizFrame>
  );
}

// ── PRIMITIVE 3 — NODE-LINK ─────────────────────────────────────────────────────────────────────────────────

export interface Node {
  id: string;
  label: string;
  kind: "hub" | "spoke";
  /** One line of true facts under the label. The wireframe's `kind · ip · status`, minus the ip we do not serve. */
  sub?: string;
  /**
   * The number inside the ring.
   *
   * ⛔ The wireframe puts a SITE COUNT here because its nodes are regions. Ours are sites, so there is no
   * count of that kind — this carries whatever real number the caller has (Sites passes the site's bound
   * gateway count). Omitted renders an empty ring rather than a zero, because "no number to show" and
   * "the number is zero" are different and only one of them is a fact about the network.
   */
  value?: number | string;
  /**
   * The node's own link state, for the ring and the status dot.
   *
   * ⛔ ABSENT MEANS "NO LINK EXISTS", NOT "HEALTHY". A site with no gateway bound, or whose gateway IS the
   * hub, has no site link at all — so it has no link STATE either, and must not be tinted as if it did.
   * The neutral rendering is the honest one; `note` says why in words.
   */
  tone?: LinkTone;
  /** Why there is no link, or what is wrong with it. Rendered verbatim; never inferred from the tone. */
  note?: string;
}

/**
 * ⛔ THREE TONES, NOT A BOOLEAN — S14.5.
 *
 * This was `healthy: boolean` and the legend it feeds has THREE entries (linked · degraded · down). A
 * two-state type under a three-state legend forces every caller to collapse `degraded` into one of the
 * neighbours, and the safe-looking collapse (degraded → healthy) is the silent-blackhole direction.
 *
 * The control plane already distinguishes them: `site_link_down` / `site_hub_down` are their own health
 * kinds. The type now carries what the data carries.
 */
export type LinkTone = "linked" | "degraded" | "down";

export interface Link {
  from: string;
  to: string;
  tone: LinkTone;
  /** Why it is not `linked`. Rendered verbatim in the list; never inferred from the tone. */
  note?: string;
}

// ⛔ TONES TAKEN FROM THE WIREFRAME'S OWN `TONE` MAP, NOT INVENTED.
//
// I had these as ok/warn/danger — a green, an amber and a red. The design is NEAR-MONOCHROME: an `ok` edge
// is light grey, and degraded/down are progressively DARKER greys, distinguished by a DASH PATTERN. Only the
// status dot carries a hue, and only for `degraded`.
//
// That is the better call and it is worth stating why, because "add colour" is the reflex. A five-node mesh
// with three red edges reads as an emergency at a glance even when one spoke is merely unreachable. Recession
// is the honest encoding for a degraded link: it RETREATS rather than shouting, and the words in the list
// below carry the actual claim. Colour is spent where it is scarce and therefore meaningful.
export const LINK_STROKE: Record<LinkTone, string> = {
  linked: "#C9C9C4",
  degraded: "#3A3A3A",
  down: "#303030",
};
// `down` is dashed as well as red, so the state survives a monochrome print and a red-green viewer.
export const LINK_DASH: Record<LinkTone, string | undefined> = {
  linked: undefined,
  degraded: "6 7",
  down: "6 7",
};

// ring / fill / dot per tone — the wireframe's TONE map, verbatim.
const NODE_RING: Record<LinkTone, string> = {
  linked: "#C9C9C4",
  degraded: "#3A3A3A",
  down: "#303030",
};
const NODE_FILL: Record<LinkTone, string> = {
  linked: "#171717",
  degraded: "#161616",
  down: "#101010",
};
const NODE_DOT: Record<LinkTone, string> = {
  linked: "#D6D6D2",
  degraded: "#C39A4E", // the ONE hue in the diagram
  down: "#5E5E5B",
};

/**
 * The site topology.
 *
 * ⛔ DELIBERATELY NOT FORCE-DIRECTED, though the wireframe drew it that way. The model already computes a
 * deterministic hub-and-spoke (`siteLinkGraph`, S8.2), and a force simulation over a known structure produces a
 * DIFFERENT PICTURE ON EVERY RENDER of the same data — which makes it untestable, unmemorable, and impossible
 * to describe over a support call. Determinism is worth more here than organic-looking placement.
 */
export function NodeLink({
  label,
  source,
  failed,
  nodes,
  links,
  empty = "No sites yet.",
  selectedId,
  onSelect,
}: {
  label: string;
  source: VizSource;
  failed: boolean;
  nodes: Node[];
  links: Link[];
  empty?: ReactNode;
  /** Controlled selection. Undefined = the diagram is inert, exactly as it was before S14.5. */
  selectedId?: string | null;
  onSelect?: (id: string | null) => void;
}) {
  const hub = nodes.find((n) => n.kind === "hub");
  const spokes = nodes.filter((n) => n.kind !== "hub");
  const pos = new Map<string, { x: number; y: number }>();
  // The wireframe's frame: 600x320, hub dead centre at (300,162). Spokes ring it. Starting at -90° puts
  // the first spoke at twelve o'clock, which is where a reader looks first; a lone spoke then sits ABOVE the
  // hub rather than at an arbitrary angle.
  // ⛔ THE LAYOUT IS FITTED TO THE NODE COUNT, NOT INHERITED FROM THE POPULATED EXAMPLE.
  //
  // The wireframe places five spokes at fixed coordinates inside a 600x320 frame, and it looks right because
  // five spokes FILL that frame. I took the frame and the ring radius and left them fixed — so ONE site
  // rendered as a column of two circles with the left two-thirds of the panel empty. It read as a broken
  // diagram rather than a sparse one.
  //
  // A LAYOUT DERIVED FROM A POPULATED EXAMPLE MUST BE CHECKED AT N=1. A design shows every diagram at its
  // most interesting size, which is the size it will almost never have on a customer's first day.
  //
  // ⚠ AND THE FIRST FIX FOR THAT WAS ALSO WRONG, IN THE EXACT OPPOSITE DIRECTION. Fitting the viewBox to
  // the placed nodes removed the empty space by MAGNIFYING everything: a two-node bounding box stretched to
  // the panel width rendered 150px rings and oversized labels.
  //
  // THE SCALE IS A CONTRACT. The design's svg is `viewBox 0 0 600 320` at `height: 320px`, so ONE USER UNIT
  // IS ONE PIXEL and a hub ring is 68px ON PURPOSE. Fitting the box breaks that silently, because the shapes
  // stay in proportion to EACH OTHER while every one of them is the wrong size — nothing looks distorted, it
  // is just all wrong together, which is the hardest kind to notice.
  //
  // SO: the FRAME stays fixed, the PLACEMENT adapts to the count, and the content is TRANSLATED to centre.
  // Sparse then reads as sparse — airy and balanced — rather than as broken or as zoomed.
  const HUB = { x: 300, y: 162 };
  const k = spokes.length;
  if (hub) pos.set(hub.id, HUB);
  if (!hub && k === 1) {
    pos.set(spokes[0]!.id, HUB);
  } else {
    // One spoke needs distance, not an orbit. Two want opposite sides. Three or more want a ring.
    const rx = k <= 1 ? 155 : k === 2 ? 185 : 200;
    const ry = k <= 2 ? 0 : 105;
    spokes.forEach((sp, i) => {
      // Twelve o'clock first for a real ring; a LONE spoke goes RIGHT, because a relationship reads
      // left-to-right and straight-up reads as a stack.
      const a = k === 1 ? 0 : (i / k) * Math.PI * 2 - Math.PI / 2;
      pos.set(sp.id, {
        x: HUB.x + Math.cos(a) * rx,
        y: HUB.y + Math.sin(a) * ry,
      });
    });
  }

  // ⛔ FIT THE BOX *AND* THE PIXEL HEIGHT TO THE SAME NUMBER — that is what keeps the scale at 1:1.
  //
  // Fitting the viewBox ALONE magnified everything (attempt 2). Pinning a 600x320 box ALONE left a 320px-tall
  // panel with two small rings adrift in it (attempt 3). Both were half the answer.
  //
  // `preserveAspectRatio="xMidYMid meet"` scales to fit the TIGHTER of the two axes. So if the viewBox height
  // in USER UNITS equals the element height in PIXELS, the scale is exactly 1 — the design's contract, a 68px
  // hub ring — and the horizontal remainder is simply empty space, centred. The frame follows the content in
  // SIZE without ever changing its SCALE.
  const pts = [...pos.values()];
  const PAD_X = 34 + 42; // widest ring + room for the label, which is wider than its circle
  const PAD_TOP = 34 + 14;
  const PAD_BOTTOM = 34 + 34; // label at r+15 and sub-line at r+27 are drawn BELOW the ring
  const xs = pts.map((p) => p.x);
  const ys = pts.map((p) => p.y);
  const boxX = pts.length ? Math.min(...xs) - PAD_X : 0;
  const boxY = pts.length ? Math.min(...ys) - PAD_TOP : 0;
  const boxW = pts.length ? Math.max(...xs) - Math.min(...xs) + PAD_X * 2 : 600;
  const boxH = pts.length
    ? Math.max(...ys) - Math.min(...ys) + PAD_TOP + PAD_BOTTOM
    : 320;

  const interactive = onSelect != null;
  const selected = nodes.find((n) => n.id === selectedId) ?? null;

  return (
    <VizFrame
      label={label}
      source={source}
      failed={failed}
      isEmpty={nodes.length === 0}
      empty={empty}
    >
      {/* ⛔ GEOMETRY TAKEN FROM THE WIREFRAME, NOT INVENTED: viewBox 600x320, hub at (300,162).
          The earlier version was a 200x120 box of FILLED discs and it was wrong twice over — `w-full` with
          no height made it ~750px tall in an 8fr column, and the nodes were solid where the design has
          HOLLOW RINGS on a dark fill. The gallery could not catch either: it renders every specimen inside
          `w-80`, where the same element is a tidy 192px and a solid dot reads as a deliberate dot.
          A COMPONENT CONSTRAINED BY ITS HARNESS IS NOT A COMPONENT THAT HAS BEEN TESTED AT SIZE. */}
      <svg
        viewBox={`${boxX} ${boxY} ${boxW} ${boxH}`}
        preserveAspectRatio="xMidYMid meet"
        style={{ height: `${boxH}px` }}
        className="w-full"
        role="presentation"
      >
        {/* The gradient the flowing overlay rides on, per the handoff's `tnxMeshEdge` def. */}
        <defs>
          <linearGradient id="tnxMeshEdge" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#D6D6D2" />
            <stop offset="1" stopColor="#C9C9C4" />
          </linearGradient>
        </defs>
        {links.map((l, i) => {
          const a = pos.get(l.from);
          const b = pos.get(l.to);
          if (!a || !b) return null;
          const touches = selectedId === l.from || selectedId === l.to;
          // Stroke width from the handoff: `1.5 + count/12`, where count is the busier endpoint's value.
          // Selection thickens it.
          const endpoint = nodes.find((n) => n.id === l.to);
          const c = typeof endpoint?.value === "number" ? endpoint.value : 0;
          const w = (touches ? 1.0 : 0) + 1.5 + c / 12;
          const dim = selectedId && !touches ? 0.18 : 1;
          return (
            <g key={`${l.from}-${l.to}`} opacity={dim}>
              <line
                // Entry only: EVERY edge draws itself in, healthy or dead. `tnx-draw` sets its own
                // stroke-dasharray, so a tone that wants a dash pattern keeps it via the overlay below.
                className={LINK_DASH[l.tone] ? undefined : "tnx-draw"}
                x1={a.x}
                y1={a.y}
                x2={b.x}
                y2={b.y}
                stroke={LINK_STROKE[l.tone]}
                strokeDasharray={LINK_DASH[l.tone]}
                strokeWidth={w}
                strokeLinecap="round"
              />
              {/* ⛔ ONLY A `linked` EDGE FLOWS. A crawling dash on a degraded or down link would animate a
                  fault as if it were alive — the loudest possible version of the reassuring-green defect.
                  Motion is reserved for the one state that is genuinely current. */}
              {l.tone === "linked" && (
                <>
                  <line
                    className="tnx-edge"
                    x1={a.x}
                    y1={a.y}
                    x2={b.x}
                    y2={b.y}
                    stroke="url(#tnxMeshEdge)"
                    strokeWidth={w}
                  />
                  {/* ⛔ A PACKET CONVERGING ON THE HUB — the handoff's `.tnx-pkt`, its timings verbatim
                      (duration 2.4 + (i%3)*0.4, delay i*0.35, linear, infinite).

                      DIRECTION IS SPOKE → HUB, not hub → spoke: the design calls these "packets converging
                      on hub", and convergence is the picture of a fabric that WORKS. Outward-radiating dots
                      read as broadcast, which is not what a transit hub does.

                      ONLY ON A `linked` EDGE. A packet crawling along a down link would animate traffic on a
                      tunnel that is carrying none — the same reassuring-green defect the flowing line
                      already avoids, one step louder because a moving dot reads as a PACKET, not a state. */}
                  <circle
                    className="tnx-pkt"
                    r="2.6"
                    fill="#E6E6E2"
                    style={{
                      offsetPath: `path("M ${b.x} ${b.y} L ${a.x} ${a.y}")`,
                      animationDuration: `${2.4 + (i % 3) * 0.4}s`,
                      animationDelay: `${i * 0.35}s`,
                    }}
                  />
                </>
              )}
            </g>
          );
        })}
        {nodes.map((n) => {
          const p = pos.get(n.id)!;
          const isSel = n.id === selectedId;
          const isHub = n.kind === "hub";
          // ⛔ RADIUS FROM THE HANDOFF'S FORMULA, not a constant I chose: `r = 16 + sqrt(count) * 3.2`
          // (dc.html meshData). The hub is a fixed 34, as it is there.
          //
          // ⚠ IT BARELY VARIES ON OUR DATA AND THAT IS HONEST. The wireframe's counts are SITES PER REGION
          // (40, 28, 22, 12, 6) so its rings differ visibly. Ours is GATEWAYS PER SITE — 0 or 1 today — so
          // the rings are nearly uniform. The encoding is the design's; the flatness is our network's, and
          // faking a spread would be drawing a distribution we do not have.
          const count = typeof n.value === "number" ? Math.max(0, n.value) : 0;
          const r = isHub ? 34 : 16 + Math.sqrt(count) * 3.2;
          const dim = selectedId && !isSel ? 0.3 : 1;
          const state = n.tone ?? n.note ?? "no link";
          return (
            // ⛔ SELECTION LIVES ON THE NODE, and it is still keyboard-operable.
            //
            // It was a list of rows beneath the diagram, which is NOT in the design — the handoff's rows are
            // an `sc-for extraSites`, i.e. sites added during the prototype session, not a permanent list.
            // So they duplicated the labels already drawn in the SVG and made the panel look like a diagram
            // with debug output stapled under it.
            //
            // An SVG shape is not focusable BY DEFAULT — that was the original reason for the rows. It is
            // focusable when you give it `tabIndex`, a `role` and a key handler, which is what this does. The
            // accessible name carries the node's state IN WORDS, so nothing is conveyed by colour alone, and
            // the sr-only list below still enumerates every link state as text.
            <g
              key={n.id}
              opacity={dim}
              role={interactive ? "button" : undefined}
              tabIndex={interactive ? 0 : undefined}
              aria-pressed={interactive ? isSel : undefined}
              aria-label={
                interactive
                  ? `${n.label}${n.sub ? ` ${n.sub}` : ""} — ${state}`
                  : undefined
              }
              className={
                interactive ? "cursor-pointer outline-none" : undefined
              }
              onClick={
                interactive ? () => onSelect(isSel ? null : n.id) : undefined
              }
              onKeyDown={
                interactive
                  ? (e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        onSelect(isSel ? null : n.id);
                      }
                    }
                  : undefined
              }
            >
              {isSel && (
                <circle
                  cx={p.x}
                  cy={p.y}
                  r={r + 6}
                  fill="none"
                  stroke="var(--tnx-text-heading)"
                  strokeWidth="1.5"
                  opacity="0.55"
                />
              )}
              {/* The RING. Dark fill + light stroke, per the design — not a solid disc. */}
              <circle
                className="tnx-pop"
                cx={p.x}
                cy={p.y}
                r={r}
                fill={
                  isHub ? "#1F1F1F" : n.tone ? NODE_FILL[n.tone] : "#171717"
                }
                stroke={
                  isHub ? "#C9C9C4" : n.tone ? NODE_RING[n.tone] : "#3A3A3A"
                }
                strokeWidth="1.6"
              />
              {/* The status dot at upper-right, coloured by the node's own worst link. Carried in the list
                  as words too — a dot alone states nothing to a screen reader. */}
              <circle
                cx={p.x + r * 0.66}
                cy={p.y - r * 0.66}
                r={4}
                fill={n.tone ? NODE_DOT[n.tone] : "#5E5E5B"}
                stroke="var(--tnx-bg)"
                strokeWidth="1.5"
              />
              <text
                x={p.x}
                y={p.y + (isHub ? 4 : 5)}
                textAnchor="middle"
                fill="var(--tnx-text-heading)"
                fontSize={isHub ? 11 : 15}
                fontWeight="700"
                fontFamily={isHub ? "JetBrains Mono, monospace" : "inherit"}
              >
                {isHub ? "HUB" : (n.value ?? "")}
              </text>
              <text
                x={p.x}
                y={p.y + r + 15}
                textAnchor="middle"
                fill="var(--tnx-text-primary)"
                fontSize="10.5"
                fontWeight="600"
              >
                {n.label}
              </text>
              {n.sub && (
                <text
                  x={p.x}
                  y={p.y + r + 27}
                  textAnchor="middle"
                  fill="var(--tnx-text-secondary)"
                  fontSize="8"
                  fontFamily="JetBrains Mono, monospace"
                >
                  {n.sub}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      {/* ⛔ THE LEGEND AND THE READOUT SHARE ONE ROW, INSIDE THE MAP — the handoff's structure (dc.html
          L456-465): three swatches, a flex spacer, then the selected-node box on the right.

          The visible node ROWS that used to sit here are GONE. They were never in the design: the handoff's
          rows are an `sc-for extraSites`, i.e. sites added during the prototype session, not a permanent
          list. They duplicated the labels already drawn in the SVG and made the panel read as a diagram with
          debug output stapled underneath.

          Selection moved ONTO the nodes, which are now real focusable controls (role, tabIndex, key handler,
          and an accessible name carrying the state in words). The sr-only list below keeps every link state
          available as TEXT — so nothing is conveyed by colour alone, which was the rows' actual job. */}
      <div className="mt-2 flex flex-wrap items-center gap-4">
        {links.length > 0 &&
          (["linked", "degraded", "down"] as const).map((tone) => (
            <span
              key={tone}
              className="flex items-center gap-1.5 font-mono text-micro text-ink-tertiary"
            >
              <span
                aria-hidden
                className="inline-block w-[18px]"
                style={
                  LINK_DASH[tone]
                    ? { borderTop: `2px dashed ${LINK_STROKE[tone]}` }
                    : {
                        height: 2,
                        borderRadius: 2,
                        background: LINK_STROKE[tone],
                      }
                }
              />
              {tone}
            </span>
          ))}
        <span className="flex-1" />
        {interactive && (
          // OCCUPIES ITS SPACE WHETHER OR NOT ANYTHING IS SELECTED: a readout that APPEARS on selection
          // shifts everything beneath it, and a diagram that reflows the page when clicked feels broken
          // though nothing is wrong. The unselected state is a real state with real copy.
          <span className="flex min-w-0 items-center gap-2.5 rounded-lg border border-line bg-ink-800 px-3 py-1.5">
            <span className="whitespace-nowrap text-cell font-semibold text-ink-emphasis">
              {selected ? selected.label : "No node selected"}
            </span>
            <span className="truncate font-mono text-micro text-ink-secondary">
              {selected
                ? [
                    selected.tone ?? selected.note ?? "no link",
                    selected.sub?.replace(/^· /, ""),
                  ]
                    .filter(Boolean)
                    .join(" · ")
                : "Click a node to inspect"}
            </span>
          </span>
        )}
      </div>

      {/* Every state as TEXT, for anyone who is not reading the picture. Visually redundant with the diagram
          and its readout, which is exactly why it is sr-only rather than deleted. */}
      <ul className="sr-only">
        {nodes.map((n) => (
          <li key={n.id}>
            {n.label} {n.sub}: {n.tone ?? n.note ?? "no link"}
          </li>
        ))}
        {links
          .filter((l) => l.tone !== "linked")
          .map((l) => (
            <li key={`${l.from}-${l.to}-d`}>
              {l.from} to {l.to}: {l.note ?? l.tone}
            </li>
          ))}
      </ul>
    </VizFrame>
  );
}

// ── PRIMITIVE 4 — AREA / TIME SERIES (S14.5) ────────────────────────────────────────────────────────────
//
// ⛔ THE ONE CHART SHAPE THIS SYSTEM DID NOT HAVE, AND THE ONE THE DESIGN ASKS FOR MOST LOUDLY.
//
// A PROPORTION (donut), a BINNED COUNT (histogram) and a GRAPH (node-link) cover current-state facts. A
// SERIES OVER TIME is a different claim: it asserts that a value was MEASURED REPEATEDLY, at a known cadence,
// and that the gaps between samples mean what the axis says they mean.
//
// ⚠ WHICH IS EXACTLY WHY IT NEEDS AN ENDPOINT THAT DOES NOT EXIST YET. `rx_bytes` is a raw gauge that RESETS
// on every handshake — plotting it against time draws a sawtooth and calls it throughput. So this primitive
// ships with its consumer rendering `source={{ roadmap: true }}`, and `VizFrame` refuses to draw anything at
// all in that state. THE COMPONENT BEING READY IS NOT THE DATA BEING READY, and the frame is what keeps those
// two facts from being confused.

export interface Series {
  label: string;
  /** Samples in chronological order. Same length across every series, or the x-axis means nothing. */
  values: number[];
  tone: "primary" | "secondary";
}

/** Catmull-Rom through the points, emitted as cubic beziers — the design's curves are smooth, not polylines. */
function smoothPath(pts: Array<{ x: number; y: number }>): string {
  if (pts.length < 2) return "";
  let d = `M ${pts[0]!.x} ${pts[0]!.y}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i - 1] ?? pts[i]!;
    const p1 = pts[i]!;
    const p2 = pts[i + 1]!;
    const p3 = pts[i + 2] ?? p2;
    const c1x = p1.x + (p2.x - p0.x) / 6;
    const c1y = p1.y + (p2.y - p0.y) / 6;
    const c2x = p2.x - (p3.x - p1.x) / 6;
    const c2y = p2.y - (p3.y - p1.y) / 6;
    d += ` C ${c1x} ${c1y}, ${c2x} ${c2y}, ${p2.x} ${p2.y}`;
  }
  return d;
}

export function AreaChart({
  label,
  source,
  failed,
  series,
  xLabels,
  formatValue,
  empty = "Nothing to show yet.",
}: {
  label: string;
  source: VizSource;
  failed: boolean;
  series: Series[];
  /** One label per sample index; only a few are rendered, evenly spaced. */
  xLabels: string[];
  formatValue?: (n: number) => string;
  empty?: ReactNode;
}) {
  const W = 600;
  const H = 220;
  const PAD_L = 44;
  const PAD_B = 22;
  const n = Math.max(...series.map((s) => s.values.length), 0);
  const max = Math.max(1, ...series.flatMap((s) => s.values));
  const fmt = formatValue ?? ((v: number) => String(v));

  const xy = (v: number, i: number) => ({
    x: PAD_L + (i / Math.max(1, n - 1)) * (W - PAD_L - 8),
    y: 8 + (1 - v / max) * (H - PAD_B - 16),
  });

  return (
    <VizFrame
      label={label}
      source={source}
      failed={failed}
      isEmpty={n === 0}
      empty={empty}
    >
      {/* ⛔ HEIGHT PINNED TO THE VIEWBOX HEIGHT — 1 user unit = 1 px, the same contract NodeLink needed.
          I FILED THAT LAW AND THEN REPEATED THE DEFECT IN THE NEXT PRIMITIVE: `w-full` on a 600x220 box with
          no height derives its height from its WIDTH, so at full column width this rendered ~500px tall.
          The gallery's wide specimen caught it on its FIRST render, which is precisely what it was added for
          — and it caught it in the component written AFTER the lesson, which is the more useful data point:
          a law in a document does not fire, an instrument does. */}
      <svg
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="xMidYMid meet"
        style={{ height: `${H}px` }}
        className="w-full"
        role="presentation"
      >
        <defs>
          {series.map((s) => (
            <linearGradient
              key={s.label}
              id={`tnxArea-${s.tone}`}
              x1="0"
              y1="0"
              x2="0"
              y2="1"
            >
              <stop
                offset="0"
                stopColor={s.tone === "primary" ? "#E6E6E2" : "#858582"}
                stopOpacity="0.28"
              />
              <stop
                offset="1"
                stopColor={s.tone === "primary" ? "#E6E6E2" : "#858582"}
                stopOpacity="0"
              />
            </linearGradient>
          ))}
        </defs>

        {/* Gridlines and their VALUES. An axis without numbers is a shape, not a measurement. */}
        {[0, 0.5, 1].map((f) => {
          const y = 8 + (1 - f) * (H - PAD_B - 16);
          return (
            <g key={f}>
              <line
                x1={PAD_L}
                y1={y}
                x2={W - 8}
                y2={y}
                stroke="#1A1A1A"
                strokeWidth="1"
              />
              <text
                x={PAD_L - 8}
                y={y + 3}
                textAnchor="end"
                fill="#5E5E5B"
                fontSize="9"
                fontFamily="JetBrains Mono, monospace"
              >
                {fmt(max * f)}
              </text>
            </g>
          );
        })}

        {series.map((s) => {
          const pts = s.values.map(xy);
          const line = smoothPath(pts);
          const last = pts[pts.length - 1];
          const first = pts[0];
          const area =
            line && first && last
              ? `${line} L ${last.x} ${H - PAD_B} L ${first.x} ${H - PAD_B} Z`
              : "";
          return (
            <g key={s.label}>
              <path d={area} fill={`url(#tnxArea-${s.tone})`} />
              <path
                className="tnx-draw"
                d={line}
                fill="none"
                stroke={s.tone === "primary" ? "#E6E6E2" : "#858582"}
                strokeWidth="1.6"
                strokeLinecap="round"
              />
            </g>
          );
        })}

        {xLabels.map((lb, i) =>
          i % Math.max(1, Math.ceil(n / 6)) === 0 ? (
            <text
              key={lb + i}
              x={xy(0, i).x}
              y={H - 6}
              textAnchor="middle"
              fill="#5E5E5B"
              fontSize="9"
              fontFamily="JetBrains Mono, monospace"
            >
              {lb}
            </text>
          ) : null,
        )}
      </svg>

      {/* Same rule as every other primitive here: the picture is the accelerant, the text is the content. */}
      <ul className="mt-1 flex flex-wrap gap-4 text-[11px]">
        {series.map((s) => (
          <li key={s.label} className="flex items-center gap-2 text-ink-body">
            <span
              aria-hidden
              className="h-[7px] w-[7px] shrink-0 rounded-full"
              style={{
                background: s.tone === "primary" ? "#E6E6E2" : "#858582",
              }}
            />
            {s.label}
            <span className="font-mono text-ink-heading">
              {fmt(s.values[s.values.length - 1] ?? 0)}
            </span>
          </li>
        ))}
      </ul>
    </VizFrame>
  );
}

// ── PRIMITIVE 5 — ADDRESS SPACE ─────────────────────────────────────────────────────────────────────────
//
// The handoff's `buildRangeMap`, read from its source and kept where it was right: x0 44, top 50, 8.4x11.4
// cells on a 10.4x13.5 pitch, divider at 356, call-out list at 392, utilisation under the list.
//
// FOUR THINGS THE FIRST BUILD GOT WRONG AGAINST IT, all caught by putting the two side by side:
//   · the free-cell grid was invisible — the drawing's frame of reference simply was not there
//   · `fontFamily="JetBrains Mono"` has NO FALLBACK and the real family is "JetBrains Mono Variable", so
//     every number rendered in SERIF. Now the `font-mono` class, which resolves through the token stack.
//   · the call-out rows said "fills its /16" instead of WHO OWNS IT — the single most useful label, dropped
//   · the utilisation block sat under the grid instead of under the list, and the panel grew a dead column
//
// ⛔ AN SVG IS UNREADABLE TO A SCREEN READER AND UNQUERYABLE BY THE TEST TIER — the same three-failures-one-
// cause the `Donut` avoids. Every fact the picture carries is also in its accessible name and in the text
// beneath it. The picture is the fast path, never the only path.

// The handoff's origin, kept. The PITCH is now derived rather than fixed — see `gridMetrics`.
const GRID = { x0: 44, top: 50 };
/** The left column's usable width, up to the divider at 356. */
const GRID_MAX = 296;
const GRID_MIN = 176;
/** Call-out row pitch. Tighter than the handoff's 42 because our list runs to eight rows, not three. */
const ROW_PITCH = 36;

/**
 * Cell pitch sized so the grid stands as tall as the call-out list beside it.
 *
 * ⛔ THE GRID IS SQUARE AND SCALES; IT DOES NOT SIT AT A FIXED 108px WHILE THE LIST GROWS. That mismatch is
 * what made the connectors look like they overflowed the drawing — they were correct, and pointing at a
 * column that had run out of picture.
 */
function gridMetrics(cols: number, rows: number, listHeight: number) {
  const box = Math.max(GRID_MIN, Math.min(GRID_MAX, listHeight));
  const pitch = box / Math.max(cols, rows);
  return { pitch, cellW: pitch * 0.78, cellH: pitch * 0.78, box };
}
export const MAP_LIST_MAX = 8;

/** Per-kind stroke. Deliberately four distinguishable tones: the cell's colour IS its constraint class. */
export const KIND_TONE: Record<AllocKind, string> = {
  approved: "var(--tnx-ok)",
  pending: "var(--tnx-warn)",
  pool: "var(--tnx-accent)",
  vip: "var(--tnx-neutral)",
};

/** "10.64" / "172.16" / "192.168.64" — the first address of a grid row, at the block's own resolution. */
export function mapRowLabel(block: Block, row: number): string {
  const addr =
    block.base + row * block.cols * Math.pow(2, 32 - block.cellPrefix);
  const o = [
    Math.floor(addr / 16777216) % 256,
    Math.floor(addr / 65536) % 256,
    Math.floor(addr / 256) % 256,
  ];
  return block.cellPrefix >= 24 ? `${o[0]}.${o[1]}.${o[2]}` : `${o[0]}.${o[1]}`;
}

function LitCell({
  cell,
  block,
  animate,
  order,
  m,
}: {
  cell: Cell;
  block: Block;
  animate: boolean;
  order: number;
  m: { pitch: number; cellW: number; cellH: number };
}) {
  const col = cell.index % block.cols;
  const row = Math.floor(cell.index / block.cols);
  const cx = GRID.x0 + col * m.pitch + m.cellW / 2;
  const cy = GRID.top + row * m.pitch + m.cellH / 2;
  const tone = KIND_TONE[cell.kind];
  const pending = cell.kind === "pending";
  // ⛔ PARTIAL IS DRAWN INSET — defect ① closed in one line. A /24 inside a /16 cell occupies a visibly
  // smaller square, so "some of this block" cannot be misread as "all of it".
  // Inset scales with the cell so a partial stays visibly smaller at every grid size.
  const inset = cell.state === "partial" ? m.cellW * 0.26 : 0;
  const w = m.cellW - inset * 2;
  const h = m.cellH - inset * 2;
  const begin = 0.15 + order * 0.09;

  return (
    <g transform={`translate(${cx} ${cy})`}>
      {cell.state === "full" && (
        <rect
          x={-(w + 3) / 2}
          y={-(h + 3) / 2}
          width={w + 3}
          height={h + 3}
          rx={3}
          fill={tone}
          opacity={0.18}
        />
      )}
      <rect
        x={-w / 2}
        y={-h / 2}
        width={w}
        height={h}
        rx={2.2}
        fill={pending ? "transparent" : tone}
        fillOpacity={pending ? 0 : 0.55}
        stroke={tone}
        strokeWidth={pending ? 1.1 : 0.9}
        strokeDasharray={pending ? "2 2" : undefined}
        opacity={animate ? 0 : 1}
      >
        {animate && (
          <animate
            attributeName="opacity"
            from="0"
            to="1"
            dur="0.5s"
            begin={`${begin}s`}
            fill="freeze"
          />
        )}
        {/* Only PENDING pulses. It is the one state on this panel that needs a human to act — withheld
            until approved — so it is the one thing that should not sit still. */}
        {animate && pending && (
          <animate
            attributeName="stroke-opacity"
            values="1;0.3;1"
            dur="1.8s"
            begin={`${begin + 0.5}s`}
            repeatCount="indefinite"
          />
        )}
      </rect>
      {animate && (
        <animateTransform
          attributeName="transform"
          type="scale"
          from="0"
          to="1"
          dur="0.5s"
          begin={`${begin}s`}
          calcMode="spline"
          keyTimes="0;1"
          keySplines="0.34 1.56 0.64 1"
          fill="freeze"
          additive="sum"
        />
      )}
    </g>
  );
}

export function AddressSpaceMap({
  map,
  animate,
}: {
  map: BlockMap;
  animate: boolean;
}) {
  const { block, lit } = map;
  const rows = Math.ceil(block.cells / block.cols);
  const showList = lit.length > 0 && lit.length <= MAP_LIST_MAX;
  const listRows = showList ? lit.length : 0;
  const listBottom = 46 + listRows * ROW_PITCH;
  // ⛔ THE UTILISATION BLOCK SITS UNDER THE LIST, NOT AT max(grid, list). Anchoring it to whichever column
  // happened to be taller left it FLOATING in space at low N — the right column ended, then 140px of nothing,
  // then a bar. It belongs to the list; it goes under the list.
  const utY = listBottom + 30;
  const rightBottom = utY + 40;
  // And the grid is sized FROM the right column's full height, so the two end level at every N. It is
  // clamped: below GRID_MIN the cells stop being legible, and above GRID_MAX it would cross the divider.
  const m = gridMetrics(block.cols, rows, rightBottom - GRID.top);
  const gridBottom = GRID.top + rows * m.pitch;
  const height = Math.max(gridBottom, rightBottom) + 14;
  const panelL = 372;
  const listX = 392;

  const centre = (index: number) => ({
    x: GRID.x0 + (index % block.cols) * m.pitch + m.cellW / 2,
    y: GRID.top + Math.floor(index / block.cols) * m.pitch + m.cellH / 2,
  });
  const barW = 120;
  const filled = Math.max(barW * map.utilised, map.utilised > 0 ? 4 : 0);

  return (
    <svg
      viewBox={`0 0 600 ${height}`}
      // Pixel height matched to the viewBox height. A `w-full` SVG with a viewBox and no height derives its
      // height from its WIDTH — the defect that shipped a 750px-tall diagram in the gallery.
      style={{ width: "100%", height: `${height}px`, display: "block" }}
      role="img"
      aria-label={`${block.label} address space: ${allocationLabel(map)}, ${utilisationLabel(map)} routed`}
    >
      <text
        x={GRID.x0}
        y={30}
        className="font-mono"
        fill="var(--tnx-neutral)"
        fontSize={8.5}
        fontWeight={700}
      >
        {block.label}
      </text>
      <text
        x={GRID.x0 + 66}
        y={30}
        className="font-mono"
        fill="var(--tnx-text-faint)"
        fontSize={7.5}
      >
        {`each cell = one /${block.cellPrefix} · ${block.cells} blocks`}
      </text>

      {Array.from({ length: rows }, (_, r) => r)
        .filter((r) => rows <= 4 || r % 4 === 0)
        .map((r) => (
          <text
            key={`rl${r}`}
            x={GRID.x0 - 9}
            y={GRID.top + r * m.pitch + m.cellH * 0.75}
            textAnchor="end"
            className="font-mono"
            fill="var(--tnx-text-faint)"
            fontSize={7.5}
          >
            {mapRowLabel(block, r)}
          </text>
        ))}

      {/* ⛔ THE FREE GRID, AND IT IS LOAD-BEARING. Without it the lit cells float with nothing to be
          positioned AGAINST — which is exactly how the first build rendered, and the reason a reader could
          not tell 10.10 from 10.40. It is also the only thing that makes "how much is left" visible at all. */}
      {Array.from({ length: block.cells }, (_, i) => (
        <rect
          key={`f${i}`}
          x={GRID.x0 + (i % block.cols) * m.pitch}
          y={GRID.top + Math.floor(i / block.cols) * m.pitch}
          width={m.cellW}
          height={m.cellH}
          rx={2.2}
          fill="var(--tnx-surface-inset)"
          stroke="var(--tnx-divider)"
          strokeWidth={0.6}
        />
      ))}

      {lit.map((cell, i) => (
        <LitCell
          key={cell.index}
          cell={cell}
          block={block}
          animate={animate}
          order={i}
          m={m}
        />
      ))}

      {showList && (
        <>
          <line
            x1={356}
            y1={26}
            x2={356}
            y2={height - 14}
            stroke="var(--tnx-divider)"
            strokeWidth={1}
          />
          {lit.map((cell, i) => {
            const y = 60 + i * ROW_PITCH;
            const c = centre(cell.index);
            const tone = KIND_TONE[cell.kind];
            const primary = cell.allocs[0];
            const extra = cell.allocs.length - 1;
            const pill = KIND_LABEL[cell.kind];
            const pw = pill.length * 5.6 + 14;
            return (
              <g key={cell.index}>
                <path
                  d={`M${c.x},${c.y} C${c.x + 30},${c.y} ${panelL - 26},${y} ${panelL - 4},${y}`}
                  fill="none"
                  stroke={tone}
                  strokeWidth={1}
                  strokeOpacity={0.3}
                  strokeDasharray={animate ? 500 : undefined}
                  strokeDashoffset={animate ? 500 : undefined}
                >
                  {animate && (
                    <animate
                      attributeName="stroke-dashoffset"
                      from="500"
                      to="0"
                      dur="0.9s"
                      begin={`${0.45 + i * 0.14}s`}
                      fill="freeze"
                    />
                  )}
                </path>
                <circle
                  cx={c.x}
                  cy={c.y}
                  r={1.6}
                  fill="var(--tnx-text-heading)"
                  opacity={0.9}
                />
                <rect
                  x={panelL}
                  y={y - 14}
                  width={3}
                  height={28}
                  rx={1.5}
                  fill={tone}
                />
                <text
                  x={listX}
                  y={y - 2}
                  className="font-mono"
                  fill="var(--tnx-text-heading)"
                  fontSize={11.5}
                  fontWeight={700}
                >
                  {primary.cidr}
                </text>
                {/* ⛔ WHO OWNS IT. The first build printed "fills its /16" here — a restatement of the
                    geometry the reader can already see, in the one slot that could have carried the fact
                    they came for. */}
                <text
                  x={listX}
                  y={y + 11}
                  fill="var(--tnx-neutral)"
                  fontSize={9.5}
                >
                  {primary.label}
                  {cell.state === "partial"
                    ? ` · part of one /${block.cellPrefix}`
                    : ""}
                  {extra > 0 ? ` · +${extra} more here` : ""}
                </text>
                <rect
                  x={584 - pw}
                  y={y - 11}
                  width={pw}
                  height={15}
                  rx={7.5}
                  fill="rgba(255,255,255,0.06)"
                  stroke={tone}
                  strokeWidth={1}
                  strokeOpacity={0.5}
                />
                <text
                  x={584 - pw / 2}
                  y={y - 0.5}
                  textAnchor="middle"
                  className="font-mono"
                  fill={tone}
                  fontSize={7.5}
                  fontWeight={700}
                >
                  {pill}
                </text>
              </g>
            );
          })}
        </>
      )}

      {/* Utilisation lives under the CALL-OUT LIST, as the handoff has it — the right column is the reading
          column, and putting it under the grid left a dead gutter and split the eye's path in two. */}
      <text
        x={listX}
        y={utY - 8}
        className="font-mono"
        fill="var(--tnx-neutral)"
        fontSize={8}
        fontWeight={600}
      >
        ADDRESS SPACE ROUTED
      </text>
      <rect
        x={listX}
        y={utY}
        width={barW}
        height={6}
        rx={3}
        fill="var(--tnx-surface-inset)"
      />
      <rect
        x={listX}
        y={utY}
        width={animate ? 0 : filled}
        height={6}
        rx={3}
        fill="var(--tnx-ok)"
      >
        {animate && (
          <animate
            attributeName="width"
            from="0"
            to={filled}
            dur="1s"
            begin="0.85s"
            fill="freeze"
          />
        )}
      </rect>
      <text
        x={listX + barW + 10}
        y={utY + 6}
        className="font-mono"
        fill="var(--tnx-text-body)"
        fontSize={8.5}
      >
        {utilisationLabel(map)}
      </text>
      <text
        x={listX}
        y={utY + 21}
        className="font-mono"
        fill="var(--tnx-text-faint)"
        fontSize={8}
      >
        {allocationLabel(map)}
      </text>
    </svg>
  );
}
