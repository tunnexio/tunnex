import { useState } from "react";
import {
  Badge,
  Button,
  Card,
  DataTable,
  EmptyState,
  Field,
  Input,
  List,
  ListItem,
  Loading,
  Modal,
  Panel,
  Select,
  StatusDot,
} from "../components/ui";
import { AreaChart, Donut, Histogram, NodeLink } from "../components/viz";
import { OneTimeSecretModal } from "../components/OneTimeSecret";
import { Icon, ICON_PATHS, type IconName } from "../components/Icon";

// ⛔ THE VISUAL GALLERY — THE SUBJECT OF THE VIEWPORT LEG.
//
// ════════════════════════════════════════════════════════════════════════════════════════════════════════
// THIS GALLERY EXISTS TO HOLD STATES THAT ONLY OCCUR IN COMBINATION.
// THAT IS A DIFFERENT THING FROM HOLDING EVERY COMPONENT.
// ════════════════════════════════════════════════════════════════════════════════════════════════════════
//
// ⛔ SO IF YOU ARE EXTENDING THIS FILE: ADD COMBINATIONS, NOT MORE COMPONENTS.
//
// THE INSTANCE THAT EARNED THE RULE. `Card` gained `backdrop-filter` (the glass recipe). That makes an
// element the containing block for `position: fixed` descendants — so all five modals rendered inside a Card
// stopped being viewport-positioned, were clipped to the card, and had the card's own body sitting over their
// buttons. Clicks stopped landing.
//
// NOTHING CAUGHT IT:
//   · tsc                                    clean
//   · 422 component tests                    green
//   · a deliberate click-through of all 12   "nothing is broken"
//     Card consumers, run FOR THIS PURPOSE
//
// It was invisible because NO TEST HAD A MODAL OPEN OVER A CARD. Every component was individually exercised
// and correct. The defect lived in the RELATIONSHIP between two of them, and a gallery of isolated components
// would have reproduced the same blind spot at higher cost.
//
// Hence: MODALS ARE RENDERED OPEN, INSIDE A CARD, ON PURPOSE. That single arrangement is worth more than
// twenty more components rendered alone.
//
// ── why a gallery rather than per-screen snapshots ──────────────────────────────────────────────────────
// All three visual defects of 2026-08-01 originated in SHARED CODE — a spacing config, a shared scale, a
// shared primitive. NONE originated in a screen. A screen-shaped suite pays per-screen maintenance to catch
// defects that are not screen-shaped, and needs re-baselining every time a screen is redesigned.
//
// ── shipping ───────────────────────────────────────────────────────────────────────────────────────────
// Behind `VITE_VISUAL_GALLERY`, unset in every production build, so this route is tree-shaken out. A test
// asserts the production bundle does not contain it — an unshipped surface must be PROVEN unshipped, not
// assumed (see apps/web/test/visualgallery.test.ts).

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="flex flex-col gap-2">
      <h2 className="font-mono text-micro font-semibold uppercase tracking-[.16em] text-ink-secondary">
        {title}
      </h2>
      <div className="flex flex-wrap items-start gap-3">{children}</div>
    </section>
  );
}

const ROWS = [
  { id: "a", name: "gw-us-east", ip: "10.99.0.2", state: "healthy" },
  { id: "b", name: "gw-eu-1", ip: "10.99.0.3", state: "apply failing" },
];
const COLS = [
  { key: "n", header: "Name", cell: (r: (typeof ROWS)[number]) => r.name },
  { key: "i", header: "Address", cell: (r: (typeof ROWS)[number]) => r.ip },
  {
    key: "s",
    header: "State",
    cell: (r: (typeof ROWS)[number]) => <Badge tone="warn">{r.state}</Badge>,
  },
];

export default function VisualGallery() {
  // Open by default: the snapshot must contain the overlay, not a button that would reveal it.
  //
  // ⛔ BUT IT MUST BE CLOSEABLE, and it was not — `onDismiss` was a no-op, so the overlay was permanent.
  // That mattered the moment a SECOND screenshot wanted a different section: the overlay is `fixed inset-0`,
  // so it sits over every element shot on the page. The first attempt to work around it masked
  // `[role="dialog"]` — which IS the full-viewport overlay — and produced a baseline that was ENTIRELY
  // magenta. A solid rectangle would have passed forever with no subject inside it.
  const [showModal, setShowModal] = useState(true);

  return (
    <div className="tnx-page flex flex-col gap-3.5 p-6" data-visual-gallery>
      <h1 className="text-[22px] font-semibold text-ink-heading">
        Visual gallery
      </h1>

      <Section title="Buttons">
        {(["primary", "ghost", "danger"] as const).map((v) => (
          <span key={v} className="flex gap-2">
            <Button variant={v}>{v}</Button>
            <Button variant={v} disabled>
              disabled
            </Button>
          </span>
        ))}
      </Section>

      <Section title="Badges and status">
        {(["ok", "warn", "danger", "neutral"] as const).map((t) => (
          <Badge key={t} tone={t}>
            {t}
          </Badge>
        ))}
        {(["on", "off", "warn"] as const).map((t) => (
          <StatusDot key={t} tone={t} />
        ))}
      </Section>

      <Section title="Fields">
        <div className="w-64">
          <Field label="Device name">
            <Input placeholder="laptop-anna" />
          </Field>
        </div>
        <div className="w-64">
          <Field label="Transport">
            <Select>
              <option>WireGuard</option>
            </Select>
          </Field>
        </div>
      </Section>

      {/* ⛔ COMBINATION 1: a table in ALL THREE of its states, side by side. The failed and empty renderings
          are the ones that historically diverge, and they are only comparable when adjacent. */}
      <Section title="DataTable — populated / empty / failed">
        <div className="w-80">
          <Panel title="Populated">
            <DataTable
              caption="Gateways"
              columns={COLS}
              rows={ROWS}
              rowKey={(r) => r.id}
              empty="None."
              failed={false}
            />
          </Panel>
        </div>
        <div className="w-80">
          <Panel title="Empty">
            <DataTable
              caption="Empty"
              columns={COLS}
              rows={[]}
              rowKey={(r) => r.id}
              empty="No gateways yet."
              failed={false}
            />
          </Panel>
        </div>
        <div className="w-80">
          <Panel title="Failed">
            <DataTable
              caption="Failed"
              columns={COLS}
              rows={[]}
              rowKey={(r) => r.id}
              empty="No gateways yet."
              failed={true}
            />
          </Panel>
        </div>
      </Section>

      <Section title="Empty / loading">
        <div className="w-80">
          <Panel title="Empty state">
            <EmptyState>No devices enrolled yet.</EmptyState>
          </Panel>
        </div>
        <div className="w-80">
          <Panel title="Loading">
            <Loading />
          </Panel>
        </div>
        <div className="w-80">
          <Panel title="List">
            <List label="Members">
              <ListItem>alice@acme.io</ListItem>
              <ListItem>bob@acme.io</ListItem>
            </List>
          </Panel>
        </div>
      </Section>

      {/* ⛔ COMBINATION 2: a donut INSIDE a panel INSIDE the page grid — the nesting where the 24px-vs-96px
          sizing defect actually lived. A donut rendered alone would have looked fine at any size. */}
      <Section title="Visualisations in situ">
        <div className="w-80">
          <Panel title="Donut">
            <Donut
              label="Peer status"
              source={{ endpoint: "/x" }}
              failed={false}
              centreLabel="devices"
              slices={[
                { label: "Connected", value: 83, tone: "ok" },
                { label: "Idle", value: 23, tone: "neutral" },
                { label: "Blocked", value: 9, tone: "warn" },
                { label: "Revoked", value: 14, tone: "danger" },
              ]}
              empty="none"
            />
          </Panel>
        </div>
        <div className="w-80">
          <Panel title="Histogram with a gap">
            <Histogram
              label="Verdicts"
              source={{ endpoint: "/x" }}
              failed={false}
              bins={[
                { label: "09", value: 5 },
                { label: "10", value: 0 },
                { label: "11", value: 0, gap: true },
                { label: "12", value: 9 },
              ]}
              empty="none"
            />
          </Panel>
        </div>
        <div className="w-80">
          <Panel title="Roadmap chart">
            <Histogram
              label="Site-link throughput"
              source={{ roadmap: true, why: "no time-series endpoint exists" }}
              failed={false}
              bins={[]}
              empty="none"
            />
          </Panel>
        </div>
        {/* ⛔ COMBINATION 4 (S14.5): ALL THREE LINK TONES AT ONCE, WITH A NODE SELECTED.
            `Link` was `healthy: boolean` under a three-entry legend. The tones only diverge visually when
            they are adjacent, and `degraded` is the one that had nowhere to live — a two-state type forces
            it to collapse into a neighbour, and collapsing it into `linked` is the silent-blackhole
            direction. Selection is rendered ON, because dimming is a RELATIVE effect: an unselected diagram
            proves nothing about what selection does to the other links. */}
        <div className="w-80">
          <Panel title="Node link — three tones, one selected">
            <NodeLink
              label="Topology"
              source={{ endpoint: "/x" }}
              failed={false}
              nodes={[
                { id: "h", label: "hub", kind: "hub", sub: "· us-east" },
                {
                  id: "a",
                  label: "eu-lan",
                  kind: "spoke",
                  sub: "· 10.2.0.0/16",
                },
                {
                  id: "b",
                  label: "ap-lan",
                  kind: "spoke",
                  sub: "· 10.3.0.0/16",
                },
                {
                  id: "c",
                  label: "sa-lan",
                  kind: "spoke",
                  sub: "· 10.4.0.0/16",
                },
              ]}
              links={[
                { from: "h", to: "a", tone: "linked" },
                {
                  from: "h",
                  to: "b",
                  tone: "degraded",
                  note: "advertises a subnet with no host address inside it",
                },
                {
                  from: "h",
                  to: "c",
                  tone: "down",
                  note: "no fresh handshake to the hub",
                },
              ]}
              selectedId="b"
              onSelect={() => {}}
              empty="none"
            />
          </Panel>
        </div>
        <div className="w-80">
          <Panel title="Node link — inert (no onSelect)">
            <NodeLink
              label="Topology"
              source={{ endpoint: "/x" }}
              failed={false}
              nodes={[
                { id: "h", label: "hub", kind: "hub" },
                { id: "s", label: "spoke", kind: "spoke" },
              ]}
              links={[{ from: "h", to: "s", tone: "down", note: "link down" }]}
              empty="none"
            />
          </Panel>
        </div>
      </Section>

      {/* ⛔ COMBINATION 3 — THE ONE THAT EARNED THIS FILE.
          A MODAL RENDERED OPEN, FROM INSIDE A CARD. `Card` carries `backdrop-filter`, which makes it the
          containing block for `position: fixed` descendants. Before the portal fix this arrangement clipped
          the overlay to the card and put the card's body over the modal's buttons.
          The modals are portalled now, so the snapshot shows them centred on the VIEWPORT. If a future change
          re-introduces the trap, this image moves and nothing else does. */}
      <Section title="Overlays, open, from inside a Card">
        <Card className="w-80">
          <p className="text-cell text-ink-body">
            A card containing an open modal.
          </p>
          {showModal && (
            <Modal
              title="Revoke device"
              onDismiss={() => setShowModal(false)}
              actions={<Button variant="danger">Revoke</Button>}
            >
              This removes the peer, releases its address, and cannot be undone.
            </Modal>
          )}
        </Card>
      </Section>

      {/* ⛔ FULL COLUMN WIDTH — THE HARNESS IS PART OF THE SPECIMEN.
          ════════════════════════════════════════════════════════════════════════════════════════════════
          EVERY SPECIMEN ABOVE RENDERS INSIDE `w-80`. That is a real context and it is not the only one.
          `NodeLink` has a viewBox and `w-full`, so its HEIGHT DERIVES FROM ITS WIDTH: 192px at 320, and
          ~750px in an 8fr column at 1440 — where it shipped, with two enormous discs floating in it.
          THE GALLERY COULD NOT SEE IT, because the gallery had pinned the only input to the function.
          A HARNESS THAT CONSTRAINS ITS SPECIMENS TESTS THE HARNESS.
          BOTH WIDTHS STAY. Neither alone is the component — that is the finding, not a compromise. */}
      <section className="flex flex-col gap-2" data-wide-specimens>
        <h2 className="font-mono text-micro font-semibold uppercase tracking-[.16em] text-ink-secondary">
          At full column width — the width-sensitive class
        </h2>
        <Panel title="Node link at column width">
          <NodeLink
            label="Topology"
            source={{ endpoint: "/x" }}
            failed={false}
            nodes={[
              {
                id: "h",
                label: "us-east hub",
                kind: "hub",
                sub: "· transit hub",
              },
              {
                id: "a",
                label: "eu-lan",
                kind: "spoke",
                sub: "· 10.2.0.0/16",
                value: 2,
                tone: "linked",
              },
              {
                id: "b",
                label: "ap-lan",
                kind: "spoke",
                sub: "· 10.3.0.0/16",
                value: 1,
                tone: "degraded",
              },
              {
                id: "c",
                label: "sa-lan",
                kind: "spoke",
                sub: "· 10.4.0.0/16",
                value: 1,
                tone: "down",
              },
            ]}
            links={[
              { from: "h", to: "a", tone: "linked" },
              {
                from: "h",
                to: "b",
                tone: "degraded",
                note: "subnet unreachable",
              },
              {
                from: "h",
                to: "c",
                tone: "down",
                note: "no fresh handshake to the hub",
              },
            ]}
            empty="none"
          />
        </Panel>
        <Panel title="Histogram at column width">
          <Histogram
            label="Verdicts"
            source={{ endpoint: "/x" }}
            failed={false}
            bins={[
              { label: "09", value: 5 },
              { label: "10", value: 12 },
              { label: "11", value: 0, gap: true },
              { label: "12", value: 9 },
              { label: "13", value: 2 },
              { label: "14", value: 0 },
            ]}
            empty="none"
          />
        </Panel>
        {/* ⛔ THE TIME-SERIES PRIMITIVE, WITH FIXTURES, SO ITS DESIGN CAN BE JUDGED BEFORE ITS DATA EXISTS.
            On Overview this same component renders `roadmap`, which draws NOTHING — correct there, useless
            for review. The gallery is where a component gets to be looked at without an endpoint. */}
        <Panel title="Area chart — site-link throughput (fixture data)">
          <AreaChart
            label="Site-link throughput"
            source={{ endpoint: "/x" }}
            failed={false}
            series={[
              {
                label: "Inbound",
                tone: "primary",
                values: [1.1, 1.4, 1.2, 1.9, 2.4, 2.1, 2.48],
              },
              {
                label: "Outbound",
                tone: "secondary",
                values: [0.7, 0.9, 0.8, 1.1, 1.3, 1.2, 1.35],
              },
            ]}
            xLabels={[
              "Jul 13",
              "Jul 14",
              "Jul 15",
              "Jul 16",
              "Jul 17",
              "Jul 18",
              "Jul 19",
            ]}
            formatValue={(v) => `${v.toFixed(1)}G`}
            empty="none"
          />
        </Panel>
        <Panel title="Donut at column width">
          <Donut
            label="Peer status"
            source={{ endpoint: "/x" }}
            failed={false}
            centreLabel="devices"
            slices={[
              { label: "Connected", value: 83, tone: "ok" },
              { label: "Idle", value: 23, tone: "neutral" },
              { label: "Blocked", value: 9, tone: "warn" },
              { label: "Revoked", value: 14, tone: "danger" },
            ]}
            empty="none"
          />
        </Panel>
      </section>

      <Section title="Icons">
        <div className="flex flex-wrap gap-3">
          {(Object.keys(ICON_PATHS) as IconName[]).map((n) => (
            <Icon key={n} name={n} size={16} className="text-ink-body" />
          ))}
        </div>
      </Section>
    </div>
  );
}

export { OneTimeSecretModal };
