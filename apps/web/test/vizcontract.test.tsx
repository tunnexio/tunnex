import { describe, expect, it, afterEach } from "vitest";
import {
  render,
  screen,
  cleanup,
  within,
  fireEvent,
} from "@testing-library/react";
import {
  Donut,
  Histogram,
  NodeLink,
  nodeLinkEdge,
  nodeLinkLayout,
  nodeLinkRoute,
  nodeLinkVisibleLabel,
} from "../src/components/viz";

// S14.3 SLICE C — THE VISUALIZATION CONTRACT.
//
// A chart is the easiest place in a UI to assert a fact nobody measured: a zero baseline LOOKS like data, and
// "no denials" and "we could not read the denials" draw identically. Both known render-floor violations in
// this repo are charts — that is the pattern, not a coincidence — so the guards live on the PRIMITIVE.

afterEach(cleanup);

const SLICES = [
  { label: "seen in last 3 min", value: 3, tone: "ok" as const },
  { label: "not seen recently", value: 1, tone: "neutral" as const },
];
const SRC = { endpoint: "/api/v1/organizations/{orgId}/overview" };

describe("⛔ A FAILED LOAD DRAWS NOTHING — never an empty axis, never a flat line at zero", () => {
  it("[Donut] failed renders no figure and no empty message", () => {
    render(
      <Donut
        label="Gateway liveness"
        source={SRC}
        failed={true}
        slices={SLICES}
        empty="none"
      />,
    );
    expect(
      screen.queryByRole("figure", { name: "Gateway liveness" }),
    ).toBeNull();
    expect(screen.queryByText("none")).toBeNull();
  });

  it("[Histogram] failed renders nothing, even with bins in hand", () => {
    // Stale bins under a failed refresh present old data as current — the same lie one step quieter.
    render(
      <Histogram
        label="Verdicts"
        source={SRC}
        failed={true}
        bins={[{ label: "09", value: 4 }]}
        empty="none"
      />,
    );
    expect(screen.queryByRole("figure", { name: "Verdicts" })).toBeNull();
  });

  it("[NodeLink] failed renders nothing", () => {
    render(
      <NodeLink
        label="Topology"
        source={SRC}
        failed={true}
        nodes={[]}
        links={[]}
        empty="none"
      />,
    );
    expect(screen.queryByRole("figure", { name: "Topology" })).toBeNull();
  });
});

describe("ZERO DATA SAYS SO — it does not draw an empty chart", () => {
  it("[Donut] a zero total renders the empty message, not a 0%% ring", () => {
    render(
      <Donut
        label="Gateway liveness"
        source={SRC}
        failed={false}
        slices={[{ label: "online", value: 0, tone: "ok" }]}
        empty="No gateways enrolled yet."
      />,
    );
    expect(screen.getByText("No gateways enrolled yet.")).toBeTruthy();
    expect(
      screen.queryByRole("figure", { name: "Gateway liveness" }),
    ).toBeNull();
  });
});

describe("⛔ A ROADMAP CHART RENDERS ITS HONEST STATE — never a plausible drawing", () => {
  it("says it is not available and why, and draws no figure", () => {
    // A greyed-out sample is still a picture. "Fleet risk" and "Site-Link Throughput" are the two known
    // violations, and both would have shipped as pictures with nothing behind them.
    render(
      <Histogram
        label="Site-link throughput"
        source={{
          roadmap: true,
          why: "no time-series endpoint exists, and the spec forbids summing the byte gauges",
        }}
        failed={false}
        bins={[]}
        empty="none"
      />,
    );
    const note = screen.getByRole("note");
    expect(note.textContent).toMatch(/isn.t available yet/);
    expect(note.textContent).toMatch(/spec forbids/);
    expect(
      screen.queryByRole("figure", { name: "Site-link throughput" }),
    ).toBeNull();
  });
});

describe("THE NUMBERS ARE TEXT, NOT ONLY GEOMETRY", () => {
  it("[Donut] every slice's value and label is readable", () => {
    // An SVG arc is unreadable to a screen reader, unqueryable by the tier, and ambiguous to anyone who
    // cannot distinguish the colours — three failures with one cause.
    render(
      <Donut
        label="Gateway liveness"
        source={SRC}
        failed={false}
        slices={SLICES}
        empty="none"
      />,
    );
    const fig = screen.getByRole("figure", { name: "Gateway liveness" });
    expect(within(fig).getByText("3")).toBeTruthy();
    expect(within(fig).getByText(/seen in last 3 min/)).toBeTruthy();
  });

  it("[NodeLink] a DOWN link is stated in words, not carried by a red line alone", () => {
    render(
      <NodeLink
        label="Topology"
        source={SRC}
        failed={false}
        nodes={[
          { id: "a", label: "hub-syd", kind: "hub" },
          { id: "b", label: "spoke-wus", kind: "spoke" },
        ]}
        links={[
          { from: "a", to: "b", tone: "down", note: "no fresh handshake" },
        ]}
        empty="none"
      />,
    );
    expect(screen.getByText(/a to b: no fresh handshake/)).toBeTruthy();
  });

  // S14.5 — the tone widened from a boolean to three states, so the MIDDLE one gets its own assertion.
  // A two-state type under a three-entry legend forces `degraded` to collapse into a neighbour, and the
  // comfortable collapse (degraded → linked) is the direction that hides a fault.
  it("[NodeLink] a DEGRADED link is stated in words too, and is not collapsed into healthy", () => {
    render(
      <NodeLink
        label="Topology"
        source={SRC}
        failed={false}
        nodes={[
          { id: "a", label: "hub-syd", kind: "hub" },
          { id: "b", label: "spoke-wus", kind: "spoke" },
        ]}
        links={[
          { from: "a", to: "b", tone: "degraded", note: "subnet unreachable" },
        ]}
        empty="none"
      />,
    );
    expect(screen.getByText(/a to b: subnet unreachable/)).toBeTruthy();
  });

  // The diagram is operable by KEYBOARD or it is not operable.
  //
  // ⛔ REWRITTEN, not patched — the premise changed and the old title asserted the implementation.
  //
  // It read "not a click target on an SVG shape", because selection lived on <button> rows beneath the
  // diagram. Those rows were never in the design (the handoff's are an `sc-for extraSites`), so selection
  // moved ONTO the nodes. The requirement never was "must be an HTML button": it is that the control is
  // REACHABLE BY KEYBOARD and ANNOUNCES ITS STATE. An <svg><g> with role, tabIndex, aria-pressed and a key
  // handler satisfies that; `getByRole` finding it is the proof.
  //
  // A TEST THAT NAMES THE ELEMENT TYPE INSTEAD OF THE CAPABILITY BLOCKS A CORRECT REFACTOR AND CALLS IT A
  // REGRESSION. Same family as an assertion derived from the implementation.
  it("[NodeLink] the node is a keyboard-reachable control that announces its pressed state", async () => {
    const picked: (string | null)[] = [];
    render(
      <NodeLink
        label="Topology"
        source={SRC}
        failed={false}
        nodes={[
          { id: "a", label: "hub-syd", kind: "hub" },
          { id: "b", label: "spoke-wus", kind: "spoke" },
        ]}
        links={[{ from: "a", to: "b", tone: "linked" }]}
        selectedId={null}
        onSelect={(id) => picked.push(id)}
        empty="none"
      />,
    );
    const btn = screen.getByRole("button", { name: /spoke-wus/ });
    expect(btn.getAttribute("aria-pressed")).toBe("false");
    expect(btn.getAttribute("tabindex")).toBe("0"); // reachable by Tab, not only by mouse
    fireEvent.click(btn);
    expect(picked).toEqual(["b"]);
    // And by KEYBOARD, which is the half a click test never covers.
    fireEvent.keyDown(btn, { key: "Enter" });
    expect(picked).toEqual(["b", "b"]);
  });

  // ⛔ THE PRESSED STATE NEEDS BOTH HALVES, AND THE MUTATION PROVED IT.
  //
  // The test above asserts `aria-pressed="false"` on an UNSELECTED node. Hard-coding the attribute to
  // `false` — deleting the selection state entirely from the announcement — LEFT IT GREEN, because false is
  // what it expected. A test that only ever observes one value of a two-valued thing cannot tell the
  // variable from the constant. This asserts the other half.
  it("[NodeLink] the SELECTED node announces aria-pressed=true — the half the mutation walked through", () => {
    render(
      <NodeLink
        label="Topology"
        source={SRC}
        failed={false}
        nodes={[
          { id: "a", label: "hub-syd", kind: "hub" },
          { id: "b", label: "spoke-wus", kind: "spoke" },
        ]}
        links={[{ from: "a", to: "b", tone: "linked" }]}
        selectedId="b"
        onSelect={() => {}}
        empty="none"
      />,
    );
    expect(
      screen
        .getByRole("button", { name: /spoke-wus/ })
        .getAttribute("aria-pressed"),
    ).toBe("true");
    expect(
      screen
        .getByRole("button", { name: /hub-syd/ })
        .getAttribute("aria-pressed"),
    ).toBe("false");
  });

  // Clicking the selected node CLEARS the selection. Without this, `onSelect` could always emit the id and
  // both tests above would still pass.
  it("[NodeLink] clicking the selected node deselects it", () => {
    const picked: (string | null)[] = [];
    render(
      <NodeLink
        label="Topology"
        source={SRC}
        failed={false}
        nodes={[{ id: "b", label: "spoke-wus", kind: "spoke" }]}
        links={[]}
        selectedId="b"
        onSelect={(id) => picked.push(id)}
        empty="none"
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /spoke-wus/ }));
    expect(picked).toEqual([null]);
  });

  // Without onSelect the primitive must stay exactly as inert as it was before S14.5 — no buttons appear on
  // a screen that never asked for selection.
  it("[NodeLink] renders NO buttons when onSelect is omitted", () => {
    render(
      <NodeLink
        label="Topology"
        source={SRC}
        failed={false}
        nodes={[{ id: "a", label: "hub-syd", kind: "hub" }]}
        links={[]}
        empty="none"
      />,
    );
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });
});

describe("NodeLink responsive fit", () => {
  it("widens the deterministic topology from the rendered container aspect without enlarging node rings", () => {
    const nodes = [
      { id: "primary", label: "gw-primary", kind: "hub" as const },
      { id: "standby", label: "gw-standby", kind: "hub-standby" as const },
      { id: "site", label: "long-site-name", kind: "spoke" as const, value: 2 },
    ];
    const base = nodeLinkLayout(nodes);
    const fitted = nodeLinkLayout(nodes, 4);
    expect(fitted.box.width).toBeGreaterThan(base.box.width);
    expect(fitted.positions.get("primary")?.r).toBe(base.positions.get("primary")?.r);
    expect(fitted.positions.get("site")?.r).toBe(base.positions.get("site")?.r);
    // Same inputs produce the same expanded geometry across reloads.
    expect(nodeLinkLayout(nodes, 4)).toEqual(fitted);
  });
});

describe("NodeLink — deterministic HA hub layout", () => {
  const haNodes = [
    { id: "primary", label: "gateway-primary-with-a-long-name", kind: "hub" as const, sub: "primary · HA set gen 9" },
    { id: "standby", label: "gateway-standby-with-a-long-name", kind: "hub-standby" as const, sub: "standby · HA set gen 9" },
    { id: "s1", label: "northwest-branch-office-with-a-long-name", kind: "spoke" as const, value: 1 },
    { id: "s2", label: "europe-branch", kind: "spoke" as const, value: 1, tone: "linked" as const },
    { id: "s3", label: "asia-branch", kind: "spoke" as const, value: 1, tone: "down" as const },
    { id: "s4", label: "unbound-site", kind: "spoke" as const, value: 0, note: "no gateway bound" },
  ];

  it("separates primary, standby, and spokes deterministically, including long labels", () => {
    const first = nodeLinkLayout(haNodes);
    const second = nodeLinkLayout(haNodes);
    expect([...first.positions.entries()]).toEqual([...second.positions.entries()]);

    const positioned = [...first.positions.values()];
    for (let i = 0; i < positioned.length; i++) {
      for (let j = i + 1; j < positioned.length; j++) {
        const a = positioned[i]!;
        const b = positioned[j]!;
        expect(Math.hypot(a.x - b.x, a.y - b.y)).toBeGreaterThan(a.r + b.r + 12);
      }
    }
    expect(nodeLinkVisibleLabel(haNodes[0].label)).toMatch(/…$/);
    expect(first.box.width).toBeGreaterThan(0);
    expect(first.box.height).toBeGreaterThan(0);
  });

  it("terminates edges at node boundaries and preserves full accessible names at narrow width", () => {
    const layout = nodeLinkLayout(haNodes);
    const primary = layout.positions.get("primary")!;
    const spoke = layout.positions.get("s2")!;
    const edge = nodeLinkEdge(primary, spoke);
    expect(Math.hypot(edge.x1 - primary.x, edge.y1 - primary.y)).toBeCloseTo(primary.r);
    expect(Math.hypot(edge.x2 - spoke.x, edge.y2 - spoke.y)).toBeCloseTo(spoke.r);

    render(
      <div style={{ width: 320 }}>
        <NodeLink
          label="HA topology"
          source={SRC}
          failed={false}
          nodes={haNodes}
          links={[
            { from: "primary", to: "s1", tone: "linked" },
            { from: "primary", to: "s2", tone: "linked" },
            { from: "primary", to: "s3", tone: "down", note: "no fresh handshake" },
          ]}
          onSelect={() => {}}
          empty="none"
        />
      </div>,
    );
    expect(screen.getByRole("button", { name: /gateway-primary-with-a-long-name/ })).toBeTruthy();
    expect(document.querySelectorAll('[data-node-kind="hub-standby"]')).toHaveLength(1);
    expect(document.querySelectorAll("[data-edge]")).toHaveLength(3);
    for (const edge of document.querySelectorAll("[data-edge] path")) {
      expect(edge.getAttribute("fill")).toBe("none");
    }
    expect(document.querySelector("svg")?.getAttribute("class")).toContain("w-full");
  });

  it("routes every Site edge clear of unrelated HA cards, badges, and labels", () => {
    const layout = nodeLinkLayout(haNodes);
    const primary = layout.positions.get("primary")!;
    const standby = layout.positions.get("standby")!;
    const euSite = layout.positions.get("s2")!;
    const route = nodeLinkRoute(primary, euSite, [primary, standby]);

    expect(route.points).toHaveLength(4);
    for (let i = 1; i < route.points.length; i++) {
      const start = route.points[i - 1]!;
      const end = route.points[i]!;
      const dx = end.x - start.x;
      const dy = end.y - start.y;
      const lengthSquared = dx * dx + dy * dy;
      const t = Math.max(0, Math.min(1, ((standby.x - start.x) * dx + (standby.y - start.y) * dy) / lengthSquared));
      const clearance = Math.hypot(standby.x - (start.x + t * dx), standby.y - (start.y + t * dy));
      // ring + badge/label envelope: the line must clear the whole readable standby card, not merely its ring.
      expect(clearance).toBeGreaterThanOrEqual(standby.r + 48);
    }
    expect(route.path).toMatch(/^M .* L .* L .* L /);
  });
});

describe("⛔ A GAP IS DRAWN AS A GAP — 'no data' must never render as zero", () => {
  it("a gap bin is labelled 'no data', distinctly from a zero-count bin", () => {
    // AccessEvent.decision carries `gap` as a first-class enum value precisely because the agent can know it
    // did not observe a window. Drawing that as a zero-height bar would make "no denials" and "we did not
    // see" identical — the reassuring-empty defect with an axis on it.
    render(
      <Histogram
        label="Verdicts"
        source={SRC}
        failed={false}
        bins={[
          { label: "09", value: 5 },
          { label: "10", value: 0 },
          { label: "11", gap: true, value: 0 },
        ]}
        empty="none"
      />,
    );
    expect(screen.getByLabelText("11: no data")).toBeTruthy();
    expect(screen.getByLabelText("10: 0")).toBeTruthy();
    // The two must not collapse into the same rendering.
    expect(screen.queryByRole("figure", { name: "11: 0" })).toBeNull();
  });
});
