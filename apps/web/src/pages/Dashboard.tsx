import { useEffect, useState, type ReactNode } from "react";
import { useOrg } from "../lib/useOrg";
import { Icon, type IconName } from "../components/Icon";
import {
  GLASS,
  PageHeader,
} from "../components/ui";
import { isEnterprise, type Edition } from "../lib/edition";
import { hubSetView } from "../lib/hubsetview";
import { assembleTopology, meshFrom } from "../lib/sitesview";
import { Donut, NodeLink } from "../components/viz";
import { assembleClusters, serviceSlices } from "../lib/k8sview";
import { motionAllowed } from "../lib/motion";
import { useMotionPreference } from "../components/MotionProvider";
import { Link } from "react-router-dom";
import { UpgradeCenter } from "../components/UpgradeCenter";
import {
  api,
  apiErrorMessage,
  loadOne,
  type Device,
  type Loaded,
  type Node,
  type OrgOverview,
  type Site,
  type Meta,
  type HubSet,
  type PolicyRule,
  type ZeroTrustMode,
  type K8sCluster,
  type K8sService,
} from "../lib/api";
import {
  Badge,
  EmptyState,
  ErrorText,
  List,
  ListItem,
  Loading,
  Panel,
} from "../components/ui";
import {
  attributionBadge,
  gatewayHealthRow,
  policyHealthBadge,
} from "../lib/healthview";
import { agentSummary, type AgentRow } from "../lib/agentview";
import {
  isFreshOrg,
  sortGateways,
  peerSlices,
  postureSplit,
  statFrom,
  statText,
  type GatewayRow,
  type StatState,
} from "../lib/overviewview";

export default function Dashboard() {
  // ⛔ THE ORG COMES FROM THE SEAM (S12.5) — the page no longer picks index zero out of a list it
  // fetched itself, which is what made a second organization unreachable.
  const { org: currentOrg, loading: orgLoading, failed: orgFailed } = useOrg();
  const [orgName, setOrgName] = useState("");
  const [data, setData] = useState<OrgOverview | null>(null);
  const [error, setError] = useState<string | null>(null);
  // WF-2 (Deck D Leg 10): bump to refetch the overview. The CP count is correct the moment a device is
  // revoked (CountActiveDevicesByOrg excludes it) — the stale number was THIS view's mount-once fetch.
  // S14.4: the six stat cards come from THREE endpoints and RESOLVE INDEPENDENTLY.
  //
  // `/overview` supplies four (members, devices, nodes, online). Sites and Pending approvals are not in that
  // response. An aggregate field was REFUSED deliberately: an API change driven by a layout converts three
  // independent failures into one blast radius — one failure would blank six cards instead of two. Screens
  // compose endpoints; endpoints do not compose themselves for screens.
  const [sitesRes, setSitesRes] = useState<Loaded<Site[]> | null>(null);
  const [pendingRes, setPendingRes] = useState<Loaded<Device[]> | null>(null);
  const [nodesRes, setNodesRes] = useState<Loaded<Node[]> | null>(null);
  // ⚠ NULL means "not entitled or not loaded", and that is deliberate: the open edition's 403 is a
  // SUCCESSFUL refusal, so it must not become an error state. The card simply does not render.
  const [agentsRes, setAgentsRes] = useState<Loaded<AgentRow[]> | null>(null);
  const [rulesRes, setRulesRes] = useState<Loaded<PolicyRule[]> | null>(null);
  const [devicesRes, setDevicesRes] = useState<Loaded<Device[]> | null>(null);
  const [hubSetRes, setHubSetRes] = useState<Loaded<HubSet> | null>(null);
  // The motion preference is read ONCE at the app edge and passed down; no component asks matchMedia itself.
  const reducedMotion = useMotionPreference();
  // `null` = not resolved yet; `{ok:false}` = the read FAILED. Neither is "there are none" — the card says which.
  const [k8sClustersRes, setK8sClustersRes] = useState<Loaded<
    K8sCluster[]
  > | null>(null);
  const [k8sServicesRes, setK8sServicesRes] = useState<Loaded<
    K8sService[]
  > | null>(null);
  const [ztRes, setZtRes] = useState<Loaded<ZeroTrustMode> | null>(null);
  // THE ONE GATING SEAM. `/meta`'s edition is the same value that decides whether every other enterprise
  // surface exists — read here, never re-derived from an error.
  const [edition, setEdition] = useState<Edition>("unknown");

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        // ⭐ THE ORG-LIST FETCH IS GONE FROM THIS PAGE (S12.5). It existed only to be indexed at zero.
        // OrgProvider reads the list once for the whole shell; a page that re-fetched it would not merely
        // waste a request, it would pick an org the switcher has no way to change.
        const orgErr = null;
        if (cancelled) return;
        if (orgErr)
          return setError(
            apiErrorMessage(orgErr, "Could not load your organizations."),
          );
        // ⛔ LOADING IS NOT ABSENCE (S12.5). The provider resolves the org list asynchronously, so this
        // effect runs once with currentOrg === null before the answer exists. Treating that as "you have no
        // organization" renders a confident, false statement — and because the second pass only sets the
        // data, the stale error stayed on screen BESIDE the correct org name.
        //
        // ⚠ THREE STATES, NOT TWO: still loading (say nothing), the read failed (say THAT), genuinely no
        // membership (say that). Collapsing the first into the third is how a slow network becomes an
        // accusation that the user does not belong here.
        if (orgLoading) return;
        const org = currentOrg;
        if (!org)
          return setError(
            orgFailed
              ? "Could not load your organizations."
              : "You are not a member of any organization yet.",
          );
        setOrgName(org.name);
        const { data: ov, error: ovErr } = await api.GET(
          "/api/v1/organizations/{orgId}/overview",
          {
            params: { path: { orgId: org.id } },
          },
        );
        if (cancelled) return;
        if (ovErr || !ov)
          return setError(
            apiErrorMessage(ovErr, "Could not load the overview."),
          );
        setData(ov);

        // ⛔ THE SEAM, AND IT DECIDES BEFORE IT FETCHES. Edition first; gated endpoints are called ONLY when
        // the edition has them. An open-edition org therefore never issues a request that can 403, so there
        // is no failure to mis-interpret — the render decision is taken at the seam rather than recovered
        // from an error at the call site. The interpretation is what drifted, twice.
        const metaRes = (await loadOne(() =>
          api.GET("/api/v1/meta"),
        )) as Loaded<Meta>;
        if (cancelled) return;
        const ed: Edition = metaRes.ok
          ? metaRes.data.edition === "enterprise"
            ? "enterprise"
            : "open"
          : "unknown";
        setEdition(ed);

        if (isEnterprise(ed)) {
          void loadOne(() =>
            api.GET("/api/v1/organizations/{orgId}/devices/pending", {
              params: { path: { orgId: org.id } },
            }),
          ).then((r) => !cancelled && setPendingRes(r as Loaded<Device[]>));
          void loadOne(() =>
            api.GET("/api/v1/organizations/{orgId}/policies", {
              params: { path: { orgId: org.id } },
            }),
          ).then((r) => !cancelled && setRulesRes(r as Loaded<PolicyRule[]>));
          void loadOne(() =>
            api.GET("/api/v1/organizations/{orgId}/zero-trust-mode", {
              params: { path: { orgId: org.id } },
            }),
          ).then((r) => !cancelled && setZtRes(r as Loaded<ZeroTrustMode>));
        }
        // Fired together, awaited independently: each sets its own state, so one failure degrades one card.
        void loadOne(() =>
          api.GET("/api/v1/organizations/{orgId}/sites", {
            params: { path: { orgId: org.id } },
          }),
        ).then((r) => !cancelled && setSitesRes(r as Loaded<Site[]>));
        void loadOne(() =>
          api.GET("/api/v1/organizations/{orgId}/nodes", {
            params: { path: { orgId: org.id } },
          }),
        ).then((r) => !cancelled && setNodesRes(r as Loaded<Node[]>));
        // ⛔ ENTERPRISE, AND A 403 IS A SUCCESSFUL REFUSAL — NOT AN ERROR. On the open edition the
        // endpoint correctly answers edition_required; the card must then be ABSENT, not "unavailable".
        // Folding a correct refusal into a failure is the defect this repo has already paid for.
        void api
          .GET("/api/v1/organizations/{orgId}/agents", {
            params: { path: { orgId: org.id } },
          })
          .then(({ data, error }) => {
            if (cancelled || error || !data) return; // 403 lands here and stays silent, by design
            setAgentsRes({ ok: true, data: data as AgentRow[] });
          })
          .catch(() => {});
        // Both OPEN endpoints — no gate needed, and the audit that cut them was wrong about the data.
        void loadOne(() =>
          api.GET("/api/v1/organizations/{orgId}/devices", {
            params: { path: { orgId: org.id } },
          }),
        ).then((r) => !cancelled && setDevicesRes(r as Loaded<Device[]>));
        void loadOne(() =>
          api.GET("/api/v1/organizations/{orgId}/hub-set", {
            params: { path: { orgId: org.id } },
          }),
        ).then((r) => !cancelled && setHubSetRes(r as Loaded<HubSet>));
        // ⛔ KUBERNETES HAS NO PLACE IN `OrgOverview`, MEASURED: that schema is
        // `members, devices, nodes, online, recent_activity` and nothing more. So the counts come from the two
        // live reads, which are BOTH `org:view` (verified at the handler in S14.7) and both second-class here:
        // a failure degrades this one card and nothing else, exactly like sites and nodes above.
        void loadOne(() =>
          api.GET("/api/v1/organizations/{orgId}/k8s/clusters", {
            params: { path: { orgId: org.id } },
          }),
        ).then(
          (r) => !cancelled && setK8sClustersRes(r as Loaded<K8sCluster[]>),
        );
        void loadOne(() =>
          api.GET("/api/v1/organizations/{orgId}/k8s/services", {
            params: { path: { orgId: org.id } },
          }),
        ).then(
          (r) => !cancelled && setK8sServicesRes(r as Loaded<K8sService[]>),
        );
      } catch {
        if (!cancelled) setError("Could not reach the API.");
      }
    })();
    return () => {
      cancelled = true;
    };
    // ⛔ THE `refresh` COUNTER WENT WITH THE DESKTOP EFFECT. Its only writer was WF-2's revocation
    // subscription; with that gone it was a state variable that could never change, and a dependency
    // array naming a constant is a dependency array that says nothing. Removed rather than left as a
    // permanent 0 — an inert knob reads as a live one to the next person.
    // ⛔ currentOrg IS A DEPENDENCY, AND ITS ABSENCE WAS A REAL BUG THE TESTS CAUGHT (S12.5).
    //
    // The provider resolves the org list ASYNCHRONOUSLY, so on this effect's first run `currentOrg` is still
    // null. With `[]` deps the effect never ran again: the page rendered "You are not a member of any
    // organization yet" — a confident, wrong statement — and stayed there forever, for every user.
    //
    // ⚠ THE SAME DEPENDENCY ALSO MAKES THE SWITCHER WORK. One line, two properties: without it the page
    // either never loads at all, or loads once and then lies about which tenant it is showing.
  }, [currentOrg]);

  // ⛔ WF-2's DESKTOP REFETCH IS GONE (S14.20 step 4). It re-pulled the overview when the client's
  // RevocationMonitor saw this device revoked — a subscription that only existed because the client
  // used to mount this dashboard. It never mounts it now, so the effect could not fire.
  //
  // ⚠ WF-2's CLAIM IS NOT ABANDONED, it moved: the client shows revocation on its OWN surface
  // (`revoked` is a first-class state with a loud banner and a notification). What is gone is a
  // browser dashboard reacting to a tunnel it cannot see.

  return (
    // ⛔ THE PAGE ROOT CARRIES THE RHYTHM. This was a bare `<div>`, and every section inside it stacked with
    // ZERO spacing — the stat row touched Get started, which touched the panel row.
    //
    // The shell's `<main>` already sets `flex flex-col gap-3.5` (the README's page-body rhythm), but a flex gap
    // reaches only DIRECT children, and the whole page is a single child of main. The gap was correct and
    // applied to exactly one element. Every screen root must therefore repeat this — see docs/S14.4.
    <div className="flex flex-col gap-3.5">
      {/* README: PAGE HEADER = title + subtitle, its own block above the body. */}
      <PageHeader title="Overview" subtitle={orgName || "…"} />
      <ErrorText>{error}</ErrorText>
      <UpgradeCenter />

      {/* Desktop only: the VPN connect surface (no-op/hidden in the browser). */}

      {data && (
        <>
          {(() => {
            // The six cards, each carrying its OWN state. `statFrom(null, …)` = still loading.
            const members = statFrom<OrgOverview>(
              { ok: true, data },
              (d) => d.members,
            );
            const devices = statFrom<OrgOverview>(
              { ok: true, data },
              (d) => d.devices,
            );
            const gateways = statFrom<OrgOverview>(
              { ok: true, data },
              (d) => d.nodes,
            );
            const sites = statFrom(sitesRes, (r: Site[]) => r.length);
            const pending = statFrom(pendingRes, (r: Device[]) => r.length);
            const rules = statFrom(rulesRes, (r: PolicyRule[]) => r.length);
            // Edition is UNKNOWN until /meta answers; treat unknown as not-enterprise so a slow load never
            // flashes an enterprise-only surface. Absent-until-known, same rule as every count on this screen.
            const enterprise = isEnterprise(edition);
            // FOUR core cards, plus Access Rules and Pending approvals on enterprise, plus AI Agents when
            // its read succeeded. ONE definition, read by both the gating below and the grid's column count.
            // ⚠ THE AGENT TERM IS THE CONDITION ITSELF, not `enterprise`: the card renders on `ok` alone, so
            // counting it on edition would re-span the row for a card that is not there — the two-column
            // hole the re-span was ruled to prevent.
            const STAT_CARDS = (enterprise ? 6 : 4) + (agentsRes?.ok ? 1 : 0);

            // NEEDS ATTENTION is COMPOSED, not fetched — every item names the source that produced it, and an
            // item appears only when its source has been READ. A source still loading contributes nothing;
            // a source that FAILED contributes nothing either, because "nothing needs attention" and "we could
            // not check" must not render identically. The panel says "loading" until every source has answered.
            // ⛔ WAIT ONLY ON SOURCES THAT WILL ACTUALLY ARRIVE.
            //
            // `pendingRes` is enterprise-gated and is NEVER FETCHED on the open edition, so it stays `null`
            // forever — and `null` was the "still loading" signal. The panel hung on "Loading…" permanently,
            // waiting for a request that was deliberately never made.
            //

            // Sub-lines are QUALIFICATIONS, and each is `null` when there is nothing honest to say. A sub-line
            // is never filler: an unqualified number is a smaller claim than a wrongly-qualified one.
            // ⛔ SAME RE-SOURCING, AND THIS IS THE ONE THE TYPE CANNOT PROTECT. A raw field read bypasses
            // any function; the widened signature ENABLES this call and cannot FORCE it. The class stays
            // open by construction — `policy_degraded` remains readable — so this line is a decision, not
            // a guarantee.
            const degraded = nodesRes?.ok
              ? nodesRes.data.filter((n) => policyHealthBadge(n) !== null)
                  .length
              : null;
            const pendingInvites = null; // no endpoint for pending invites — the slot stays empty, not invented
            const siteSub = sitesRes?.ok
              ? sitesRes.data.length === 0
                ? "none configured"
                : `${sitesRes.data.length} in the mesh`
              : null;
            const zeroTrust = ztRes?.ok
              ? ztRes.data.mode === "enforcing"
                ? "enforcing"
                : "not enforced"
              : null;
            // ⛔ THE SUB-LINE IS WHERE THE PANEL'S ONE REAL SENTENCE SURVIVES. The AI Agents panel named
            // the unattributable count, and a count with the gap dropped is a smaller claim than it looks:
            // "3 agents" reads as three accounted-for agents. The qualification moves into the sub-line
            // rather than being lost with the card that used to carry it.
            // ⚠ Still named ONLY when non-zero (agentSummary's rule) — a permanent "0 unattributable"
            // trains the reader to stop seeing the line that matters when it is not zero.
            const agentSum = agentsRes?.ok
              ? agentSummary(agentsRes.data)
              : null;
            const agentSub = agentSum
              ? (agentSum.note ?? "enrolled in this organization")
              : null;
            const fresh = isFreshOrg(gateways, devices, members);

            return (
              // The same reason, one level down: these three sections are siblings and need the page rhythm
              // between them, not zero.
              <div className="flex flex-col gap-3.5">
                {/* README: the Overview stat row is `repeat(12,1fr)` gap 12 — SIX cards at span 2.
                    Settled from the SOURCE prototype, not from the README's generic "4-up" sentence (which
                    describes the other screens) and not from the screenshot alone. */}
                {/* ⛔ THE ROW RE-SPANS TO FILL 12. RULED, and the argument matters more than the choice:
                    a fixed six-slot row leaves the open edition with five cards and a two-column hole, which
                    is the SAME ragged-row defect already fixed for the panels — and worse here, because a gap
                    in a stat row reads as a card that failed to render rather than as a capability the org
                    does not have. Absence should be invisible when the thing absent was never offered.
                    Six cards -> span 2 each. Five -> the row is a 5-column grid. Either way it fills. */}
                {/* ⛔ THE ROW RE-SPANS TO FILL, AND IT COLLAPSES BEFORE IT OVERFLOWS.
                    Six (or five) fixed columns at 390px gives ~60px per card and the page scrolls sideways —
                    which the viewport leg caught on its FIRST baseline (390px viewport, 455px capture).
                    The edition-dependent count only applies once there is room for it. */}
                {/* ⛔ THE COLUMN COUNT IS DERIVED FROM THE CARD COUNT, IN ONE PLACE.
                    It was hard-coded `lg:grid-cols-6` while SEVEN cards were rendered — enterprise adds both
                    Access Rules and Pending approvals — so the seventh wrapped to a second row and sat alone
                    beneath five empty columns. It read as a card that failed to render rather than as a row
                    that did not fit.

                    THE COUNT WAS WRITTEN TWICE, IN TWO LANGUAGES: once as JSX elements and once as a Tailwind
                    class, with nothing to make them agree. Now the class reads a CSS variable set from the
                    same constant the cards are gated on, so adding a card cannot silently orphan it.

                    ⚠ THE VARIABLE IS `--stat-cols`, NOT `--tnx-stat-cols`. The first name I used borrowed the
                    `--tnx-` prefix, which in this codebase means "a GENERATED DESIGN TOKEN" — and the
                    tokenrefs census failed on it within seconds of being written, on its own author. A local
                    layout variable is not a design token and must not wear the namespace that promises it is
                    held to the generated set. */}
                <div
                  className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:[grid-template-columns:repeat(var(--stat-cols),minmax(0,1fr))]"
                  style={{ "--stat-cols": STAT_CARDS } as React.CSSProperties}
                >
                  <Stat
                    label="Members"
                    icon="users"
                    value={members}
                    sub={
                      pendingInvites === null
                        ? null
                        : `${pendingInvites} pending invite${pendingInvites === 1 ? "" : "s"}`
                    }
                  />
                  <Stat
                    label="Devices"
                    icon="laptop"
                    value={devices}
                    sub={
                      pending.state === "ok"
                        ? `${pending.value} awaiting approval`
                        : null
                    }
                  />
                  <Stat
                    label="Gateways"
                    icon="server"
                    value={gateways}
                    sub={
                      degraded === null
                        ? null
                        : `${degraded} reporting degraded kinds`
                    }
                  />
                  {/* ⛔ ENTERPRISE, AND RENDERED ONLY ON `ok` — NOT ON "enterprise". The agents fetch
                      swallows every error, 403 and genuine failure alike, so `agentsRes` stays `null` in
                      both cases. Gating on the EDITION would make a failed read on enterprise render a
                      permanent "loading" card — which is the exact `pendingRes` defect documented above,
                      reintroduced from the other direction. `ok` is the only state that means the number
                      is known. */}
                  {agentsRes?.ok && (
                    <Stat
                      label="AI Agents"
                      icon="bot"
                      value={statFrom(agentsRes, (r: AgentRow[]) => r.length)}
                      sub={agentSub}
                    />
                  )}
                  <Stat
                    label="Sites"
                    icon="network"
                    value={sites}
                    sub={siteSub}
                  />
                  {/* ⛔ ENTERPRISE. `/policies` and `/zero-trust-mode` are both gated, so on the open edition
                      this card is ABSENT — not "0", not "could not load" in red. It was the SECOND instance of
                      the same conflation in this slice, still live after the first was fixed at one call
                      site: only an enumeration finds the rest (src/lib/edition.ts). */}
                  {enterprise && (
                    <Stat
                      label="Access Rules"
                      icon="shield"
                      value={rules}
                      sub={zeroTrust === null ? null : zeroTrust}
                    />
                  )}
                  {/* Sixth card only where the capability exists. On the open edition the row is five wide —
                      which is the honest layout, not a gap where a broken card used to be. */}
                  {enterprise && (
                    <Stat
                      label="Pending approvals"
                      icon="user-plus"
                      value={pending}
                      sub="awaiting an admin"
                    />
                  )}
                </div>

                {/* Not in a grid — a sibling in the page column, so a `col-span-*` here would be a dead class. */}
                {fresh && (
                  <Panel title="Get started">
                    {/* The floating "Get started" widget is CUT — it becomes this. Rendered only when we KNOW
                        the org is empty: showing it because a fetch failed would tell a founder with a working
                        fleet that they have nothing. */}
                    <ol className="space-y-1.5 text-explainer leading-[1.55] text-ink-body">
                      <li>
                        1. Enroll a tunnex-node agent to serve WireGuard peers.
                      </li>
                      <li>2. Add your first device and download its config.</li>
                      <li>3. Define who may reach what under Access.</li>
                    </ol>
                    <Link
                      to="/devices"
                      className="mt-2.5 inline-block text-mono text-ink-emphasis hover:text-ink-heading"
                    >
                      Enroll a gateway →
                    </Link>
                  </Panel>
                )}

                {/* ⛔ MULTI-COLUMN FLOW, NOT A GRID — AND THE GRID'S OWN COMMENT IS WHY.
                    It claimed "EVERY ROW SUMS TO 12 … Row 3: Needs Attention 8 · System Health 4". Measured:
                    ALL ELEVEN panels carry `lg:col-span-4`. Nothing spans 8. The bento was documented, then
                    flattened into a uniform 3-across grid, and the comment kept describing the design rather
                    than the code — so `lg:grid-cols-12` bought a twelve-column system that only ever
                    expressed thirds.

                    ⛔ AND A GRID ALIGNS ROWS, WHICH IS THE DEFECT THE FOUNDER REPORTED: every card in a row
                    is as tall as the TALLEST card in that row. "AI Agents" is three lines and was rendering
                    the height of a donut plus a four-row legend — a bordered box mostly full of nothing.
                    Panel's own comment called the stretch deliberate ("keeps every panel in a row the same
                    height"); that is the thing being reversed, on the founder's word, and deliberately.

                    Multi-column flow packs each card directly under the previous one in its column, so a
                    height difference costs nothing. This is the same fix already accepted on Settings, where
                    the identical grid produced the identical holes.

                    ⚠ IT CHANGES THE READING ORDER to column-major: panels fill down column 1, then column 2.
                    Called out because it is a real consequence, not a side effect to discover later.

                    ⚠ AND EVERY CHILD NEEDS `break-inside-avoid`, or a card splits down the middle across a
                    column boundary — the one hazard of this layout, and it looks like a rendering bug. The
                    wrapper carries it so no panel has to remember, INCLUDING ones added later.

                    Panels are conditional (AI Agents needs enterprise + a non-empty list; Kubernetes, HA Hub
                    Set and others gate too), so hand-ordering rows by height could not have worked: which
                    panels are present varies per org, and a row tuned for one tenant is ragged for the next.
                    Packing has to be automatic for that reason alone. */}
                <div className="columns-1 gap-3 lg:columns-3 [&>*]:mb-3 [&>*]:break-inside-avoid">
                  <Panel title="Peer Connection Status">
                    {/* ⚠ RE-SOURCED TO DEVICES. This counted GATEWAYS — a different and smaller population
                        than the one the panel is named for. A chart can be perfectly honest about the wrong
                        denominator, and nothing in the render would look wrong. */}
                    <Donut
                      label="Peer connection status"
                      source={{
                        endpoint: "/api/v1/organizations/{orgId}/devices",
                      }}
                      failed={devicesRes !== null && !devicesRes.ok}
                      slices={devicesRes?.ok ? peerSlices(devicesRes.data) : []}
                      centreLabel="devices"
                      empty="No devices enrolled yet."
                    />
                    {/* The design's caption, verbatim — it states the product's rule, not a decoration. */}
                    <p className="mt-2 text-explainer leading-[1.55] text-ink-tertiary">
                      Status derived from WireGuard handshake liveness. Never
                      green while dead.
                    </p>
                  </Panel>

                  <Panel title="Gateway Health">
                    {nodesRes === null ? (
                      <Loading />
                    ) : !nodesRes.ok ? (
                      <ErrorText>Gateway health is unavailable.</ErrorText>
                    ) : nodesRes.data.length === 0 ? (
                      <EmptyState>No gateway enrolled yet.</EmptyState>
                    ) : (
                      <List label="Gateway health">
                        {sortGateways(
                          nodesRes.data.map((n): GatewayRow => {
                            // ⛔ THE ROW VERDICT IS NOT FORMED HERE (S14.21). This panel used to read
                            // `b ? b.label : "healthy"` — turning "no badge" into the CLAIM "healthy",
                            // which is what put a green verdict on a revoked gateway. Deciding it here at
                            // all was the defect; gatewayHealthRow owns it now.
                            const v = gatewayHealthRow(n);
                            // ⛔ A SECOND, INDEPENDENT BADGE — NOT A REPLACEMENT (S15.2, D25(C)). A gateway
                            // can be perfectly healthy AND unattributable, so folding attribution into the
                            // health verdict would force a choice between reporting an enforcement problem
                            // and reporting an accountability one. Both, or neither.
                            const a = attributionBadge(n);
                            return {
                              id: n.id,
                              name: n.name,
                              label: v.label,
                              tone: v.tone,
                              attribution: a ? a.label : null,
                              attributionDetail: a ? a.detail : null,
                            };
                          }),
                        ).map((g) => (
                          <ListItem key={g.id}>
                            <span className="flex items-center justify-between gap-2">
                              <span className="truncate font-mono text-mono text-ink-primary">
                                {g.name}
                              </span>
                              <span className="flex shrink-0 items-center gap-1.5">
                                {/* ⚠ The detail rides a wrapping <span title>, not the Badge — Badge takes
                                    only tone+children, and widening a shared primitive to carry one
                                    caller's tooltip is how a design system stops being one. */}
                                {g.attribution && (
                                  <span
                                    title={g.attributionDetail ?? undefined}
                                  >
                                    <Badge tone="warn">{g.attribution}</Badge>
                                  </span>
                                )}
                                <Badge tone={g.tone}>{g.label}</Badge>
                              </span>
                            </span>
                          </ListItem>
                        ))}
                      </List>
                    )}
                  </Panel>

                  {/* ⛔ KUBERNETES ON OVERVIEW, AND ITS COUNTS DO NOT COME FROM `OrgOverview`.
                      Measured: that schema is `members, devices, nodes, online, recent_activity` and carries
                      nothing about clusters. So this reads the two live endpoints directly (both `org:view`,
                      verified at the handler) as a SECOND-CLASS read — a failure degrades this card alone.

                      THREE STATES, NOT TWO. `null` = still loading · `{ok:false}` = we could not look ·
                      `[]` = there are genuinely none. A zero standing in for the middle case would claim an
                      org has no clusters on the strength of a failed request. */}
                  <Panel title="Kubernetes">
                    {k8sClustersRes === null || k8sServicesRes === null ? (
                      <Loading />
                    ) : !k8sClustersRes.ok ? (
                      <p className="text-cell text-warn">
                        Could not read clusters. This card only; the rest of the
                        page is unaffected.
                      </p>
                    ) : k8sClustersRes.data.length === 0 ? (
                      <EmptyState>
                        No clusters registered. Registering one reserves a VIP
                        range and a DNS zone, and then in-cluster Services can
                        be reached by name over the tunnel.
                      </EmptyState>
                    ) : (
                      <>
                        {/* ⛔ THE RING IS "EXPOSED SERVICES BY CLUSTER", not "1 cluster and 3 services".
                            Two unrelated counts drawn as a ring would be a picture pretending to be a
                            proportion; this is one total split by who carries it, and the legend states every
                            number as text so the arc is never the only path to the value. */}
                        {k8sServicesRes.ok ? (
                          <Donut
                            label="Exposed Services by cluster"
                            // The endpoint the ring is drawn FROM, which is the contract VizSource exists to
                            // force: a chart names its source or it cannot be audited later.
                            source={{
                              endpoint:
                                "GET /organizations/{orgId}/k8s/clusters + /k8s/services",
                            }}
                            failed={false}
                            slices={serviceSlices(
                              assembleClusters(
                                k8sClustersRes.data,
                                k8sServicesRes.data,
                              ),
                            )}
                            centreLabel="services"
                            empty="No Services exposed yet. Exposing one allocates a VIP and gives it a name clients can reach."
                            animate={motionAllowed(reducedMotion)}
                          />
                        ) : (
                          // The services read is INDEPENDENT of the clusters read, so it has its own failure
                          // arm. A ring drawn from a failed read would be a shape asserting a proportion.
                          <p className="text-cell text-warn">
                            {k8sClustersRes.data.length} cluster
                            {k8sClustersRes.data.length === 1 ? "" : "s"}{" "}
                            registered. The Service count could not be read, so
                            no proportion is drawn.
                          </p>
                        )}
                        <Link
                          to="/kubernetes"
                          className="text-micro text-ink-tertiary underline decoration-dotted underline-offset-2 hover:text-ink-body"
                        >
                          Open Kubernetes &rarr;
                        </Link>
                      </>
                    )}
                  </Panel>

                  <Panel title="Device Posture">
                    {devicesRes === null ? (
                      <Loading />
                    ) : !devicesRes.ok ? (
                      <ErrorText>Device posture is unavailable.</ErrorText>
                    ) : (
                      (() => {
                        const ps = postureSplit(devicesRes.data);
                        const none =
                          ps.compliant + ps.blocked + ps.unknown === 0;
                        if (none)
                          return (
                            <EmptyState>No devices enrolled yet.</EmptyState>
                          );
                        return (
                          <>
                            <Donut
                              label="Device posture"
                              source={{
                                endpoint:
                                  "/api/v1/organizations/{orgId}/devices",
                              }}
                              failed={false}
                              slices={[
                                {
                                  label: "Compliant",
                                  value: ps.compliant,
                                  tone: "ok",
                                },
                                {
                                  label: "Blocked",
                                  value: ps.blocked,
                                  tone: "danger",
                                },
                                {
                                  label: "Unknown",
                                  value: ps.unknown,
                                  tone: "neutral",
                                },
                              ]}
                              centreLabel="devices"
                              empty="No devices enrolled yet."
                            />
                            {/* ⛔ THE STATE, IN WORDS — not "n/a".
                                A big "n/a" is indistinguishable from a failed load at a glance, which is the
                                exact confusion this screen exists to remove. When nothing has reported there
                                is no percentage to state (0% would claim total non-compliance, 100% the
                                opposite, and neither was measured) — so the SENTENCE says what is true. */}
                            <p className="mt-2 text-explainer leading-[1.55] text-ink-tertiary">
                              {ps.percent === null
                                ? `No device has reported posture yet, so there is no compliance rate to show. Unknown is its own state: absence is not compliance.`
                                : `${ps.percent}% of the ${ps.compliant + ps.blocked} devices that have reported are compliant. The ${ps.unknown} that have not reported are excluded — absence is not compliance.`}
                            </p>
                          </>
                        );
                      })()
                    )}
                  </Panel>

                  <Panel title="HA Hub Set">
                    {/* ⚠ THIS PANEL WAS CUT ON A WRONG MEASUREMENT. The audit checked the `Site` schema for
                        hub/generation/pin fields, found none, and declared the data absent — but the hub set
                        is its OWN endpoint and schema, and `hubsetview.ts` already projects it. An absence
                        found by looking in one place is not an absence (docs/laws.md). */}
                    {hubSetRes === null ? (
                      <Loading />
                    ) : !hubSetRes.ok ? (
                      <ErrorText>The hub set is unavailable.</ErrorText>
                    ) : (
                      (() => {
                        // Defensive: a served object without `members` must not throw the whole screen. One panel's
                        // bad shape taking the page down is a blast radius nobody chose.
                        const hv = hubSetRes.data?.members
                          ? hubSetView(hubSetRes.data, Date.now())
                          : null;
                        if (!hv)
                          return (
                            <EmptyState>
                              No HA hub set. Pin two or more gateways to create
                              one.
                            </EmptyState>
                          );
                        return (
                          <>
                            <Badge tone="neutral">GEN {hv.generation}</Badge>
                            <List label="Hub set">
                              {hv.members.map((m) => {
                                // The row carries a nodeId; the NAME lives on /nodes, so the two are joined
                                // here. An unjoinable id renders as the id rather than as a blank — an
                                // unnamed member is still a member, and hiding it would understate the set.
                                const node = nodesRes?.ok
                                  ? nodesRes.data.find((n) => n.id === m.nodeId)
                                  : undefined;
                                const memberName =
                                  node?.name ?? m.nodeId.slice(0, 8);
                                const memberRole = m.demoted
                                  ? "demoted"
                                  : m.role;
                                const memberStatus = !m.reporting
                                  ? "not reporting"
                                  : `hs ${m.handshakeAge}`;
                                const memberLabel = `${memberName} (${memberRole}): ${memberStatus}`;

                                return (
                                  <ListItem
                                    key={m.nodeId}
                                    aria-label={memberLabel}
                                  >
                                    <span className="flex items-center justify-between gap-2">
                                      <span className="truncate font-mono text-mono text-ink-primary">
                                        {memberName}
                                      </span>
                                      <span
                                        className="shrink-0 text-micro text-ink-tertiary"
                                        role="status"
                                      >
                                        {memberRole} · {memberStatus}
                                      </span>
                                    </span>
                                  </ListItem>
                                );
                              })}
                            </List>
                            <p className="mt-2 text-explainer leading-[1.55] text-ink-tertiary">
                              Pinned gateways form the hub set. members[0] is
                              the acting primary, and the generation bumps on
                              every promotion. Absent metrics are not an idle
                              link.
                            </p>
                          </>
                        );
                      })()
                    )}
                  </Panel>

                  <Panel title="Network map">
                    {/* ⚠ ALSO A RETRACTED CUT. Cut as "no SiteLink schema" — true, and beside the point:
                        `assembleTopology()` already projects sites + their gateways from data this screen
                        fetches. CATEGORY ONE, not category three: the capability exists and has no data yet,
                        so it gets an EMPTY STATE rather than absence (docs/EPIC-14, the three-way test). */}
                    {sitesRes === null || nodesRes === null ? (
                      <Loading />
                    ) : !sitesRes.ok || !nodesRes.ok ? (
                      <ErrorText>The topology is unavailable.</ErrorText>
                    ) : (
                      <NodeLink
                        label="Site topology"
                        source={{
                          endpoint: "/api/v1/organizations/{orgId}/sites",
                        }}
                        failed={false}
                        {...(() => {
                          // ⛔ THE SAME FUNCTION THE SITES SCREEN USES. This panel built its own node list
                          // inline with `links={[]}` — so Overview drew rings and NO EDGES while Sites drew
                          // the mesh, from the same data, and the two screens disagreed about what the
                          // network looks like.
                          //
                          // TWO RENDERINGS OF ONE FACT IS TWO PLACES TO BE WRONG. `meshFrom` is now the only
                          // thing that turns sites + nodes into a topology.
                          //
                          // `subnetsKnown: false` because Overview does not fetch per-site subnets: without
                          // it every node would claim "no approved subnet", which is a measurement this
                          // screen never took.
                          const m = meshFrom(
                            assembleTopology(sitesRes.data, {}, nodesRes.data),
                            nodesRes.data,
                            hubSetRes?.ok
                              ? hubSetRes.data?.generation
                              : undefined,
                            false,
                          );
                          return { nodes: m.nodes, links: m.links };
                        })()}
                        empty="No sites configured yet. Bind a gateway to a site to build the mesh."
                      />
                    )}
                  </Panel>
                </div>
              </div>
            );
          })()}
        </>
      )}
    </div>
  );
}

/**
 * A stat card — the README's composition, exactly:
 *
 *   [30px icon tile]  LABEL 500 11px
 *   VALUE 700 26px
 *   SUB-LINE 10px
 *
 * ⛔ `value` IS A STATE, NOT A NUMBER. `number` would let a caller write `data?.members ?? 0` — one keystroke,
 * typechecks, looks reasonable, and renders a confident zero for an org whose fetch failed. The three states
 * mean different things: loading (not learned yet) · failed (tried, could not learn) · ok (this is the number).
 *
 * ⛔ THE SUB-LINE IS STRUCTURAL, NOT DECORATION. In the design every card carries one and it holds the
 * QUALIFICATION — "seen in last 3 min", "3 awaiting approval". A card with a bare number states more than it
 * knows; the sub-line is where the number is told what it means.
 */
function Stat({
  label,
  icon,
  value,
  sub,
  tone,
}: {
  label: string;
  icon: IconName;
  value: StatState;
  /** The qualification. `null` when there is nothing honest to say — never filler. */
  sub?: ReactNode;
  tone?: "ok";
}) {
  const text = statText(value);
  return (
    // Composes GLASS rather than restating it — the divergence between this card and Panel is exactly what
    // produced a screenshot with glass stat cards above flat panels.
    // ⛔ role="group" + aria-label MAKES THE CARD ADDRESSABLE BY NAME.
    //
    // The e2e specs read a stat's value with `getByText('Members').locator('xpath=preceding-sibling::div[1]')`
    // — the value happened to be the div BEFORE the label. The design puts the icon+label row first and the
    // value second, so that xpath now points at nothing, and three specs failed on a layout change that was
    // asked for.
    //
    // Re-pointing the xpath would preserve the coupling. A NAMED GROUP survives any internal rearrangement,
    // which is the same fix the DataTable conversion needed and the same lesson: when adding semantics breaks
    // a query, the query was weak (docs/laws.md).
    <div
      role="group"
      aria-label={label}
      className={`${GLASS} flex flex-col gap-2 p-3.5`}
    >
      <div className="flex items-center gap-[9px]">
        <span className="flex h-[30px] w-[30px] shrink-0 items-center justify-center rounded-inset border border-white/[.2] bg-white/[.09] text-ink-emphasis">
          <Icon name={icon} size={15} />
        </span>
        <span className="text-cell font-medium text-ink-secondary">
          {label}
        </span>
      </div>
      {text === null ? (
        <span
          className="text-stat font-bold leading-none text-ink-secondary"
          title={
            value.state === "failed" ? "Could not load this count." : "Loading…"
          }
        >
          {value.state === "failed" ? "n/a" : "…"}
        </span>
      ) : (
        <span
          className={`text-stat font-bold leading-none ${tone === "ok" ? "text-ok" : "text-ink-heading"}`}
        >
          {text}
        </span>
      )}
      <span className="text-mono font-medium text-ink-tertiary">
        {value.state === "failed" ? (
          <span className="text-danger">could not load</span>
        ) : (
          sub
        )}
      </span>
    </div>
  );
}
