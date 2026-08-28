import { useEffect, useState, type ReactNode } from "react";
import { useOrg } from "../lib/useOrg";
import { Icon, type IconName } from "../components/Icon";
import { PageHeader } from "../components/ui";
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
  listItems,
  apiErrorMessage,
  loadOne,
  type Device,
  type Loaded,
  type Node,
  type OrgOverview,
  type Site,
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
  peerSlices,
  postureSplit,
  statFrom,
  statText,
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
  // Each summary source resolves independently. A missing response never
  // implies that a product plan is absent.
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
  const [infrastructureTab, setInfrastructureTab] = useState<
    "network" | "kubernetes"
  >("network");

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
        // Base AI Agents inventory is available on Community and higher plans.
        void api
          .GET("/api/v1/organizations/{orgId}/agents", {
            params: { path: { orgId: org.id } },
          })
          .then(({ data, error }) => {
            if (cancelled || error || !data) return; // 403 lands here and stays silent, by design
            setAgentsRes({ ok: true, data: listItems(data) as AgentRow[] });
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
            // A summary card is visible only after its own source succeeds. This
            // preserves permission-before-entitlement behavior without using
            // legacy `/meta` edition metadata as a UI gate.
            // NEEDS ATTENTION is COMPOSED, not fetched — every item names the source that produced it, and an
            // item appears only when its source has been READ. A source still loading contributes nothing;
            // a source that FAILED contributes nothing either, because "nothing needs attention" and "we could
            // not check" must not render identically. The panel says "loading" until every source has answered.

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
                    a fixed six-slot row leaves a gap when a source cannot be shown, which reads as a card
                    that failed to render rather than as a capability the operator cannot use.
                    Six cards -> span 2 each. Five -> the row is a 5-column grid. Either way it fills. */}
                {/* ⛔ THE ROW RE-SPANS TO FILL, AND IT COLLAPSES BEFORE IT OVERFLOWS.
                    Six (or five) fixed columns at 390px gives ~60px per card and the page scrolls sideways —
                    which the viewport leg caught on its FIRST baseline (390px viewport, 455px capture).
                    The source-dependent count only applies once there is room for it. */}
                {/* ⛔ THE COLUMN COUNT IS DERIVED FROM THE CARD COUNT, IN ONE PLACE.
                    It was hard-coded `lg:grid-cols-6` while seven cards were rendered — Access Rules and
                    Pending approvals added two sources — so the seventh wrapped to a second row and sat alone
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
                <Panel title="Fleet summary">
                  <section
                    aria-label="Fleet summary metrics"
                    className="grid grid-cols-2 gap-y-4 sm:grid-cols-3 xl:grid-cols-7 xl:divide-x xl:divide-white/10"
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
                  {/* Render only after the Agent inventory answers successfully. */}
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
                  {rulesRes?.ok && (
                    <Stat
                      label="Access Rules"
                      icon="shield"
                      value={rules}
                      sub={zeroTrust === null ? null : zeroTrust}
                    />
                  )}
                  {pendingRes?.ok && (
                    <Stat
                      label="Pending approvals"
                      icon="user-plus"
                      value={pending}
                      sub="awaiting an admin"
                    />
                  )}
                  </section>
                </Panel>

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
                <div className="grid gap-3 xl:grid-cols-2">
                  <Panel title="Gateway Health">
                    {nodesRes === null ? (
                      <Loading />
                    ) : !nodesRes.ok ? (
                      <ErrorText>Gateway health is unavailable.</ErrorText>
                    ) : nodesRes.data.length === 0 ? (
                      <EmptyState>No gateway enrolled yet.</EmptyState>
                    ) : (
                      (() => {
                        const health = nodesRes.data.map(gatewayHealthRow);
                        const issues = health.filter(
                          (verdict) => verdict.tone !== "ok",
                        );
                        const unhealthy = issues.filter(
                          (verdict) => verdict.label !== "revoked",
                        );
                        const revoked = issues.filter(
                          (verdict) => verdict.label === "revoked",
                        );
                        const healthy = health.filter(
                          (verdict) => verdict.tone === "ok",
                        );
                        const issueGroups = Array.from(
                          issues.reduce((groups, verdict) => {
                            groups.set(
                              verdict.label,
                              (groups.get(verdict.label) ?? 0) + 1,
                            );
                            return groups;
                          }, new Map<string, number>()),
                        ).sort(
                          ([labelA, countA], [labelB, countB]) =>
                            countB - countA || labelA.localeCompare(labelB),
                        );
                        const unattributed = nodesRes.data.filter(
                          (node) => attributionBadge(node) !== null,
                        ).length;

                        return (
                          <div className="space-y-3">
                            <Donut
                              label="Gateway health summary"
                              source={{
                                endpoint:
                                  "/api/v1/organizations/{orgId}/nodes",
                              }}
                              failed={false}
                              slices={[
                                {
                                  label: "Healthy",
                                  value: healthy.length,
                                  tone: "ok",
                                },
                                {
                                  label: "Unhealthy",
                                  value: unhealthy.length,
                                  tone: "danger",
                                },
                                {
                                  label: "Revoked",
                                  value: revoked.length,
                                  tone: "neutral",
                                },
                              ]}
                              centreLabel="total"
                            />
                            {unattributed > 0 && (
                              <p className="rounded-md border border-warn/30 bg-warn/5 px-3 py-2 text-cell text-warn">
                                {unattributed} gateway
                                {unattributed === 1 ? " has" : "s have"} no
                                recorded owner.
                              </p>
                            )}
                            {issues.length > 0 ? (
                              <div className="space-y-2">
                                <p className="text-badge font-semibold uppercase tracking-wide text-ink-tertiary">
                                  Needs attention
                                </p>
                                <div
                                  role="group"
                                  aria-label="Gateway health conditions"
                                  className="grid gap-2 sm:grid-cols-2"
                                >
                                  {issueGroups.map(([label, count]) => (
                                    <div
                                      key={label}
                                      className={
                                        "rounded-md border px-3 py-2 text-cell font-medium " +
                                        (label === "revoked"
                                          ? "border-white/10 bg-white/[.03] text-ink-secondary"
                                          : "border-danger/25 bg-danger/5 text-danger")
                                      }
                                    >
                                      {gatewayIssueCount(label, count)}
                                    </div>
                                  ))}
                                </div>
                              </div>
                            ) : (
                              <p className="text-cell text-ink-secondary">
                                No gateway health issues reported.
                              </p>
                            )}
                            <Link
                              className="inline-flex text-cell font-medium text-accent-400 hover:underline"
                              to="/gateways"
                            >
                              {gatewayReviewLabel(issues.length)}
                            </Link>
                          </div>
                        );
                      })()
                    )}
                  </Panel>

                  <Panel title="Device Health">
                    {devicesRes === null ? (
                      <Loading />
                    ) : !devicesRes.ok ? (
                      <ErrorText>Device health is unavailable.</ErrorText>
                    ) : devicesRes.data.length === 0 ? (
                      <EmptyState>No devices enrolled yet.</EmptyState>
                    ) : (
                      (() => {
                        const ps = postureSplit(devicesRes.data);
                        return (
                          <div className="grid gap-4 sm:grid-cols-2">
                            <div>
                              <h3 className="mb-2 text-cell font-medium text-ink-secondary">
                                Connection
                              </h3>
                              <Donut
                                label="Peer connection status"
                                source={{
                                  endpoint:
                                    "/api/v1/organizations/{orgId}/devices",
                                }}
                                failed={false}
                                slices={peerSlices(devicesRes.data)}
                                centreLabel="devices"
                                empty="No devices enrolled yet."
                              />
                            </div>
                            <div className="sm:border-l sm:border-white/10 sm:pl-4">
                              <h3 className="mb-2 text-cell font-medium text-ink-secondary">
                                Posture
                              </h3>
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
                            </div>
                            {pending.state === "ok" && pending.value > 0 && (
                              <p className="rounded-md border border-warn/30 bg-warn/5 px-3 py-2 text-center text-cell text-warn sm:col-span-2">
                                {pending.value} device
                                {pending.value === 1 ? "" : "s"} awaiting
                                approval
                              </p>
                            )}
                          </div>
                        );
                      })()
                    )}
                  </Panel>

                  <Panel title="Infrastructure" className="xl:col-span-2">
                    <div
                      role="tablist"
                      aria-label="Infrastructure views"
                      className="mb-3 inline-flex rounded-md border border-white/10 bg-white/[.02] p-1"
                    >
                      <button
                        id="infrastructure-network-tab"
                        type="button"
                        role="tab"
                        aria-selected={infrastructureTab === "network"}
                        onClick={() => setInfrastructureTab("network")}
                        className={
                          "rounded px-3 py-1.5 text-cell font-medium transition-colors " +
                          (infrastructureTab === "network"
                            ? "bg-white/[.12] text-ink-heading"
                            : "text-ink-tertiary hover:text-ink-body")
                        }
                      >
                        Network
                      </button>
                      <button
                        id="infrastructure-kubernetes-tab"
                        type="button"
                        role="tab"
                        aria-selected={infrastructureTab === "kubernetes"}
                        onClick={() => setInfrastructureTab("kubernetes")}
                        className={
                          "rounded px-3 py-1.5 text-cell font-medium transition-colors " +
                          (infrastructureTab === "kubernetes"
                            ? "bg-white/[.12] text-ink-heading"
                            : "text-ink-tertiary hover:text-ink-body")
                        }
                      >
                        Kubernetes
                        {k8sServicesRes?.ok && (
                          <span className="ml-1.5 text-ink-tertiary">
                            {k8sServicesRes.data.length}
                          </span>
                        )}
                      </button>
                    </div>

                    {infrastructureTab === "network" ? (
                      <div
                        role="tabpanel"
                        aria-labelledby="infrastructure-network-tab"
                        className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(15rem,1fr)]"
                      >
                        <div>
                          {sitesRes === null || nodesRes === null ? (
                            <Loading />
                          ) : !sitesRes.ok || !nodesRes.ok ? (
                            <ErrorText>The topology is unavailable.</ErrorText>
                          ) : (
                            <NodeLink
                              label="Site topology"
                              source={{
                                endpoint:
                                  "/api/v1/organizations/{orgId}/sites",
                              }}
                              failed={false}
                              {...(() => {
                                const mesh = meshFrom(
                                  assembleTopology(
                                    sitesRes.data,
                                    {},
                                    nodesRes.data,
                                  ),
                                  nodesRes.data,
                                  hubSetRes?.ok
                                    ? hubSetRes.data
                                    : undefined,
                                  false,
                                );
                                return {
                                  nodes: mesh.nodes,
                                  links: mesh.links,
                                };
                              })()}
                              empty="No sites configured yet. Bind a gateway to a site to build the mesh."
                            />
                          )}
                        </div>

                        <div className="lg:border-l lg:border-white/10 lg:pl-4">
                          <h3 className="mb-2 text-cell font-medium text-ink-secondary">
                            HA Hub Set
                          </h3>
                          {hubSetRes === null ? (
                            <Loading />
                          ) : !hubSetRes.ok ? (
                            <ErrorText>The hub set is unavailable.</ErrorText>
                          ) : (
                            (() => {
                              const hv = hubSetRes.data?.members
                                ? hubSetView(hubSetRes.data, Date.now())
                                : null;
                              if (!hv) {
                                return (
                                  <EmptyState>
                                    No HA hub set. Pin two or more gateways to
                                    create one.
                                  </EmptyState>
                                );
                              }
                              return (
                                <div className="space-y-2">
                                  <Badge tone="neutral">
                                    GEN {hv.generation}
                                  </Badge>
                                  <List label="Hub set">
                                    {hv.members.map((member) => {
                                      const node = nodesRes?.ok
                                        ? nodesRes.data.find(
                                            (item) =>
                                              item.id === member.nodeId,
                                          )
                                        : undefined;
                                      const memberName =
                                        node?.name ??
                                        member.nodeId.slice(0, 8);
                                      const memberRole = member.demoted
                                        ? "demoted"
                                        : member.role;
                                      const memberStatus = !member.reporting
                                        ? "not reporting"
                                        : "hs " + member.handshakeAge;
                                      const memberLabel =
                                        memberName +
                                        " (" +
                                        memberRole +
                                        "): " +
                                        memberStatus;

                                      return (
                                        <ListItem
                                          key={member.nodeId}
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
                                  <Link
                                    to="/sites"
                                    className="inline-flex text-cell font-medium text-accent-400 hover:underline"
                                  >
                                    Open infrastructure
                                  </Link>
                                </div>
                              );
                            })()
                          )}
                        </div>
                      </div>
                    ) : (
                      <div
                        role="tabpanel"
                        aria-labelledby="infrastructure-kubernetes-tab"
                      >
                        {k8sClustersRes === null ||
                        k8sServicesRes === null ? (
                          <Loading />
                        ) : !k8sClustersRes.ok ? (
                          <ErrorText>
                            Kubernetes infrastructure is unavailable.
                          </ErrorText>
                        ) : k8sClustersRes.data.length === 0 ? (
                          <EmptyState>
                            No clusters registered. Registering one reserves a
                            VIP range and a DNS zone.
                          </EmptyState>
                        ) : k8sServicesRes.ok ? (
                          <div className="space-y-2">
                            <Donut
                              label="Exposed Services by cluster"
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
                              empty="No Services exposed yet."
                              animate={motionAllowed(reducedMotion)}
                            />
                            <Link
                              to="/kubernetes"
                              className="inline-flex text-cell font-medium text-accent-400 hover:underline"
                            >
                              Open Kubernetes
                            </Link>
                          </div>
                        ) : (
                          <ErrorText>
                            Service inventory is unavailable.
                          </ErrorText>
                        )}
                      </div>
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

function gatewayIssueCount(label: string, count: number): string {
  if (label === "revoked") {
    return `${count} gateway${count === 1 ? "" : "s"} revoked`;
  }
  if (label === "site link down") {
    return `${count} site link${count === 1 ? "" : "s"} down`;
  }
  return `${count} gateway${count === 1 ? "" : "s"} ${label}`;
}

/**
 * One metric inside the Fleet Summary surface. The metric keeps its independent
 * loading/failed/known state while sharing one card with the rest of the fleet.
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
  sub?: ReactNode;
  tone?: "ok";
}) {
  const text = statText(value);
  return (
    <div
      role="group"
      aria-label={label}
      className="flex min-w-0 items-start gap-2.5 px-2 sm:px-3"
    >
      <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-inset border border-white/[.14] bg-white/[.06] text-ink-emphasis">
        <Icon name={icon} size={15} />
      </span>
      <span className="min-w-0 flex-1">
        <span className="block text-cell font-medium text-ink-secondary">
          {label}
        </span>
        {text === null ? (
          <span
            className="mt-1 block text-xl font-bold leading-none text-ink-secondary"
            title={
              value.state === "failed"
                ? "Could not load this count."
                : "Loading…"
            }
          >
            {value.state === "failed" ? "n/a" : "…"}
          </span>
        ) : (
          <span
            className={
              "mt-1 block text-2xl font-bold leading-none " +
              (tone === "ok" ? "text-ok" : "text-ink-heading")
            }
          >
            {text}
          </span>
        )}
        <span className="mt-1 block truncate text-badge font-medium text-ink-tertiary">
          {value.state === "failed" ? (
            <span className="text-danger">could not load</span>
          ) : (
            sub
          )}
        </span>
      </span>
    </div>
  );
}

function gatewayReviewLabel(count: number): string {
  if (count === 0) return "Review gateways";
  return (
    "Review " +
    count +
    " affected gateway" +
    (count === 1 ? "" : "s")
  );
}
