import { useCallback, useEffect, useMemo, useState } from "react";
import { useOrg } from "../lib/useOrg";
import {
  api,
  apiErrorMessage,
  loadOne,
  type Loaded,
  type Device,
  type Node,
  type Org,
  type Site,
} from "../lib/api";
import { Gateways as EnrolCeremony } from "../components/Gateways";
import { LoadRetry } from "../components/LoadRetry";
import {
  Badge,
  DataTable,
  EmptyState,
  PageHeader,
  Panel,
} from "../components/ui";
import { badgeClass } from "../lib/healthview";
import { relativeAge } from "../lib/format";
import { CeilingUpgrade, ceilingSentence } from "../components/CeilingUpgrade";
import {
  applyGatewayFilter,
  gatewayFilterCounts,
  groupGateways,
  groupNotes,
  type GatewayFilter,
  type GatewayRow,
  revokeConsequence,
  transferConsequence,
} from "../lib/gatewaysview";

// ── S14.6 — GATEWAYS, THE SECTION PASS ──────────────────────────────────────────────────────────────────
//
// Slice 1 promoted this from a component buried in Devices into a screen. This is the layout.
//
// ⛔ `Fleet risk` IS CUT (epic open) — the handoff's biggest panel here is a bubble plot of agent version ×
// peer load, and risk scoring is an unbuilt Tier-3 name. Its ruled replacement is the HEALTH-GROUPED LIST,
// which is what the left column is.
//
// ⛔ AND THREE OF THE HANDOFF TABLE'S FIVE COLUMNS HAVE NO DATA BEHIND THEM. `PEERS`, `cloud · region` and
// `egress ✓` are not fields we serve. They are absent WITH THEIR REASON on the panel grid rather than
// silently dropped — "redesign the gateway table" sounds like layout work and is actually a column-by-column
// availability audit.
//
// SCALE: one row per gateway, constant height, grouped by what is wrong. A 200-gateway fleet reads the same
// as a 5-gateway one, and the teaching text renders ONCE rather than per row.

const GROUP_LABEL: Record<string, string> = {
  degraded: "Needs attention",
  healthy: "Healthy",
  revoked: "Revoked",
};

function FilterChip({
  label,
  count,
  active,
  onClick,
}: {
  label: string;
  count: number;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={`rounded-full border px-3 py-1 text-cell ${
        active
          ? "border-white/40 bg-white/[.16] text-ink-heading"
          : "border-line text-ink-tertiary hover:text-ink-body"
      }`}
    >
      {label} ({count})
    </button>
  );
}

export default function GatewaysPage() {
  const { org: currentOrg, loading: orgLoading, failed: orgFailed } = useOrg();
  const [org, setOrg] = useState<Org | null>(null);
  const [nodes, setNodes] = useState<Node[] | null>(null);
  // Site NAMES for the gateway sub-line. NON-FATAL: a failed sites read leaves the sub-line absent rather
  // than blanking the fleet — the gateway list is this screen's subject and the site name is a courtesy.
  const [siteNames, setSiteNames] = useState<Record<string, string>>({});
  const [loadError, setLoadError] = useState<string | null>(null);
  // A SUCCESS message, separate from loadError: the transfer's outcome is not an error and must not
  // render as one, but it is the only place the re-import count is ever shown.
  const [notice, setNotice] = useState<string | null>(null);
  const [filter, setFilter] = useState<GatewayFilter>("all");

  const [lic, setLic] = useState<{
    tier: string;
    gateway_ceiling?: number | null;
  } | null>(null);

  // ⚠ TWO-STEP, NOT window.confirm — the same shape the original control used (WF-S11-9): a confirm dialog
  // in a table row is a modal over a list, and the row is the thing being acted on.
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);
  const [revoking, setRevoking] = useState(false);
  // node id -> devices homed there that would be disconnected. NULL = the count could not be read.
  const [homedCounts, setHomedCounts] = useState<Record<string, number> | null>(
    null,
  );
  // The destination an operator picked for the move, per gateway being retired. Kept beside confirmRevoke
  // rather than inside it because cancelling the revoke must forget the destination too — a stale choice
  // silently applied to the NEXT gateway is the shape of mistake this whole screen is trying to prevent.
  const [moveTarget, setMoveTarget] = useState<string>("");
  const [moving, setMoving] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  // Which gateway is being renamed, and the text in the field. Two pieces of state rather than one, because
  // an empty draft is a legitimate intermediate state (the operator cleared it to retype) and must not read
  // as "nobody is renaming anything".
  const [renaming, setRenaming] = useState<string | null>(null);
  const [renameDraft, setRenameDraft] = useState("");
  const [savingName, setSavingName] = useState(false);

  /**
   * ⛔ DELETE IS ONLY REACHABLE ON A REVOKED GATEWAY (S12.12 D2), and the sequence is what makes it safe:
   * revoke refuses while devices are homed there, so by the time a row can be deleted its devices have
   * already been moved and the cascading foreign keys have nothing left to destroy.
   */
  async function deleteGateway(nodeId: string) {
    if (!org) return;
    setDeleting(true);
    const { error } = await api.DELETE(
      "/api/v1/organizations/{orgId}/nodes/{nodeId}",
      { params: { path: { orgId: org.id, nodeId } } },
    );
    setDeleting(false);
    setConfirmDelete(null);
    if (error) {
      setLoadError(apiErrorMessage(error, "Could not delete the gateway."));
      return;
    }
    await reload();
  }

  /** D3 — the name is a label and nothing consumes it structurally, which is what makes it safe to edit. */
  async function saveName(nodeId: string) {
    if (!org) return;
    setSavingName(true);
    const { error } = await api.PATCH(
      "/api/v1/organizations/{orgId}/nodes/{nodeId}",
      {
        params: { path: { orgId: org.id, nodeId } },
        body: { name: renameDraft },
      },
    );
    setSavingName(false);
    if (error) {
      setLoadError(apiErrorMessage(error, "Could not rename the gateway."));
      return;
    }
    setRenaming(null);
    setRenameDraft("");
    await reload();
  }

  /**
   * ⛔ THE STEP THAT COMES BEFORE THE DESTRUCTIVE ONE (S12.12 D1). Revoke is refused while devices are homed
   * here, and this is the only way past it.
   *
   * ⭐ TRANSFER-FIRST MEANS NOTHING BREAKS IF THE OPERATOR WALKS AWAY. Half-done here is "devices moved, old
   * gateway still running" — harmless, and they can pick the revoke up later. The other order's half-done
   * state is a disconnected fleet and a gateway that can never come back.
   *
   * ⚠ AND THE RESULT IS REPORTED, NOT SWALLOWED. The server answers with how many configs must be
   * re-imported, which is a different number from how many rows moved — see the transfer endpoint.
   */
  async function moveDevices(fromNodeId: string) {
    if (!org || !moveTarget) return;
    setMoving(true);
    const { data, error } = await api.POST(
      "/api/v1/organizations/{orgId}/nodes/{nodeId}/transfer-devices",
      {
        params: { path: { orgId: org.id, nodeId: fromNodeId } },
        body: { target_node_id: moveTarget },
      },
    );
    setMoving(false);
    if (error) {
      setLoadError(apiErrorMessage(error, "Could not move the devices."));
      return;
    }
    setMoveTarget("");
    // ⛔ THE RE-IMPORT COUNT IS SURFACED, not left in the response. An operator who is not told that eleven
    // people must re-import will find out when eleven people cannot connect, which is the failure mode this
    // whole story exists to stop happening one layer down.
    if (data && data.needs_reissue > 0) {
      setNotice(
        `${data.moved} moved. ${data.needs_reissue} of them must re-import a new configuration before ` +
          `reconnecting \u2014 their current profile names the gateway they just left. The Devices list ` +
          `marks them.`,
      );
    } else if (data) {
      setNotice(`${data.moved} moved.`);
    }
    await reload();
  }

  /** Revoke, then reload — the row must stop looking live the moment the server says it is not. */
  async function revokeGateway(nodeId: string) {
    if (!org) return;
    setRevoking(true);
    const { error } = await api.POST(
      "/api/v1/organizations/{orgId}/nodes/{nodeId}/revoke",
      { params: { path: { orgId: org.id, nodeId } } },
    );
    setRevoking(false);
    setConfirmRevoke(null);
    if (error) {
      setLoadError(apiErrorMessage(error, "Could not revoke the gateway."));
      return;
    }
    await reload();
  }

  const reload = useCallback(async () => {
    setLoadError(null);
    // ⛔ THE ORG COMES FROM THE SEAM, NOT FROM INDEX ZERO (S12.5). This used to fetch the org list here and
    // take `[0]`, which meant a user in two organizations could reach only one of them and the switcher in
    // the header would have had nothing to switch.
    // ⛔ LOADING IS NOT ABSENCE (S12.5). See the note in Dashboard.tsx — three states, not two: still
    // loading (say nothing), the read failed (say THAT), genuinely no membership (say that).
    if (orgLoading) return;
    const first = currentOrg;
    if (!first)
      return setLoadError(
        orgFailed
          ? "Could not load your organizations."
          : "You are not a member of any organization yet.",
      );
    setOrg(first);
    const nRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/nodes", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<Node[]>;
    // ⛔ A FAILED LOAD IS NOT AN EMPTY FLEET. `[].length === 0` is how "we could not read the gateways"
    // becomes a confident "you have none", on the screen whose job is telling you what is running.
    if (!nRes.ok) return setLoadError(nRes.error);
    setNodes(nRes.data);
    // ⚠ DEPLOYMENT-SCOPED, so no orgId — the licence belongs to the box, not the tenant. A failed read
    // leaves `lic` null and the notice simply does not render: an unknown ceiling must never be guessed at.
    const lRes = await loadOne(() => api.GET("/api/v1/license"));
    if (lRes.ok)
      setLic(lRes.data as { tier: string; gateway_ceiling?: number | null });
    // ⛔ THE DEVICES HOMED TO EACH GATEWAY — read so the revoke confirm can COUNT THE PEOPLE IT
    // DISCONNECTS. Revoking cascades (`RevokeDevicesForNode`, in the same transaction as the node revoke),
    // so the act is not the tidy-up the ceiling notice made it sound like: it is a disconnection, and the
    // operator must be told the size of it at the moment they click.
    //
    // ⚠ COUNTED OVER `active` + `pending` ONLY — the two states the cascade actually sweeps
    // (devices.sql:174). Counting revoked rows here would inflate the warning with devices that already
    // cannot connect, and a warning that overstates is disbelieved the second time.
    //
    // ⚠ A FAILED READ LEAVES THE MAP NULL, NOT EMPTY. `{}` renders every gateway as "0 devices" — a silent
    // all-clear produced by a failure, on the one sentence whose whole job is to stop a destructive click.
    // Null makes the confirm say it could not count instead.
    const dRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/devices", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<Device[]>;
    setHomedCounts(
      dRes.ok
        ? dRes.data.reduce<Record<string, number>>((acc, d) => {
            if (!d.node_id) return acc;
            if (d.status !== "active" && d.status !== "pending") return acc;
            acc[d.node_id] = (acc[d.node_id] ?? 0) + 1;
            return acc;
          }, {})
        : null,
    );
    const sRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/sites", {
        params: { path: { orgId: first.id } },
      }),
    )) as Loaded<Site[]>;
    if (sRes.ok) {
      setSiteNames(Object.fromEntries(sRes.data.map((x) => [x.id, x.name])));
    }
    // ⚠ currentOrg IS A DEPENDENCY, AND THAT IS THE HALF THAT MAKES THE SWITCHER WORK. Without it the
    // page keeps rendering the org it mounted with — the control moves, the data does not, and the user is
    // looking at one tenant's screen labelled with another's name.
  }, [currentOrg, orgLoading, orgFailed]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const counts = useMemo(() => gatewayFilterCounts(nodes ?? []), [nodes]);
  const groups = useMemo(
    () => applyGatewayFilter(groupGateways(nodes ?? [], siteNames), filter),
    [nodes, filter, siteNames],
  );

  const columns = [
    {
      key: "name",
      header: "Gateway",
      // ⚠ THE SITE NAME IS SEARCHABLE THOUGH IT IS A SUB-LINE, and "HUB" is searchable though it is a badge.
      // A term an operator can SEE on the row must be a term that finds the row.
      sortValue: (r: GatewayRow) =>
        `${r.name} ${r.siteName ?? ""}${r.isHub ? " hub" : ""}`,
      cell: (r: GatewayRow) => (
        <span className="flex flex-col gap-0.5">
          <span className="flex items-center gap-2">
            {/* ⛔ D3 — THE TYPO WAS PERMANENT UNTIL NOW. Enrolment is a CLI act on the operator's own
                server, so the name it supplies was written once and never again; a gateway called
                `gw-lodnon` stayed that way for the life of the deployment.
                ⚠ EDITED IN PLACE, on a revoked row too — no. A revoked gateway is terminal and nothing
                will serve it again, so renaming one produces a tidier record of something that does not
                exist; the server refuses it and the control is not offered. */}
            {renaming === r.id ? (
              <span className="flex items-center gap-1.5">
                <input
                  value={renameDraft}
                  onChange={(e) => setRenameDraft(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") void saveName(r.id);
                    if (e.key === "Escape") setRenaming(null);
                  }}
                  aria-label={`Rename ${r.name}`}
                  className="w-40 rounded-md border border-line bg-surface-inset px-1.5 py-0.5 font-mono text-cell text-ink-body"
                />
                <button
                  type="button"
                  onClick={() => void saveName(r.id)}
                  disabled={savingName || renameDraft.trim() === ""}
                  className="text-micro font-medium text-accent hover:underline disabled:text-ink-tertiary disabled:no-underline"
                >
                  {savingName ? "Saving…" : "Save"}
                </button>
                <button
                  type="button"
                  onClick={() => setRenaming(null)}
                  className="text-micro text-ink-tertiary hover:underline"
                >
                  Cancel
                </button>
              </span>
            ) : (
              <>
                <span className="font-mono text-ink-primary">{r.name}</span>
                {r.status !== "revoked" && (
                  <button
                    type="button"
                    onClick={() => {
                      setRenaming(r.id);
                      setRenameDraft(r.name);
                    }}
                    aria-label={`Rename ${r.name}`}
                    className="text-micro text-ink-tertiary hover:text-accent hover:underline"
                  >
                    Rename
                  </button>
                )}
              </>
            )}
            {r.isHub && <Badge tone="neutral">HUB</Badge>}
          </span>
          {/* ⛔ THE SERVEABLE THIRD OF A SUB-LINE I CUT WHOLESALE. The handoff shows
              `AWS · ap-southeast-1 · site: ap-lan`; cloud and region are genuinely absent, and I took
              `site` with them. It IS served (`Node.site_id`) and it is what connects this screen to Sites. */}
          {r.siteName && (
            <span className="font-mono text-micro text-ink-faint">
              site: {r.siteName}
            </span>
          )}
        </span>
      ),
    },
    {
      key: "health",
      header: "State",
      // ⛔ THE STATE AS TEXT — the cell is a Badge, so without this a search for "revoked" finds nothing.
      sortValue: (r: GatewayRow) =>
        r.status === "revoked" ? "revoked" : (r.health?.label ?? "healthy"),
      cell: (r: GatewayRow) =>
        r.status === "revoked" ? (
          // WF-S11-10: `revoked` IS the state. No health badge beside it.
          <Badge tone="neutral">revoked</Badge>
        ) : r.health ? (
          <span className={badgeClass(r.health.tone)}>{r.health.label}</span>
        ) : (
          <Badge tone="ok">healthy</Badge>
        ),
    },
    {
      key: "agent",
      header: "Agent",
      sortValue: (r: GatewayRow) => r.agentVersion || "n/a",
      cell: (r: GatewayRow) => (
        <span className="font-mono text-micro text-ink-body">
          {r.agentVersion || "n/a"}
        </span>
      ),
    },
    {
      key: "seen",
      header: "Last seen",
      // ⚠ SORTS BY THE TIMESTAMP, SEARCHES BY THE WORDS. A never-connected gateway sorts to one end rather
      // than into the middle of a lexicographic jumble of "3h ago" / "17m ago".
      sortValue: (r: GatewayRow) =>
        r.lastSeenAt ? Date.parse(r.lastSeenAt) : 0,
      cell: (r: GatewayRow) => (
        <span className="text-micro text-ink-tertiary" data-volatile>
          {r.lastSeenAt ? relativeAge(r.lastSeenAt) : "never connected"}
        </span>
      ),
    },
    {
      key: "egress",
      header: "Egress",
      sortValue: (r: GatewayRow) => r.egressMode ?? "checking",
      cell: (r: GatewayRow) => {
        const mode = r.egressMode ?? "checking";
        const label =
          mode === "dual_stack"
            ? "Dual-stack"
            : mode === "ipv4_only"
              ? "IPv4-only"
              : "Checking";
        const title =
          mode === "dual_stack"
            ? "IPv4 and IPv6 egress verified; new full-tunnel profiles use both."
            : mode === "ipv4_only"
              ? "IPv4 egress verified; IPv6 is blocked for full-tunnel profiles."
              : "Waiting for the gateway to report verified egress capability.";
        return (
          <span
            title={title}
            className={`text-micro ${
              mode === "dual_stack"
                ? "text-ok"
                : mode === "ipv4_only"
                  ? "text-accent"
                  : "text-ink-tertiary"
            }`}
          >
            {label}
          </span>
        );
      },
    },
    {
      key: "actions",
      header: "",
      sortValue: () => "",
      /**
       * ⛔ REVOKE, ON EVERY TABLE — AND ITS ABSENCE IS THE DEFECT THIS COLUMN EXISTS FOR.
       *
       * The control has existed since S11 (`POST /nodes/{nodeId}/revoke`, two-step confirm) inside
       * `EnrolCeremony`'s own list. This page passes `renderList={false}` because it owns the list — so the
       * action went off with the list, and the tables that replaced it never grew one. Nothing went red:
       * the component still exists and its own tests still pass.
       *
       * ⛔ AND IT IS ON THE HEALTHY TABLE TOO, WHICH IS THE CASE THAT WAS BROKEN. A healthy-but-unused
       * gateway is exactly the one an operator retires to free a licence slot — the ceiling notice says
       * "revoke a gateway you no longer use", and revoking genuinely frees a slot (`CountLiveNodes` counts
       * `revoked_at IS NULL`). The remedy was true and the button was missing.
       *
       * ⚠ Already-revoked rows get no button: `revoked` is terminal here, and there is no un-revoke.
       */
      cell: (r: GatewayRow) => {
        // The gateways this one's devices could move to: live, and not itself. Computed from the SAME rows
        // the table renders, so a destination an operator can pick is a destination they can see.
        const destinations = groups
          .flatMap((g) => g.rows)
          .filter((d) => d.id !== r.id && d.status === "active");
        const homed = homedCounts === null ? null : (homedCounts[r.id] ?? 0);
        const chosen = destinations.find((d) => d.id === moveTarget) ?? null;
        // ⛔ CROSS-SITE IS A POLICY CHANGE (D5), so it is computed from what BOTH ends are bound to. Unknown
        // on either side reads as same-site: claiming a policy change that may not happen would train
        // operators to dismiss the sentence that matters when it does.
        const crossSite =
          !!chosen && !!r.siteId && !!chosen.siteId && chosen.siteId !== r.siteId;
        return r.status === "revoked" ? (
          confirmDelete === r.id ? (
            <span className="flex flex-col items-end gap-1">
              {/* ⛔ WHAT A DELETE TAKES WITH IT, INCLUDING THE PART NOBODY EXPECTS. The enrolment token that
                  produced this gateway is deleted with it (D2) — it would otherwise survive unlinked and
                  still enrol one. Someone may be holding it: it can be in a colleague's terminal history,
                  about to be run, and they will get a refusal with no explanation unless this said so. */}
              <span className="max-w-[19rem] text-right text-micro text-warn">
                This removes the gateway permanently, along with its enrolment token — if anyone still holds
                that token, it stops working.
              </span>
              <span className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => void deleteGateway(r.id)}
                  disabled={deleting}
                  className="text-micro font-medium text-danger hover:underline"
                >
                  {deleting ? "Deleting…" : "Confirm"}
                </button>
                <button
                  type="button"
                  onClick={() => setConfirmDelete(null)}
                  className="text-micro text-ink-tertiary hover:underline"
                >
                  Cancel
                </button>
              </span>
            </span>
          ) : (
            /* ⚠ THE ROW USED TO END HERE WITH NO ACTION AT ALL. A revoked gateway is terminal, so its row
               stayed on the list forever and a deployment silently accumulated dead entries nobody could
               clear — the same shape as the missing Revoke button one story earlier. */
            <button
              type="button"
              onClick={() => setConfirmDelete(r.id)}
              className="text-micro text-ink-tertiary hover:text-danger hover:underline"
            >
              Delete
            </button>
          )
        ) : confirmRevoke === r.id ? (
          <span className="flex flex-col items-end gap-1">
            {/* ⛔ THE COST OF THE ACT, AT THE MOMENT OF THE ACT. Revoking cascades to every device homed
                here, so this is a disconnection, not a tidy-up — and the operator reaching for it is
                usually reaching for a licence slot, which is the worst moment to be surprised.
                ⚠ SILENT WHEN THERE ARE NONE — same shape as the deactivate warning: a caution that fires
                on the harmless case teaches people to click through the dangerous one. */}
            <span className="max-w-[19rem] text-right text-micro text-warn">
              {revokeConsequence(homedCounts, r.id)}
            </span>
            {/* ⛔ THE MOVE, IN PLACE, WHEN THERE IS SOMETHING TO MOVE. The server refuses the revoke while
                devices are homed here, so a Confirm button in this state is a button whose only outcome is
                a 409 — and a control that exists only to fail teaches an operator that the screen is
                broken rather than that the order is deliberate.
                ⚠ SHOWN WHEN THE COUNT IS UNKNOWN TOO. A failed read must not hide the step: the operator
                can still move devices, and the alternative is a Confirm that may be refused for a reason
                the screen chose not to mention. */}
            {homed !== 0 && destinations.length > 0 && (
              <span className="flex flex-col items-end gap-1">
                <span className="flex items-center gap-2">
                  <label
                    htmlFor={`move-${r.id}`}
                    className="text-micro text-ink-tertiary"
                  >
                    Move to
                  </label>
                  <select
                    id={`move-${r.id}`}
                    value={moveTarget}
                    onChange={(e) => setMoveTarget(e.target.value)}
                    className="rounded-input border border-line bg-surface-inset px-1.5 py-0.5 text-micro"
                  >
                    <option value="">Choose a gateway…</option>
                    {destinations.map((d) => (
                      <option key={d.id} value={d.id}>
                        {d.name}
                        {d.siteName ? ` (${d.siteName})` : ""}
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    onClick={() => void moveDevices(r.id)}
                    disabled={moving || !moveTarget}
                    className="text-micro font-medium text-accent hover:underline disabled:text-ink-tertiary disabled:no-underline"
                  >
                    {moving ? "Moving…" : "Move devices"}
                  </button>
                </span>
                {/* The cost of the MOVE, stated once a destination exists to state it about — including
                    the cross-site policy consequence, which is the clause that turns a maintenance step
                    into an access change (D5). */}
                {chosen && homed !== null && homed > 0 && (
                  <span className="max-w-[19rem] text-right text-micro text-ink-tertiary">
                    {transferConsequence(homed, crossSite)}
                  </span>
                )}
              </span>
            )}
            {/* ⚠ NO DESTINATION EXISTS AND DEVICES ARE HOMED HERE — the one dead end this screen can
                actually reach, so it is named rather than left as a disabled control with no explanation.
                Enrolling a gateway is a CLI act on the operator's own server, which is why the sentence
                points at that rather than at a button. */}
            {homed !== null && homed > 0 && destinations.length === 0 && (
              <span className="max-w-[19rem] text-right text-micro text-ink-tertiary">
                There is no other live gateway to move them to. Enrol one first — this gateway cannot
                be retired while anyone is homed to it.
              </span>
            )}
            <span className="flex items-center gap-2">
            {/* ⛔ CONFIRM IS OFFERED ONLY WHEN THE COUNT IS KNOWN TO BE ZERO. Anything else is a click the
                server will refuse. */}
            {homed === 0 && (
              <button
                type="button"
                onClick={() => void revokeGateway(r.id)}
                disabled={revoking}
                className="text-micro font-medium text-danger hover:underline"
              >
                {revoking ? "Revoking…" : "Confirm"}
              </button>
            )}
            <button
              type="button"
              onClick={() => {
                setConfirmRevoke(null);
                setMoveTarget("");
              }}
              className="text-micro text-ink-tertiary hover:underline"
            >
              Cancel
            </button>
            </span>
          </span>
        ) : (
          <button
            type="button"
            onClick={() => {
              setConfirmRevoke(r.id);
              setMoveTarget("");
            }}
            className="text-micro text-ink-tertiary hover:text-danger hover:underline"
          >
            Revoke
          </button>
        );
      },
    },
  ];

  return (
    <div className="flex flex-col gap-3.5">
      <PageHeader title="Gateways" subtitle={org ? org.name : "…"} />

      {/* ⛔ THE STANDING CEILING NOTICE. Shown whenever used >= ceiling, with NO refusal behind it.
          Gateways enrol by CLI/API — the 403 lands in a terminal on the customer's own server — so an
          operator about to add one must learn there is no room HERE, before they go and try. */}
      {lic &&
        nodes &&
        lic.gateway_ceiling != null &&
        nodes.length >= lic.gateway_ceiling && (
          <CeilingUpgrade
            kind="gateway"
            message={ceilingSentence(
              nodes.length,
              lic.gateway_ceiling,
              lic.tier,
            )}
          />
        )}

      {loadError && <LoadRetry error={loadError} onRetry={reload} />}
      {/* ⛔ THE MOVE'S OUTCOME, AND IT IS NOT AN ERROR. It carries the only number that says how many people
          must act — how many configs are now stale — which the row count never could. Rendered above the
          table because the rows it describes have just been re-drawn underneath it. */}
      {notice && (
        <div className="rounded-card border border-hairline bg-surface-inset p-3">
          <p className="text-cell text-ink-body">{notice}</p>
          <button
            type="button"
            onClick={() => setNotice(null)}
            className="mt-1.5 text-micro text-ink-tertiary hover:underline"
          >
            Dismiss
          </button>
        </div>
      )}
      {!loadError && (org === null || nodes === null) && (
        <p className="text-cell text-ink-faint">Loading…</p>
      )}

      {!loadError && org && nodes && (
        <>
          {/* The handoff's chips: All / Healthy / Degraded, counts derived from the SAME grouping the table
              renders below, so the two can never disagree. */}
          <div className="flex flex-wrap items-center gap-2">
            <FilterChip
              label="All"
              count={counts.all}
              active={filter === "all"}
              onClick={() => setFilter("all")}
            />
            <FilterChip
              label="Healthy"
              count={counts.healthy}
              active={filter === "healthy"}
              onClick={() => setFilter("healthy")}
            />
            <FilterChip
              label="Needs attention"
              count={counts.degraded}
              active={filter === "degraded"}
              onClick={() => setFilter("degraded")}
            />
            {counts.revoked > 0 && (
              // Stated rather than left to arithmetic: `All` includes revoked and the other two do not, so
              // healthy + degraded < all, which reads as a bug unless the screen says why.
              <span className="text-micro text-ink-faint">
                {counts.revoked} revoked, shown under All
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 items-start gap-3 lg:grid-cols-[8fr_4fr]">
            <div className="flex min-w-0 flex-col gap-3">
              {groups.map((g) => (
                <Panel
                  key={g.key}
                  title={`${GROUP_LABEL[g.key]} (${g.rows.length})`}
                >
                  <DataTable
                    caption={`${GROUP_LABEL[g.key]} gateways`}
                    columns={columns}
                    rows={g.rows}
                    rowKey={(r: GatewayRow) => r.id}
                    empty={
                      g.key === "degraded"
                        ? "Nothing needs attention."
                        : g.key === "revoked"
                          ? "No revoked gateways."
                          : "No healthy gateways."
                    }
                    // The page blanks to a retry on any failed load, so reaching this render means the
                    // read succeeded.
                    failed={false}
                  />
                  {/* ⛔ THE NOTES — the epic's KEEP list, rendered ONCE PER GROUP rather than per row.
                      The badge names the state; these say what it MEANS. They are a property of the health
                      KIND, so four `site link down` rows would otherwise carry four copies of one sentence. */}
                  {groupNotes(g.rows).map((n) => (
                    <p key={n} className="text-micro text-ink-tertiary">
                      {n}
                    </p>
                  ))}
                </Panel>
              ))}

              {/* ⛔ THE COLUMNS THAT ARE NOT HERE, AND WHY — once, at the panel, not per row.
                  Absence recorded is a decision; absence unrecorded gets re-proposed at the next review. */}
              <p className="text-micro text-ink-faint">
                Not shown, and why: <strong>peers</strong> is its own slice (a
                hub&rsquo;s WireGuard peers include site links, so counting
                devices would under-report on exactly the gateway you are
                looking at hardest). <strong>Cloud and region</strong> are not
                fields we serve, nor is <strong>egress capability</strong>. The{" "}
                <strong>subtitle</strong> the design carries here is held behind
                a separate ruling on where control-plane health is stated, since
                the page header would be its third appearance.
              </p>
            </div>

            <div className="flex min-w-0 flex-col gap-3">
              {/* The enrolment ceremony, with its one-time join token. The list is suppressed because this
                  page owns it above. */}
              <EnrolCeremony
                org={org}
                nodes={nodes}
                onNodesChanged={reload}
                renderList={false}
              />

              {/* ⛔ CONDITIONAL ON OPT-IN, not six `n/a` cells. The per-row column was dropped with this:
                  an org that never opted in has no service to report, and the same four values belong in ONE
                  place rather than repeated per gateway. Below the threshold the panel names the precondition
                  instead of offering the surface. */}
              <Panel title="OpenVPN service">
                {!org.ovpn_enabled ? (
                  <EmptyState>
                    This organization has not opted into OpenVPN, so there is no
                    service to report. Enable it in Org Settings.
                  </EmptyState>
                ) : nodes.filter((n) => n.ovpn_health).length === 0 ? (
                  <EmptyState>
                    Every OpenVPN-enabled gateway is serving.
                  </EmptyState>
                ) : (
                  <ul className="flex flex-col gap-1.5">
                    {nodes
                      .filter((n) => n.ovpn_health)
                      .map((n) => (
                        <li
                          key={n.id}
                          className="flex items-center justify-between gap-2 rounded-lg border border-line bg-ink-800 px-2.5 py-2"
                        >
                          <span className="font-mono text-cell text-ink-body">
                            {n.name}
                          </span>
                          <Badge tone="warn">
                            {String(n.ovpn_health).replace(/^ovpn_/, "")}
                          </Badge>
                        </li>
                      ))}
                  </ul>
                )}
                <p className="text-micro text-ink-faint">
                  A separate axis from policy health. An opted-in gateway that
                  is not serving says why rather than reading green.
                </p>
              </Panel>

              <Panel title="Deployment requirement">
                {/* Carried VERBATIM from the handoff. It is the honest NAT-traversal statement the epic's
                    KEEP list specifically protects, and softening it would be the reassuring-copy defect. */}
                <p className="text-cell text-ink-body">
                  Gateways need public reachability or a port-forward. Tunnex
                  ships no relay fleet.
                </p>
                <p className="text-micro text-ink-faint">
                  A gateway behind NAT with no forwarded port can still reach
                  the control plane, but peers cannot dial it, so it cannot
                  carry site transit.
                </p>
              </Panel>
            </div>
          </div>
        </>
      )}

      {!loadError && org && nodes && nodes.length === 0 && (
        <EmptyState>
          No gateways enrolled yet. Use the enrolment panel to add the first
          one.
        </EmptyState>
      )}
    </div>
  );
}
