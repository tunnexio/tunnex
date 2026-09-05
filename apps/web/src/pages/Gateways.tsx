import "../network-workspaces.css";
import { useEffect, useMemo, useRef } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { Gateways as EnrolCeremony } from "../components/Gateways";
import {
  Button,
  Card,
  DataTable,
  EmptyState,
  Loading,
  Modal,
  PageHeader,
  StatusDot,
} from "../components/ui";
import { CeilingUpgrade, ceilingSentence } from "../components/CeilingUpgrade";
import { LoadRetry } from "../components/LoadRetry";
import { relativeAge } from "../lib/format";
import {
  gatewayEgressLabel,
  gatewayFilterCounts,
  gatewayOperationalLabel,
  toGatewayRow,
  type GatewayRow,
} from "../lib/gatewaysview";
import { useGatewayInventory } from "../lib/useGatewayInventory";

type HealthFilter = "all" | "healthy" | "degraded" | "revoked";
type SortKey = "name" | "health" | "seen" | "version";

const validFilter = (value: string | null): HealthFilter =>
  value === "healthy" || value === "degraded" || value === "revoked"
    ? value
    : "all";
const validSort = (value: string | null): SortKey =>
  value === "health" || value === "seen" || value === "version" ? value : "name";

function lifecycle(row: GatewayRow) {
  return row.operationalState;
}

function matchesHealthFilter(row: GatewayRow, filter: HealthFilter) {
  const state = lifecycle(row);
  if (filter === "all") return true;
  if (filter === "degraded") {
    return state === "degraded" || state === "awaiting_first_connection";
  }
  return state === filter;
}

export default function GatewaysPage() {
  const { org, state, reload, canEnroll } = useGatewayInventory();
  const [params, setParams] = useSearchParams();
  const q = params.get("q") ?? "";
  const filter = validFilter(params.get("health"));
  const sort = validSort(params.get("sort"));
  const dir = params.get("dir") === "desc" ? "desc" : "asc";
  const enrolling = params.get("enroll") === "1";
  const previousOrgId = useRef(org?.id);

  const setParam = (key: string, value: string, defaultValue = "") => {
    const next = new URLSearchParams(params);
    if (value === defaultValue) next.delete(key);
    else next.set(key, value);
    setParams(next);
  };

  const rows = useMemo(() => {
    if (state.kind !== "ready") return [];
    const needle = q.trim().toLowerCase();
    const result = state.nodes
      .map((node) => toGatewayRow(node, state.siteNames))
      .filter((row) => matchesHealthFilter(row, filter))
      .filter((row) =>
        needle
          ? `${row.name} ${row.siteName ?? ""} ${row.agentVersion} ${lifecycle(row)}`
              .toLowerCase()
              .includes(needle)
          : true,
      );
    const value = (row: GatewayRow): string | number => {
      if (sort === "seen") return row.lastSeenAt ? Date.parse(row.lastSeenAt) : 0;
      if (sort === "health") return lifecycle(row);
      if (sort === "version") return row.agentVersion;
      return row.name.toLowerCase();
    };
    return result.sort((a, b) => {
      const av = value(a);
      const bv = value(b);
      const compared = av < bv ? -1 : av > bv ? 1 : 0;
      return dir === "asc" ? compared : -compared;
    });
  }, [dir, filter, q, sort, state]);

  const counts = gatewayFilterCounts(state.kind === "ready" ? state.nodes : []);
  const ceilingReached =
    state.kind === "ready" &&
    state.licence?.gateway_ceiling != null &&
    state.licence.gateways_in_use != null &&
    state.licence.gateways_in_use >= state.licence.gateway_ceiling;

  useEffect(() => {
    if (state.kind !== "ready" || !enrolling || (canEnroll && !ceilingReached)) return;
    const next = new URLSearchParams(params);
    next.delete("enroll");
    setParams(next, { replace: true });
  }, [canEnroll, ceilingReached, enrolling, params, setParams, state.kind]);

  useEffect(() => {
    const previous = previousOrgId.current;
    previousOrgId.current = org?.id;
    if (!previous || !org?.id || previous === org.id || !enrolling) return;
    const next = new URLSearchParams(params);
    next.delete("enroll");
    setParams(next, { replace: true });
  }, [enrolling, org?.id, params, setParams]);

  const columns = [
    {
      key: "name",
      header: "Gateway",
      cell: (row: GatewayRow) => (
        <span className="flex flex-col gap-0.5">
          <Link className="font-medium text-ink-heading hover:text-accent-400" to={`/gateways/${row.id}`}>
            {row.name}
          </Link>
          <span className="text-micro text-ink-faint">
            {row.siteName ? `Site: ${row.siteName}` : "No site assigned"}
          </span>
        </span>
      ),
    },
    {
      key: "state",
      header: "State",
      cell: (row: GatewayRow) => {
        const status = lifecycle(row);
        return (
          <span className="inline-flex items-center gap-2 text-cell text-ink-body">
            <StatusDot
              tone={
                status === "healthy"
                  ? "on"
                  : status === "degraded"
                    ? "warn"
                    : "off"
              }
            />
            <span>{gatewayOperationalLabel(row)}</span>
          </span>
        );
      },
    },
    {
      key: "runtime",
      header: "Runtime",
      cell: (row: GatewayRow) => (
        <span className="flex flex-col gap-0.5">
          <span className="font-sans text-cell text-ink-body">
            {row.agentVersion || "Not reported"}
          </span>
          <span className="text-micro text-ink-faint" data-volatile>
            {row.lastSeenAt ? `Seen ${relativeAge(row.lastSeenAt)}` : "Never connected"}
          </span>
        </span>
      ),
    },
    {
      key: "egress",
      header: "Egress",
      cell: (row: GatewayRow) => gatewayEgressLabel(row),
    },
    {
      key: "details",
      header: "",
      cell: (row: GatewayRow) => (
        <Link
          to={`/gateways/${row.id}`}
          aria-label={`Open details for ${row.name}`}
          className="inline-flex min-h-8 items-center justify-center gap-1 rounded-md px-2 text-sm text-ink-tertiary hover:bg-white/[.06] hover:text-ink-heading focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-400"
        >
          Open <span aria-hidden="true">→</span>
        </Link>
      ),
    },
  ];

  const openEnrollment = () => setParam("enroll", "1");
  const closeEnrollment = () => setParam("enroll", "", "");

  return (
    <div className="network-management space-y-6">
      <PageHeader
        title="Gateways"
        subtitle={org?.name || "Your network infrastructure"}
        actions={
          canEnroll ? (
            <div className="network-header-actions"><Link className="network-setup-link" to="/network/setup">Set up a network →</Link><Button onClick={openEnrollment} disabled={ceilingReached}>
              Enroll gateway
            </Button></div>
          ) : undefined
        }
      />

      {state.kind === "ready" && state.licence?.gateway_ceiling != null && ceilingReached && (
        <CeilingUpgrade
          kind="gateway"
          compact
          used={state.licence.gateways_in_use ?? state.nodes.length}
          ceiling={state.licence.gateway_ceiling}
          message={ceilingSentence(
            state.licence.gateways_in_use ?? state.nodes.length,
            state.licence.gateway_ceiling,
            state.licence.tier,
          )}
        />
      )}

      {state.kind === "loading" && <Card><Loading label="Loading gateways…" /></Card>}
      {state.kind === "error" && <LoadRetry error={state.error ?? "Could not load gateways."} onRetry={reload} />}

      {state.kind === "ready" && (
        <>
          <section className="tnx-card-surface overflow-hidden">
            <div className="network-inventory-toolbar">
              <div className="flex min-w-0 flex-wrap items-center gap-2">
                <input
                  aria-label="Search gateways"
                  placeholder="Search gateway, site, version, or state"
                  value={q}
                  onChange={(event) => setParam("q", event.target.value)}
                  className="h-9 min-w-[16rem] flex-1 rounded-md border border-white/10 bg-black/25 px-3 text-cell text-ink-heading placeholder:text-ink-faint focus-visible:border-white/25 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-white/35"
                />
                <span className="ml-auto whitespace-nowrap px-1 text-micro font-medium tabular-nums text-ink-tertiary">
                  {rows.length === counts.all
                    ? `${counts.all} gateways`
                    : `${rows.length} of ${counts.all}`}
                </span>
                <label className="sr-only" htmlFor="gateway-sort">Sort gateways</label>
                <select
                  id="gateway-sort"
                  aria-label="Sort gateways"
                  value={sort}
                  onChange={(event) => setParam("sort", event.target.value, "name")}
                  className="h-9 rounded-md border border-white/10 bg-black/25 px-2.5 text-cell text-ink-body focus-visible:border-white/25 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-white/35"
                >
                  <option value="name">Name</option>
                  <option value="health">State</option>
                  <option value="seen">Freshness</option>
                  <option value="version">Agent version</option>
                </select>
                <button
                  type="button"
                  className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-white/10 text-base text-ink-secondary hover:bg-white/[.05] hover:text-ink-heading focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-400"
                  aria-label={dir === "asc" ? "Ascending" : "Descending"}
                  title={dir === "asc" ? "Sort ascending" : "Sort descending"}
                  onClick={() => setParam("dir", dir === "asc" ? "desc" : "asc", "asc")}
                >
                  <span aria-hidden="true">{dir === "asc" ? "↑" : "↓"}</span>
                </button>
              </div>

              <div
                role="group"
                aria-label="Filter gateway health"
                className="network-filter-tabs"
              >
                {(
                  [
                    ["all", "All", counts.all],
                    ["healthy", "Healthy", counts.healthy],
                    ["degraded", "Needs attention", counts.degraded],
                    ["revoked", "Revoked", counts.revoked],
                  ] as const
                ).map(([value, label, count]) => (
                  <button
                    key={value}
                    type="button"
                    aria-pressed={filter === value}
                    onClick={() => setParam("health", value, "all")}
                    className={
                      "whitespace-nowrap rounded px-3 py-1.5 text-micro font-medium transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-400 " +
                      (filter === value
                        ? "network-filter-active"
                        : "text-ink-tertiary hover:bg-white/[.05] hover:text-ink-heading")
                    }
                  >
                    {label} <span className="tabular-nums opacity-70">{count}</span>
                  </button>
                ))}
              </div>
            </div>
            <DataTable
              caption="Gateway inventory"
              rows={rows}
              rowKey={(row) => row.id}
              failed={false}
              filterable={false}
              pageSize={25}
              variant="flat"
              columns={columns}
              empty={
                <EmptyState>
                  {state.nodes.length === 0
                    ? "No gateways are enrolled. Issue a one-time command to bring the first gateway online."
                    : "No gateways match the current search and health filter."}
                </EmptyState>
              }
            />
            {state.licence && (
              <div className="border-t border-white/[.08] px-3 py-2 text-micro text-ink-faint">
                {state.licence.tier} plan · {state.licence.gateways_in_use ?? "not reported"} / {state.licence.gateway_ceiling == null ? "unlimited" : state.licence.gateway_ceiling} gateways
              </div>
            )}
          </section>
        </>
      )}

      {enrolling && org && state.kind === "ready" && canEnroll && !ceilingReached && (
        <Modal
          title="Enroll gateway"
          onDismiss={closeEnrollment}
          size="enrollment"
        >
          <p className="mb-3 text-cell text-ink-tertiary">
            Create a one-time command, then run it on the Linux host that will carry private traffic.
          </p>
          <EnrolCeremony
            org={org}
            initiallyOpen
            hideHeader
            onCancel={closeEnrollment}
            onEnrollmentAcknowledged={closeEnrollment}
          />
        </Modal>
      )}
    </div>
  );
}
