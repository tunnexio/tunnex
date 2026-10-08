import "../network-workspaces.css";
import "../app-access-workspace.css";
import "../gateway-workspace.css";
import { useEffect, useMemo, useRef } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { Gateways as EnrolCeremony } from "../components/Gateways";
import AppAccessEmptyState from "../components/AppAccessEmptyState";
import AppAccessPagination, { appAccessPageSize } from "../components/AppAccessPagination";
import AppAccessRowMenu from "../components/AppAccessRowMenu";
import { Icon } from "../components/Icon";
import { Button, DataTable, Loading, Modal, PageHeader, StatusDot, RefreshButton } from "../components/ui";
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
  const pageSize = appAccessPageSize(params.get("page_size"));
  const requestedPage = Number(params.get("page") ?? "1");
  const previousOrgId = useRef(org?.id);

  const setParam = (key: string, value: string, defaultValue = "") => {
    const next = new URLSearchParams(params);
    if (value === defaultValue) next.delete(key);
    else next.set(key, value);
    if (["q", "health", "sort", "dir", "page_size"].includes(key)) next.delete("page");
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
          ? `${row.name} ${row.siteName ?? ""} ${row.endpoint ?? ""} ${row.agentVersion} ${lifecycle(row)}`
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

  const page = Math.min(
    Number.isSafeInteger(requestedPage) && requestedPage > 0 ? requestedPage : 1,
    Math.max(1, Math.ceil(rows.length / pageSize)),
  );
  const pageRows = rows.slice((page - 1) * pageSize, page * pageSize);

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
        <div className="gw-gateway-name">
          <div>
            <Link className="gw-name-link" to={`/gateways/${row.id}`}>{row.name}</Link>
            <span className="gw-secondary">{row.siteName ?? "No site assigned"}</span>
          </div>
        </div>
      ),
    },
    {
      key: "address",
      header: "IP / hostname",
      cell: (row: GatewayRow) => (
        <div>
          <span className="gw-address">{row.address ?? "Not reported"}</span>
          {row.address && row.status === "revoked" && <span className="gw-secondary">Last reported address</span>}
        </div>
      ),
    },
    {
      key: "state",
      header: "State",
      cell: (row: GatewayRow) => {
        const status = lifecycle(row);
        return <span className="gw-status"><StatusDot tone={status === "healthy" ? "on" : status === "degraded" ? "warn" : "off"} /><span>{gatewayOperationalLabel(row)}</span></span>;
      },
    },
    {
      key: "runtime",
      header: "Agent",
      cell: (row: GatewayRow) => (
        <div><span>{row.agentVersion || "Not reported"}</span><span className="gw-secondary" data-volatile>{row.lastSeenAt ? `Seen ${relativeAge(row.lastSeenAt)}` : "Never connected"}</span></div>
      ),
    },
    { key: "egress", header: "Egress", cell: (row: GatewayRow) => gatewayEgressLabel(row) },
    {
      key: "actions",
      header: "Actions",
      cell: (row: GatewayRow) => <AppAccessRowMenu label={`Actions for ${row.name}`} actions={[
        { key: "overview", label: "Overview", href: `/gateways/${row.id}` },
        { key: "health", label: "Health", href: `/gateways/${row.id}?tab=health` },
        { key: "lifecycle", label: "Lifecycle", href: `/gateways/${row.id}?tab=lifecycle` },
      ]} />,
    },
  ];

  const openEnrollment = () => setParam("enroll", "1");
  const closeEnrollment = () => setParam("enroll", "", "");
  const clearFilters = () => {
    const next = new URLSearchParams(params);
    next.delete("q");
    next.delete("health");
    next.delete("page");
    setParams(next);
  };

  return (
    <div className="gateway-workspace gw-inventory-workspace network-management">
      <PageHeader navigationTitle title="Gateways" />
      <div className="gw-topbar">
        {state.kind === "ready" && <div role="group" aria-label="Filter gateway health" className="gw-filter-tabs">
          {([
            ["all", "All", counts.all],
            ["healthy", "Healthy", counts.healthy],
            ["degraded", "Needs attention", counts.degraded],
            ["revoked", "Revoked", counts.revoked],
          ] as const).map(([value, label, count]) => <button key={value} type="button" aria-pressed={filter === value} onClick={() => setParam("health", value, "all")}>
            {label}<span>{count}</span>
          </button>)}
        </div>}
        <div className="gw-topbar-actions">
          {canEnroll && <Link className="gw-setup-link" to="/network/setup">Set up a network</Link>}
          <RefreshButton label="Refresh gateways" disabled={state.kind === "loading"} onClick={() => void reload()} />
          {canEnroll && <Button size="sm" onClick={openEnrollment} disabled={ceilingReached}>Enroll gateway</Button>}
        </div>
      </div>

      {state.kind === "ready" && state.licence?.gateway_ceiling != null && ceilingReached && <CeilingUpgrade
        kind="gateway" compact used={state.licence.gateways_in_use ?? state.nodes.length} ceiling={state.licence.gateway_ceiling}
        message={ceilingSentence(state.licence.gateways_in_use ?? state.nodes.length, state.licence.gateway_ceiling, state.licence.tier)}
      />}
      {state.kind === "loading" && <div className="gw-inventory-state"><Loading label="Loading gateways…" /></div>}
      {state.kind === "error" && <LoadRetry error={state.error ?? "Could not load gateways."} onRetry={reload} />}

      {state.kind === "ready" && <section className="gw-inventory">
        <div className="gw-inventory-toolbar">
          <div className="gw-search"><Icon name="search" size={16} /><input aria-label="Search gateways" placeholder="Search gateways…" value={q} onChange={event => setParam("q", event.target.value)} /></div>
          <span className="gw-inventory-count">{rows.length === counts.all ? `${counts.all} gateway${counts.all === 1 ? "" : "s"}` : `${rows.length} of ${counts.all}`}</span>
          <div className="gw-sort-controls">
            <label className="sr-only" htmlFor="gateway-sort">Sort gateways</label>
            <select id="gateway-sort" value={sort} onChange={event => setParam("sort", event.target.value, "name")}>
              <option value="name">Name</option><option value="health">State</option><option value="seen">Last seen</option><option value="version">Agent version</option>
            </select>
            <button type="button" aria-label={dir === "asc" ? "Ascending" : "Descending"} title={dir === "asc" ? "Sort ascending" : "Sort descending"} onClick={() => setParam("dir", dir === "asc" ? "desc" : "asc", "asc")}><span aria-hidden="true">{dir === "asc" ? "↑" : "↓"}</span></button>
          </div>
        </div>
        <div className="gw-inventory-table">{pageRows.length ? <DataTable caption="Gateway inventory" rows={pageRows} rowKey={row => row.id} failed={false} filterable={false} pageSize={0} variant="flat" columns={columns} empty={null} /> :
          <AppAccessEmptyState icon={null} title={state.nodes.length === 0 ? "No gateways are enrolled" : "No matching gateways"}
            description={state.nodes.length === 0 ? "Enroll a Linux host to connect your network." : "Try another search or clear the health filter."}
            action={state.nodes.length > 0 ? <Button size="sm" variant="ghost" onClick={clearFilters}>Clear filters</Button> : undefined}
          />
        }</div>
        <AppAccessPagination page={page} pageSize={pageSize} count={pageRows.length} hasNext={page * pageSize < rows.length} previousLabel="Previous gateways" nextLabel="Next gateways" onPageChange={nextPage => setParam("page", String(nextPage), "1")} onPageSizeChange={size => setParam("page_size", String(size), "20")} />
        {state.licence && <p className="gw-plan-usage">{state.licence.tier} plan · {state.licence.gateways_in_use ?? "not reported"} / {state.licence.gateway_ceiling == null ? "unlimited" : state.licence.gateway_ceiling} gateways</p>}
      </section>}

      {enrolling && org && state.kind === "ready" && canEnroll && !ceilingReached && <Modal title="Enroll gateway" onDismiss={closeEnrollment} size="enrollment" showClose placement="right">
        <EnrolCeremony key={org.id} org={org} initiallyOpen hideHeader onCancel={closeEnrollment} onEnrollmentAcknowledged={closeEnrollment} />
      </Modal>}
    </div>
  );
}
