import { useEffect, useMemo, useRef } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { Gateways as EnrolCeremony } from "../components/Gateways";
import {
  Button,
  Card,
  DataTable,
  EmptyState,
  Input,
  Loading,
  Modal,
  PageHeader,
  Select,
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
      .filter((row) => filter === "all" || lifecycle(row) === filter)
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
          <Link className="font-mono font-medium text-ink-heading hover:text-accent-400" to={`/gateways/${row.id}`}>
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
      key: "seen",
      header: "Freshness",
      cell: (row: GatewayRow) => (
        <span className="text-cell text-ink-tertiary" data-volatile>
          {row.lastSeenAt ? `Last seen ${relativeAge(row.lastSeenAt)}` : "Never connected"}
        </span>
      ),
    },
    {
      key: "agent",
      header: "Agent",
      cell: (row: GatewayRow) => (
        <span className="font-mono text-cell text-ink-body">{row.agentVersion || "Not reported"}</span>
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
          className="inline-flex h-8 w-8 items-center justify-center rounded-md text-lg text-ink-tertiary hover:bg-white/[.06] hover:text-ink-heading focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-400"
        >
          <span aria-hidden="true">›</span>
        </Link>
      ),
    },
  ];

  const openEnrollment = () => setParam("enroll", "1");
  const closeEnrollment = () => setParam("enroll", "", "");

  return (
    <div className="space-y-5">
      <PageHeader
        title="Gateways"
        subtitle="Enroll, inspect, and safely retire the gateways carrying private traffic."
        actions={
          canEnroll ? (
            <Button onClick={openEnrollment} disabled={ceilingReached}>
              Enroll gateway
            </Button>
          ) : undefined
        }
      />

      {state.kind === "ready" && state.licence?.gateway_ceiling != null && ceilingReached && (
        <CeilingUpgrade
          kind="gateway"
          compact
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
          <Card>
            <div className="mb-3 flex min-w-0 flex-wrap items-center gap-2 border-b border-white/10 pb-3">
              <div className="min-w-[15rem] flex-1">
                <Input
                  aria-label="Search gateways"
                  placeholder="Search gateway, site, version, or state"
                  value={q}
                  onChange={(event) => setParam("q", event.target.value)}
                />
              </div>
              <span className="order-first mr-1 whitespace-nowrap text-micro font-medium tabular-nums text-ink-tertiary sm:order-none">
                {rows.length === counts.all
                  ? `${counts.all} gateways`
                  : `${rows.length} of ${counts.all}`}
              </span>
              <Select
                aria-label="Filter gateway health"
                width="auto"
                value={filter}
                onChange={(event) => setParam("health", event.target.value, "all")}
              >
                <option value="all">All ({counts.all})</option>
                <option value="healthy">Healthy ({counts.healthy})</option>
                <option value="degraded">Needs attention ({counts.degraded})</option>
                <option value="revoked">Revoked ({counts.revoked})</option>
              </Select>
              <Select aria-label="Sort gateways" width="auto" value={sort} onChange={(event) => setParam("sort", event.target.value, "name")}>
                <option value="name">Name</option>
                <option value="health">State</option>
                <option value="seen">Freshness</option>
                <option value="version">Agent version</option>
              </Select>
              <Button
                variant="ghost"
                className="w-11 px-0 text-lg"
                aria-label={dir === "asc" ? "Ascending" : "Descending"}
                title={dir === "asc" ? "Sort ascending" : "Sort descending"}
                onClick={() => setParam("dir", dir === "asc" ? "desc" : "asc", "asc")}
              >
                <span aria-hidden="true">{dir === "asc" ? "↑" : "↓"}</span>
              </Button>
            </div>
            <DataTable
              caption="Gateway inventory"
              rows={rows}
              rowKey={(row) => row.id}
              failed={false}
              filterable={false}
              pageSize={25}
              columns={columns}
              empty={
                <EmptyState>
                  {state.nodes.length === 0
                    ? "No gateways are enrolled. Issue a one-time command to bring the first gateway online."
                    : "No gateways match the current search and health filter."}
                </EmptyState>
              }
            />
          </Card>
          {state.licence && (
            <p className="text-micro text-ink-faint">
              Plan: {state.licence.tier}. Deployment usage: {state.licence.gateways_in_use ?? "not reported"} / {state.licence.gateway_ceiling == null ? "unlimited" : state.licence.gateway_ceiling} gateways.
            </p>
          )}
        </>
      )}

      {enrolling && org && state.kind === "ready" && canEnroll && !ceilingReached && (
        <Modal
          title="Enroll gateway"
          onDismiss={closeEnrollment}
          size="wide"
          actions={<Button variant="ghost" onClick={closeEnrollment}>Close</Button>}
        >
          <p className="mb-3 text-cell text-ink-tertiary">
            Issue a one-time command for a Linux gateway. Token issuance means only that the command is ready; enrollment and connectivity are not yet server-correlated.
          </p>
          <EnrolCeremony
            org={org}
            initiallyOpen
            hideHeader
            onEnrollmentAcknowledged={closeEnrollment}
          />
        </Modal>
      )}
    </div>
  );
}
