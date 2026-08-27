import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useOrg } from "../lib/useOrg";
import {
  api,
  listItems,
  type GroupMember,
  apiErrorMessage,
  apiErrorCode,
  loadOne,
  type Loaded,
  type Org,
  type Member,
  type Role,
  type UserGroup,
  type Resource,
  type FQDNResource,
  type Site,
  type K8sService,
  type PolicyRule,
  type ZeroTrustMode,
  type AffectedDevice,
  type CreatePolicyRuleRequest,
  type AgentAccessDiagnostic,
  type AgentAccessDestination,
  type AgentAccessRequest,
  type AgentGroup,
} from "../lib/api";
import type { components } from "@tunnex/shared";
import { useAuth } from "../lib/auth";
import { can } from "../lib/rbac";
import {
  Button,
  Card,
  DataTable,
  ErrorText,
  Field,
  Input,
  Modal,
  PageHeader,
  Select,
} from "../components/ui";
import { relativeAge } from "../lib/format";
import { EntityPicker } from "../components/EntityPicker";
import { ComposeGate } from "../components/ComposeGate";
import { LoadRetry } from "../components/LoadRetry";
import {
  accessView,
  modeEnableConfirm,
  policyGate,
  roleFromMembers,
  ruleRow as resolveRuleRow,
  disableConfirmText,
  sectionRender,
  staleNoticeText,
  pruneStaleRuleIds,
  swapRule,
  grantExpiry,
  rulesSummary,
  rulesEmptyState,
  rulesEmptyCopy,
  flowLayout,
  FLOW_GRAPH_MAX_RULES,
  srcGroupEmptyWarn,
  srcGroupEmptyBadge,
  srcGroupEmptyExplain,
  flowGlyph,
  flowTag,
  type FlowKind,
  ruleBody,
  defaultSrcKind,
  defaultDstKind,
  extendErrorCopy,
  activeMembers,
  canEditRuleInModal,
  grantControls,
  managedGrantWarning,
  type LoadState,
  sourceOptions,
  destinationOptions,
  ruleEffectSummary,
  ruleEffectCaution,
  ruleSourceReady,
} from "../lib/policyview";
import { ManagedBadge } from "../components/ManagedBadge";
import { AccessTabRail } from "../components/AccessTabRail";
// swapRule + swapPartialMessage power the create-then-delete rule edit (D-a5) in RuleFormModal.
// Every GET here goes through loadOne — a raw api.GET whose emptiness is user-meaningful is
// review-refused (S7.4a review): a fetch failure must render a legible retry, never a
// reassuring empty state. (LoadRetry — the shared legible-retry affordance — lives in components/LoadRetry.)

export default function Access() {
  const { org: currentOrg, loading: orgLoading, failed: orgFailed } = useOrg();
  const { state } = useAuth();
  const myId = state.status === "authed" ? state.user.id : "";
  const emailVerified = state.status === "authed" && state.user.email_verified;
  const [org, setOrg] = useState<Org | null>(null);
  const [myRole, setMyRole] = useState<Role | undefined>(undefined);
  // Page-level gating inputs, kept DISTINCT so no signal blanks another (fold-2):
  // - loadError: organization context could not be loaded → retry, nothing renderable.
  // - fatal: terminal, non-retryable (no org).
  // - roleError / roleResolved: the members fetch — its failure affects ONLY the
  //   role-gated path; role in-flight must render "loading", never the gate notice ([101]).
  const [loadError, setLoadError] = useState<string | null>(null);
  const [fatal, setFatal] = useState<string | null>(null);
  const [roleError, setRoleError] = useState<string | null>(null);
  // Rules owns its own bounded subject inventory. Groups and Resources are dedicated
  // Access routes, so a Rules refresh is no longer coupled to a second management
  // surface mounted below this page.
  const [subjectsRev] = useState(0);
  const [roleResolved, setRoleResolved] = useState(false);
  const reloadEpoch = useRef(0);
  const selectedOrgId = useRef<string | null>(currentOrg?.id ?? null);
  selectedOrgId.current = currentOrg?.id ?? null;

  const reload = useCallback(async () => {
    const epoch = ++reloadEpoch.current;
    const target = currentOrg;
    const isCurrent = () =>
      reloadEpoch.current === epoch &&
      selectedOrgId.current === (target?.id ?? null);
    setLoadError(null);
    setFatal(null);
    setRoleError(null);
    setRoleResolved(false);
    setOrg(null);
    setMyRole(undefined);
    if (orgLoading) return;
    if (!target) {
      if (isCurrent()) {
        setFatal(
          orgFailed
            ? "Could not load your organizations."
            : "You are not a member of any organization yet.",
        );
      }
      return;
    }
    // ⛔ THE ORG COMES FROM THE SEAM, NOT FROM INDEX ZERO (S12.5).
    // ⛔ LOADING IS NOT ABSENCE (S12.5). See the note in Dashboard.tsx — three states, not two: still
    // loading (say nothing), the read failed (say THAT), genuinely no membership (say that).
    setOrg(target);
    const memRes = (await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/members", {
        params: { path: { orgId: target.id } },
      }),
    )) as Loaded<Member[]>;
    if (!isCurrent()) return;
    const resolved = roleFromMembers(memRes, myId);
    if (resolved.failed)
      return setRoleError(
        memRes.ok ? "Couldn't determine your role." : memRes.error,
      );
    setMyRole(resolved.role);
    setRoleResolved(true);
    // ⚠ currentOrg IS A DEPENDENCY, AND THAT IS THE HALF THAT MAKES THE SWITCHER WORK. Without it the
    // page keeps rendering the org it mounted with — the control moves, the data does not, and the user is
    // looking at one tenant's screen labelled with another's name.
  }, [currentOrg, myId, orgFailed, orgLoading]);
  useEffect(() => {
    reload();
    return () => {
      reloadEpoch.current += 1;
    };
  }, [reload]);

  const gate = policyGate({
    role: myRole,
    emailVerified,
  });
  const view = accessView({
    fatal: fatal != null,
    loadError: loadError != null,
    accessReady: org != null,
    roleError: roleError != null,
    roleResolved,
    canView: gate.canView,
    role: myRole,
  });

  // The shell switches currentOrg synchronously, while this page deliberately reloads
  // membership before accepting the next org into page state. Do not render one
  // tenant's rules or agent names under another tenant's shell during that interval.
  if (currentOrg && org?.id !== currentOrg.id) {
    return (
      <Card className="mt-6">
        <p className="text-sm text-slate-500">Loading access policies…</p>
      </Card>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
      {/* ⛔ THIS TITLE WAS A `<div>`, so the page had NO h1 at all — and its type/colour were an inline
          style object using `Instrument Sans` and raw hex, neither of which is in the token set. */}
      <PageHeader
        title="Access policies"
        subtitle={
          <>
            {org ? org.name : "…"} ·{" "}
            <span className="text-ink-secondary">control plane</span>{" "}
            <span className="text-ink-body">● healthy</span>
          </>
        }
      />
      <AccessTabRail />

      {view === "fatal" && <ErrorText>{fatal}</ErrorText>}
      {view === "load_retry" && (
        <LoadRetry error={loadError ?? "Couldn't load."} onRetry={reload} />
      )}
      {view === "role_retry" && (
        <LoadRetry
          error={roleError ?? "Couldn't determine your role."}
          onRetry={reload}
        />
      )}
      {(view === "loading" || view === "role_loading") && (
        <p className="mt-6 text-sm text-slate-500">Loading access policies…</p>
      )}

      {view === "member_gate" && (
        <Card className="mt-6">
          <p className="text-sm text-slate-400">
            Access policies are managed by owners and admins.
          </p>
        </Card>
      )}

      {org && gate.canView && roleResolved && (
        <TestAccessSection key={org.id} orgId={org.id} />
      )}

      {org && roleResolved && (can(myRole, "agent:grant_access") || can(myRole, "agent_access:approve")) && (
        <AgentJITCapabilitySection
          key={`f10-${org.id}`}
          orgId={org.id}
          enabled={org.agent_jit_access_enabled}
          canApprove={can(myRole, "agent_access:approve")}
          currentUserId={myId}
        />
      )}

      {view === "admin_body" && org && (
        <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          <ModeSection orgId={org.id} canManage={gate.canManagePolicy} />
          <RulesSection
            orgId={org.id}
            canManage={gate.canManagePolicy}
            canManageAgentTemplates={gate.canManageAgentTemplates}
            canViewFQDNResources={can(myRole, "fqdn_resource:view")}
            subjectsRev={subjectsRev}
          />
        </div>
      )}
    </div>
  );
}

type TestableAgent = { device_id: string; name: string };

type LicenceStatus = components["schemas"]["LicenseStatus"];

function AgentJITCapabilitySection({ orgId, enabled, canApprove, currentUserId }: {
  orgId: string; enabled: boolean; canApprove: boolean; currentUserId: string;
}) {
  const [licence, setLicence] = useState<Loaded<LicenceStatus> | null>(null);
  useEffect(() => { void loadOne(() => api.GET("/api/v1/license")).then((result) => setLicence(result as Loaded<LicenceStatus>)); }, []);
  if (licence === null) return <Card><p className="text-cell text-ink-tertiary">Loading just-in-time access capability…</p></Card>;
  if (!licence.ok) return <Card><p className="text-cell text-ink-tertiary">Could not load just-in-time access capability.</p><ErrorText>{licence.error}</ErrorText></Card>;
  if (!Array.isArray(licence.data.features)) return <Card><h2 className="text-sm font-semibold text-ink-heading">Just-in-time access</h2><p className="mt-1 text-cell text-ink-tertiary">The control plane returned an invalid licence capability response.</p><ErrorText>Refresh the page or contact an administrator if the problem continues.</ErrorText></Card>;
  if (!licence.data.features.includes("agent_jit_access")) return null;
  if (!enabled) return <div className="rounded-md border border-border bg-white/5 px-3 py-2 text-cell text-ink-tertiary">Just-in-time access is available on this plan but disabled for this organization. <Link className="font-medium text-accent-400 hover:underline" to="/settings">Enable it in Org Settings</Link>.</div>;
  return <AgentJITAccessSection orgId={orgId} enabled={enabled} canApprove={canApprove} currentUserId={currentUserId} />;
}

function AgentJITAccessSection({
  orgId,
  enabled,
  canApprove,
  currentUserId,
}: {
  orgId: string;
  enabled: boolean;
  canApprove: boolean;
  currentUserId: string;
}) {
  const [authorized, setAuthorized] = useState<boolean | null>(null);
  const [agents, setAgents] = useState<Array<{ device_id: string; name: string }>>([]);
  const [destinations, setDestinations] = useState<AgentAccessDestination[]>([]);
  const [requests, setRequests] = useState<AgentAccessRequest[]>([]);
  const [agentId, setAgentId] = useState("");
  const [destinationKey, setDestinationKey] = useState("");
  const [reason, setReason] = useState("");
  const [durationSeconds, setDurationSeconds] = useState("3600");
  const [history, setHistory] = useState<Record<string, string[]>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const loadEpoch = useRef(0);

  const load = useCallback(async () => {
    const epoch = ++loadEpoch.current;
    setError(null);
    setHistory({});
    const agentResult = await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/agents", {
        params: { path: { orgId } },
      }),
    );
    if (epoch !== loadEpoch.current) return;
    if (!agentResult.ok) {
      if (canApprove) setError(agentResult.error);
      else setAuthorized(false);
      return;
    }
    const visible = await Promise.all(
      listItems(agentResult.data).map(async (agent) => {
        const profile = await loadOne(() =>
          api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}", {
            params: { path: { orgId, deviceId: agent.device_id } },
          }),
        );
        return profile.ok ? { device_id: agent.device_id, name: agent.name } : null;
      }),
    );
    if (epoch !== loadEpoch.current) return;
    const scoped = visible.filter(
      (agent): agent is { device_id: string; name: string } => agent != null,
    );
    const requestResult = await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/agent-access-requests", {
        params: { path: { orgId }, query: { page_size: 50 } },
      }),
    );
    if (epoch !== loadEpoch.current) return;
    if (!requestResult.ok) {
      if (!canApprove && scoped.length === 0) setAuthorized(false);
      else {
        setAuthorized(true);
        setError(requestResult.error);
      }
      return;
    }
    // A rolling upgrade can briefly return the pre-F10 list shape here. Fail
    // the optional panel visibly; never fabricate an empty history and never
    // crash the whole Access page.
    const requestItems = listItems(requestResult.data);
    if (scoped.length === 0) {
      setAuthorized(true);
      setAgents([]);
      setDestinations([]);
      setRequests(requestItems);
      return;
    }
    const destinationResult = await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/agent-access-destinations", {
        params: { path: { orgId } },
      }),
    );
    if (epoch !== loadEpoch.current) return;
    if (!destinationResult.ok) {
      setAuthorized(true);
      setError(destinationResult.error);
      return;
    }
    if (!Array.isArray(destinationResult.data)) {
      setAuthorized(true);
      setError("Could not load access destinations.");
      return;
    }
    const destinationItems = destinationResult.data;
    setAuthorized(true);
    setAgents(scoped);
    setDestinations(destinationItems);
    setRequests(requestItems);
    setAgentId((current) =>
      scoped.some((agent) => agent.device_id === current)
        ? current
        : (scoped[0]?.device_id ?? ""),
    );
    setDestinationKey((current) =>
      destinationItems.some(
        (destination) => `${destination.kind}:${destination.id}` === current,
      )
        ? current
        : destinationItems[0]
          ? `${destinationItems[0].kind}:${destinationItems[0].id}`
          : "",
    );
  }, [canApprove, orgId]);

  useEffect(() => {
    void load();
    return () => {
      loadEpoch.current += 1;
    };
  }, [load]);

  async function submitRequest() {
    const destination = destinations.find(
      (item) => `${item.kind}:${item.id}` === destinationKey,
    );
    if (!destination || !agentId || !reason.trim()) return;
    setBusy(true);
    setError(null);
    const response = await api.POST(
      "/api/v1/organizations/{orgId}/agent-access-requests",
      {
        params: { path: { orgId } },
        body: {
          device_id: agentId,
          destination_kind: destination.kind,
          destination_id: destination.id,
          reason: reason.trim(),
          duration_seconds: Number(durationSeconds),
          idempotency_key: `web-create-${crypto.randomUUID()}`,
        },
      },
    );
    setBusy(false);
    if (response.error) {
      return setError(
        apiErrorMessage(response.error, "Could not request temporary access."),
      );
    }
    setReason("");
    await load();
  }

  async function transition(
    request: AgentAccessRequest,
    action: "approve" | "reject" | "cancel" | "revoke",
  ) {
    setBusy(true);
    setError(null);
    const key = `web-${action}-${crypto.randomUUID()}`;
    let response;
    if (action === "approve") {
      response = await api.POST(
        "/api/v1/organizations/{orgId}/agent-access-requests/{requestId}/approve",
        { params: { path: { orgId, requestId: request.id } }, body: { idempotency_key: key } },
      );
    } else if (action === "reject") {
      const rejection = window.prompt("Why is this request being rejected?")?.trim();
      if (!rejection) {
        setBusy(false);
        return;
      }
      response = await api.POST(
        "/api/v1/organizations/{orgId}/agent-access-requests/{requestId}/reject",
        { params: { path: { orgId, requestId: request.id } }, body: { idempotency_key: key, reason: rejection } },
      );
    } else if (action === "cancel") {
      response = await api.POST(
        "/api/v1/organizations/{orgId}/agent-access-requests/{requestId}/cancel",
        { params: { path: { orgId, requestId: request.id } }, body: { idempotency_key: key } },
      );
    } else {
      response = await api.POST(
        "/api/v1/organizations/{orgId}/agent-access-requests/{requestId}/revoke",
        { params: { path: { orgId, requestId: request.id } }, body: { idempotency_key: key } },
      );
    }
    setBusy(false);
    if (response.error) {
      return setError(
        apiErrorMessage(response.error, `Could not ${action} the request.`),
      );
    }
    await load();
  }

  async function showHistory(requestId: string) {
    const response = await api.GET(
      "/api/v1/organizations/{orgId}/agent-access-requests/{requestId}",
      { params: { path: { orgId, requestId } } },
    );
    if (response.error || !response.data) {
      return setError(apiErrorMessage(response.error, "Could not load request history."));
    }
    setHistory((current) => ({
      ...current,
      [requestId]: response.data.events.map((event) => event.state),
    }));
  }

  if (authorized === false) return null;
  if (authorized == null) return null;

  return (
    <Card data-testid="agent-jit-access-panel">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-200">
            Just-in-time agent access
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Request one expiring destination grant. Pending requests change no policy.
          </p>
        </div>
        <Button disabled={busy} onClick={() => void load()}>Refresh</Button>
      </div>
      {!enabled && (
        <p className="mt-3 text-xs text-amber-300">
          JIT agent access is off. An owner or admin can enable it in Org Settings.
        </p>
      )}
      {enabled && agents.length > 0 && destinations.length > 0 && (
        <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
          <Field label="Agent">
            <Select value={agentId} onChange={(event) => setAgentId(event.target.value)}>
              {agents.map((agent) => <option key={agent.device_id} value={agent.device_id}>{agent.name}</option>)}
            </Select>
          </Field>
          <Field label="Destination">
            <Select value={destinationKey} onChange={(event) => setDestinationKey(event.target.value)}>
              {destinations.map((destination) => (
                <option key={`${destination.kind}:${destination.id}`} value={`${destination.kind}:${destination.id}`}>
                  {destination.name} · {destination.kind.replace("_", " ")}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Reason">
            <Input value={reason} maxLength={500} onChange={(event) => setReason(event.target.value)} placeholder="Why is access needed?" />
          </Field>
          <Field label="Duration">
            <Select value={durationSeconds} onChange={(event) => setDurationSeconds(event.target.value)}>
              <option value="900">15 minutes</option>
              <option value="3600">1 hour</option>
              <option value="14400">4 hours</option>
              <option value="86400">24 hours</option>
            </Select>
            <p className="mt-1 text-[10px] text-slate-500">
              Requested window; exact expiry is calculated when approved.
            </p>
          </Field>
          <div className="flex items-end">
            <Button disabled={busy || !reason.trim()} onClick={() => void submitRequest()}>
              {busy ? "Saving…" : "Request access"}
            </Button>
          </div>
        </div>
      )}
      {enabled && (agents.length === 0 || destinations.length === 0) && (
        <p className="mt-3 text-xs text-slate-500">
          {agents.length === 0 ? "No manageable agents are available." : "No access destinations are configured."}
        </p>
      )}
      <ErrorText>{error}</ErrorText>
      {requests.length > 0 && (
        <div className="mt-5 space-y-2">
          {requests.map((request) => (
            <div key={request.id} id={`jit-request-${request.id}`} className="rounded border border-slate-800 px-3 py-3" data-testid={`jit-request-${request.id}`}>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <p className="text-sm text-slate-300">{request.agent_name} → {request.destination_name}</p>
                  <p className="mt-1 text-xs text-slate-500">{request.reason} · {request.state} · requested {relativeAge(request.requested_at)}</p>
                  {request.approved_expires_at && <p className="mt-1 text-xs text-amber-300">Expires {relativeAge(request.approved_expires_at)}</p>}
                  {history[request.id] && <p className="mt-1 font-mono text-[10px] text-slate-500">{history[request.id].join(" → ")}</p>}
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button onClick={() => void showHistory(request.id)}>History</Button>
                  {canApprove && request.state === "pending" && (
                    <><Button disabled={busy} onClick={() => void transition(request, "approve")}>Approve</Button><Button disabled={busy} onClick={() => void transition(request, "reject")}>Reject</Button></>
                  )}
                  {!canApprove && request.state === "pending" && request.requested_by_user_id === currentUserId && (
                    <Button disabled={busy} onClick={() => void transition(request, "cancel")}>Cancel</Button>
                  )}
                  {canApprove && request.state === "approved" && (
                    <Button disabled={busy} onClick={() => void transition(request, "revoke")}>Revoke</Button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

function TestAccessSection({ orgId }: { orgId: string }) {
  const [agents, setAgents] = useState<TestableAgent[] | null>(null);
  const [agentId, setAgentId] = useState("");
  const [destination, setDestination] = useState("");
  const [protocol, setProtocol] = useState<"tcp" | "udp">("tcp");
  const [port, setPort] = useState("443");
  const [result, setResult] = useState<AgentAccessDiagnostic | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const loadEpoch = useRef(0);
  const runEpoch = useRef(0);
  const tupleKey = `${orgId}\u0000${agentId}\u0000${destination.trim()}\u0000${protocol}\u0000${port}`;
  const tupleKeyRef = useRef(tupleKey);
  tupleKeyRef.current = tupleKey;

  useEffect(() => {
    const epoch = ++loadEpoch.current;
    setAgents(null);
    setAgentId("");
    setResult(null);
    setError(null);
    void (async () => {
      const listed = await loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/agents", {
          params: { path: { orgId } },
        }),
      );
      if (epoch !== loadEpoch.current || !listed.ok) return;
      const visible = await Promise.all(
        listItems(listed.data).map(async (agent) => {
          const profile = await loadOne(() =>
            api.GET("/api/v1/organizations/{orgId}/agents/{deviceId}", {
              params: { path: { orgId, deviceId: agent.device_id } },
            }),
          );
          if (!profile.ok) return null;
          return { device_id: agent.device_id, name: agent.name };
        }),
      );
      if (epoch !== loadEpoch.current) return;
      const scoped = visible.filter((v): v is TestableAgent => v != null);
      setAgents(scoped);
      setAgentId(scoped[0]?.device_id ?? "");
    })();
    return () => {
      loadEpoch.current += 1;
      runEpoch.current += 1;
    };
  }, [orgId]);

  useEffect(() => {
    runEpoch.current += 1;
    setBusy(false);
    setResult(null);
    setError(null);
  }, [orgId, agentId, destination, protocol, port]);

  if (!agents || agents.length === 0) return null;

  const numericPort = Number(port);
  const runnable =
    agentId !== "" && destination.trim() !== "" && Number.isInteger(numericPort) && numericPort >= 1 && numericPort <= 65535;

  async function run() {
    if (!runnable) return;
    const epoch = ++runEpoch.current;
    const requestedTupleKey = tupleKey;
    const tuple = { agentId, destination: destination.trim(), protocol, port: numericPort };
    setBusy(true);
    setResult(null);
    setError(null);
    try {
      const response = await api.GET(
        "/api/v1/organizations/{orgId}/agents/{deviceId}/test-access",
        {
          params: {
            path: { orgId, deviceId: tuple.agentId },
            query: { destination: tuple.destination, protocol: tuple.protocol, port: tuple.port },
          },
        },
      );
      if (epoch !== runEpoch.current || requestedTupleKey !== tupleKeyRef.current) return;
      if (response.error || !response.data) setError(apiErrorMessage(response.error, "Could not test access."));
      else setResult(response.data);
    } catch {
      if (epoch === runEpoch.current) setError("Could not reach the API.");
    } finally {
      if (epoch === runEpoch.current) setBusy(false);
    }
  }

  return (
    <div data-testid="test-access-panel">
      <Card>
      <div className="flex flex-wrap items-end gap-3">
        <div className="min-w-52 flex-1">
          <h2 className="text-sm font-semibold text-slate-200">Test access</h2>
          <p className="mt-1 text-xs text-slate-500">
            Explain current control-plane intent. No packet, DNS query, or policy change is sent.
          </p>
        </div>
        <Field label="Agent">
          <Select value={agentId} onChange={(e) => setAgentId(e.target.value)}>
            {agents.map((agent) => (
              <option key={agent.device_id} value={agent.device_id}>{agent.name}</option>
            ))}
          </Select>
        </Field>
        <Field label="Destination IP or hostname">
          <Input value={destination} placeholder="10.20.0.15" onChange={(e) => setDestination(e.target.value)} />
        </Field>
        <Field label="Protocol">
          <Select value={protocol} onChange={(e) => setProtocol(e.target.value as "tcp" | "udp")}>
            <option value="tcp">TCP</option><option value="udp">UDP</option>
          </Select>
        </Field>
        <Field label="Port">
          <Input type="number" min={1} max={65535} value={port} onChange={(e) => setPort(e.target.value)} />
        </Field>
        <Button disabled={busy || !runnable} onClick={run}>{busy ? "Testing…" : "Test access"}</Button>
      </div>
      <ErrorText>{error}</ErrorText>
      {result && (
        <div className="mt-4" data-testid="test-access-result">
          <p className="text-sm font-medium text-slate-200">
            {result.overall === "allowed" ? "Allowed by current Tunnex intent" : result.overall === "denied" ? "Blocked by current Tunnex intent" : "Inconclusive from current evidence"}
          </p>
          {result.first_blocker && <p className="mt-1 text-xs text-amber-300">First blocker: {result.first_blocker}</p>}
          <ol className="mt-3 space-y-2">
            {result.checks.map((check, index) => (
              <li key={`${index}-${check.code}`} className="rounded border border-slate-800 px-3 py-2">
                <div className="flex gap-2 text-xs">
                  <span aria-hidden="true">{check.status === "pass" ? "✓" : check.status === "fail" ? "×" : "?"}</span>
                  <span className="font-medium text-slate-300">{check.code}</span>
                  <span className="text-slate-500">{check.message}</span>
                </div>
                {check.facts && Object.keys(check.facts).length > 0 && (
                  <dl className="mt-2 grid gap-1 font-mono text-[10px] text-slate-500 sm:grid-cols-2">
                    {Object.entries(check.facts).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => (
                      <div key={key} className="flex gap-1"><dt>{key}:</dt><dd className="break-all text-slate-400">{value}</dd></div>
                    ))}
                  </dl>
                )}
              </li>
            ))}
          </ol>
        </div>
      )}
      </Card>
    </div>
  );
}

// ── Zero Trust mode ─────────────────────────────────────────────────────────────────
function ModeSection({
  orgId,
  canManage,
}: {
  orgId: string;
  canManage: boolean;
}) {
  const [mode, setMode] = useState<"off" | "enforcing" | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [confirmCount, setConfirmCount] = useState(0);
  const [busy, setBusy] = useState(false);
  const [affected, setAffected] = useState<AffectedDevice[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    const r = await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/zero-trust-mode", {
        params: { path: { orgId } },
      }),
    );
    if (!r.ok) {
      setLoadError(r.error); // never hide the toggle on a failure ([5]) — show retry
      return;
    }
    setLoadError(null);
    setMode((r.data as ZeroTrustMode).mode);
  }, [orgId]);
  useEffect(() => {
    load();
  }, [load]);

  // [1]+[7]: fetch the rule count FRESH at Enable-click — never a stale/defaulted-0 count that
  // would show the false zero-rules danger gate. A failed count fetch aborts LEGIBLY.
  async function openEnableConfirm() {
    setErr(null);
    const r = await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/policies", {
        params: { path: { orgId } },
      }),
    );
    if (!r.ok) return setErr("Couldn't verify the current rule count. retry.");
    setConfirmCount((r.data as PolicyRule[]).length);
    setConfirming(true);
  }

  async function setModeTo(next: "off" | "enforcing") {
    setBusy(true);
    setErr(null);
    setAffected(null);
    const { data, error } = await api.PUT(
      "/api/v1/organizations/{orgId}/zero-trust-mode",
      {
        params: { path: { orgId } },
        body: { mode: next },
      },
    );
    setBusy(false);
    setConfirming(false);
    if (error)
      return setErr(apiErrorMessage(error, "Could not change the mode."));
    const zt = data as ZeroTrustMode | undefined;
    if (zt) {
      setMode(zt.mode);
      if (zt.affected_full_tunnel_devices?.length)
        setAffected(zt.affected_full_tunnel_devices);
    }
  }

  const confirm = modeEnableConfirm(confirmCount);

  return (
    <Card className="mt-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-slate-300">
            Zero Trust mode
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            {mode === "enforcing"
              ? "Enforcing. default-deny; only your allow rules pass."
              : mode === "off"
                ? "Off. legacy full-mesh (all devices reach all devices)."
                : loadError
                  ? "n/a"
                  : "…"}
          </p>
        </div>
        {canManage && mode != null && !loadError && (
          <Button
            variant={mode === "enforcing" ? "ghost" : "primary"}
            disabled={busy}
            onClick={() =>
              mode === "enforcing" ? setModeTo("off") : openEnableConfirm()
            }
          >
            {mode === "enforcing" ? "Disable" : "Enable enforcing"}
          </Button>
        )}
      </div>
      {loadError && <LoadRetry error={loadError} onRetry={load} />}
      <ErrorText>{err}</ErrorText>

      {affected && (
        <div className="mt-3 rounded-md border border-warn/30 bg-warn/5 px-3 py-2 text-xs text-amber-300">
          Now enforcing. {affected.length} full-tunnel device(s) lost internet
          egress until a rule allows it:
          <span className="text-amber-200">
            {" "}
            {affected.map((d) => d.name).join(", ")}
          </span>
        </div>
      )}

      {confirming && (
        <Modal
          title={confirm.title}
          danger={confirm.danger}
          onDismiss={() => setConfirming(false)}
          actions={
            <>
              <Button variant="ghost" onClick={() => setConfirming(false)}>
                Cancel
              </Button>
              <Button
                variant={confirm.danger ? "danger" : "primary"}
                disabled={busy}
                onClick={() => setModeTo("enforcing")}
              >
                {confirm.confirmLabel}
              </Button>
            </>
          }
        >
          {confirm.body}
        </Modal>
      )}
    </Card>
  );
}

// ── Rules ─────────────────────────────────────────────────────────────────────────────
function RulesSection({
  orgId,
  canManage,
  canManageAgentTemplates,
  canViewFQDNResources,
  subjectsRev,
}: {
  orgId: string;
  canManage: boolean;
  canManageAgentTemplates: boolean;
  canViewFQDNResources: boolean;
  subjectsRev: number;
}) {
  const [rules, setRules] = useState<PolicyRule[]>([]);
  const [groups, setGroups] = useState<UserGroup[]>([]);
  const [resources, setResources] = useState<Resource[]>([]);
  const [fqdnResources, setFQDNResources] = useState<FQDNResource[]>([]);
  const [members, setMembers] = useState<Member[]>([]);
  const [sites, setSites] = useState<Site[]>([]); // S8.2c D5: site rule subjects
  const [services, setServices] = useState<K8sService[]>([]); // S10.3: k8s_service dst subjects
  const [agents, setAgents] = useState<
    Array<{ device_id: string; name: string; gateway_name: string }>
  >([]);
  const [agentsOrgId, setAgentsOrgId] = useState("");
  const [loaded, setLoaded] = useState<LoadState>({
    groupsLoaded: false,
    resourcesLoaded: false,
    membersLoaded: false,
  });
  const [loadError, setLoadError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<PolicyRule | null>(null);
  const [extendingGrant, setExtendingGrant] = useState<PolicyRule | null>(null);
  // F3: the rules pending a disable-confirm. PLURAL since the verbs moved to the selection bar — and
  // disabling five live allows at once is strictly MORE consequential than disabling one, so the ceremony
  // grew with the set rather than being dropped for convenience.
  const [disablingRules, setDisablingRules] = useState<PolicyRule[]>([]);
  // ⛔ DELETE NOW CONFIRMS, AND THAT IS A DELIBERATE ADDITION. Per-row it was one click on one rule; from a
  // selection bar the same click can destroy fifteen. An unconfirmed bulk delete of authorization rules is
  // the kind of control that is only ever wrong once.
  const [deletingRules, setDeletingRules] = useState<PolicyRule[]>([]);
  // SINGLE source of truth for the partial-swap warning: the SET of rule ids a create-then-
  // delete left un-deleted. The notice is DERIVED (staleNoticeText) — no separate state to
  // desync ([291]/[309]/[371]). Pruned ONLY on a successful load (amendment A), per-id (B).
  const [staleRuleIds, setStaleRuleIds] = useState<string[]>([]);
  const [err, setErr] = useState<string | null>(null);
  // S8.3 CP summary line: BOTH derived from real load results (never an empty default) so a failed load
  // can't render the loud "0 rules — all denied". null until the first load resolves.
  const [modeResult, setModeResult] = useState<Loaded<
    "off" | "enforcing"
  > | null>(null);
  const [rulesResult, setRulesResult] = useState<Loaded<number> | null>(null);
  const [visualizing, setVisualizing] = useState(false);
  // The graph is only ever a shortcut over this same filtered inventory. Keeping
  // filtering in the route (rather than hidden inside DataTable) means it cannot
  // silently draw rules the operator has narrowed out of the authoritative table.
  const [ruleQuery, setRuleQuery] = useState("");
  // ⛔ MEMBER COUNTS FOR SOURCE GROUPS ONLY — the bounded half of the coupling.
  // Lazy counts in the Groups panel LOSE the visibly-empty property; src_group_empty restores it HERE, on the
  // rule row, where the operator's attention already is. The fan-out is the DISTINCT SOURCE GROUPS of the
  // rules, not every group — the rules are what need judging.
  // `undefined` = not fetched yet, `null` = fetched and FAILED. Neither warns: "could not check" is not "empty".
  const [srcGroupCounts, setSrcGroupCounts] = useState<
    Map<string, number | null>
  >(new Map());
  // Keep every existing rule-list consumer on the same FQDN-aware resolver. A failed
  // FQDN inventory read stays visibly unavailable rather than becoming a deleted target.
  const ruleRow = useCallback((
    rule: PolicyRule,
    ruleGroups: UserGroup[],
    ruleResources: Resource[],
    ruleMembers: Member[],
    ruleSites: Site[],
    ruleLoaded: LoadState,
    ruleServices: K8sService[] = [],
  ) => resolveRuleRow(rule, ruleGroups, ruleResources, ruleMembers, ruleSites, ruleLoaded, ruleServices, fqdnResources), [fqdnResources]);

  const load = useCallback(async () => {
    setErr(null); // [310]: never carry a stale partial-load/mutation error into a fresh load
    setAgentsOrgId("");
    setLoaded((previous) => ({
      ...previous,
      agentsLoaded: false,
      agents: [],
    }));
    const [rr, gr, resr, fr, mr, mo, sr, ksr, ar, agr] = await Promise.all([
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/policies", {
          params: { path: { orgId } },
        }),
      ),
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/groups", {
          params: { path: { orgId } },
        }),
      ),
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/resources", {
          params: { path: { orgId } },
        }),
      ),
      canViewFQDNResources
        ? loadOne(() =>
            api.GET("/api/v1/organizations/{orgId}/fqdn-resources", {
              params: { path: { orgId } },
            }),
          )
        : Promise.resolve({ ok: false as const, error: "FQDN resources are unavailable because your role lacks fqdn_resource:view." }),
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/members", {
          params: { path: { orgId } },
        }),
      ),
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/zero-trust-mode", {
          params: { path: { orgId } },
        }),
      ),
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/sites", {
          params: { path: { orgId } },
        }),
      ), // S8.2c D5: site rule subjects
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/k8s/services", {
          params: { path: { orgId } },
        }),
      ), // S10.3: k8s_service dst subjects
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/agents", {
          params: { path: { orgId } },
        }),
      ),
      canManageAgentTemplates
        ? loadOne(() =>
            api.GET("/api/v1/organizations/{orgId}/agent-groups", {
              params: { path: { orgId } },
            }),
          )
        : Promise.resolve({ ok: true as const, data: [] as AgentGroup[] }),
    ]);
    // Summary inputs — set from the SAME results (a rules-load failure → summary shows "failed", never 0).
    setRulesResult(
      rr.ok ? { ok: true, data: (rr.data as PolicyRule[]).length } : rr,
    );
    setModeResult(
      mo.ok
        ? { ok: true, data: (mo.data as ZeroTrustMode).mode }
        : (mo as Loaded<"off" | "enforcing">),
    );
    // The RULES fetch failing means the section cannot render truthfully — show retry, NOT
    // the reassuring "No rules — enforcing denies everything" ([2]). Amendment A: on this
    // FAILED path the stale-rule set is left untouched (the warning persists).
    if (!rr.ok) return setLoadError(rr.error);
    setLoadError(null);
    const freshRules = rr.data as PolicyRule[];
    setRules(freshRules);
    // Bounded: one call per DISTINCT source group actually referenced by a rule.
    const srcIds = [
      ...new Set(
        freshRules
          .filter((r) => (r.src_kind ?? "group") === "group" && r.src_group_id)
          .map((r) => r.src_group_id as string),
      ),
    ];
    void Promise.all(
      srcIds.map(async (gid) => {
        const mr = (await loadOne(() =>
          api.GET("/api/v1/organizations/{orgId}/groups/{groupId}/members", {
            params: { path: { orgId, groupId: gid } },
          }),
        )) as Loaded<GroupMember[]>;
        return [gid, mr.ok ? mr.data.length : null] as const;
      }),
    ).then((pairs) => setSrcGroupCounts(new Map(pairs)));
    setGroups((gr.ok ? (gr.data as UserGroup[]) : []) as UserGroup[]);
    setResources((resr.ok ? (resr.data as Resource[]) : []) as Resource[]);
    setFQDNResources(fr.ok ? (fr.data as FQDNResource[]) : []);
    setMembers((mr.ok ? (mr.data as Member[]) : []) as Member[]);
    setSites((sr.ok ? (sr.data as Site[]) : []) as Site[]); // D5
    setServices((ksr.ok ? (ksr.data as K8sService[]) : []) as K8sService[]); // S10.3: k8s_service dst subjects
    const loadedAgents = ar.ok
      ? (listItems(ar.data) as Array<{
          device_id: string;
          name: string;
          gateway_name: string;
        }>)
      : [];
    setAgents(loadedAgents);
    setAgentsOrgId(orgId);
    // D-a6 loaded flags come from the SAME source: a set that FAILED to load → its refs are
    // "unresolved", not "deleted".
    setLoaded({
      groupsLoaded: gr.ok,
      resourcesLoaded: resr.ok,
      fqdnResourcesLoaded: fr.ok,
      membersLoaded: mr.ok,
      sitesLoaded: sr.ok,
      k8sServicesLoaded: ksr.ok,
      agentsLoaded: ar.ok,
      agents: loadedAgents,
      agentGroupsLoaded: agr.ok,
      agentGroups: agr.ok ? (agr.data as AgentGroup[]) : [],
    }); // sitesLoaded → WF-8; k8sServicesLoaded → S10.3
    setErr(
      gr.ok && resr.ok && fr.ok && mr.ok && sr.ok && ksr.ok && ar.ok && agr.ok
        ? null
        : "Some groups/resources/FQDN resources/members/sites/services/agents failed to load. names may show as unavailable. Refresh.",
    ); // ksr.ok: a services-load failure must raise the banner too
    // The ONLY clear path (amendment A: gated on this successful load): drop stale ids no
    // longer present, keep the rest (B).
    setStaleRuleIds((prev) => pruneStaleRuleIds(prev, true, freshRules));
  }, [canManageAgentTemplates, canViewFQDNResources, orgId]);
  useEffect(() => {
    load();
  }, [load, subjectsRev]); // S8.5: re-load when a sibling section mutates groups/resources (stale-button fix)

  const notice = staleNoticeText(staleRuleIds); // DERIVED — no notice state
  const visibleAgents = agentsOrgId === orgId ? agents : [];
  const filteredRules = useMemo(() => {
    const query = ruleQuery.trim().toLowerCase();
    if (!query) return rules;
    return rules.filter((rule) => {
      const row = ruleRow(
        rule,
        groups,
        resources,
        members,
        sites,
        loaded,
        services,
      );
      return [row.src.label, row.dst.label, rule.src_kind, rule.dst_kind]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(query));
    });
  }, [groups, loaded, members, resources, ruleQuery, rules, services, sites]);
  // The optional graph is derived from the same filtered inventory as the table before it can open.
  // It is complete-or-withheld: a graph that omits even one loaded flow is not an operational summary.
  const flowRows = useMemo(() => filteredRules.map((rule) => {
    const row = ruleRow(rule, groups, resources, members, sites, loaded, services);
    return {
      id: rule.id,
      src: row.src.label,
      dst: row.dst.label,
      temp: rule.expires_at != null,
      srcKind: rule.src_kind as FlowKind,
      dstKind: rule.dst_kind as FlowKind,
    };
  }), [filteredRules, groups, loaded, members, resources, services, sites]);
  const flowProbe = useMemo(() => flowLayout(flowRows), [flowRows]);
  const visualization = useMemo(() => {
    if (!rulesResult || !modeResult) return { kind: "loading" as const };
    if (flowRows.length === 0) return { kind: "empty" as const };
    if (flowRows.length > FLOW_GRAPH_MAX_RULES) return { kind: "too-many" as const };
    if (flowProbe.shown.length !== flowRows.length) return { kind: "omitted" as const };
    return { kind: "draw" as const };
  }, [flowProbe.shown.length, flowRows.length, modeResult, rulesResult]);
  useEffect(() => {
    if (visualizing && visualization.kind !== "draw") setVisualizing(false);
  }, [visualization.kind, visualizing]);

  async function del(id: string) {
    const { error } = await api.DELETE(
      "/api/v1/organizations/{orgId}/policies/{ruleId}",
      {
        params: { path: { orgId, ruleId: id } },
      },
    );
    if (error)
      return setErr(apiErrorMessage(error, "Could not delete the rule."));
    load();
  }

  // F3: toggle a rule enabled/disabled. Disabling withdraws its allow (in-hash push, effective in seconds);
  // ENABLE is one-click (additive/harmless), DISABLE goes through the confirm modal (asymmetric ceremony).
  async function setEnabled(id: string, enabled: boolean) {
    const { error } = await api.PATCH(
      "/api/v1/organizations/{orgId}/policies/{ruleId}",
      {
        params: { path: { orgId, ruleId: id } },
        body: { enabled },
      },
    );
    if (error)
      return setErr(
        apiErrorMessage(
          error,
          enabled
            ? "Could not enable the rule."
            : "Could not disable the rule.",
        ),
      );
    load();
  }

  const view = sectionRender(loadError, notice);
  const ruleEmptyState = rulesEmptyState({ rulesResult, modeResult, renderedCount: rules.length });
  const rulesAuthoritative = rulesResult?.ok === true;

  return (
    <Card className="mt-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-300">Rules</h2>
        {/* TWO seams, both producing ABSENCE, and the ORDER is the decision (S14.2 D3):
            PERMISSION first, WIDTH second. A member who may not manage rules sees nothing — never
            "read-only on this screen size", which would imply a wider window grants what their role does not. */}
        {canManage && !view.showRetry && (
          <ComposeGate surface="Access rules">
            <Button
              onClick={() => setCreating(true)}
              disabled={
                !rulesAuthoritative ||
                (groups.length === 0 &&
                  sites.length === 0 &&
                  visibleAgents.length === 0)
              }
            >
              Add rule
            </Button>
          </ComposeGate>
        )}
      </div>
      <p className="mt-1 text-xs text-slate-500">
        Allow rules: a source group may reach a destination group or resource.
      </p>

      {/* S8.3 CP: the posture summary line. enforcing+0 is LOUD (a live default-deny with no rules); a
          failed load reads "unavailable", never the reassuring 0-rules message. */}
      {(() => {
        const s = rulesSummary({ modeResult, rulesResult });
        if (s.state === "loading") return null;
        return (
          <p
            className={
              s.loud
                ? "mt-2 rounded-md border border-danger/40 bg-danger/10 px-3 py-1.5 text-sm font-semibold text-danger"
                : `mt-2 text-xs ${s.state === "failed" ? "text-amber-300" : "text-slate-400"}`
            }
          >
            {s.text}
          </p>
        );
      })()}

      {/* [291] legibility signals COMPOSE: the partial-swap notice + a mutation error render at
          TOP LEVEL — a load failure replaces the LIST (content), never a warning. */}
      {view.showNotice && (
        <p className="mt-2 text-xs text-amber-300">{notice}</p>
      )}
      <ErrorText>{err}</ErrorText>
      {view.showRetry && (
        <>
          {ruleEmptyState.kind === "failed" && <p className="mt-3 text-xs text-amber-300">{rulesEmptyCopy(ruleEmptyState).text}</p>}
          <LoadRetry error={loadError ?? "Couldn't load rules."} onRetry={load} />
        </>
      )}

      {view.showContent && ruleEmptyState.kind === "loading" && (
        <p role="status" className="mt-3 text-xs text-slate-500">Loading rules…</p>
      )}

      {view.showContent && ruleEmptyState.kind !== "loading" && (
        <>
          {groups.length === 0 &&
            sites.length === 0 &&
            visibleAgents.length === 0 &&
            loaded.groupsLoaded && (
            <p className="mt-2 text-xs text-slate-500">
              Create a group of users, register a site, or enrol an agent to add
              a rule.
            </p>
          )}
          <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-xs text-slate-500">The table is the authoritative rules inventory.</p>
              <p className="mt-1 text-xs text-slate-400" data-testid="visualization-count">{filteredRules.length} matching rules · visualization limit {FLOW_GRAPH_MAX_RULES}</p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Input
                aria-label="Filter Rules"
                value={ruleQuery}
                onChange={(event) => setRuleQuery(event.target.value)}
                placeholder="Filter loaded rules…"
              />
              <Button size="sm" variant="ghost" aria-describedby="rules-visualization-status" disabled={visualization.kind !== "draw"} onClick={() => {
                if (visualizing) setVisualizing(false);
                else if (visualization.kind === "draw") setVisualizing(true);
              }}>
                {visualizing && visualization.kind === "draw" ? "Hide visualization" : "Visualize filtered rules"}
              </Button>
            </div>
          </div>
          {visualization.kind === "empty" && <p id="rules-visualization-status" className="mt-2 text-xs text-slate-500">No matching rules to visualize. Adjust the filter to include rules.</p>}
          {visualization.kind === "too-many" && <p id="rules-visualization-status" className="mt-2 text-xs text-amber-300">{flowRows.length} matching rules; visualization limit is {FLOW_GRAPH_MAX_RULES}. Narrow the filter.</p>}
          {visualization.kind === "omitted" && <p id="rules-visualization-status" className="mt-2 text-xs text-amber-300">Only {flowProbe.shown.length} of {flowRows.length} flows can be represented. Narrow the filter.</p>}
          {visualization.kind === "draw" && <p id="rules-visualization-status" className="sr-only">All matching rules can be visualized.</p>}
          {/* ── ACCESS FLOW ({{ polFlow }}) — built from the handoff's buildPolicyFlow(), not from a screenshot.
              GEOMETRY VERBATIM: canvas 600x312 rx14 over a 16px dot field; node boxes 152x36 rx10 at cx±76,
              columns at LX=95 / RX=505 so the paths own the middle 260px; vertical pitch 68 from cy=54;
              glyph circle r8 at cx-60. EDGES are cubic beziers with HORIZONTAL control points ±130 —
              `M170,sy C300,sy 300,dy 430,dy` — so they leave and arrive flat and read as flows, not chords.
              Temporary grants are DASHED (5 6), allow is solid: the design distinguishes them by dash, not
              by colour. Legend bottom-left, readout bottom-right, both INSIDE the panel.

              ⛔ ORDERING IS THE FIX, NOT THE CURVE. The handoff's own data crosses ZERO times because a human
              ordered the destination column so each source's edge is level or one slot away. Ours was
              insertion order and crossed six times out of nine. Destinations are now placed by the MEAN slot
              of their sources (one barycentric pass), which reproduces the handoff's hand-chosen order on its
              own data. A prettier line over the same tangle would have been worse — it would look deliberate.

              ⛔ THE COLUMN IS CAPPED AT THE DESIGN'S OWN FOUR SLOTS. Unlike the historical handoff, this
              operational graph is complete-or-withheld: it never draws a subset of the filtered inventory. */}
          {visualizing && visualization.kind === "draw" && (() => {
            const { srcs, dsts, shown } = flowProbe;
            const si = (l: string) => srcs.findIndex((n) => n.label === l);
            const di = (l: string) => dsts.findIndex((n) => n.label === l);
            const cy = (i: number) => 54 + i * 68;
            const node = (
              n: { label: string; kind: FlowKind },
              i: number,
              isSrc: boolean,
            ) => {
              const cx = isSrc ? 95 : 505;
              return (
                <g key={(isSrc ? "s" : "d") + n.label}>
                  <rect
                    x={cx - 76}
                    y={cy(i) - 18}
                    width="152"
                    height="36"
                    rx="10"
                    fill="var(--tnx-surface-inset)"
                    stroke="var(--tnx-divider)"
                    strokeWidth="1.4"
                  />
                  <circle
                    cx={cx - 60}
                    cy={cy(i)}
                    r="8"
                    fill="var(--tnx-surface)"
                    stroke="var(--tnx-divider)"
                  />
                  <text
                    x={cx - 60}
                    y={cy(i) + 3}
                    textAnchor="middle"
                    style={{ fontSize: "8px" }}
                    className="fill-slate-400"
                  >
                    {flowGlyph(n.kind)}
                  </text>
                  <text
                    x={cx - 46}
                    y={cy(i) - 2}
                    style={{ fontSize: "10px" }}
                    className="fill-slate-200"
                  >
                    {n.label.length > 18
                      ? n.label.slice(0, 17) + "\u2026"
                      : n.label}
                  </text>
                  <text
                    x={cx - 46}
                    y={cy(i) + 9}
                    style={{ fontSize: "7px", letterSpacing: ".08em" }}
                    className="fill-slate-500"
                  >
                    {flowTag(n.kind)}
                  </text>
                </g>
              );
            };
            return (
              <div className="mt-3">
                {/* ⛔ FIXED 600x312 — ONE USER UNIT IS ONE PIXEL. `w-full` on a viewBox scaled the whole
                    drawing to the container (~1900px), magnifying 152x36 boxes to ~490x130 and truncating
                    every name. THE SCALE IS A CONTRACT: same law, same panel shape, second occurrence after
                    the Sites map. width/height are set explicitly and the SVG is centred, never stretched. */}
                <svg
                  width="600"
                  height="312"
                  viewBox="0 0 600 312"
                  className="mx-auto block max-w-full"
                  role="img"
                  aria-label={`Access flow: ${shown.length} of ${flowRows.length} rules drawn, ${srcs.length} sources to ${dsts.length} destinations`}
                >
                  <defs>
                    <pattern
                      id="tnxPolDots"
                      width="16"
                      height="16"
                      patternUnits="userSpaceOnUse"
                    >
                      <circle
                        cx="1.5"
                        cy="1.5"
                        r="1"
                        fill="var(--tnx-divider)"
                      />
                    </pattern>
                  </defs>
                  <rect
                    x="0"
                    y="0"
                    width="600"
                    height="312"
                    rx="14"
                    fill="url(#tnxPolDots)"
                  />
                  <g className="tnx-flow-edges">
                    {shown.map((r) => {
                      const sy = cy(si(r.src)),
                        dy = cy(di(r.dst));
                      return (
                        <path
                          key={r.id}
                          fill="none"
                          strokeWidth="2"
                          stroke={
                            r.temp ? "var(--tnx-neutral)" : "var(--tnx-accent)"
                          }
                          strokeDasharray={r.temp ? "5 6" : undefined}
                          d={`M170,${sy} C300,${sy} 300,${dy} 430,${dy}`}
                        />
                      );
                    })}
                  </g>
                  {srcs.map((n, i) => node(n, i, true))}
                  {dsts.map((n, i) => node(n, i, false))}
                </svg>
                <div className="mx-auto mt-1 flex max-w-[600px] items-center justify-between text-[10px] text-slate-500">
                  <span>
                    <span className="text-slate-300">&#8212;&#8212;</span>{" "}
                    allow&nbsp;&nbsp;
                    <span className="text-slate-300">- - -</span> temporary
                  </span>
                  <span>All filtered access flows</span>
                </div>
              </div>
            );
          })()}
          {/* ⛔ THE RULES TABLE. Converted from a <ul> so it can be searched, sorted and paged like every
              other roster — 15 rules already overflowed a screen, and the list gave no way to find one.

              ⚠ THE BADGE COLOURS STAY. The founder asked for the mockup's SHAPE without its palette, and
              these are not palette: OUTSIDE RANGES, VANISHED, SOURCE GROUP EMPTY and TEMP are the four
              warn-kinds, each meaning "this rule renders as active and compiles to NOTHING". Draining their
              colour would remove the only thing that distinguishes them from decoration. What did go is the
              mockup's decorative green/blue/purple on Active and Managed-by-GitOps, which carried no state
              this product does not already say in words. */}
          {/* ⛔ THE FAILED COPY IS THE PAGE'S JOB, NOT THE TABLE'S — and forgetting it was one edit away.
              DataTable renders NOTHING when `failed`, deliberately, because only the page knows what to
              retry. Converting this list without this block would have replaced "Rules could not be loaded"
              with a blank area: the screen would say nothing at all about a read that failed, which is the
              reassuring-empty defect wearing its quietest possible face. */}
          {rulesEmptyState({
            rulesResult,
            modeResult,
            renderedCount: rules.length,
          }).kind === "failed" && (
            <p className="mt-3 rounded-md border border-danger/40 bg-danger/5 px-3 py-2 text-xs text-danger">
              {
                rulesEmptyCopy(
                  rulesEmptyState({
                    rulesResult,
                    modeResult,
                    renderedCount: rules.length,
                  }),
                ).text
              }
            </p>
          )}
          <div className="mt-3">
            <DataTable<PolicyRule>
              caption="Rules"
              rows={filteredRules}
              rowKey={(r) => r.id}
              filterable={false}
              // ⛔ THE PAGE OWNS THE EMPTY COPY, because it distinguishes states this component cannot see:
              // an ENFORCING org with zero rules is a lockout warning, not an emptiness.
              failed={
                rulesEmptyState({
                  rulesResult,
                  modeResult,
                  renderedCount: rules.length,
                }).kind === "failed"
              }
              empty={
                filteredRules.length === 0 && rules.length > 0 ? (
                  <span className="text-xs text-slate-500">No loaded rules match this filter.</span>
                ) : (
                  <span
                    className={
                      rulesEmptyState({
                        rulesResult,
                        modeResult,
                        renderedCount: rules.length,
                      }).kind === "enforcing_empty"
                        ? "text-xs font-semibold text-warn"
                        : "text-xs text-slate-500"
                    }
                  >
                    {
                      rulesEmptyCopy(
                        rulesEmptyState({
                          rulesResult,
                          modeResult,
                          renderedCount: rules.length,
                        }),
                      ).text
                    }
                  </span>
                )
              }
              // ⛔ THE VERBS LIVE IN ONE BAR, NOT ON EVERY ROW. Fifteen rules meant forty-five buttons —
              // the same three verbs redrawn fifteen times, crowding out the thing the row is actually
              // about. `unavailable` is what makes that safe rather than merely tidier: a GitOps-managed
              // grant refuses every mutation, and the bar names that BEFORE the click instead of skipping
              // the row afterwards.
              rowActions={
                canManage
                  ? [
                      {
                        key: "edit",
                        label: "Edit",
                        arity: "single",
                        unavailable: (r: PolicyRule) =>
                          grantControls(
                            ruleRow(
                              r,
                              groups,
                              resources,
                              members,
                              sites,
                              loaded,
                              services,
                            ),
                          ).withheld
                            ? managedGrantWarning()
                            : canEditRuleInModal(r)
                              ? null
                              : "This rule's source or destination is not editable here.",
                        run: (rs: PolicyRule[]) => setEditing(rs[0]),
                      },
                      {
                        key: "extend",
                        label: "Extend",
                        arity: "single",
                        unavailable: (r: PolicyRule) =>
                          grantControls(
                            ruleRow(
                              r,
                              groups,
                              resources,
                              members,
                              sites,
                              loaded,
                              services,
                            ),
                          ).withheld
                            ? managedGrantWarning()
                            : grantExpiry(r, Date.now()).extendable
                              ? null
                              : "Only a temporary grant can be extended.",
                        run: (rs: PolicyRule[]) => setExtendingGrant(rs[0]),
                      },
                      {
                        key: "enable",
                        label: "Enable",
                        // F3: enable is ADDITIVE and therefore one click, in bulk as on a single row.
                        unavailable: (r: PolicyRule) =>
                          grantControls(
                            ruleRow(
                              r,
                              groups,
                              resources,
                              members,
                              sites,
                              loaded,
                              services,
                            ),
                          ).withheld
                            ? managedGrantWarning()
                            : r.enabled
                              ? "Already enabled."
                              : null,
                        run: (rs: PolicyRule[]) => {
                          void Promise.all(
                            rs.map((r) => setEnabled(r.id, true)),
                          );
                        },
                      },
                      {
                        key: "disable",
                        label: "Disable",
                        // ⛔ F3'S ASYMMETRIC CEREMONY SURVIVES THE MOVE. Disabling withdraws a live allow in
                        // seconds, so it confirms — and it must still confirm when it is doing so to five
                        // rules at once, which is strictly more consequential than doing it to one.
                        unavailable: (r: PolicyRule) =>
                          grantControls(
                            ruleRow(
                              r,
                              groups,
                              resources,
                              members,
                              sites,
                              loaded,
                              services,
                            ),
                          ).withheld
                            ? managedGrantWarning()
                            : r.enabled
                              ? null
                              : "Already disabled.",
                        run: (rs: PolicyRule[]) => setDisablingRules(rs),
                      },
                      {
                        key: "delete",
                        label: "Delete",
                        danger: true,
                        unavailable: (r: PolicyRule) =>
                          grantControls(
                            ruleRow(
                              r,
                              groups,
                              resources,
                              members,
                              sites,
                              loaded,
                              services,
                            ),
                          ).withheld
                            ? managedGrantWarning()
                            : null,
                        run: (rs: PolicyRule[]) => setDeletingRules(rs),
                      },
                    ]
                  : undefined
              }
              columns={[
                {
                  key: "src",
                  header: "Source",
                  sortValue: (r) =>
                    ruleRow(
                      r,
                      groups,
                      resources,
                      members,
                      sites,
                      loaded,
                      services,
                    ).src.label,
                  cell: (r) => {
                    const row = ruleRow(
                      r,
                      groups,
                      resources,
                      members,
                      sites,
                      loaded,
                      services,
                    );
                    return (
                      <RefText
                        label={row.src.label}
                        broken={row.src.state !== "ok"}
                      />
                    );
                  },
                },
                {
                  key: "arrow",
                  header: "",
                  cell: () => (
                    <span aria-hidden className="text-slate-600">
                      →
                    </span>
                  ),
                },
                {
                  key: "dst",
                  header: "Destination",
                  sortValue: (r) =>
                    ruleRow(
                      r,
                      groups,
                      resources,
                      members,
                      sites,
                      loaded,
                      services,
                    ).dst.label,
                  cell: (r) => {
                    const row = ruleRow(
                      r,
                      groups,
                      resources,
                      members,
                      sites,
                      loaded,
                      services,
                    );
                    return (
                      <RefText
                        label={row.dst.label}
                        broken={row.dst.state !== "ok"}
                      />
                    );
                  },
                },
                {
                  key: "status",
                  header: "Status",
                  // ⛔ THE WORD, NOT THE STYLING. A disabled rule used to be signalled by opacity on the
                  // whole row; opacity is invisible to a search and to anyone who cannot see it.
                  sortValue: (r) => (r.enabled ? "active" : "disabled"),
                  cell: (r) =>
                    r.enabled ? (
                      <span className="text-xs text-slate-400">active</span>
                    ) : (
                      /* F3: a disabled rule is shown DISTINCTLY, never hidden — the list must not lie
                         about what is enforcing. */
                      <span className="rounded-full border border-slate-700 bg-slate-800/80 px-2 py-0.5 font-mono text-[10px] font-semibold text-slate-400">
                        disabled
                      </span>
                    ),
                },
                {
                  key: "type",
                  header: "Type",
                  sortValue: (r) => {
                    const row = ruleRow(
                      r,
                      groups,
                      resources,
                      members,
                      sites,
                      loaded,
                      services,
                    );
                    if (row.managedByAgentAccess)
                      return "managed by jit access";
                    if (row.managedByAgentTemplate)
                      return "managed by agent template";
                    if (row.managedByOperator) return "managed by gitops";
                    return grantExpiry(r, Date.now()).state === "permanent"
                      ? "standard"
                      : "temporary";
                  },
                  cell: (r) => {
                    const row = ruleRow(
                      r,
                      groups,
                      resources,
                      members,
                      sites,
                      loaded,
                      services,
                    );
                    /* S10.2 D2 cond 1: a GitOps-managed grant is badged; its mutation controls are
                       withheld in the actions column. */
                    if (row.managedByAgentAccess)
                      return (
                        <a href={row.agentAccessRequestId ? `#jit-request-${row.agentAccessRequestId}` : undefined} className="rounded-full border border-violet-800/50 bg-violet-950/40 px-2 py-0.5 font-mono text-[10px] font-semibold text-violet-300">
                          JIT access
                        </a>
                      );
                    if (row.managedByAgentTemplate)
                      return (
                        <span className="rounded-full border border-sky-800/50 bg-sky-950/40 px-2 py-0.5 font-mono text-[10px] font-semibold text-sky-300">
                          Managed by agent template
                        </span>
                      );
                    if (row.managedByOperator) return <ManagedBadge />;
                    const exp = grantExpiry(r, Date.now());
                    return exp.state === "permanent" ? (
                      <span className="text-xs text-slate-600">standard</span>
                    ) : (
                      /* S7.5.4 linger model: a temporary grant shows its window; an EXPIRED grant stays
                         visible (audit history), rendered distinctly — never hidden. */
                      <span
                        className={`rounded-full border px-2 py-0.5 font-mono text-[10px] font-semibold ${exp.state === "expired" ? "border-rose-800/50 bg-rose-950/40 text-rose-400" : "border-amber-800/50 bg-amber-950/40 text-amber-300"}`}
                      >
                        TEMP · {exp.label}
                      </span>
                    );
                  },
                },
                {
                  key: "notes",
                  header: "Notes",
                  // ⚠ EVERY WARN KIND IS SEARCHABLE BY ITS OWN WORDS. These are the states an operator most
                  // needs to find — each one means a rule that reads ACTIVE and compiles to NOTHING — and a
                  // badge contributes no text, so without this they would be the least findable rows here.
                  sortValue: (r) => {
                    const row = ruleRow(
                      r,
                      groups,
                      resources,
                      members,
                      sites,
                      loaded,
                      services,
                    );
                    const empty =
                      (r.src_kind ?? "group") === "group" && r.src_group_id
                        ? srcGroupEmptyBadge(
                            srcGroupEmptyWarn(
                              srcGroupCounts.get(r.src_group_id),
                            ),
                          )
                        : null;
                    return [
                      row.cidrOutsideRanges ? "outside ranges" : "",
                      row.k8sServiceVanished ? "vanished" : "",
                      row.fqdnPendingCompiler ? "pending compiler no traffic" : "",
                      empty ?? "",
                    ]
                      .filter(Boolean)
                      .join(" ");
                  },
                  cell: (r) => {
                    const row = ruleRow(
                      r,
                      groups,
                      resources,
                      members,
                      sites,
                      loaded,
                      services,
                    );
                    const emptyBadge =
                      (r.src_kind ?? "group") === "group" && r.src_group_id
                        ? srcGroupEmptyBadge(
                            srcGroupEmptyWarn(
                              srcGroupCounts.get(r.src_group_id),
                            ),
                          )
                        : null;
                    return (
                      <span className="flex flex-wrap items-center gap-1">
                        {/* S8.7 warn-not-refuse (D1): the SERVER's read-time judgment, rendered verbatim —
                            a CIDR rule matching no current org range. Self-clears when a range lands. */}
                        {row.cidrOutsideRanges && (
                          <span
                            className="rounded-full border border-amber-800/50 bg-amber-950/40 px-2 py-0.5 font-mono text-[10px] font-semibold text-amber-400"
                            title="This CIDR is inside no current site subnet. the rule matches nothing until the range is declared."
                          >
                            OUTSIDE RANGES
                          </span>
                        )}
                        {/* S10.3 warn-not-refuse: the dst Service was unexposed or its cluster
                            deregistered, so the grant compiles to nothing. Self-clears if it returns. */}
                        {row.k8sServiceVanished && (
                          <span
                            className="rounded-full border border-rose-800/50 bg-rose-950/40 px-2 py-0.5 font-mono text-[10px] font-semibold text-rose-400"
                            title="The Kubernetes Service this rule reaches is no longer exposed. the grant matches nothing until it is re-exposed."
                          >
                            VANISHED
                          </span>
                        )}
                        {row.fqdnPendingCompiler && (
                          <span
                            className="rounded-full border border-warn/40 bg-warn/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-warn"
                            title="The server reports this FQDN destination is pending compiler. It is stored safely but grants no traffic in this release."
                          >
                            PENDING COMPILER · NO TRAFFIC
                          </span>
                        )}
                        {/* ⛔ src_group_empty (S14.12) — measured at compiler.go:399: a group with zero
                            members matches NO device, so this rule COMPILES TO NOTHING while rendering
                            ACTIVE. Derived from the member COUNT, never from group existence, and it does
                            NOT fire while the count is unfetched or failed — "could not check" is not
                            "empty". */}
                        {emptyBadge && (
                          <span
                            className="rounded-full border border-warn/40 bg-warn/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-warn"
                            title={
                              srcGroupEmptyExplain(
                                srcGroupEmptyWarn(
                                  srcGroupCounts.get(r.src_group_id as string),
                                ),
                              ) ?? undefined
                            }
                          >
                            {emptyBadge}
                          </span>
                        )}
                      </span>
                    );
                  },
                },
              ]}
            />
          </div>
        </>
      )}

      {(creating || editing) && (
        <RuleFormModal
          orgId={orgId}
          groups={groups}
          resources={resources}
          fqdnResources={fqdnResources}
          members={activeMembers(members)}
          sites={sites}
          services={services}
          agents={visibleAgents}
          editing={editing}
          onClose={() => {
            setCreating(false);
            setEditing(null);
          }}
          onDone={(staleId) => {
            // A partial swap adds the un-deleted rule id to the set; a clean create adds
            // nothing (so it can never drop a live warning — [371]).
            if (staleId)
              setStaleRuleIds((prev) =>
                prev.includes(staleId) ? prev : [...prev, staleId],
              );
            setCreating(false);
            setEditing(null);
            load();
          }}
        />
      )}
      {extendingGrant && (
        <ExtendGrantModal
          orgId={orgId}
          rule={extendingGrant}
          onClose={() => setExtendingGrant(null)}
          onDone={() => {
            setExtendingGrant(null);
            load();
          }}
        />
      )}
      {/* F3: the disable-confirm — NAMES the rule's own subject→destination + the immediate effect. Only
          disable gets this (enable is one-click). Danger-styled; Cancel or backdrop dismisses. */}
      {disablingRules.length > 0 &&
        (() => {
          const rs = disablingRules;
          const one = rs.length === 1 ? rs[0] : null;
          const row = one
            ? ruleRow(one, groups, resources, members, sites, loaded, services)
            : null;
          return (
            <Modal
              title={
                rs.length === 1
                  ? "Disable rule?"
                  : `Disable ${rs.length} rules?`
              }
              danger
              onDismiss={() => setDisablingRules([])}
              actions={
                <>
                  <Button variant="ghost" onClick={() => setDisablingRules([])}>
                    Cancel
                  </Button>
                  <Button
                    variant="danger"
                    onClick={async () => {
                      setDisablingRules([]);
                      await Promise.all(rs.map((r) => setEnabled(r.id, false)));
                    }}
                  >
                    Disable
                  </Button>
                </>
              }
            >
              {/* ⚠ ONE RULE STILL NAMES ITSELF. The single-rule sentence was specific — which source loses
                  which destination — and a plural rewrite that dropped it would make the common case vaguer
                  in order to serve the rare one. */}
              {row ? (
                <p className="text-sm text-slate-300">
                  {disableConfirmText(row.src.label, row.dst.label)}
                </p>
              ) : (
                <div className="text-sm text-slate-300">
                  <p>
                    These allow rules stop applying within seconds. Access they
                    grant is withdrawn.
                  </p>
                  {/* ⛔ THE SET IS SHOWN, NOT COUNTED. "Disable 5 rules?" asks the operator to trust their
                      own memory of a selection they made across pages and filters. */}
                  <ul className="mt-2 max-h-48 space-y-0.5 overflow-y-auto text-xs text-slate-400">
                    {rs.map((r) => {
                      const rr = ruleRow(
                        r,
                        groups,
                        resources,
                        members,
                        sites,
                        loaded,
                        services,
                      );
                      return (
                        <li key={r.id}>
                          {rr.src.label} → {rr.dst.label}
                        </li>
                      );
                    })}
                  </ul>
                </div>
              )}
            </Modal>
          );
        })()}

      {deletingRules.length > 0 && (
        <Modal
          title={
            deletingRules.length === 1
              ? "Delete rule?"
              : `Delete ${deletingRules.length} rules?`
          }
          danger
          onDismiss={() => setDeletingRules([])}
          actions={
            <>
              <Button variant="ghost" onClick={() => setDeletingRules([])}>
                Cancel
              </Button>
              <Button
                variant="danger"
                onClick={async () => {
                  const rs = deletingRules;
                  setDeletingRules([]);
                  for (const r of rs) await del(r.id);
                }}
              >
                Delete
              </Button>
            </>
          }
        >
          <div className="text-sm text-slate-300">
            <p>
              Deleting is permanent. Disabling keeps the rule and its history —
              prefer it if you may want this access back.
            </p>
            <ul className="mt-2 max-h-48 space-y-0.5 overflow-y-auto text-xs text-slate-400">
              {deletingRules.map((r) => {
                const rr = ruleRow(
                  r,
                  groups,
                  resources,
                  members,
                  sites,
                  loaded,
                  services,
                );
                return (
                  <li key={r.id}>
                    {rr.src.label} → {rr.dst.label}
                  </li>
                );
              })}
            </ul>
          </div>
        </Modal>
      )}
    </Card>
  );
}

// ExtendGrantModal moves a temporary grant's window forward (S7.5.4). A LAPSED grant is
// refused by the server (409 grant_lapsed) — surfaced legibly here, not as a raw error;
// this is a WINDOW BUMP (PUT expires_at), never a delete+recreate.
function ExtendGrantModal({
  orgId,
  rule,
  onClose,
  onDone,
}: {
  orgId: string;
  rule: PolicyRule;
  onClose: () => void;
  onDone: () => void;
}) {
  const now = grantExpiry(rule, Date.now());
  const [when, setWhen] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit() {
    setBusy(true);
    setErr(null);
    const iso = new Date(when).toISOString();
    const { error } = await api.PUT(
      "/api/v1/organizations/{orgId}/policies/{ruleId}",
      {
        params: { path: { orgId, ruleId: rule.id } },
        body: { expires_at: iso },
      },
    );
    setBusy(false);
    if (error) return setErr(extendErrorCopy(apiErrorCode(error))); // 409 grant_lapsed / not_temporary → legible copy
    onDone();
  }

  return (
    <Modal
      title="Extend grant"
      onDismiss={onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button disabled={busy || !when} onClick={submit}>
            Extend
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        <p className="text-xs text-slate-400">
          {now.state === "expired"
            ? `This grant ${now.label}. Extending a lapsed grant is refused. create a new grant instead.`
            : `This grant ${now.label}. Move its expiry to a later time (the grant is not re-created. only its window moves).`}
        </p>
        <Field label="New expiry">
          <Input
            type="datetime-local"
            value={when}
            onChange={(e) => setWhen(e.target.value)}
          />
        </Field>
        <ErrorText>{err}</ErrorText>
      </div>
    </Modal>
  );
}

function RefText({ label, broken }: { label: string; broken: boolean }) {
  return broken ? (
    <span className="text-amber-400">⚠ {label}</span>
  ) : (
    <span>{label}</span>
  );
}

// RuleFormModal creates OR edits a rule. Editing = CREATE-THEN-DELETE (D-a5) via swapRule —
// gap-free (allow-only union), never delete-first, with a LEGIBLE partial on delete-fail.
function RuleFormModal({
  orgId,
  groups,
  resources,
  fqdnResources,
  members,
  sites,
  services,
  agents,
  editing,
  onClose,
  onDone,
}: {
  orgId: string;
  groups: UserGroup[];
  resources: Resource[];
  fqdnResources: FQDNResource[];
  members: Member[];
  sites: Site[];
  services: K8sService[];
  agents: Array<{ device_id: string; name: string; gateway_name: string }>;
  editing: PolicyRule | null;
  onClose: () => void;
  onDone: (staleRuleId?: string) => void;
}) {
  // S8.2c D5: the modal now CREATES site-source + site-dest rules too (was API-only). src_kind ∈
  // {group,user,site}; dst_kind ∈ {group,resource,site} — all through the same policies API (validation +
  // audit intact; the demo's raw DB insert was the anti-pattern this closes).
  // Review #4: when the org has sites but no groups, defaulting to "group" opens a modal that can't submit
  // (empty group select) until BOTH dropdowns are flipped — a dead end. Default to the kind that's actually
  // available so a fresh site-to-site org can Create immediately.
  const hasGroups = groups.length > 0;
  // ⛔ S15.3 — agents enrolled in this org, offered as a policy SOURCE. Without this the AI-agents screen
  // says an agent "reaches only what it is granted" and nothing could grant it anything: a capability the
  // product had and the operator could not reach.
  const [srcAgent, setSrcAgent] = useState(
    editing?.src_device_id ?? agents[0]?.device_id ?? "",
  );
  const visibleAgents = agents;
  const [srcKind, setSrcKind] = useState<
    "group" | "user" | "site" | "cidr" | "agent"
  >(
    defaultSrcKind({
      editingKind:
        editing?.src_kind === "user"
          ? "user"
          : editing?.src_kind === "site"
            ? "site"
            : editing?.src_kind === "cidr"
              ? "cidr"
              : editing?.src_kind === "agent"
                ? "agent"
                : undefined,
      hasGroups,
      hasSites: sites.length > 0,
      hasAgents: agents.length > 0,
    }),
  );
  const [src, setSrc] = useState(editing?.src_group_id ?? groups[0]?.id ?? "");
  const [srcUser, setSrcUser] = useState(
    editing?.src_user_id ?? members[0]?.user_id ?? "",
  );
  const [srcSite, setSrcSite] = useState(
    editing?.src_site_id ?? sites[0]?.id ?? "",
  );
  const [srcCidr, setSrcCidr] = useState(editing?.src_cidr ?? ""); // S8.7: literal source CIDR (free-text)
  // Default to the first dst kind that HAS options (re-review #4: the src-side fix left the dst side able to
  // dead-end — a no-groups org with resources/sites opened on "group" with an empty select, un-submittable).
  const [dstKind, setDstKind] = useState<
    "group" | "resource" | "site" | "k8s_service" | "fqdn_resource"
  >(
    editing?.dst_kind === "k8s_service"
      ? "k8s_service"
      : editing?.dst_kind === "fqdn_resource"
        ? "fqdn_resource"
      : defaultDstKind({
          editingKind:
            editing?.dst_kind === "resource"
              ? "resource"
              : editing?.dst_kind === "site"
                ? "site"
                : editing?.dst_kind === "fqdn_resource"
                  ? "fqdn_resource"
                  : undefined,
          hasGroups,
          hasResources: resources.length > 0,
          hasSites: sites.length > 0,
          hasFQDNResources: fqdnResources.length > 0,
        }),
  );
  const [dstGroup, setDstGroup] = useState(
    editing?.dst_group_id ?? groups[0]?.id ?? "",
  );
  const [dstResource, setDstResource] = useState(
    editing?.dst_resource_id ?? resources[0]?.id ?? "",
  );
  const [dstSite, setDstSite] = useState(
    editing?.dst_site_id ?? sites[0]?.id ?? "",
  );
  const [dstK8sService, setDstK8sService] = useState(
    editing?.dst_k8s_service_id ?? services[0]?.id ?? "",
  ); // S10.3
  const [dstFQDNResource, setDstFQDNResource] = useState(
    editing?.dst_fqdn_resource_id ?? fqdnResources[0]?.id ?? "",
  );
  // Temporary grant: an optional expiry (datetime-local). Empty = permanent.
  // Expiry is a CREATE-only field ([2]/[3] fix): editing a rule is create-then-delete, and a
  // same-(src,dst) edit carrying an expiry collides on the unique index (or resubmits a past
  // expiry). Changing a temporary grant's window goes through Extend (a window bump), not Edit.
  const [expiresAt, setExpiresAt] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  function bodyFor(): CreatePolicyRuleRequest {
    return ruleBody({
      srcKind,
      dstKind,
      src,
      srcUser,
      srcAgent,
      srcSite,
      srcCidr,
      dstGroup,
      dstResource,
      dstSite,
      dstK8sService,
      dstFQDNResource,
      expiresAt,
      editing: !!editing,
    });
  }

  async function submit() {
    setBusy(true);
    setErr(null);
    // [8]: guard a 2xx-with-no-body — never let (data).id throw and strand busy=true.
    const create = async (): Promise<{ id: string } | { error: unknown }> => {
      const { data, error } = await api.POST(
        "/api/v1/organizations/{orgId}/policies",
        {
          params: { path: { orgId } },
          body: bodyFor(),
        },
      );
      if (error) return { error };
      const id = (data as PolicyRule | undefined)?.id;
      if (!id)
        return { error: { error: { message: "Server returned no rule id." } } };
      return { id };
    };

    if (!editing) {
      const created = await create();
      setBusy(false);
      if ("error" in created)
        return setErr(
          apiErrorMessage(created.error, "Could not create the rule."),
        );
      return onDone();
    }

    const out = await swapRule(editing.id, create, async (id) =>
      api.DELETE("/api/v1/organizations/{orgId}/policies/{ruleId}", {
        params: { path: { orgId, ruleId: id } },
      }),
    );
    setBusy(false);
    if (out.outcome === "create_failed")
      return setErr(
        apiErrorMessage(out.error, "Could not create the new rule."),
      );
    if (out.outcome === "partial") return onDone(out.oldId); // notice derived from the id (staleNoticeText)
    onDone();
  }

  return (
    <Modal
      title={editing ? "Edit rule" : "Add rule"}
      size="wide"
      onDismiss={onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            disabled={
              busy ||
              !ruleSourceReady({
                kind: srcKind,
                group: src,
                user: srcUser,
                site: srcSite,
                cidr: srcCidr,
                agent: srcAgent,
              }) ||
              (dstKind === "group"
                ? !dstGroup
                : dstKind === "resource"
                  ? !dstResource
                  : dstKind === "k8s_service"
                    ? !dstK8sService
                    : dstKind === "fqdn_resource"
                      ? !dstFQDNResource
                      : !dstSite)
            }
            onClick={submit}
          >
            {editing ? "Save" : "Create"}
          </Button>
        </>
      }
    >
      <div className="space-y-3">
        {/* S8.3 CP layout: source + destination each read as a labeled panel (was a flat field list),
            so the "who → what" of a rule is legible at a glance. Layout only — no behavior change. */}
        {/* ⛔ ONE PICKER PER SIDE. Four controls became two, and the KIND stopped being a thing you choose
            first — you look for "Engineering", you do not first decide that Engineering is a Group. The
            cascade let a source type be chosen against any destination type, which is how a site reaching
            itself became creatable; here the other side's choice is reflected in what this side offers.

            ⚠ THE GUARD IS THE SERVER'S (invalid_rule_self_site). This mirrors it — the CLI and the GitOps CR
            path reach the same API and never see this form, so a picker that merely hid the option would be
            guarding one caller of three. What the picker adds is the EXPLANATION. */}
        <EntityPicker
          label="Source"
          placeholder="Search groups, people, sites, agents… or type a CIDR"
          acceptCidr
          value={
            srcKind === "group"
              ? src
              : srcKind === "user"
                ? srcUser
                : srcKind === "site"
                  ? srcSite
                  : srcKind === "agent"
                    ? srcAgent
                    : srcCidr
          }
          options={sourceOptions({
            groups,
            members,
            sites,
            agents: visibleAgents,
            dstKind,
            dstSite,
          })}
          onSelect={(o) => {
            setSrcKind(o.kind as typeof srcKind);
            if (o.kind === "group") setSrc(o.value);
            else if (o.kind === "user") setSrcUser(o.value);
            else if (o.kind === "site") setSrcSite(o.value);
            else if (o.kind === "agent") setSrcAgent(o.value);
            else setSrcCidr(o.value);
          }}
        />
        {dstKind === "fqdn_resource" && (
          <p role="status" className="rounded-md border border-warn/40 bg-warn/5 px-3 py-2 text-xs text-warn">
            Pending compiler — this FQDN destination is stored as a rule reference, but the server reports that this release does not compile it into enforcement. It grants no traffic.
          </p>
        )}
        <EntityPicker
          label="Destination"
          placeholder="Search groups, resources, FQDN resources, sites, services…"
          value={
            dstKind === "group"
              ? dstGroup
              : dstKind === "resource"
                ? dstResource
                : dstKind === "site"
                  ? dstSite
                  : dstKind === "k8s_service"
                    ? dstK8sService
                    : dstFQDNResource
          }
          options={destinationOptions({
            groups,
            resources,
            sites,
            services,
            fqdnResources,
            srcKind,
            srcSite,
          })}
          onSelect={(o) => {
            setDstKind(o.kind as typeof dstKind);
            if (o.kind === "group") setDstGroup(o.value);
            else if (o.kind === "resource") setDstResource(o.value);
            else if (o.kind === "site") setDstSite(o.value);
            else if (o.kind === "k8s_service") setDstK8sService(o.value);
            else setDstFQDNResource(o.value);
          }}
        />
        {/* ⛔ WHAT THE RULE WILL DO, IN WORDS, BEFORE Create. Two pickers and a button let an operator
            choose two nouns and press go; nothing in that gesture says what the compiler will emit. The gap
            is enormous — "agent rajan → group Contractors" grants ONE MACHINE UNRESTRICTED ACCESS TO EVERY
            DEVICE OWNED BY EVERY CONTRACTOR, because a group destination is port-unscoped by construction
            (compiler.go:442, Protocol: ProtoAny).

            ⚠ A DESCRIPTION, NEVER A REFUSAL. Every pair compiles and every one has a legitimate use. The
            form's job is that the operator cannot be SURPRISED by their own rule. */}
        {(() => {
          const srcLabel =
            sourceOptions({
              groups,
              members,
              sites,
              agents: visibleAgents,
              dstKind,
              dstSite,
            }).find(
              (o) =>
                o.kind === srcKind &&
                o.value ===
                  (srcKind === "group"
                    ? src
                    : srcKind === "user"
                      ? srcUser
                      : srcKind === "site"
                        ? srcSite
                        : srcKind === "agent"
                          ? srcAgent
                          : srcCidr),
            )?.label ?? (srcKind === "cidr" ? srcCidr : "");
          const dstLabel =
            destinationOptions({
              groups,
              resources,
              sites,
              services,
              fqdnResources,
              srcKind,
              srcSite,
            }).find(
              (o) =>
                o.kind === dstKind &&
                o.value ===
                  (dstKind === "group"
                    ? dstGroup
                    : dstKind === "resource"
                      ? dstResource
                      : dstKind === "site"
                        ? dstSite
                        : dstKind === "k8s_service"
                          ? dstK8sService
                          : dstFQDNResource),
            )?.label ?? "";
          if (!srcLabel || !dstLabel) return null;
          const eff = ruleEffectSummary({
            srcKind,
            srcLabel,
            dstKind,
            dstLabel,
          });
          const caution = ruleEffectCaution(srcKind, dstKind);
          return (
            <div
              data-testid="rule-effect"
              className={`rounded-md border px-3 py-2 text-xs ${eff.wide ? "border-warn/40 bg-warn/5 text-warn" : "border-white/10 bg-white/5 text-ink-body"}`}
            >
              {eff.text}
              {/* ⚠ THE EXTRA SENTENCE FOR THE ONE SHAPE THAT IS USUALLY A MISTAKE — attached to it alone,
                  because a caution on every rule is a caution nobody reads. */}
              {caution && (
                <span className="mt-1 block text-ink-secondary">{caution}</span>
              )}
            </div>
          );
        })()}
        {/* Temporary grant (CREATE only): set an expiry to auto-revoke; empty = permanent.
            Editing an existing rule changes its src/dst; change a temporary grant's window
            with Extend (a window bump), not Edit. */}
        {!editing && (
          <Field label="Expires (optional. leave empty for a permanent grant)">
            <Input
              type="datetime-local"
              value={expiresAt}
              onChange={(e) => setExpiresAt(e.target.value)}
            />
          </Field>
        )}
        <ErrorText>{err}</ErrorText>
      </div>
    </Modal>
  );
}
