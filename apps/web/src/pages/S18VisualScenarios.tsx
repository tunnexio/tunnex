import { useLayoutEffect } from "react";
import type { Org } from "../lib/api";
import { AuthProvider } from "../lib/auth";
import { OrgProvider } from "../lib/useOrg";
import { AddAgentFlow, type AddAgentVisualStage } from "../components/AddAgentFlow";
import AgentDetail, { type AgentDetailFixture } from "./AgentDetail";
import AgentsIndex, { type AgentsIndexFixture } from "./AgentsIndex";
import AgentsMCP from "./AgentsMCP";
import AgentsPolicyTemplates from "./AgentsPolicyTemplates";
import Access from "./Access";

/**
 * Development-only S18 state harness. It deliberately mounts the real route
 * component behind the real org seam and replaces only its transport. Keep
 * fixture facts here, not in a second copy of the Agents UI.
 */
export type S18IndexScenario =
  | "index-populated"
  | "index-empty"
  | "index-loading"
  | "index-error"
  | "index-partial"
  | "index-denied"
  | "index-community"
  | "index-filtered";

export type S18ManagementScenario =
  | "policies-empty" | "policies-populated" | "policies-loading" | "policies-error" | "policies-denied"
  | "mcp-empty" | "mcp-populated" | "mcp-inherited" | "mcp-unobserved" | "mcp-loading" | "mcp-error" | "mcp-denied";

export type S18RulesScenario =
  | "rules-populated"
  | "rules-empty"
  | "rules-error"
  | "rules-denied";

export type S18VisualScenario = S18IndexScenario | S18ManagementScenario | S18RulesScenario | "detail-overview" | "detail-runtime" | "detail-mcp" | "detail-access" | "detail-activity" | "add-details" | "add-review" | "add-token" | "add-waiting";

const ORG: Org = {
  id: "11111111-1111-4111-8111-111111111111",
  name: "S18 review organization",
  slug: "s18-review",
  pool_cidr: "10.99.0.0/24",
  max_agent_identities: null,
  managed_agent_runtime_enabled: true,
  agent_policy_templates_enabled: true,
  agent_jit_access_enabled: true,
  created_at: "2026-08-23T12:00:00Z",
  updated_at: "2026-08-23T12:00:00Z",
};

const ROWS = [
  { device_id: "11111111-1111-4111-8111-111111111101", name: "jira-prod", owner_email: "ops@demo.tunnex.local", unattributable: false, address: "10.99.0.41", gateway_name: "us-east-gw", config_issued: true, online: true, last_handshake_at: "2026-08-23T11:59:30Z", gateway_reporting: true, status: "active" },
  { device_id: "11111111-1111-4111-8111-111111111102", name: "support-triage", owner_email: "secops@demo.tunnex.local", unattributable: false, address: "10.99.0.42", gateway_name: "us-east-gw", config_issued: true, online: false, last_handshake_at: "2026-08-22T11:59:30Z", gateway_reporting: true, status: "active" },
  { device_id: "11111111-1111-4111-8111-111111111103", name: "release-bot", owner_email: null, unattributable: true, address: "10.99.0.43", gateway_name: "eu-west-gw", config_issued: true, online: false, last_handshake_at: null, gateway_reporting: false, status: "active" },
];

function json(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
}

function routeResponse(scenario: S18VisualScenario, url: URL, init?: RequestInit): Promise<Response> {
  if (url.pathname === "/api/v1/auth/me") return Promise.resolve(json({ id: "11111111-1111-4111-8111-111111111001", email: "owner@s18.fixture", email_verified: true }));
  if (url.pathname === "/api/v1/organizations") return Promise.resolve(json([ORG]));
  if (url.pathname === "/api/v1/license") return Promise.resolve(json({ state: "unlicensed", tier: "community", gateway_ceiling: 1, gateways_in_use: 0, features: [] }));
  if (url.pathname.endsWith("/members")) return Promise.resolve(json([{ user_id: "11111111-1111-4111-8111-111111111001", role: scenario === "policies-denied" || scenario === "rules-denied" ? "member" : "admin", email_verified: true }]));
  if (url.pathname.endsWith("/policies")) {
    if (scenario === "rules-error") return Promise.resolve(json({ error: { code: "service_unavailable", message: "Rules inventory is unavailable." } }, 503));
    return Promise.resolve(json(scenario === "rules-empty" ? [] : [
      { id: "11111111-1111-4111-8111-111111111801", enabled: true, src_kind: "group", src_group_id: "11111111-1111-4111-8111-111111111901", dst_kind: "resource", dst_resource_id: "11111111-1111-4111-8111-111111111902" },
    ]));
  }
  if (url.pathname.endsWith("/zero-trust-mode")) return Promise.resolve(json({ mode: "enforcing" }));
  if (url.pathname.endsWith("/groups")) return Promise.resolve(json([{ id: "11111111-1111-4111-8111-111111111901", name: "Operations", description: "", member_count: 3, created_at: "2026-08-23T10:00:00Z", updated_at: "2026-08-23T10:00:00Z" }]));
  if (url.pathname.endsWith("/agent-policy-templates")) {
    if (scenario === "policies-loading") return new Promise<Response>(() => {});
    if (scenario === "policies-error" || scenario === "policies-denied") return Promise.resolve(json({ error: { code: scenario === "policies-denied" ? "permission_denied" : "service_unavailable", message: "Policy template inventory is unavailable." } }, scenario === "policies-denied" ? 403 : 503));
    return Promise.resolve(json(scenario === "policies-populated" ? [{ id: "11111111-1111-4111-8111-111111111601", name: "Production resources", created_at: "2026-08-23T10:00:00Z", updated_at: "2026-08-23T10:00:00Z" }] : []));
  }
  if (url.pathname.endsWith("/agent-policy-template-assignments")) return Promise.resolve(json([]));
  if (url.pathname.endsWith("/resources")) return Promise.resolve(json([{ id: "11111111-1111-4111-8111-111111111902", name: "Production database", cidr: "10.88.0.0/24", protocol: "tcp", created_at: "2026-08-23T10:00:00Z", updated_at: "2026-08-23T10:00:00Z" }]));
  if (url.pathname.endsWith("/agent-mcp-profiles")) {
    if (scenario === "mcp-loading") return new Promise<Response>(() => {});
    if (scenario === "mcp-error" || scenario === "mcp-denied") return Promise.resolve(json({ error: { code: scenario === "mcp-denied" ? "permission_denied" : "service_unavailable", message: "MCP profile inventory is unavailable." } }, scenario === "mcp-denied" ? 403 : 503));
    return Promise.resolve(json(["mcp-populated", "mcp-inherited", "mcp-unobserved"].includes(scenario) ? [{ id: "11111111-1111-4111-8111-111111111701", org_id: ORG.id, name: "Jira tools", endpoint: "https://mcp.fixture.example/jira", created_at: "2026-08-23T10:00:00Z", updated_at: "2026-08-23T10:00:00Z", archived_at: null }] : []));
  }
  if (url.pathname.endsWith("/agent-mcp-assignments")) return Promise.resolve(json(scenario === "mcp-inherited" ? [{ id: "11111111-1111-4111-8111-111111111702", org_id: ORG.id, profile_id: "11111111-1111-4111-8111-111111111701", profile_name: "Jira tools", group_id: "11111111-1111-4111-8111-111111111301", group_name: "Production assistants", state: "active", assigned_at: "2026-08-23T10:00:00Z", ended_at: null, quarantine_reason: null }] : []));
  if (url.pathname.endsWith("/agent-groups")) return Promise.resolve(json([{ id: "11111111-1111-4111-8111-111111111301", name: "Production assistants", created_at: "2026-08-23T10:00:00Z", updated_at: "2026-08-23T10:00:00Z" }]));
  if (url.pathname.endsWith("/agents")) {
    if (scenario === "index-loading") return new Promise<Response>(() => {});
    if (scenario === "index-denied") return Promise.resolve(json({ error: { code: "permission_denied", message: "You do not have permission to view AI Agents." } }, 403));
    if (scenario === "index-error") return Promise.resolve(json({ error: { code: "service_unavailable", message: "The inventory service is unavailable." } }, 503));
    const filtered = scenario === "index-filtered" ? [ROWS[1]] : ROWS;
    return Promise.resolve(json({ items: scenario === "index-empty" ? [] : filtered, next_cursor: null, partial: scenario === "index-partial" }));
  }
  if (url.pathname.endsWith("/nodes")) return Promise.resolve(json([{ id: "11111111-1111-4111-8111-111111111201", name: "us-east-gw", status: "active" }]));
  if (url.pathname.endsWith("/agents/bootstrap-token") && init?.method === "POST") return Promise.resolve(json({ bootstrap_token: "tnx_fixture_one_time_token", release: { tag: "v0.0.0-fixture", source_sha: "fixture", manifest_url: "https://example.invalid/release.json", verifier_key_id: "fixture", verifier_public_key: "fixture", runtime: { version: "fixture" } } }));
  return Promise.resolve(json({ error: { code: "fixture_unhandled", message: `Unhandled fixture request: ${url.pathname}` } }, 500));
}

function FixtureTransport({ scenario, children }: { scenario: S18VisualScenario; children: React.ReactNode }) {
  useLayoutEffect(() => {
    const original = window.fetch;
    window.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url, window.location.origin);
      return routeResponse(scenario, url, init);
    }) as typeof window.fetch;
    return () => { window.fetch = original; };
  }, [scenario]);
  return <>{children}</>;
}

export function S18IndexVisualScenario({ scenario }: { scenario: S18IndexScenario }) {
  const fixture: AgentsIndexFixture = {
    state: scenario === "index-loading" ? { kind: "loading" }
      : scenario === "index-denied" ? { kind: "denied" }
      : scenario === "index-error" ? { kind: "failed", message: "The inventory service is unavailable." }
      : { kind: "ready", canEnroll: true, canManageMCP: true, page: { items: scenario === "index-empty" ? [] : scenario === "index-filtered" ? [ROWS[1]] : ROWS, next_cursor: null, partial: scenario === "index-partial" } },
  };
  return <FixtureTransport scenario={scenario}><AuthProvider><OrgProvider><AgentsIndex fixture={fixture} /></OrgProvider></AuthProvider></FixtureTransport>;
}

const DETAIL_FIXTURE: AgentDetailFixture = {
  profile: {
    device_id: ROWS[0].device_id,
    name: ROWS[0].name,
    environment: "production",
    runtime: "managed",
    labels: { service: "jira", owner: "platform" },
    owner_id: "11111111-1111-4111-8111-111111111001",
    owner_email: "ops@demo.tunnex.local",
    managing_group_id: "11111111-1111-4111-8111-111111111301",
    managing_group_name: "Production assistants",
    status: "active",
    last_handshake_at: "2026-08-23T11:59:30Z",
    rx_bytes: 1200,
    tx_bytes: 3400,
    permissions: { view_privileged: true, manage: true, assign: true, grant_access: true, revoke: true, rotate_credentials: true },
  },
  runtime: { device_id: ROWS[0].device_id, desired_revision: 9, applied_revision: 8, last_attempted_revision: 9, client_version: "1.4.0", connectivity: "connected", health: "last_good", stale: true, last_seen_at: "2026-08-23T11:50:00Z", last_error_code: "apply_failed", last_error_revision: 9 },
  inventory: { device_id: ROWS[0].device_id, observed_at: "2026-08-23T11:50:00Z", snapshot: { servers: [{ name: "jira", tools: 6 }], source: "runtime report" } },
  effectiveMCP: { assigned: true, profile_id: "11111111-1111-4111-8111-111111111401", profile_name: "Production Jira", endpoint: "https://mcp.internal.example/jira", group_id: "11111111-1111-4111-8111-111111111301", group_name: "Production assistants" },
  licence: { state: "unlicensed", tier: "community", gateway_ceiling: 1, org_ceiling: 1, features: [] },
  provenance: [{ id: "11111111-1111-4111-8111-111111111501", assertion_id: "11111111-1111-4111-8111-111111111502", key_id: "workflow-prod-01", verification_state: "verified", verification_reason: "verified", received_at: "2026-08-23T11:45:00Z", verified_chain: { workflow_id: "jira-triage", run_id: "run-284", trigger_kind: "webhook", initiating_subject_ref: "user:ops", tool: "create_issue", resource: "jira:OPS", issued_at: "2026-08-23T11:44:00Z", expires_at: "2026-08-23T12:00:00Z" } }],
};

export function S18DetailVisualScenario({ scenario }: { scenario: Extract<S18VisualScenario, `detail-${string}`> }) {
  return <FixtureTransport scenario={scenario}><OrgProvider><AgentDetail fixture={DETAIL_FIXTURE} agentIdOverride={ROWS[0].device_id} /></OrgProvider></FixtureTransport>;
}

export function S18AddAgentVisualScenario({ scenario }: { scenario: Extract<S18VisualScenario, `add-${string}`> }) {
  const stage: AddAgentVisualStage = scenario.replace("add-", "") as AddAgentVisualStage;
  return <FixtureTransport scenario={scenario}><AddAgentFlow orgId={ORG.id} enabled visualStage={stage} onDismiss={() => {}} /></FixtureTransport>;
}

/** Real management pages under the same org/auth seams; only fetch is fixture-backed. */
export function S18ManagementVisualScenario({ scenario }: { scenario: S18ManagementScenario }) {
  const page = scenario.startsWith("policies-") ? <AgentsPolicyTemplates /> : <AgentsMCP />;
  return <FixtureTransport scenario={scenario}><AuthProvider><OrgProvider>{page}</OrgProvider></AuthProvider></FixtureTransport>;
}

/** The real Rules route with a bounded, non-mutating transport fixture. */
export function S18RulesVisualScenario({ scenario }: { scenario: S18RulesScenario }) {
  return <FixtureTransport scenario={scenario}><AuthProvider><OrgProvider><Access /></OrgProvider></AuthProvider></FixtureTransport>;
}
