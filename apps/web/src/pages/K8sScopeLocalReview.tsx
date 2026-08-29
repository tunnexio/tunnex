import { useEffect, useState } from "react";
import { AuthProvider } from "../lib/auth";
import { OrgProvider } from "../lib/useOrg";
import { api } from "../lib/api";
import { Badge } from "../components/ui";
import AccessKubernetesScopes from "./AccessKubernetesScopes";

const now = "2026-08-28T10:00:00Z";
const org = { id: "10000000-0000-4000-8000-000000000001", name: "Acme Production", slug: "acme-production", pool_cidr: "100.64.0.0/16", agent_jit_access_enabled: false, agent_policy_templates_enabled: false, created_at: now, updated_at: now };
const user = { id: "20000000-0000-4000-8000-000000000001", email: "admin@acme.example", name: "Asha Admin", email_verified: true, cp_admin: false, must_change_password: false, mfa_enrollment_required: false };
const cluster = { id: "30000000-0000-4000-8000-000000000001", site_id: "site-a", connector_node_id: "node-a", provider: "aws", platform: "eks", name: "production-eks", vip_range: "100.64.32.0/20", service_cidr: "10.96.0.0/12", dns_zone: "k8s.acme.internal", dns_vip: "100.64.32.1", managed_by_operator: false, created_at: now };
const scope = { rule_id: "40000000-0000-4000-8000-000000000001", cluster_id: cluster.id, source: { kind: "group", id: "50000000-0000-4000-8000-000000000001" }, active: true, revision: 7, initial_candidate_count: 3, created_by_user_id: user.id, created_at: now, updated_at: now };
const pending = { rule_id: scope.rule_id, cluster_id: cluster.id, service_child_id: "60000000-0000-4000-8000-000000000003", namespace: "payments", service: "ledger", protocol: "tcp", port: 8443, origin: "later", status: "pending", current: true, effective: false, inactive_reason: "pending", created_at: now };

type ReviewTransport = {
  GET: (path: string) => Promise<{ data?: unknown; error?: unknown }>;
  POST: (path: string) => Promise<{ data?: unknown; error?: unknown }>;
  PUT: (path: string) => Promise<{ data?: unknown; error?: unknown }>;
  DELETE: (path: string) => Promise<{ data?: unknown; error?: unknown }>;
};

/** Build-flagged visual review. The released component runs against a temporary in-memory transport. */
export default function K8sScopeLocalReview() {
  const [ready, setReady] = useState(false);
  useEffect(() => {
    const mutable = api as unknown as ReviewTransport;
    const original = { GET: mutable.GET, POST: mutable.POST, PUT: mutable.PUT, DELETE: mutable.DELETE };
    mutable.GET = async (path) => {
      if (path === "/api/v1/auth/me") return { data: user };
      if (path === "/api/v1/organizations") return { data: [org] };
      if (path.endsWith("/members")) return { data: [{ user_id: user.id, email: user.email, name: user.name, role: "admin", status: "active", email_verified: true, joined_at: now }] };
      if (path.endsWith("/cluster-scope-settings")) return { data: { enabled: true, revision: 4, entitlement_unlocked: true, effective: true, updated_at: now } };
      if (path.endsWith("/cluster-scopes")) return { data: [scope] };
      if (path.endsWith("/cluster-scope-review-queue")) return { data: { items: [pending] } };
      if (path.endsWith("/k8s/clusters")) return { data: [cluster] };
      if (path.endsWith("/k8s/services")) return { data: [
        { id: "60000000-0000-4000-8000-000000000001", cluster_id: cluster.id, name: "checkout-api", namespace: "payments", protocol: "tcp", port_low: 443, port_high: 443, vip: "100.64.32.2", fqdn: "checkout-api.payments.svc.production-eks.k8s.acme.internal", managed_by_operator: false },
        { id: "60000000-0000-4000-8000-000000000002", cluster_id: cluster.id, name: "orders-grpc", namespace: "orders", protocol: "tcp", port_low: 8443, port_high: 8443, vip: "100.64.32.3", fqdn: "orders-grpc.orders.svc.production-eks.k8s.acme.internal", managed_by_operator: false },
        { id: pending.service_child_id, cluster_id: cluster.id, name: "ledger", namespace: "payments", protocol: "tcp", port_low: 8443, port_high: 8443, vip: "100.64.32.4", fqdn: "ledger.payments.svc.production-eks.k8s.acme.internal", managed_by_operator: false },
      ] };
      if (path.endsWith("/groups")) return { data: [{ id: scope.source.id, org_id: org.id, name: "Payments platform", description: "Production payment operators", member_count: 8, created_at: now, updated_at: now }] };
      if (path.endsWith("/sites")) return { data: [{ id: "site-a", name: "Production VPC", link_transport: "wireguard", created_at: now }] };
      if (path.endsWith("/agents")) return { data: { items: [] } };
      if (path.endsWith("/initial-candidates")) return { data: { items: [
        { service_child_id: "60000000-0000-4000-8000-000000000001", namespace: "payments", service: "checkout-api", protocol: "tcp", port: 443, selected: true, current: true, effective: true, inactive_reason: null },
        { service_child_id: "60000000-0000-4000-8000-000000000002", namespace: "orders", service: "orders-grpc", protocol: "tcp", port: 8443, selected: false, current: true, effective: false, inactive_reason: "not_selected" },
        { service_child_id: "60000000-0000-4000-8000-000000000009", namespace: "legacy", service: "old-api", protocol: "tcp", port: 443, selected: true, current: false, effective: false, inactive_reason: "identity_changed" },
      ] } };
      if (path.endsWith("/memberships")) return { data: { items: [
        { rule_id: scope.rule_id, cluster_id: cluster.id, service_child_id: "60000000-0000-4000-8000-000000000001", namespace: "payments", service: "checkout-api", protocol: "tcp", port: 443, origin: "initial", status: "approved", current: true, effective: true, inactive_reason: null, decided_by_user_id: user.id, decided_at: now, created_at: now },
        pending,
        { rule_id: scope.rule_id, cluster_id: cluster.id, service_child_id: "60000000-0000-4000-8000-000000000009", namespace: "legacy", service: "old-api", protocol: "tcp", port: 443, origin: "initial", status: "approved", current: false, effective: false, inactive_reason: "identity_changed", decided_by_user_id: user.id, decided_at: now, created_at: now },
      ] } };
      return { data: [] };
    };
    mutable.POST = async (path) => path.endsWith("/cluster-scopes") ? { data: scope } : { data: { ...pending, status: "approved", decided_by_user_id: user.id, decided_at: now } };
    mutable.PUT = async () => ({ data: { ...scope, revision: scope.revision + 1 } });
    mutable.DELETE = async () => ({ data: undefined });
    setReady(true);
    return () => {
      mutable.GET = original.GET;
      mutable.POST = original.POST;
      mutable.PUT = original.PUT;
      mutable.DELETE = original.DELETE;
    };
  }, []);

  if (!ready) return null;
  return <main className="tnx-page min-h-dvh p-4 sm:p-6"><div className="mx-auto mb-4 max-w-[92rem]"><Badge tone="warn">LOCAL FIXTURE — NO CLUSTER OR POLICY MUTATION</Badge></div><AuthProvider><OrgProvider><div className="mx-auto max-w-[92rem]"><AccessKubernetesScopes /></div></OrgProvider></AuthProvider></main>;
}
