import { useCallback, useEffect, useRef, useState } from "react";

import { useAuth } from "./auth";
import {
  api,
  loadOne,
  type Device,
  type Loaded,
  type Member,
  type Node,
  type Role,
  type Site,
} from "./api";
import { can } from "./rbac";
import { useOrg } from "./useOrg";

export type GatewayLicence = {
  tier: string;
  gateway_ceiling?: number | null;
  gateways_in_use?: number;
};

export type GatewayInventoryState = {
  kind: "loading" | "error" | "ready";
  orgId: string | null;
  error?: string;
  nodes: Node[];
  siteNames: Record<string, string>;
  homedCounts: Record<string, number> | null;
  licence: GatewayLicence | null;
  role?: Role;
};

const loadingState = (orgId: string | null = null): GatewayInventoryState => ({
  kind: "loading",
  orgId,
  nodes: [],
  siteNames: {},
  homedCounts: null,
  licence: null,
});

/**
 * One bounded inventory load shared by the Gateway index and detail workspace.
 * Courtesy/read failures never become fabricated facts: a failed device read leaves
 * homedCounts null, a failed licence read leaves the ceiling unknown, and only a
 * successful Node read may produce a fleet or a not-found detail result.
 */
export function useGatewayInventory() {
  const { org, loading: orgLoading, failed: orgFailed } = useOrg();
  const { state: auth } = useAuth();
  const [state, setState] = useState<GatewayInventoryState>(loadingState);
  const requestSequence = useRef(0);

  const reload = useCallback(async () => {
    const request = ++requestSequence.current;
    const requestedOrgId = org?.id ?? null;
    setState(loadingState(requestedOrgId));
    if (orgLoading) return;
    if (!org) {
      setState({
        ...loadingState(null),
        kind: "error",
        error: orgFailed
          ? "Could not load your organizations."
          : "You are not a member of an organization.",
      });
      return;
    }

    const [nodesResult, devicesResult, sitesResult, licenceResult, membersResult] =
      await Promise.all([
        loadOne(() =>
          api.GET("/api/v1/organizations/{orgId}/nodes", {
            params: { path: { orgId: org.id } },
          }),
        ) as Promise<Loaded<Node[]>>,
        loadOne(() =>
          api.GET("/api/v1/organizations/{orgId}/devices", {
            params: { path: { orgId: org.id } },
          }),
        ) as Promise<Loaded<Device[]>>,
        loadOne(() =>
          api.GET("/api/v1/organizations/{orgId}/sites", {
            params: { path: { orgId: org.id } },
          }),
        ) as Promise<Loaded<Site[]>>,
        loadOne(() => api.GET("/api/v1/license")) as Promise<
          Loaded<GatewayLicence>
        >,
        loadOne(() =>
          api.GET("/api/v1/organizations/{orgId}/members", {
            params: { path: { orgId: org.id } },
          }),
        ) as Promise<Loaded<Member[]>>,
      ]);

    if (request !== requestSequence.current) return;

    if (!nodesResult.ok) {
      setState({
        ...loadingState(org.id),
        kind: "error",
        error: nodesResult.error,
      });
      return;
    }

    const homedCounts = devicesResult.ok
      ? devicesResult.data.reduce<Record<string, number>>((counts, device) => {
          if (
            !device.node_id ||
            (device.status !== "active" && device.status !== "pending")
          ) {
            return counts;
          }
          counts[device.node_id] = (counts[device.node_id] ?? 0) + 1;
          return counts;
        }, {})
      : null;
    const userId = auth.status === "authed" ? auth.user.id : null;
    const role =
      membersResult.ok && userId
        ? membersResult.data.find((member) => member.user_id === userId)?.role
        : undefined;

    setState({
      kind: "ready",
      orgId: org.id,
      nodes: nodesResult.data,
      siteNames: sitesResult.ok
        ? Object.fromEntries(sitesResult.data.map((site) => [site.id, site.name]))
        : {},
      homedCounts,
      licence: licenceResult.ok ? licenceResult.data : null,
      role,
    });
  }, [auth, org?.id, orgFailed, orgLoading]);

  useEffect(() => {
    void reload();
  }, [reload]);

  // Effects run after render. Key the visible state to the selected organization so
  // the previous organization's inventory and permissions are withdrawn synchronously.
  const activeOrgId = org?.id ?? null;
  const visibleState = state.orgId === activeOrgId ? state : loadingState(activeOrgId);

  return {
    org,
    state: visibleState,
    reload,
    canEnroll: can(visibleState.role, "org:update"),
    canManage: can(visibleState.role, "org:update"),
    canTransfer: can(visibleState.role, "device:transfer"),
    canRestore: can(visibleState.role, "device:restore"),
  };
}
