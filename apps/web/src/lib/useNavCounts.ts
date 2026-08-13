import { useCallback, useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { useOrg } from "./useOrg";
import {
  api,
  loadOne,
  type Loaded,
  type Node,
  type Site,
  type Device,
} from "./api";
import {
  FAILED,
  INITIAL_NAV_COUNTS,
  NAV_COUNT_REFRESH_MS,
  countFrom,
  gatewayTotalFrom,
  type NavCounts,
} from "./navcounts";

// S14.4 — the shell's ONE data dependency, owned in ONE place.
//
// AppShell owned no data before this. Giving it some is a real cost, so it is confined: one hook, one set of
// counts, four sources, and every source resolves INDEPENDENTLY. A failure in one never blanks another —
// which is the same reasoning that kept the six stat cards off an aggregated endpoint.
//
// Each source goes through `loadOne`, so a failed fetch produces FAILED rather than an empty array whose
// length is zero. `[].length === 0` is exactly how a failure becomes a confident `0` in permanent chrome.

const isOnline = (n: Node) => {
  if (!n.last_seen_at) return false;
  // Same recency window the Overview's `online` count uses (S3.6). Derived from LAST HANDSHAKE, not a session
  // — which is why the label everywhere says "seen recently", never "online".
  return Date.now() - new Date(n.last_seen_at).getTime() < 3 * 60 * 1000;
};

export function useNavCounts(): NavCounts {
  const { org: currentOrg } = useOrg();
  const [counts, setCounts] = useState<NavCounts>(INITIAL_NAV_COUNTS);
  const location = useLocation();

  const refresh = useCallback(async () => {
    // ⭐ The org-list fetch is gone (S12.5); the seam supplies it.
    if (!currentOrg) {
      // No org, or the org list failed: every count is UNKNOWN. Not zero — we did not learn that there are
      // none, we failed to learn anything.
      setCounts({
        gatewaysOnline: FAILED,
        gatewaysTotal: FAILED,
        gatewayCeiling: FAILED,
        sites: FAILED,
        devices: FAILED,
      });
      return;
    }
    const orgId = currentOrg.id;

    const [nodes, sites, devices, lic] = await Promise.all([
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/nodes", {
          params: { path: { orgId } },
        }),
      ) as Promise<Loaded<Node[]>>,
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/sites", {
          params: { path: { orgId } },
        }),
      ) as Promise<Loaded<Site[]>>,
      loadOne(() =>
        api.GET("/api/v1/organizations/{orgId}/devices", {
          params: { path: { orgId } },
        }),
      ) as Promise<Loaded<Device[]>>,
      // ⚠ DEPLOYMENT-SCOPED, so it takes no orgId — the licence belongs to the box, not the tenant.
      loadOne(() => api.GET("/api/v1/license")) as Promise<
        Loaded<{ gateway_ceiling?: number | null; gateways_in_use?: number }>
      >,
    ]);

    setCounts({
      // ⛔ THE NUMERATOR MUST BE THE SAME ORG-SCOPED GATEWAY LIST THE PAGE RENDERS.
      //
      // The licence endpoint's `gateways_in_use` is deployment-wide and can include stale or
      // non-gateway rows (for example, historical enrolments). Using it here made the sidebar say
      // "240/1" while the Gateways page correctly showed "All (0)". The ceiling is deployment-wide,
      // but the numerator answers the current organization's gateway count, so it comes from `nodes`.
      gatewaysTotal: gatewayTotalFrom(nodes),
      gatewaysOnline: countFrom(nodes, (n) => n.filter(isOnline).length),
      // ⚠ THE CEILING IS DEPLOYMENT-WIDE AND COMES FROM THE LICENCE, not from anything org-scoped. A null
      // ceiling is UNLIMITED — a real answer — and must not be confused with a read that failed.
      gatewayCeiling: lic.ok
        ? lic.data.gateway_ceiling == null
          ? null
          : { state: "ok" as const, value: lic.data.gateway_ceiling }
        : FAILED,
      sites: countFrom(sites, (r) => r.length),
      devices: countFrom(devices, (r) => r.length),
    });
    // ⚠ currentOrg IS A DEPENDENCY — the sidebar counts belong to ONE organization, and a switch that left
    // them stale would put another tenant's numbers beside this tenant's name.
  }, [currentOrg]);

  // Refresh on ROUTE CHANGE — the case that actually matters, because the user just did something and moved.
  useEffect(() => {
    void refresh();
  }, [refresh, location.pathname]);

  // Plus a SLOW interval, so a count left on screen does not become a remembered number wearing a live badge.
  useEffect(() => {
    const t = setInterval(() => void refresh(), NAV_COUNT_REFRESH_MS);
    return () => clearInterval(t);
  }, [refresh]);

  return counts;
}
