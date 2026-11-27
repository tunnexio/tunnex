import { useEffect, useState } from "react";
import { api, loadOne } from "./api";
import { FAILED, LOADING, ok, type NavCount } from "./navcounts";
import { useOrg } from "./useOrg";

/** How often the sidebar asks how many MCP calls are waiting. A request lives five minutes, so a minute would miss most. */
export const MCP_APPROVAL_COUNT_REFRESH_MS = 15_000;
/** Pages that change the count announce it, so the sidebar does not wait for its next read. */
export const MCP_APPROVAL_COUNT_CHANGED = "tunnex:mcp-approval-count-changed";
export const announceMCPApprovalCountChanged = () => window.dispatchEvent(new Event(MCP_APPROVAL_COUNT_CHANGED));

/**
 * MCP calls waiting for a person, for the sidebar. Unknown stays unknown: a failed read never becomes 0,
 * and nothing is asked for a person who cannot approve.
 */
export function useMCPApprovalCount(enabled: boolean): NavCount {
  const { org } = useOrg();
  const orgId = org?.id ?? "";
  const [count, setCount] = useState<NavCount>(LOADING);
  useEffect(() => {
    if (!enabled || !orgId) { setCount(LOADING); return; }
    let cancelled = false;
    const read = () => void loadOne(() => api.GET("/api/v1/organizations/{orgId}/mcp-tool-approval-requests/count", { params: { path: { orgId } } })).then((result) => {
      if (cancelled) return;
      setCount(result.ok && Number.isInteger(result.data.pending) && result.data.pending >= 0 ? ok(result.data.pending) : FAILED);
    });
    read();
    const timer = window.setInterval(read, MCP_APPROVAL_COUNT_REFRESH_MS);
    window.addEventListener(MCP_APPROVAL_COUNT_CHANGED, read);
    return () => { cancelled = true; window.clearInterval(timer); window.removeEventListener(MCP_APPROVAL_COUNT_CHANGED, read); };
  }, [enabled, orgId]);
  return count;
}
