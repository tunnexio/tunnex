import { useEffect, useId, useState } from "react";
import { api, apiErrorMessage } from "../lib/api";
import { lanEgressOptions, type LanEgress } from "../lib/sitesview";
import { Button, ErrorText } from "./ui";

// SiteLanEgress (SSI-8) — how this network's LAN sees traffic from other networks.
//
// The choice is saved explicitly, never on click: it changes what every gateway of the network does to
// forwarded traffic, and a radio that applied itself would make an exploratory click a production change.
// What is shown as current is what the server last confirmed, not what was last clicked.
export function SiteLanEgress({ orgId, siteId, current, canManage, onSaved }: {
  orgId: string;
  siteId: string;
  current: LanEgress;
  canManage: boolean;
  onSaved: () => void;
}) {
  const group = useId();
  const [applied, setApplied] = useState<LanEgress>(current);
  const [choice, setChoice] = useState<LanEgress>(current);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { setApplied(current); setChoice(current); setError(null); }, [current, siteId]);

  async function save() {
    if (busy || choice === applied) return;
    setBusy(true);
    setError(null);
    try {
      const { data, error: failure } = await api.PUT("/api/v1/organizations/{orgId}/sites/{siteId}/lan-egress", {
        params: { path: { orgId, siteId } },
        body: { lan_egress: choice },
      });
      if (failure || !data) {
        setError(apiErrorMessage(failure, "Could not change how this network sees remote traffic."));
        return;
      }
      setApplied(data.lan_egress);
      setChoice(data.lan_egress);
      onSaved();
    } catch {
      setError("The response was interrupted. Refresh to see which setting is applied.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <fieldset className="s2s-disclosure-body" aria-describedby={`${group}-context`}>
      <legend className="text-sm">Traffic from other networks arrives as</legend>
      <p id={`${group}-context`} className="s2s-operation-context">Access rules match the remote machine's real address either way.</p>
      {lanEgressOptions.map((option) => (
        <label key={option.value} className="mt-2 flex items-start gap-2 text-sm">
          <input
            type="radio"
            name={group}
            value={option.value}
            checked={choice === option.value}
            disabled={!canManage || busy}
            onChange={() => { setChoice(option.value); setError(null); }}
          />
          <span>
            <strong>{option.label}</strong>{applied === option.value && <span className="text-ink-secondary"> · current</span>}
            <span className="block text-ink-secondary">{option.sees} {option.needs}</span>
          </span>
        </label>
      ))}
      <ErrorText>{error}</ErrorText>
      {canManage && <div className="mt-3"><Button size="sm" disabled={busy || choice === applied} onClick={() => void save()}>{busy ? "Saving…" : "Save"}</Button></div>}
    </fieldset>
  );
}
