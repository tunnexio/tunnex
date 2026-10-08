import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Icon, type IconName } from "./Icon";
import { ErrorText } from "./ui";
import { beamUIFixtures, filterBeamUIFixtures } from "../lib/beam-ui-fixtures";
import { beamCountdown } from "../lib/beam-clock";
import { beamStatus, type BeamShare, type BeamShareFilters } from "../lib/beam";

type Props = { orgId: string; sampleId?: string; search?: string; filters?: BeamShareFilters; now: number; onAvailable?: (available: boolean) => void };

// Imported only by Vite development builds. Sample data never enters API inventories,
// permissions, quotas, paging or the real /beam/shares/:id detail path.
export default function BeamUIPreview({ orgId, sampleId, search, filters = {}, now, onAvailable }: Props) {
  const shares = filterBeamUIFixtures(orgId, search, filters);
  useEffect(() => { onAvailable?.(shares.length > 0); }, [onAvailable, shares.length]);
  if (sampleId) {
    const share = beamUIFixtures(orgId).find(item => item.id === sampleId);
    return share ? <SampleShareDetail share={share} /> : <div className="beam-fixture-detail"><ErrorText>This local sample is unavailable.</ErrorText><Link className="beam-inline-link" to="/beam/my-shares">Back to my shares</Link></div>;
  }
  return shares.length ? <SampleShares shares={shares} now={now} /> : null;
}

function statusTone(label: string) {
  return label === "Live" ? "live" : ["Publisher offline", "Reconnecting", "Refresh required", "Starting"].includes(label) ? "warning" : ["Local app unavailable", "Unavailable"].includes(label) ? "danger" : "neutral";
}
function Status({ share, uncertain = false, now, example = false }: { share: BeamShare; uncertain?: boolean; now?: number; example?: boolean }) {
  const label = uncertain ? "Refresh required" : beamStatus(share, now);
  return <span className="beam-status" data-tone={statusTone(label)}>{example && <span className="beam-example-prefix">Example:</span>}{label}</span>;
}
const sampleIcons: Record<string, IconName> = { "Dashboard redesign": "layout-dashboard", "Customer onboarding": "users", "API documentation": "file-text", "Checkout experiment": "boxes" };
function ShareAvatar({ share, sample = false }: { share: BeamShare; sample?: boolean }) {
  const color = Array.from(share.name).reduce((sum, character) => sum + character.charCodeAt(0), 0) % 4;
  const initials = share.name.trim().split(/\s+/).slice(0, 2).map(word => word[0]).join("").toUpperCase();
  return <span className="beam-app-icon" data-color={color} aria-hidden="true">{sample ? <Icon name={sampleIcons[share.name] ?? "local-sharing"} size={19} /> : initials || <Icon name="local-sharing" size={19} />}</span>;
}
function ConnectionPreview({ share }: { share: BeamShare }) {
  const offline = share.connectivity === "offline" || share.connectivity === "reconnecting";
  const appUnavailable = share.connectivity === "origin_unavailable";
  const paused = share.state === "paused";
  return <div className="beam-connection-preview" aria-label="Sample connection path">
    <div className="beam-connection-end" data-unavailable={appUnavailable || undefined}><span className="beam-connection-icon"><Icon name={appUnavailable ? "circle-alert" : "laptop"} size={19} /></span><strong>Local app</strong><code>{share.target ? `localhost:${share.target.port}` : "Local port unavailable"}</code></div>
    <div className="beam-connection-link" data-tone={offline ? "warning" : paused ? "paused" : "connected"} aria-hidden="true"><span>Private link</span><i /><Icon name={offline ? "wifi-off" : paused ? "ban" : "local-sharing"} size={16} /></div>
    <div className="beam-connection-end"><span className="beam-connection-icon"><Icon name="chrome" size={19} /></span><strong>Browser</strong><span>Invited reviewers</span></div>
  </div>;
}
function SampleShares({ shares, now }: { shares: BeamShare[]; now: number }) {
  const [selectedId, setSelectedId] = useState(shares[0]?.id);
  const list = useRef<HTMLDivElement>(null);
  const selected = shares.find(share => share.id === selectedId) ?? shares[0];
  if (!selected) return null;
  const label = beamStatus(selected, now);
  const explanation = label === "Live" ? "The app and publisher are connected." : label === "Paused" ? "Sharing is paused. The local app stays connected." : label === "Publisher offline" ? "The publisher disconnected. The link is unavailable." : label === "Local app unavailable" ? "The publisher is connected; the local app isn't responding." : "This preview has ended.";
  return <section className="beam-preview-fixtures" aria-label="Local UI previews">
    <div className="beam-section-heading"><h3>Sample shares</h3><span className="beam-sample-label"><Icon name="monitor" size={13} />Read only · sample states</span></div>
    <div className="beam-sample-explorer">
      <div className="beam-sample-list" role="tablist" aria-label="Sample shares" aria-orientation="vertical" ref={list} onKeyDown={event => {
        if (event.altKey || event.ctrlKey || event.metaKey) return;
        const tabs = list.current?.querySelectorAll<HTMLButtonElement>("[role=tab]");
        const focusedIndex = tabs ? Array.from(tabs).findIndex(tab => tab.contains(event.target as Node)) : -1;
        const currentIndex = focusedIndex < 0 ? shares.indexOf(selected) : focusedIndex;
        const index = event.key === "ArrowDown" ? (currentIndex + 1) % shares.length : event.key === "ArrowUp" ? (currentIndex + shares.length - 1) % shares.length : event.key === "Home" ? 0 : event.key === "End" ? shares.length - 1 : -1;
        if (index < 0) return;
        event.preventDefault(); setSelectedId(shares[index].id); list.current?.querySelectorAll<HTMLButtonElement>("[role=tab]")[index]?.focus();
      }}>
        {shares.map(share => <button type="button" role="tab" key={share.id} id={`sample-tab-${share.id}`} aria-controls={`sample-panel-${share.id}`} aria-selected={share.id === selected.id} tabIndex={share.id === selected.id ? 0 : -1} aria-label={share.name} onClick={() => setSelectedId(share.id)}>
          <ShareAvatar share={share} sample /><span className="beam-sample-identity"><strong>{share.name}</strong><code>{share.target ? `localhost:${share.target.port}` : "Local port unavailable"}</code></span><span className="beam-sample-dot" data-tone={statusTone(beamStatus(share, now))} aria-hidden="true" /><Icon name="chevron-right" size={14} />
        </button>)}
      </div>
      <div className="beam-sample-panel" role="tabpanel" id={`sample-panel-${selected.id}`} aria-labelledby={`sample-tab-${selected.id}`} tabIndex={0}>
        <div className="beam-sample-panel-heading"><span>Connection preview</span><Status share={selected} now={now} example /></div>
        <ConnectionPreview share={selected} />
        <p className="beam-sample-explanation">{explanation}</p>
        <div className="beam-sample-address"><span>Sample address</span><code title={selected.hostname}>{selected.hostname}</code></div>
        <div className="beam-sample-panel-footer"><span>Nothing is published.</span><Link to={`/beam/my-shares?sample=${encodeURIComponent(selected.id)}`} aria-label={`View fixture ${selected.name}`}>View details<Icon name="chevron-right" size={14} /></Link></div>
      </div>
    </div>
  </section>;
}
function SampleShareDetail({ share }: { share: BeamShare }) {
  const now = Date.now();
  return <section className="beam-fixture-detail">
    <nav aria-label="Breadcrumb" className="beam-breadcrumb"><Link to="/beam/my-shares">My shares</Link><Icon name="chevron-right" size={13} /><span>{share.name}</span></nav>
    <div className="beam-sample-detail-heading"><ShareAvatar share={share} sample /><div><h1>{share.name}</h1><p>Sample share · Read only</p></div><Status share={share} now={now} example /></div>
    <p role="status" className="beam-fixture-notice">Read-only sample. Nothing is published.</p>
    <div className="beam-sample-detail-body"><div><h2>Connection</h2><ConnectionPreview share={share} /><dl className="beam-sample-detail-address"><dt>Sample address</dt><dd>{share.hostname}</dd></dl></div><dl className="beam-facts"><div><dt>Publisher</dt><dd>{share.publisher_name}</dd></div><div><dt>Local port</dt><dd>{share.target?.port}</dd></div><div><dt>Expires</dt><dd>{beamCountdown(share.expires_at, now)}</dd></div><div><dt>Access</dt><dd>Invited reviewers</dd></div></dl></div>
  </section>;
}
