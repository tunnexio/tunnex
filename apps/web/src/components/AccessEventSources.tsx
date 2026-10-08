import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import "../access-events-workspace.css";

export default function AccessEventSources({ source, actions }: { source: "network" | "applications" | "beam"; actions?: ReactNode }) {
  return <div className="event-workspace-nav"><nav aria-label="Access event sources" className="workspace-tabs">
    {([ ["network", "/access-events", "Network events"], ["applications", "/access-events?source=applications", "Application events"], ["beam", "/access-events?source=beam", "Local Sharing access"] ] as const).map(([key,href,label]) => <Link key={key} to={href} aria-current={source === key ? "page" : undefined}>{label}</Link>)}
  </nav>{actions && <div className="event-workspace-actions">{actions}</div>}</div>;
}
