import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { StatusDot } from "./ui";

// A small control-plane health indicator. It also keeps the /healthz correlation
// chain (request-id plumbing, an EPIC-0 cross-cutting guard) exercised from the
// SPA on load — the e2e asserts the SPA issues GET /healthz and shows a status.
type State = "checking" | "up" | "down";

export function HealthStatus() {
  const [state, setState] = useState<State>("checking");
  useEffect(() => {
    let cancelled = false;
    api
      .GET("/healthz")
      .then(({ data, error }) => {
        if (!cancelled) setState(data && !error ? "up" : "down");
      })
      .catch(() => {
        if (!cancelled) setState("down");
      });
    return () => {
      cancelled = true;
    };
  }, []);
  const label = {
    checking: "checking…",
    up: "operational",
    down: "unreachable",
  }[state];
  const tone = state === "up" ? "on" : state === "down" ? "warn" : "off";
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-slate-500">
      <StatusDot tone={tone} />
      control plane {label}
    </span>
  );
}
