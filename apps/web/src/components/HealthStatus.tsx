import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { StatusDot } from "./ui";

// A small control-plane health indicator. It also keeps the /healthz correlation
// chain (request-id plumbing, an EPIC-0 cross-cutting guard) exercised from the
// SPA on load — the e2e asserts the SPA issues GET /healthz and shows a status.
type State = "checking" | "up" | "down";

export function HealthStatus() {
  const [state, setState] = useState<State>("checking");
  const [version, setVersion] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    api
      .GET("/healthz")
      .then(({ data, error }) => {
        if (cancelled) return;
        if (!data || error) {
          setState("down");
          return;
        }
        setState("up");
        void api
          .GET("/api/v1/meta")
          .then(({ data: meta }) => {
            if (!cancelled) {
              setVersion(meta?.upgrade?.current_version?.trim() || null);
            }
          })
          .catch(() => undefined);
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
    up: version ?? "online",
    down: "unreachable",
  }[state];
  const tone = state === "up" ? "on" : state === "down" ? "warn" : "off";
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-slate-500">
      <StatusDot tone={tone} />
      {label}
    </span>
  );
}
