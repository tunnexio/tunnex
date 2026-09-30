import { Link, useSearchParams } from "react-router-dom";
import { setupReturnPath } from "../lib/setuproute";

export function SetupReturn() {
  const [params] = useSearchParams();
  const purpose = params.get("purpose");
  if (params.get("from") !== "setup" || !purpose || !["vpn", "networks", "kubernetes"].includes(purpose)) return null;
  return <div className="flex flex-wrap items-center justify-between gap-2 rounded-card border border-border bg-surface-inset px-4 py-3 text-sm">
    <span className="text-ink-secondary">Working through your first setup</span>
    <Link className="text-accent-400 hover:underline" to={setupReturnPath(purpose, params.get("setupStep"))}>Continue setup →</Link>
  </div>;
}
