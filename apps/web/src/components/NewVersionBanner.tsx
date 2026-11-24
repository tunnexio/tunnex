import { useEffect, useState } from "react";
import { newerBuildAvailable } from "../lib/newVersion";
import { Button } from "./ui";

const interval = 5 * 60 * 1000;

// Non-blocking: never reloads by itself (a live terminal or an unsaved form may be open).
export function NewVersionBanner({ check = newerBuildAvailable, reload = () => window.location.reload() }: { check?: () => Promise<boolean>; reload?: () => void }) {
  const [available, setAvailable] = useState(false);
  useEffect(() => {
    if (available) return;
    let live = true;
    const run = () => { void check().then(newer => { if (live && newer) setAvailable(true); }); };
    run();
    const timer = window.setInterval(run, interval);
    const visible = () => { if (document.visibilityState === "visible") run(); };
    document.addEventListener("visibilitychange", visible);
    return () => { live = false; window.clearInterval(timer); document.removeEventListener("visibilitychange", visible); };
  }, [available, check]);
  if (!available) return null;
  return <div role="status" className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-input border border-line px-3 py-2 text-sm">
    <span>A new version of Tunnex is available. Reload to use it; unsaved changes on this page are lost.</span>
    <Button variant="ghost" onClick={reload}>Reload</Button>
  </div>;
}
