import { useEffect, useState } from "react";
import type { Role } from "../lib/api";

export function RoleAssignment({ email, roles, options, soleOwner, onSave }: {
  email: string;
  roles: Role[];
  options: Role[];
  soleOwner: boolean;
  onSave: (roles: Role[]) => Promise<void>;
}) {
  const [selected, setSelected] = useState(roles);
  const [busy, setBusy] = useState(false);
  const signature = roles.join(",");
  useEffect(() => setSelected(roles), [signature]);
  const unchanged = selected.length === roles.length && roles.every((r) => selected.includes(r));
  return <details className="relative min-w-40">
    <summary className="cursor-pointer text-sm" aria-label={`Roles for ${email}`}>{roles.join(" + ")}</summary>
    <fieldset className="my-2 space-y-2 rounded-lg border border-white/10 bg-ink-900 p-3" disabled={busy}>
      <legend className="sr-only">Roles for {email}</legend>
      {options.map((role) => <label key={role} className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={selected.includes(role)}
          disabled={soleOwner && role === "owner"}
          title={soleOwner && role === "owner" ? "An organization must always have at least one owner." : undefined}
          onChange={(e) => setSelected((current) => e.target.checked ? [...current, role] : current.filter((r) => r !== role))} />
        {role}
      </label>)}
      {soleOwner && <p className="text-xs text-ink-secondary">Keep at least one owner.</p>}
      <button type="button" className="rounded border border-white/10 px-3 py-1 text-sm disabled:opacity-50"
        disabled={busy || unchanged || selected.length === 0}
        onClick={async () => { setBusy(true); try { await onSave(selected); } finally { setBusy(false); } }}>
        {busy ? "Saving…" : "Save roles"}
      </button>
    </fieldset>
  </details>;
}
