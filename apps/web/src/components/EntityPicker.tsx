import { useMemo, useRef, useState } from "react";

/**
 * ONE PICKER PER SIDE, ACROSS EVERY KIND — the shape ruled in `docs/rule-validity-matrix.md`.
 *
 * ⛔ WHY NOT NETBIRD'S TWO PICKERS AS-IS. Netbird's rule form is groups → groups because netbird has two
 * kinds. This product has five source kinds and four destination kinds — sites, CIDRs, Kubernetes Services
 * and AI agents each earned their own story and each has a live call site. Copying the LAYOUT while keeping
 * the kinds behind a disclosure would make our own capabilities harder to find than the cascade did.
 *
 * So the simplification is real but it is not subtraction: **four controls become two**, and the kind stops
 * being a thing you choose FIRST and becomes a property of the thing you chose. You look for `Engineering`;
 * you do not first decide that Engineering is a Group.
 *
 * ⚠ THE TAG IS NOT DECORATION. It is the only thing distinguishing a site named `eu-lan` from a group named
 * `eu-lan`, and the two behave completely differently in the compiler. It is rendered as TEXT, never as a
 * colour alone.
 */
export interface PickerOption {
  /** Stable value handed back on select. For a literal CIDR this is the CIDR itself. */
  value: string;
  kind: string;
  /** Short uppercase tag — GROUP, SITE, AGENT. */
  tag: string;
  label: string;
  /** Extra searchable/displayed context, e.g. an agent's gateway. */
  detail?: string;
  /** Heading this option is filed under. Carries facts a per-row tag cannot — e.g. that a whole section is
   *  port-unscoped. */
  section?: string;
  /**
   * ⛔ A reason this option cannot be chosen RIGHT NOW, given the other side's selection.
   *
   * Rendered, never hidden. An option that silently vanishes when you change the other side teaches nothing;
   * one that says *"a site cannot reach itself"* teaches the rule. This mirrors the server's refusal — the
   * API is the guard, this is the explanation.
   */
  unavailable?: string;
}

export function EntityPicker({
  label,
  options,
  value,
  onSelect,
  /** Accept a typed CIDR as an option even though it is in no list. */
  acceptCidr,
  placeholder,
}: {
  label: string;
  options: PickerOption[];
  value: string;
  onSelect: (o: PickerOption) => void;
  acceptCidr?: boolean;
  placeholder?: string;
}) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const box = useRef<HTMLDivElement>(null);

  const selected = options.find((o) => o.value === value);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    const base = q
      ? options.filter(
          (o) =>
            o.label.toLowerCase().includes(q) ||
            o.tag.toLowerCase().includes(q) ||
            (o.detail ?? "").toLowerCase().includes(q),
        )
      : options;
    // ⚠ A TYPED CIDR IS OFFERED AS ITSELF. A literal prefix is the one source that cannot be in a list —
    // there is nothing to enumerate — so the search box doubles as its entry field rather than the form
    // carrying a separate control that is empty 95% of the time.
    if (acceptCidr && isCidr(query.trim())) {
      return [
        {
          value: query.trim(),
          kind: "cidr",
          tag: "CIDR",
          label: query.trim(),
        } as PickerOption,
        ...base,
      ];
    }
    return base;
  }, [options, query, acceptCidr]);

  return (
    <div className="relative" ref={box}>
      <label className="block text-sm text-slate-300" htmlFor={`pick-${label}`}>
        {label}
      </label>
      <input
        id={`pick-${label}`}
        role="combobox"
        aria-expanded={open}
        aria-controls={`list-${label}`}
        autoComplete="off"
        value={open ? query : selected ? `${selected.label}` : ""}
        placeholder={placeholder ?? "Search…"}
        onFocus={() => {
          setOpen(true);
          setQuery("");
        }}
        onBlur={() => window.setTimeout(() => setOpen(false), 120)}
        onChange={(e) => {
          setQuery(e.target.value);
          setOpen(true);
          setActive(0);
        }}
        onKeyDown={(e) => {
          // ⛔ A COMBOBOX YOU CANNOT DRIVE FROM THE KEYBOARD IS A TEXT BOX WITH DECORATION. What this
          // replaced was four <select>s — every one arrow-navigable and type-ahead searchable for FREE.
          // Something prettier that only works with a mouse is a regression wearing a redesign, so the keys
          // the native control gave us are re-implemented rather than quietly lost.
          if (e.key === "ArrowDown" || e.key === "ArrowUp") {
            e.preventDefault();
            setOpen(true);
            setActive((a) => {
              const n = shown.length;
              if (n === 0) return 0;
              return e.key === "ArrowDown" ? (a + 1) % n : (a - 1 + n) % n;
            });
          } else if (e.key === "Enter") {
            const o = shown[active];
            // ⚠ Enter must not select what the rules forbid — the same refusal the click path honours.
            if (o && !o.unavailable) {
              e.preventDefault();
              onSelect(o);
              setOpen(false);
              setQuery("");
            }
          } else if (e.key === "Escape") {
            setOpen(false);
          }
        }}
        className="mt-1 w-full rounded-md border border-white/10 bg-ink-900 px-3 py-2 text-sm text-white placeholder:text-slate-600 focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-400"
      />
      {/* The chosen thing keeps saying WHAT it is once the box is closed — otherwise "eu-lan" alone is
          ambiguous between a site and a group with the same name. */}
      {!open && selected && (
        <span className="pointer-events-none absolute right-3 top-[2.1rem] font-mono text-[10px] text-slate-500">
          {selected.tag}
        </span>
      )}
      {open && (
        <ul
          id={`list-${label}`}
          role="listbox"
          aria-label={label}
          className="absolute z-30 mt-1 max-h-64 w-full overflow-y-auto rounded-md border border-white/20 bg-ink-900 py-1 shadow-[0_12px_32px_rgba(0,0,0,.6)]"
        >
          {shown.length === 0 && (
            <li className="px-3 py-2 text-xs text-ink-secondary">
              Nothing matches “{query}”.
              {acceptCidr &&
                " Type a CIDR (e.g. 10.0.5.0/24) to use a literal address."}
            </li>
          )}
          {/* ⛔ GROUPED BY SECTION, IN ORDER. Nine flat options teach nothing; a heading that reads
              "Networks & devices — ALL ports" teaches the model's most consequential fact at the exact
              moment the choice is made. The index used for keyboard focus is the FLAT one, so grouping
              changes what the eye sees without changing what the arrow keys do. */}
          {shown.map((o, idx) => (
            <li
              key={`${o.kind}:${o.value}`}
              role="option"
              aria-selected={o.value === value}
            >
              {o.section && o.section !== shown[idx - 1]?.section && (
                <div
                  role="presentation"
                  className="px-3 pb-0.5 pt-2 font-mono text-[10px] uppercase tracking-wide text-ink-tertiary"
                >
                  {o.section}
                </div>
              )}
              <button
                type="button"
                disabled={!!o.unavailable}
                title={o.unavailable}
                onMouseDown={(e) => e.preventDefault()}
                onClick={() => {
                  if (o.unavailable) return;
                  onSelect(o);
                  setOpen(false);
                  setQuery("");
                }}
                className={`flex w-full items-center gap-3 px-3 py-2 text-left text-sm ${
                  o.unavailable
                    ? "cursor-not-allowed text-slate-600"
                    : active === idx
                      ? "bg-white/10 text-slate-100"
                      : "text-slate-200 hover:bg-white/10"
                }`}
              >
                {/* ⚠ A FIXED-WIDTH TAG COLUMN. Ragged tags turn the list into a staircase and the labels
                    stop forming a scannable column, which is the entire point of one picker. */}
                <span className="w-[4.5rem] shrink-0 font-mono text-[10px] uppercase tracking-wide text-slate-500">
                  {o.tag}
                </span>
                <span className="min-w-0 flex-1 truncate">{o.label}</span>
                {o.detail && (
                  <span className="shrink-0 truncate text-xs text-ink-secondary">
                    {o.detail}
                  </span>
                )}
                {/* ⛔ THE REASON IS SHOWN IN THE ROW, not only on hover. A disabled option whose
                    explanation requires a mouse is no explanation on a touch screen or to a reader. */}
                {o.unavailable && (
                  <span className="ml-auto shrink-0 text-[10px] text-warn">
                    {o.unavailable}
                  </span>
                )}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Loose CIDR shape check — the server parses authoritatively; this only decides whether to OFFER it. */
export function isCidr(s: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(s);
}
