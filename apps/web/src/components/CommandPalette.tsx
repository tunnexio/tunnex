import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { NAV_DESTINATIONS } from "./AppShell";
import { motionAllowed } from "../lib/motion";
import { useMotionPreference } from "./MotionProvider";

// S14.3 SLICE B — THE COMMAND PALETTE. ⌘K / Ctrl-K, plus `g` sequences.
//
// ⛔ NAVIGATION ONLY IN THIS SLICE, and the reason is this slice's own measurement rather than taste: an
// ACTION in a palette is a mutation two keystrokes from a typo, and lib/undo.ts measured that MOST OF THIS
// PRODUCT'S MUTATIONS ARE NOT REVERSIBLE — six state toggles are, deletes and revocations are not. Offering
// "revoke device" behind a fuzzy match, with no undo behind it, is the worst affordance in the product.
// Actions become a decide-item once the undoable set is shipped and proven.
//
// ⛔ AND S14.2's RULE BINDS IT: the palette may RE-ARRANGE AND RANK; it may NEVER BE THE ONLY ROUTE to a
// destination. A destination reachable only by typing is hidden from everyone who does not already know it
// exists. Hence it reads NAV_DESTINATIONS — the same source the sidebar renders — rather than a second list.
// A palette with its own list would drift, and the drift would be invisible: both surfaces would look fine.

/** `g`-prefixed shortcuts, mapped onto destinations that must ALSO exist in the nav. */
const G_KEYS: Record<string, string> = {
  o: "/dashboard",
  g: "/sites",
  s: "/settings",
  d: "/devices",
  a: "/access",
};

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  // Focus is RETURNED on close. A dialog that drops focus to <body> strands a keyboard user at the top of the
  // document with no indication anything happened.
  const openerRef = useRef<Element | null>(null);
  const reduced = useMotionPreference();

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return NAV_DESTINATIONS;
    return NAV_DESTINATIONS.filter(
      (d) => d.label.toLowerCase().includes(q) || d.to.includes(q),
    );
  }, [query]);

  useEffect(() => {
    let pendingG = false;
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        openerRef.current = document.activeElement;
        setOpen((o) => !o);
        setQuery("");
        setActive(0);
        return;
      }
      if (open) return;
      // `g`-sequences must never fire while the user is typing into something.
      const el = document.activeElement;
      const typing =
        el instanceof HTMLInputElement ||
        el instanceof HTMLTextAreaElement ||
        (el as HTMLElement)?.isContentEditable;
      if (typing) return;
      if (pendingG) {
        pendingG = false;
        const to = G_KEYS[e.key.toLowerCase()];
        if (to) {
          e.preventDefault();
          navigate(to);
        }
        return;
      }
      if (e.key === "g") pendingG = true;
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, navigate]);

  useEffect(() => {
    if (open) inputRef.current?.focus();
  }, [open]);

  if (!open) return null;

  function close() {
    setOpen(false);
    // Return focus where it came from.
    (openerRef.current as HTMLElement | null)?.focus?.();
  }

  function go(to: string) {
    close();
    navigate(to);
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 p-4 pt-24"
      onClick={close}
      // Motion is a DECISION here, not a style: with the preference set, no transition class is emitted at
      // all. The CSS half (durations zeroed under the media query) is unconditional; this is the JS half,
      // for the animations CSS cannot reach.
      style={motionAllowed(reduced) ? undefined : { transition: "none" }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        className="w-full max-w-lg rounded-xl border border-white/10 bg-ink-800 p-3 shadow-xl"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === "Escape") return close();
          if (e.key === "ArrowDown") {
            e.preventDefault();
            setActive((i) => Math.min(i + 1, results.length - 1));
          }
          if (e.key === "ArrowUp") {
            e.preventDefault();
            setActive((i) => Math.max(i - 1, 0));
          }
          if (e.key === "Enter" && results[active]) go(results[active]!.to);
        }}
      >
        <input
          ref={inputRef}
          role="combobox"
          aria-expanded="true"
          aria-controls="palette-results"
          aria-label="Go to"
          className="w-full rounded-md border border-white/10 bg-ink-900 px-3 py-2 text-sm text-white placeholder:text-slate-600"
          placeholder="Go to…"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setActive(0);
          }}
        />
        <ul
          id="palette-results"
          role="listbox"
          aria-label="Destinations"
          className="mt-2 max-h-72 overflow-y-auto"
        >
          {results.map((d, i) => (
            <li key={d.to} role="option" aria-selected={i === active}>
              <button
                type="button"
                onClick={() => go(d.to)}
                onMouseEnter={() => setActive(i)}
                className={`block w-full rounded-md px-3 py-2 text-left text-sm ${
                  i === active ? "bg-white/10 text-white" : "text-slate-400"
                }`}
              >
                {d.label}
              </button>
            </li>
          ))}
          {results.length === 0 && (
            <li className="px-3 py-2 text-sm text-slate-500">
              No destination matches.
            </li>
          )}
        </ul>
      </div>
    </div>
  );
}
