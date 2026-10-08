import { useEffect, useId, useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { Link } from "react-router-dom";

export type AppAccessRowMenuAction = {
  key: string;
  label: string;
  icon?: ReactNode;
  disabledReason?: string | null;
  danger?: boolean;
} & ({ onSelect: () => void; href?: never } | { href: string; onSelect?: never });

/** A shared row menu. Callers own permissions, availability, and confirmation. */
export default function AppAccessRowMenu({ label, actions }: { label: string; actions: AppAccessRowMenuAction[] }) {
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState({ top: 0, left: 0 });
  const trigger = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  const initialFocus = useRef<"first" | "last">("first");
  const menuId = useId();
  const enabledItems = () => Array.from(menu.current?.querySelectorAll<HTMLElement>('[role="menuitem"]:not(:disabled):not([aria-disabled="true"])') ?? []);
  const close = () => { setOpen(false); trigger.current?.focus({ preventScroll: true }); };
  useLayoutEffect(() => {
    if (!open || !trigger.current || !menu.current) return;
    const anchor = trigger.current.getBoundingClientRect();
    const bounds = menu.current.getBoundingClientRect();
    const left = Math.max(8, Math.min(anchor.right - bounds.width, window.innerWidth - bounds.width - 8));
    const top = anchor.bottom + bounds.height + 6 <= window.innerHeight - 8 ? anchor.bottom + 6 : Math.max(8, anchor.top - bounds.height - 6);
    setPosition({ top, left });
    const items = enabledItems();
    ((initialFocus.current === "last" ? items.at(-1) : items[0]) ?? menu.current).focus({ preventScroll: true });
  }, [open]);
  useEffect(() => {
    if (!open) return;
    const isInside = (target: EventTarget | null) => target instanceof Node && (trigger.current?.contains(target) || menu.current?.contains(target));
    const dismissOutside = (event: PointerEvent | FocusEvent) => { if (!isInside(event.target)) setOpen(false); };
    const dismissOnScroll = (event: Event) => { if (!(event.target instanceof Node && menu.current?.contains(event.target))) setOpen(false); };
    const dismissOnResize = () => setOpen(false);
    const dismissOnEscape = (event: globalThis.KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.preventDefault(); close();
    };
    document.addEventListener("pointerdown", dismissOutside);
    document.addEventListener("focusin", dismissOutside);
    document.addEventListener("keydown", dismissOnEscape);
    document.addEventListener("scroll", dismissOnScroll, true);
    window.addEventListener("resize", dismissOnResize);
    return () => {
      document.removeEventListener("pointerdown", dismissOutside);
      document.removeEventListener("focusin", dismissOutside);
      document.removeEventListener("keydown", dismissOnEscape);
      document.removeEventListener("scroll", dismissOnScroll, true);
      window.removeEventListener("resize", dismissOnResize);
    };
  }, [open]);
  function navigateMenu(event: React.KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Tab") { close(); return; }
    if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const items = enabledItems();
    if (!items.length) return;
    const current = items.findIndex(item => item === document.activeElement);
    const next = event.key === "Home" ? 0 : event.key === "End" ? items.length - 1 : (current + (event.key === "ArrowDown" ? 1 : -1) + items.length) % items.length;
    items[next].focus({ preventScroll: true });
  }
  if (!actions.length) return null;
  return <div className="aa-row-menu aa-inventory-row-actions">
    <button ref={trigger} type="button" className="aa-row-menu-trigger aa-inventory-menu-trigger" aria-label={label} aria-haspopup="menu" aria-expanded={open} aria-controls={open ? menuId : undefined} onClick={() => { initialFocus.current = "first"; setOpen(value => !value); }} onKeyDown={event => { if (event.key === "ArrowDown" || event.key === "ArrowUp") { event.preventDefault(); initialFocus.current = event.key === "ArrowUp" ? "last" : "first"; setOpen(true); } }}>
      <svg aria-hidden="true" width="20" height="20" viewBox="0 0 20 20" fill="currentColor"><circle cx="4" cy="10" r="1.5" /><circle cx="10" cy="10" r="1.5" /><circle cx="16" cy="10" r="1.5" /></svg>
    </button>
    {open && createPortal(<div ref={menu} id={menuId} role="menu" tabIndex={-1} aria-label={label} className="aa-row-menu-popup aa-inventory-menu" style={{ position: "fixed", top: position.top, left: position.left, maxWidth: "calc(100vw - 16px)", maxHeight: "calc(100vh - 16px)", overflowY: "auto" }} onKeyDown={navigateMenu}>
      {actions.map(action => {
        const itemClass = `aa-row-menu-item aa-inventory-menu-item${action.danger ? " aa-row-menu-item-danger aa-inventory-menu-item-danger" : ""}`;
        const reasonId = action.disabledReason ? `${menuId}-${action.key}-reason` : undefined;
        return <div key={action.key} role="none" className="aa-row-menu-entry aa-inventory-menu-entry">
          {action.href !== undefined ? <Link role="menuitem" tabIndex={-1} aria-disabled={action.disabledReason ? true : undefined} aria-describedby={reasonId} className={itemClass} to={action.href} onClick={event => { if (action.disabledReason) { event.preventDefault(); return; } close(); }}>{action.icon}{action.label}</Link> : <button type="button" role="menuitem" tabIndex={-1} disabled={!!action.disabledReason} aria-describedby={reasonId} className={itemClass} onClick={() => { if (action.disabledReason) return; close(); action.onSelect(); }}>{action.icon}{action.label}</button>}
          {action.disabledReason && <p id={reasonId} className="aa-row-menu-note aa-inventory-menu-note">{action.disabledReason}</p>}
        </div>;
      })}
    </div>, document.body)}
  </div>;
}
