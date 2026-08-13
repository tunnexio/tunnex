import {
  cloneElement,
  Fragment,
  isValidElement,
  useId,
  useMemo,
  useState,
} from "react";
import { createPortal } from "react-dom";
import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactElement,
  ReactNode,
  SelectHTMLAttributes,
} from "react";

// A small, deliberate set of primitives — enough to compose the app's pages
// consistently without a heavyweight component library. Colors come only from the
// theme tokens (accent/ink/slate), so a palette swap restyles everything.

/**
 * ⛔ THE GLASS RECIPE, IN ONE PLACE. Every surface in the product composes from this constant.
 *
 * It was previously spelled out on `Stat` and NOT on `Panel`, so the stat row rendered as glass and every
 * panel below it rendered as flat plastic — in the same screenshot. A material defined per-component is a
 * material that WILL be half-applied, and the half that is missing reads as a rendering bug rather than a
 * missing class.
 *
 * `bg-surface` is TRANSLUCENT (`rgba(31,31,31,.72)`), and the blur needs the page's radial field behind it to
 * refract (index.css). Opaque fill or flat backdrop and the effect disappears entirely.
 *
 * NO INSET WHITE HIGHLIGHT LINE — the designer removed it explicitly. Do not reintroduce
 * `inset 0 1px 0 rgba(255,255,255,…)`.
 */
export const GLASS =
  "rounded-card border border-white/[.14] bg-surface shadow-card backdrop-blur-[24px] backdrop-saturate-[1.4]";

export function Button({
  variant = "primary",
  size = "default",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "ghost" | "danger";
  /**
   * `sm` for a button that lives INSIDE A TABLE ROW.
   *
   * ⛔ A REAL PROP RATHER THAN AN OVERRIDE CLASS, and the reason is Tailwind: `px-4 py-2` is baked into `base`,
   * so a caller passing `px-2.5 py-1` gets whichever rule the generated stylesheet happens to order last —
   * which is not the attribute order, so the "fix" works or does not depending on the build. Swapping the
   * classes here means one of them exists, not both.
   *
   * THE DEFECT IT FIXES: a default button is ~36px tall against a ~20px row line, so at `align-top` its label
   * sat visibly BELOW the row's own text and the action stopped reading as part of that row.
   */
  size?: "default" | "sm";
}) {
  const pad = size === "sm" ? "px-2.5 py-1 text-xs" : "px-4 py-2 text-sm";
  const base = `inline-flex items-center justify-center rounded-md ${pad} font-medium transition-colors disabled:opacity-50 disabled:pointer-events-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-400`;
  // ⛔ THE PRIMARY BUTTON WAS UNREADABLE, PRODUCT-WIDE, AND THE PALETTE SWAP IS WHY.
  //
  // It was `bg-accent-500 text-white`. In the mono palette `--tnx-accent` is **#C9C9C4** — a LIGHT GREY — so
  // every primary button in the app rendered WHITE TEXT ON LIGHT GREY. It was legible under the old violet
  // accent (#7C5CFC) and stopped being legible the moment the palette was re-pointed at the handoff's mono
  // set, because the class names did not change and nothing asserts contrast.
  //
  // A SEMANTIC NAME SURVIVES A PALETTE SWAP; THE CONTRAST IT ASSUMED DOES NOT. `accent` kept meaning
  // "the accent", and the thing it pointed at went from dark-enough-for-white-text to far too light.
  //
  // THE FIX IS THE DESIGN'S OWN RECIPE (dc.html L449, the `+ Add site` button):
  //   background rgba(255,255,255,.16) · border rgba(255,255,255,.4) · blur(10px)
  //   shadow 0 4px 16px rgba(0,0,0,.4) · color #F5F5F5
  // A 16%-white wash over a near-black page lands around #2F2F2F, so #F5F5F5 sits at roughly 12:1 — and it
  // stays legible on the glass panels too, which is why the design uses a translucent fill rather than a
  // solid one.
  //
  // ⚠ `backdrop-blur` makes an element a containing block for `position: fixed` descendants — the trap that
  // clipped five modals inside `Card`. Safe here: a button has no fixed descendants. Do not lift this recipe
  // onto a container without re-reading that law.
  const variants = {
    primary:
      "border border-white/40 bg-white/[.16] text-ink-heading shadow-[0_4px_16px_rgba(0,0,0,.4)] backdrop-blur-[10px] hover:bg-white/25",
    ghost: "border border-white/10 text-slate-200 hover:bg-white/5",
    danger: "text-slate-400 hover:text-danger",
  } as const;
  return (
    <button
      className={`${base} ${variants[variant]} ${className}`}
      {...props}
    />
  );
}

export function Card({
  className = "",
  children,
}: {
  className?: string;
  children: ReactNode;
}) {
  return <div className={`${GLASS} p-4 ${className}`}>{children}</div>;
}

export function Field({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  // Explicit id/htmlFor association (not just implicit wrapping) so the label
  // stays linked to the control even once helper/error text is added, and the
  // accessible name is exactly the label — not the concatenated subtree text.
  const id = useId();
  const control = isValidElement(children)
    ? cloneElement(children as ReactElement<{ id?: string }>, { id })
    : children;
  return (
    <div className="block">
      <label htmlFor={id} className="block text-sm text-slate-300">
        {label}
      </label>
      <span className="mt-1 block">{control}</span>
    </div>
  );
}

export function Input({
  className = "",
  ...props
}: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={`w-full rounded-md border border-white/10 bg-ink-900 px-3 py-2 text-sm text-white placeholder:text-slate-600 focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-400 ${className}`}
      {...props}
    />
  );
}

/** StatusDot: a small colored dot for online/offline/neutral state (semantic
 * tokens, deliberately not the brand accent). */
export function StatusDot({ tone }: { tone: "on" | "off" | "warn" }) {
  const cls = { on: "bg-ok", off: "bg-slate-600", warn: "bg-warn" }[tone];
  return <span className={`inline-block h-1.5 w-1.5 rounded-full ${cls}`} />;
}

export function ErrorText({ children }: { children: ReactNode }) {
  return children ? <p className="text-xs text-danger">{children}</p> : null;
}

// Select: themed <select>, promoted from the raw <select>+selectCls that pages rolled
// inline (S7.4a). Same border/bg/focus tokens as Input so the two read as one family.
export function Select({
  className = "",
  width = "full",
  children,
  ...props
}: SelectHTMLAttributes<HTMLSelectElement> & {
  children: ReactNode;
  /**
   * `auto` for a control that should be as wide as its options, not as wide as its container.
   *
   * ⛔ A REAL PROP, NOT AN OVERRIDE CLASS — the same Tailwind trap `Button.size` documents, and it had
   * already bitten here. `w-full` is baked into the base, so a caller passing `className="w-32"` gets
   * whichever rule the generated stylesheet happens to order LAST, which is not attribute order. The two
   * posture selects were written `w-32` and rendered full width: an Off/Warn/Require control stretched
   * across two thirds of a card, which reads as a text field, not a choice of three.
   *
   * Swapping the class means only one of them exists.
   */
  width?: "full" | "auto";
}) {
  return (
    <select
      className={`${width === "auto" ? "w-auto min-w-[9rem]" : "w-full"} rounded-md border border-white/10 bg-ink-900 px-3 py-2 text-sm text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent-400 ${className}`}
      {...props}
    >
      {children}
    </select>
  );
}

// Modal: the one generic overlay+dismiss shell (S7.4a), extracted from the
// OneTimeSecretModal structure but content-agnostic — reused for every create/edit
// form and the two confirm dialogs. Deliberately NOT a live "switch": consequential,
// confirm-gated actions must not wear switch clothing. Esc + backdrop-click dismiss;
// `danger` tints the title for the strong (zero-rules lockout) gate.
export function Modal({
  title,
  danger = false,
  onDismiss,
  children,
  actions,
  size = "default",
}: {
  title: string;
  danger?: boolean;
  onDismiss: () => void;
  children: ReactNode;
  actions: ReactNode;
  /**
   * `wide` for a dialog whose content is a pair of searchable pickers rather than a sentence and a button.
   *
   * ⚠ A PROP RATHER THAN AN OVERRIDE CLASS, for the same Tailwind reason `Button.size` is one: `max-w-md` is
   * baked into the shell, so a caller passing `max-w-2xl` gets whichever rule the generated stylesheet
   * happens to order last — which is not attribute order, so the "fix" works or does not depending on the
   * build.
   */
  size?: "default" | "wide";
}) {
  // Dismiss on backdrop-click or the Cancel action only. Esc-to-dismiss was DROPPED after a
  // 3-finding churn (broken → too-global → focus-steal) on a nice-to-have that's also a
  // data-loss footgun on a form modal. If a11y later needs Esc, it returns as the full
  // designed dialog pattern (focus trap + first-field focus + panel listener), not a patch.
  //
  // ⛔ PORTALLED TO <body>, AND THIS IS NOT COSMETIC.
  //
  // `position: fixed` is relative to the VIEWPORT — unless an ancestor has `filter`, `transform`,
  // `perspective`, `will-change` or `backdrop-filter`, any of which makes that ancestor the containing block.
  // S14.4 gave `Card` the glass recipe, which includes `backdrop-filter` — and FIVE modals across FOUR screens
  // render inside a Card. Every one of them silently stopped being viewport-positioned: the overlay was
  // clipped to the card, and the card's own body sat on top of the modal's buttons, so clicks never landed.
  //
  // It surfaced as ONE Playwright click timing out with a Card listed as the intercepting element. It did not
  // surface in the component tier at all — jsdom has no layout engine, so a containing-block change is
  // invisible there, and a click-through of all twelve screens reported "nothing broken" because nothing
  // crashed and no content was lost.
  //
  // A portal is the correct fix independent of the cause: an overlay's position must never depend on WHERE IN
  // THE TREE it happens to be rendered.
  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onClick={onDismiss}
    >
      <div
        className={`w-full ${size === "wide" ? "max-w-2xl" : "max-w-md"} rounded-card border border-white/10 bg-surface p-4 shadow-modal backdrop-blur-[24px] backdrop-saturate-[1.4]`}
        onClick={(e) => e.stopPropagation()}
      >
        <h2
          className={`text-title font-semibold ${danger ? "text-danger" : "text-ink-heading"}`}
        >
          {title}
        </h2>
        <div className="mt-3 text-cell text-ink-body">{children}</div>
        <div className="mt-5 flex justify-end gap-2">{actions}</div>
      </div>
    </div>,
    document.body,
  );
}

// ── S14.3 SLICE A — STRUCTURAL PRIMITIVES, SEMANTIC BY CONSTRUCTION ─────────────────────────────────────────
//
// ⚠ THE MEASUREMENT THAT MADE THIS A DEFECT RATHER THAN A POLISH ITEM: this app contained ZERO `<table>`
// elements. Thirty-seven `.map()` calls rendered `<div>` rows.
//
// The cost was not cosmetic and it was not confined to the UI. Query rule 1 says query by ROLE — and
// `role="table"` / `row` / `cell` DID NOT EXIST ANYWHERE TO QUERY, so every wiring test in the component tier
// worked around the gap by MATCHING TEXT. Text matching is the most brittle query there is and the first thing
// a redesign breaks. A missing semantic primitive degrades the UI once and the TESTS OF THAT UI a second time,
// and the second cost is invisible from either side: the tests look like they work, the components look like
// they render (docs/laws.md).
//
// So these primitives ship WITH their consumers converted and the tier's assertions re-pointed at roles. A
// primitive that ships while its consumers keep the workaround has only half landed.

/** A named region. `aria-labelledby` is the point: an unnamed region cannot be found by role + name. */
export function Panel({
  title,
  actions,
  className = "",
  children,
}: {
  title: string;
  actions?: ReactNode;
  className?: string;
  children: ReactNode;
}) {
  const id = useId();
  return (
    // README: card padding 16, internal gap 10, title 600 13.5px. `flex-col` with the body in a `flex-1`
    // wrapper keeps every panel in a row the same height WITHOUT centring its content — the row stretches,
    // the content stays top-aligned. Centred content in a stretched panel is what makes a bento look
    // "overlapped": each panel floats its text at a different vertical position.
    <section
      aria-labelledby={id}
      className={`${GLASS} flex flex-col gap-2.5 p-4 ${className}`}
    >
      <div className="flex items-center justify-between gap-2">
        <h2 id={id} className="text-title font-semibold text-ink-heading">
          {title}
        </h2>
        {actions}
      </div>
      <div className="flex-1">{children}</div>
    </section>
  );
}

/**
 * A status badge.
 *
 * ⛔ THE TEXT IS THE STATUS; THE COLOUR IS AN ACCELERANT. A badge that says its state only in colour is
 * unreadable to a colour-blind user, invisible to a screen reader, and unqueryable by the tier — three
 * failures with one cause. `tone` may never be the only carrier of meaning, which is why `children` is
 * required rather than optional.
 *
 * `ok` REMAINS LIVENESS-ONLY (S4.4 decision f). The reservation scan in tokens.test.ts reads these use-sites.
 */
export type BadgeTone = "ok" | "warn" | "danger" | "neutral" | "unknown";

export function Badge({
  tone = "neutral",
  children,
}: {
  tone?: BadgeTone;
  children: ReactNode;
}) {
  const cls = {
    ok: "border-ok/40 text-ok",
    warn: "border-warn/40 text-warn",
    danger: "border-danger/40 text-danger",
    neutral: "border-white/10 text-slate-400",
    unknown: "border-amber-500/40 text-amber-300",
  }[tone];
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs ${cls}`}
    >
      {children}
    </span>
  );
}

/**
 * The empty state.
 *
 * ⚠ EMPTY IS NOT THE SAME AS FAILED, and this component may only ever express the first. Twelve hand-written
 * "No X yet." strings existed before it; the risk in unifying them is that a FAILED load starts borrowing the
 * empty wording, which is the reassuring-empty defect the `loadOne` law exists to prevent. A failed load
 * renders `LoadRetry`, never this.
 */
export function EmptyState({
  children,
  action,
}: {
  children: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="py-10">
      <p className="text-cell text-ink-tertiary">{children}</p>
      {action && <div className="mt-3">{action}</div>}
    </div>
  );
}

/** In-flight state. Announced, not merely drawn: a spinner nothing announces is invisible to a screen reader. */
export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <p role="status" className="py-10 text-cell text-ink-tertiary">
      {label}
    </p>
  );
}

/** A non-tabular collection. `<ul>/<li>`, so it is a list to the accessibility tree — never a table pretending. */
export function List({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <ul aria-label={label} className="divide-y divide-white/5">
      {children}
    </ul>
  );
}

export interface ListItemProps {
  children: ReactNode;
  "aria-label"?: string;
  className?: string;
}

export function ListItem({
  children,
  className,
  "aria-label": ariaLabel,
}: ListItemProps) {
  return (
    <li className={`py-3 ${className ?? ""}`.trim()} aria-label={ariaLabel}>
      {children}
    </li>
  );
}

export interface Column<T> {
  /** Stable key — React's key and the mutation-visible identity of the column. */
  key: string;
  /** The column's HEADER TEXT. Required: a `<th>` with no text is a cell the tier cannot name. */
  header: string;
  /**
   * `ctx` carries the row's expansion state and a toggle, so a cell can BE the disclosure control.
   *
   * ⚠ A SECOND ARGUMENT RATHER THAN A NEW COLUMN TYPE: the trigger belongs on whichever cell reads as the
   * way in — a member count, a name — not on a chevron in a column of its own that means nothing until you
   * click it.
   */
  cell: (row: T, ctx: { expanded: boolean; toggle: () => void }) => ReactNode;
  /** Numeric/right-aligned columns. Presentation only — never a reason to drop the header. */
  numeric?: boolean;
  /**
   * The row's value for this column AS TEXT — what sorting orders by and what the filter matches.
   *
   * ⛔ SEPARATE FROM `cell` ON PURPOSE, AND THE REASON IS THE ONE THAT MATTERS: `cell` returns a ReactNode.
   * Deriving a search key from rendered JSX means reaching into element trees, and anything a cell shows as
   * an icon, a badge or a coloured dot contributes NOTHING to it. A row would then be invisible to a search
   * for the very state its badge is announcing.
   *
   * ⚠ It may also carry text the cell does NOT display — an owner's email, an id — so a search finds rows by
   * facts the operator knows even when the column is showing something shorter.
   */
  sortValue?: (row: T) => string | number;
}

/**
 * ONE ACTION, DECLARED ONCE, APPLIED TO A SELECTION.
 *
 * ⛔ THE PROBLEM THIS REPLACES: every row carrying its own Edit / Disable / Delete. On a fifteen-row table
 * that is forty-five buttons, the same three verbs re-drawn fifteen times, and the row's actual CONTENT — who
 * may reach what — is squeezed into whatever space they leave. It also makes acting on five rows five separate
 * gestures with five separate confirmations.
 *
 * The verbs move to ONE bar. What makes that safe rather than merely tidier is `unavailable`.
 */
export interface RowAction<T> {
  key: string;
  label: string;
  /**
   * `single` — the verb only makes sense on exactly one row (Edit a rule; you cannot edit five at once).
   * `many` (default) — it applies across the selection.
   */
  arity?: "single" | "many";
  danger?: boolean;
  /**
   * ⛔ THE FIELD THAT MAKES A BULK VERB HONEST. Return a reason and this row cannot take this action.
   *
   * A selection is almost never uniform: five rules where one is GitOps-managed, or three devices where one
   * is already revoked. Without this, a bulk action has two bad options — silently skip the ineligible rows,
   * or silently attempt them. Both leave the operator believing they did something they did not do.
   *
   * > **THE SET AN ACTION APPLIES TO MUST BE STATED BEFORE IT RUNS, NOT DISCOVERED AFTERWARDS.** The bar
   * > says "3 of 5 selected" and names the reason for the other two.
   */
  unavailable?: (row: T) => string | null;
  /** Receives ONLY the eligible rows — the same set the bar counted out loud. */
  run: (rows: T[]) => void;
}

/**
 * The page numbers to render, with `null` marking an elided run.
 *
 * ⛔ ALWAYS FIRST AND LAST, ALWAYS THE CURRENT ONE AND ITS NEIGHBOURS. A pager that elides the last page
 * hides how much there is — and "how much is there" is the question a pager exists to answer. Kept as a pure
 * function so the windowing is testable without rendering a table.
 */
export function pageWindow(
  current: number,
  last: number,
): Array<number | null> {
  if (last <= 6) return Array.from({ length: last + 1 }, (_, i) => i);
  const keep = new Set([0, last, current, current - 1, current + 1]);
  const out: Array<number | null> = [];
  for (let i = 0; i <= last; i++) {
    if (keep.has(i)) out.push(i);
    else if (out[out.length - 1] !== null) out.push(null);
  }
  return out;
}

function PagerButton({
  label,
  disabled,
  onClick,
  children,
}: {
  label: string;
  disabled: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      disabled={disabled}
      onClick={onClick}
      className="min-w-[1.75rem] rounded border border-white/10 px-1.5 py-0.5 text-slate-400 hover:bg-white/5 disabled:opacity-30 disabled:hover:bg-transparent"
    >
      {children}
    </button>
  );
}

/**
 * A real table.
 *
 * `<table>` + `<caption>` + `<thead>` + `<th scope="col">` + `<tbody>`, so the tier can ask for
 * `getByRole("table", { name })`, `getAllByRole("row")`, `getByRole("columnheader", { name })` — the queries
 * that were impossible in this app until now.
 *
 * THE CAPTION IS THE TABLE'S ACCESSIBLE NAME and it is REQUIRED. Two unnamed tables on one screen are two
 * `role="table"` matches with no way to tell them apart, which pushes the tier straight back to text matching.
 *
 * `caption` is visually hidden by default (`sr-only`) because the surrounding Panel usually shows the same
 * heading — hidden from sight, PRESENT in the accessibility tree. That is the correct direction of the
 * invisible-is-not-absent rule: absent to the eye, present to the machine, never the reverse.
 */
export function DataTable<T>({
  caption,
  columns,
  rows,
  rowKey,
  empty,
  failed,
  filterable,
  defaultSortKey,
  pageSize: initialPageSize = 25,
  selectable,
  rowLabel,
  onSelectionChange,
  toolbar,
  bulkActions,
  rowActions,
  rowAttrs,
  expandable,
}: {
  caption: string;
  columns: Array<Column<T>>;
  rows: T[];
  rowKey: (row: T) => string;
  /** What to render when there are GENUINELY zero rows. */
  empty: ReactNode;
  /**
   * ⛔ REQUIRED, AND REQUIRED ON PURPOSE — did the load that produced `rows` FAIL?
   *
   * An empty array means two different things and the difference is the whole point: "there are none" and
   * "we never found out". Rendering the second as the first is the REASSURING-EMPTY defect the `loadOne` law
   * exists to prevent, and on a roster or a rule list it is not a neutral emptiness — it is a claim about
   * who has access, made by a screen that never successfully read anything.
   *
   * THIS PROP IS NOT OPTIONAL BECAUSE A DEFAULT WOULD PICK THE DANGEROUS ANSWER SILENTLY. Every call site
   * must state which case it is in, and forgetting is a COMPILE ERROR rather than a review note — a guard
   * enforced by types beats one enforced by discipline (docs/laws.md).
   *
   * FOUND THE HARD WAY, IN THIS SLICE: converting Users to a table dropped the page's `&& !error` guard and
   * reintroduced exactly this defect — inside the slice whose own EmptyState comment warns against it. The
   * component tier caught it. That is the third time in this epic that a near miss landed inside the guard
   * written to prevent it, which is why this is a type and not a comment.
   *
   * When `failed` is true the table renders NOTHING: the page owns the retry affordance (LoadRetry), because
   * only the page knows what to retry.
   */
  failed: boolean;
  /**
   * Show the filter box. Defaults ON whenever any column carries `sortValue` — a table you cannot search is
   * the reason people reach for the browser's own find bar, which searches only what is on screen and
   * silently misses everything the page has not rendered.
   */
  filterable?: boolean;
  /** Column key to sort by initially. Omit to keep the caller's order, which is often deliberate. */
  defaultSortKey?: string;
  /**
   * Rows per page. Defaults to 25.
   *
   * ⛔ PASS `0` TO DISABLE, AND THERE IS EXACTLY ONE REASON TO: THE PAGE ALREADY PAGES SERVER-SIDE. AuditLog
   * and AccessEvents fetch with a keyset cursor behind a "Load more" button. A client pager on top of that
   * puts TWO paging controls on one screen that disagree — "Load more" appends rows the operator cannot see
   * without also advancing a second pager, and the row count then describes neither the fetch nor the view.
   */
  pageSize?: number;
  /**
   * Add a leading checkbox column and the selection footer.
   *
   * ⛔ SELECTION IS THE MOST DANGEROUS THING A TABLE CAN OFFER, because the operator's next click is a BULK
   * action and the set it applies to is whatever this component says it is. Two ambiguities are resolved
   * explicitly rather than left to convention, and both are resolved the CONSERVATIVE way:
   *
   *  · **The header checkbox selects THIS PAGE, never the whole result set.** "Select all" meaning 500
   *    invisible rows is how a bulk revoke becomes an outage. Selecting everything is still possible — it is
   *    a separate, labelled control that states the number out loud.
   *  · **Selection SURVIVES paging and filtering, and the footer says when part of it is off-screen.** The
   *    alternative — silently dropping rows from the selection when they scroll out of view — makes the
   *    applied set differ from the counted set, which is worse than an honest warning.
   */
  selectable?: boolean;
  /**
   * A HUMAN name for the row, used as the checkbox's accessible name.
   *
   * ⛔ THE KEY IS NOT A NAME. `rowKey` is a uuid or a database id, so without this a screen-reader user hears
   * "select 019fcda7-7718-77e3" — a control they cannot identify, on the one interaction whose next step is
   * a bulk action. Defaults to the FIRST column's search value, which is the name column by convention on
   * every table in this app; falls back to the key only when there is nothing better.
   */
  rowLabel?: (row: T) => string;
  /** Called with the selected row keys whenever the selection changes. */
  onSelectionChange?: (keys: string[]) => void;
  /** Controls that belong beside the filter — a status dropdown, a date range. Rendered right-aligned. */
  toolbar?: ReactNode;
  /** Rendered in the selection footer. Receives the selected keys and a clear callback. */
  bulkActions?: (selected: string[], clear: () => void) => ReactNode;
  /**
   * Declarative verbs for the selection bar. Supplying these IMPLIES `selectable` — a set of actions with no
   * way to choose what they act on is not a feature.
   */
  rowActions?: Array<RowAction<T>>;
  /**
   * Data attributes for the `<tr>` — e.g. `{ "data-owned": "yes" }`.
   *
   * ⛔ THE ROW IS THE UNIT A TEST SCOPES TO, and without this the state has to be stamped on a span inside
   * some cell instead. That reads as equivalent and is not: `row.textContent` then covers ONE column, so an
   * assertion like "the owned row names its owner" silently checks the wrong half of the row and passes for
   * the wrong reason. Converting a list to a table is exactly when that breaks, because `<li>` was the row
   * and a cell is not.
   */
  rowAttrs?: (row: T) => Record<string, string>;
  /**
   * Content revealed beneath a row, full width. Return `null` for rows that do not expand.
   *
   * ⛔ RENDERED IN A `<tr>` OF ITS OWN, spanning every column — not inside a cell. A nested panel inside one
   * column is constrained to that column's width, so a member roster would render in the space taken by a
   * count. The row below is the only placement that gives it the table's full width.
   */
  expandable?: (row: T) => ReactNode | null;
}) {
  const searchable = columns.some((c) => c.sortValue);
  const showFilter = filterable ?? searchable;
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 } | null>(
    defaultSortKey ? { key: defaultSortKey, dir: 1 } : null,
  );
  const [pageSize, setPageSize] = useState(initialPageSize);
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());

  // The first column is the name column by convention here; using it keeps the checkbox's name meaningful
  // without every call site having to remember a prop.
  const showSelect = selectable || !!rowActions?.length;
  const labelFor = (r: T) =>
    rowLabel?.(r) ??
    (columns[0]?.sortValue ? String(columns[0].sortValue(r)) : rowKey(r));

  const setSel = (next: Set<string>) => {
    setSelected(next);
    onSelectionChange?.([...next]);
  };

  const visible = useMemo(() => {
    let out = rows;
    const q = query.trim().toLowerCase();
    if (q) {
      out = out.filter((r) =>
        columns.some(
          (c) =>
            c.sortValue && String(c.sortValue(r)).toLowerCase().includes(q),
        ),
      );
    }
    if (sort) {
      const col = columns.find((c) => c.key === sort.key);
      if (col?.sortValue) {
        // Copy before sorting: `rows` belongs to the caller and mutating it would reorder their state.
        out = [...out].sort((a, b) => {
          const x = col.sortValue!(a);
          const y = col.sortValue!(b);
          if (typeof x === "number" && typeof y === "number")
            return (x - y) * sort.dir;
          return String(x).localeCompare(String(y)) * sort.dir;
        });
      }
    }
    return out;
  }, [rows, columns, query, sort]);

  // ⛔ THE PAGE INDEX IS CLAMPED AT RENDER, NOT TRUSTED FROM STATE. Rows shrink underneath this component
  // all the time — a revoke, a filter, a refetch — and a page index that was valid a moment ago then points
  // past the end. The result is a table that renders ZERO ROWS while the data is right there, which is the
  // reassuring-empty defect arriving by arithmetic instead of by a failed load.
  //
  // Clamping here rather than in an effect means there is no frame in which the out-of-range value renders.
  const paged = pageSize > 0;
  const lastPage = paged
    ? Math.max(0, Math.ceil(visible.length / pageSize) - 1)
    : 0;
  const safePage = Math.min(page, lastPage);
  const pageRows = paged
    ? visible.slice(safePage * pageSize, safePage * pageSize + pageSize)
    : visible;
  const pageAllSelected =
    pageRows.length > 0 && pageRows.every((r) => selected.has(rowKey(r)));
  // ⚠ HOW MUCH OF THE SELECTION THE OPERATOR CANNOT SEE. Selection survives paging and filtering on
  // purpose; hiding that it did is what would make the applied set differ from the counted one.
  const visibleKeys = new Set(visible.map(rowKey));
  const offscreenSelected = [...selected].filter(
    (k) => !visibleKeys.has(k),
  ).length;

  if (failed) return null;

  // ⛔ THREE EMPTINESSES, NOT ONE, AND THEY ARE DIFFERENT CLAIMS. `failed` (handled above) is "we never found
  // out". `rows.length === 0` is "there are none". A filter matching nothing is "there are some, none match
  // what you typed" — and rendering that third case as the second tells an operator a resource does not
  // exist when it is sitting one keystroke away.
  //
  // > **A FILTER IS A NEW WAY TO MANUFACTURE A REASSURING EMPTY**, on a screen whose whole `failed` prop
  // > exists because of that class. The row count stays visible so the difference is never inferred.
  if (rows.length === 0) return <EmptyState>{empty}</EmptyState>;

  const toggle = (key: string) =>
    // Re-sorting returns to the first page: the row you were looking at is not where it was, and staying on
    // page 3 of a freshly reordered list lands the operator somewhere arbitrary.
    (
      setPage(0),
      setSort((s: { key: string; dir: 1 | -1 } | null) =>
        s && s.key === key
          ? { key, dir: s.dir === 1 ? -1 : 1 }
          : { key, dir: 1 },
      )
    );

  return (
    <div>
      {(showFilter || toolbar) && (
        <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
          {showFilter ? (
            <input
              type="search"
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                // ⛔ NARROWING RETURNS TO PAGE ONE. Typing while on page 3 of a list that now has four
                // matches would show an empty table — the operator's own search reading as "nothing exists".
                setPage(0);
              }}
              placeholder={`Search ${caption.toLowerCase()}…`}
              aria-label={`Filter ${caption}`}
              className="w-64 rounded-md border border-white/10 bg-white/5 px-2.5 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 focus:border-white/20 focus:outline-none"
            />
          ) : (
            <span />
          )}
          {toolbar}
        </div>
      )}
      {/* THE SELECTION BAR, ABOVE THE TABLE. Always present when the table is selectable — an empty-state bar that says
          "0 selected" teaches where the count will appear, and a bar that only materialises on the first
          click moves the layout under the operator's cursor. */}
      {showSelect && (
        <div className="mb-2 flex flex-wrap items-center justify-between gap-3 rounded-md border border-white/10 bg-white/[0.03] px-3 py-2 text-xs">
          <span className="text-ink-secondary">
            <span className="tabular-nums text-slate-300">{selected.size}</span>{" "}
            selected
            {/* ⛔ THE HALF THAT PREVENTS A SURPRISE. An action applies to the whole selection, including rows
                a filter or a page turn has hidden. Saying so is the difference between a bulk action the
                operator authorised and one they merely appeared to. */}
            {offscreenSelected > 0 && (
              <span className="ml-1 text-warn">
                ({offscreenSelected} not visible under the current filter)
              </span>
            )}
            {selected.size > 0 && (
              <button
                type="button"
                onClick={() => setSel(new Set())}
                className="ml-2 underline hover:text-slate-300"
              >
                Clear
              </button>
            )}
            {/* Selecting everything is possible, but it is its own control and it says the number. */}
            {!pageAllSelected || visible.length <= pageRows.length ? null : (
              <button
                type="button"
                onClick={() => setSel(new Set(visible.map(rowKey)))}
                className="ml-2 underline hover:text-slate-300"
              >
                Select all {visible.length} matching
              </button>
            )}
          </span>
          <span className="flex items-center gap-2">
            {selected.size === 0 ? (
              <span className="text-ink-tertiary">
                Select one or more rows to act on them
              </span>
            ) : (
              <>
                {rowActions?.map((a) => {
                  const chosen = rows.filter((r) => selected.has(rowKey(r)));
                  const eligible = chosen.filter((r) => !a.unavailable?.(r));
                  const arityOK =
                    a.arity === "single"
                      ? chosen.length === 1
                      : chosen.length > 0;
                  // ⛔ THE FIRST REASON WINS AND IS SHOWN. A disabled control with no explanation is a
                  // dead end an operator cannot reason about — they cannot tell "not allowed" from "broken".
                  const reason =
                    chosen.map((r) => a.unavailable?.(r)).find(Boolean) ??
                    undefined;
                  const blocked = !arityOK || eligible.length === 0;
                  return (
                    <span key={a.key} className="flex items-center gap-1">
                      {/* ⚠ THE PARTIAL COUNT, SAID BEFORE THE CLICK. A selection is almost never uniform,
                          and an action that quietly applies to a subset leaves the operator believing they
                          did something they did not do. */}
                      {!blocked && eligible.length < chosen.length && (
                        <span className="text-warn" title={reason}>
                          {eligible.length} of {chosen.length}
                        </span>
                      )}
                      <Button
                        size="sm"
                        variant={a.danger ? "danger" : "ghost"}
                        disabled={blocked}
                        title={
                          !arityOK && a.arity === "single"
                            ? `${a.label} applies to exactly one row at a time`
                            : eligible.length === 0
                              ? reason
                              : undefined
                        }
                        onClick={() => a.run(eligible)}
                      >
                        {a.label}
                      </Button>
                    </span>
                  );
                })}
                {bulkActions?.([...selected], () => setSel(new Set()))}
              </>
            )}
          </span>
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <caption className="sr-only">{caption}</caption>
          <thead>
            {/* Sticky: on a long roster the header is the only thing telling you what a column means, and
                scrolling past it turns every cell into an unlabelled string. */}
            <tr className="sticky top-0 z-10 bg-ink-900 text-[11px] uppercase tracking-wide text-slate-500">
              {showSelect && (
                <th
                  scope="col"
                  className="w-8 border-b border-white/10 py-1.5 pl-3 pr-2"
                >
                  {/* ⛔ THIS BOX SELECTS THE PAGE, AND ITS LABEL SAYS SO. A header checkbox that quietly
                      means "all 500 matches" is how a bulk revoke becomes an outage — the operator sees ten
                      rows and reasons about ten. Selecting everything is offered separately, by a control
                      that states the number out loud. */}
                  <input
                    type="checkbox"
                    aria-label={`Select all ${pageRows.length} on this page`}
                    checked={pageAllSelected}
                    ref={(el) => {
                      // Indeterminate is a DOM property, not an attribute — a partly-selected page must not
                      // render as either fully selected or untouched.
                      if (el)
                        el.indeterminate =
                          !pageAllSelected &&
                          pageRows.some((r) => selected.has(rowKey(r)));
                    }}
                    onChange={() => {
                      const next = new Set(selected);
                      if (pageAllSelected)
                        pageRows.forEach((r) => next.delete(rowKey(r)));
                      else pageRows.forEach((r) => next.add(rowKey(r)));
                      setSel(next);
                    }}
                    className="h-3.5 w-3.5 rounded border-white/20 bg-white/5 accent-slate-400"
                  />
                </th>
              )}
              {columns.map((c, i) => {
                const active = sort?.key === c.key;
                return (
                  <th
                    key={c.key}
                    scope="col"
                    aria-sort={
                      active
                        ? sort!.dir === 1
                          ? "ascending"
                          : "descending"
                        : undefined
                    }
                    // ⚠ A RIGHT-ALIGNED COLUMN NEEDS PADDING ON ITS *LEFT*, not only its right. `pr-4`
                    // alone pushes a numeric column's content to its own right edge, where it lands flush
                    // against the next column's left edge — "0" and a role select ended up touching, and
                    // the eye reads two adjacent columns as one field.
                    // ⚠ THE FIRST COLUMN NEEDS LEFT PADDING OR IT TOUCHES THE TABLE'S EDGE. Every cell had
                    // `pr-4` and nothing on the left, so column one sat flush against the container while
                    // every other column had a gap in front of it — the row read as starting at a hard edge
                    // rather than inside a surface. `i === 0` also covers the checkbox column, which is
                    // rendered separately and had the same problem.
                    className={`border-b border-white/10 py-1.5 pr-4 font-medium ${i === 0 && !showSelect ? "pl-3" : ""} ${c.numeric ? "pl-6 text-right" : ""}`}
                  >
                    {c.sortValue ? (
                      <button
                        type="button"
                        onClick={() => toggle(c.key)}
                        className="inline-flex items-center gap-1 uppercase tracking-wide hover:text-slate-300"
                      >
                        {c.header}
                        {/* ⛔ AN SVG, NOT A CHARACTER, AND THAT IS NOT A STYLE CHOICE. A text glyph lands in
                            the header's textContent, so `<th>` text becomes "Member↕" and every test and
                            query that names a column by its header stops matching. `aria-hidden` does not
                            help: it removes the glyph from the accessibility tree, not from the text. An
                            icon with no text node leaves the column's NAME exactly what it says it is. */}
                        <svg
                          aria-hidden
                          viewBox="0 0 8 12"
                          className={`h-2.5 w-2 shrink-0 ${active ? "text-slate-300" : "text-slate-700"}`}
                          fill="currentColor"
                        >
                          {(!active || sort!.dir === 1) && (
                            <path d="M4 0 L8 5 L0 5 Z" />
                          )}
                          {(!active || sort!.dir === -1) && (
                            <path d="M4 12 L0 7 L8 7 Z" />
                          )}
                        </svg>
                      </button>
                    ) : (
                      c.header
                    )}
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody>
            {pageRows.map((r: T, i: number) => {
              const key = rowKey(r);
              const isOpen = expanded.has(key);
              const toggle = () =>
                setExpanded((e) => {
                  const n = new Set(e);
                  if (n.has(key)) n.delete(key);
                  else n.add(key);
                  return n;
                });
              const panel = isOpen ? expandable?.(r) : null;
              return (
                <Fragment key={key}>
                  <tr
                    {...(rowAttrs?.(r) ?? {})}
                    // Zebra + hover: scanning across a wide row is where the eye loses its line, and this is
                    // presentation only — never the carrier of a state the row needs to announce in words.
                    className={`border-b border-white/5 hover:bg-white/[0.06] ${i % 2 ? "bg-white/[0.02]" : ""}`}
                  >
                    {showSelect && (
                      <td className="w-8 py-1.5 pl-3 pr-2 align-middle">
                        <input
                          type="checkbox"
                          aria-label={`Select ${labelFor(r)}`}
                          checked={selected.has(rowKey(r))}
                          onChange={() => {
                            const next = new Set(selected);
                            if (next.has(rowKey(r))) next.delete(rowKey(r));
                            else next.add(rowKey(r));
                            setSel(next);
                          }}
                          className="h-3.5 w-3.5 rounded border-white/20 bg-white/5 accent-slate-400"
                        />
                      </td>
                    )}
                    {columns.map((c, i) => (
                      <td
                        key={c.key}
                        className={`py-1.5 pr-4 align-middle ${i === 0 && !showSelect ? "pl-3" : ""} ${c.numeric ? "pl-6 text-right tabular-nums" : ""}`}
                      >
                        {c.cell(r, { expanded: isOpen, toggle })}
                      </td>
                    ))}
                  </tr>
                  {/* ⚠ The panel is a row, so it inherits the table's width rather than a column's. */}
                  {panel && (
                    <tr>
                      <td
                        colSpan={columns.length + (showSelect ? 1 : 0)}
                        className="px-0 pb-3"
                      >
                        {panel}
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
      {/* ⛔ THE FOOTER ONLY EXISTS WHEN IT HAS SOMETHING TO SAY, and the first version of this got it wrong
          in exactly the way the pager comment warned against. "No pager when everything fits" hid the page
          BUTTONS and left the rows-per-page control and the range behind — so a five-row table carried
          "Rows per page [25]   1–5 of 5", a control that can only no-op and a range that restates the
          obvious. Repeated on every table on a screen, that is more chrome than content.

          It renders when there is MORE THAN ONE PAGE (there is somewhere to go, and a size worth changing),
          or when a FILTER is narrowing (the "3 of 47" that stops a filtered view reading as a short one).
          On a table that fits and is unfiltered it renders nothing at all. */}
      {paged && (lastPage > 0 || query.trim() !== "") && (
        <div className="mt-2 flex flex-wrap items-center justify-between gap-3 border-t border-white/5 pt-2 text-[11px] text-ink-secondary">
          {/* ⚠ ABSENT WHEN EVERYTHING FITS — changing "rows per page" on a table showing all of them does
              nothing, and a control whose every value produces the same screen teaches that the controls
              here are decorative. */}
          {lastPage > 0 ? (
            <label className="flex items-center gap-1.5">
              <span>Rows per page</span>
              <select
                aria-label="Rows per page"
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  // Resizing changes what "page 3" means; returning to the first page is the only
                  // interpretation that cannot land the operator past the end.
                  setPage(0);
                }}
                className="rounded border border-white/10 bg-white/5 px-1.5 py-0.5 text-[11px] text-slate-300 focus:outline-none"
              >
                {[10, 25, 50, 100].map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
            </label>
          ) : (
            <span />
          )}

          {/* ⚠ THE RANGE DESCRIBES THE VIEW *AND* THE WHOLE, because with a pager the two are almost never
              the same number. And when a filter is on, the total it was filtered FROM stays visible, so the
              narrowing is never something the operator has to infer. */}
          <span className="tabular-nums">
            {visible.length === 0
              ? `0 of ${rows.length}`
              : lastPage === 0
                ? // One page: the RANGE is noise ("1–5 of 5"), but the fact that a filter narrowed it is not.
                  `${visible.length} of ${rows.length}`
                : `${safePage * pageSize + 1}–${Math.min((safePage + 1) * pageSize, visible.length)} of ${visible.length}` +
                  (query.trim() ? ` (filtered from ${rows.length})` : "")}
          </span>

          {lastPage > 0 ? (
            <div className="flex items-center gap-1">
              <PagerButton
                label="Previous page"
                disabled={safePage === 0}
                onClick={() => setPage(safePage - 1)}
              >
                ‹
              </PagerButton>
              {pageWindow(safePage, lastPage).map((n, i) =>
                n === null ? (
                  <span key={`gap-${i}`} className="px-1 text-slate-700">
                    …
                  </span>
                ) : (
                  <button
                    key={n}
                    type="button"
                    aria-label={`Page ${n + 1}`}
                    aria-current={n === safePage ? "page" : undefined}
                    onClick={() => setPage(n)}
                    className={`min-w-[1.75rem] rounded border px-1.5 py-0.5 tabular-nums ${
                      n === safePage
                        ? "border-white/25 bg-white/10 text-ink-heading"
                        : "border-white/10 text-slate-400 hover:bg-white/5"
                    }`}
                  >
                    {n + 1}
                  </button>
                ),
              )}
              <PagerButton
                label="Next page"
                disabled={safePage >= lastPage}
                onClick={() => setPage(safePage + 1)}
              >
                ›
              </PagerButton>
            </div>
          ) : (
            <span />
          )}
        </div>
      )}

      {/* ⛔ THE THIRD EMPTINESS, SAID IN WORDS. Never the `empty` copy — that one claims none exist. */}
      {visible.length === 0 && (
        <p className="py-6 text-center text-xs text-ink-secondary">
          No {caption.toLowerCase()} match{" "}
          <span className="font-mono text-slate-300">{query}</span>.{" "}
          <button
            type="button"
            onClick={() => setQuery("")}
            className="underline hover:text-slate-300"
          >
            Clear filter
          </button>{" "}
          to see all {rows.length}.
        </p>
      )}
    </div>
  );
}
