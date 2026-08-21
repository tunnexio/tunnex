# F17 — final CSS and UX polish decisions

## Decision

F17 is a bounded, behaviour-preserving usability pass over the settled control
plane. It has no schema, API, RBAC, policy, licence, or network changes. The
customer outcome is simple: every established control-plane screen remains
truthful while becoming usable on a narrow viewport, by keyboard, and through
assistive technology.

The accessibility target is WCAG 2.2 AA. The relevant current guidance is
[WCAG 2.2](https://www.w3.org/TR/WCAG22/), including target size, focus-not-
obscured, and keyboard requirements; the [WAI ARIA Authoring Practices
Guide](https://www.w3.org/WAI/ARIA/apg/); and WAI guidance for
[announced errors](https://www.w3.org/WAI/WCAG21/Techniques/aria/ARIA19).

## D1 — Improve the existing component seams, never create a parallel UI kit

F17 reuses the shared `ui` controls, `AppShell`, `LoadRetry`, `ErrorText`,
`Toasts`, and existing motion preference seam. A page-specific class may be
adjusted only when a shared primitive cannot express the requirement without
changing another stable surface. No new component library, CSS framework,
theme switcher, or colour-system replacement is in scope.

## D2 — A load failure is not an empty result

Each touched read surface must preserve three visible states: loading, genuine
empty result, and failed fetch. A retry appears only for a failed fetch; a
genuine empty result never implies that an API call failed. Existing truthful
empty-state language and `LoadRetry` are the preferred implementations.

This is a truthfulness rule, not decorative polish: no screen may hide a
failed read behind an empty table, zero count, or reassuring health state.

## D3 — Native semantics first; ARIA describes, it does not repair

Use native buttons, links, labels, inputs, and table semantics where they fit.
F17 fixes missing accessible names, focus visibility, keyboard reachability,
dialog focus/escape/return behaviour, and live status/error announcement only
at the component that owns each interaction. It does not add generic ARIA
roles to plain layout elements or invent keyboard behaviour for a control that
does not need it.

Transient non-blocking status uses the existing toast/status surface. A
blocking destructive confirmation remains a modal dialog with a labelled
action and an explicit safe exit. No critical message may disappear before an
operator can read or recover it.

## D4 — Responsive means retained capability, not forced card conversion

At narrow widths, navigation collapses without hiding a route, forms retain
their labels and actions, and overflow is explicit. Dense data tables may
remain tables with a labelled horizontal-scroll container when preserving
column comparison is more truthful than collapsing fields into ambiguous
cards. F17 must not silently remove a destructive action, status, owner, or
policy fact to make a layout fit.

The baseline is keyboard-operable controls and WCAG 2.2 minimum target size
where practical; compact inline controls retain adequate spacing or an
equivalent reachable action.

## D5 — Terminology changes only correct a user-visible lie

F17 may normalize labels such as loading, unavailable, pending, connected,
and offline when the rendered wording contradicts the data source. It must not
rename product concepts, rewrite audit terminology, or simplify a state by
omitting its uncertainty. Existing backend/API terms stay the source of truth.

## D6 — Slice order follows shared reach, then rendered acceptance

1. Establish shared focus, status/error, dialog, and responsive-overflow
   contracts with focused rendered tests.
2. Apply them to the app shell, global navigation, auth pages, and common
   list/table/form surfaces.
3. Audit high-density operational pages — Dashboard, Devices, Gateways,
   Sites, Access, Audit Log, Kubernetes, and AI agents — for the absence
   questions: unreachable UI mutations and uncommunicated destructive impact.
4. Run a viewport and keyboard rendered pass across every route, then stop.

## Non-goals and stop conditions

- No API/data migrations, backend changes, RBAC changes, protocol changes,
  dashboard redesign, new visual brand, dark/light mode, localization,
  analytics, or bulk rewrite of page components.
- No inferred feature additions: an API capability without a caller is
  recorded as an absence finding for disposition, not exposed by F17.
- Do not change business behaviour to satisfy a visual test.
- Stop when each touched route has a truthful load/empty/error treatment,
  keyboard reachability, visible focus, a narrow viewport rendering, and a
  focused regression test. Any discovered missing product capability or
  destructive-impact ambiguity is held as a decide-item for the founder.
