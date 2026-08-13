import { useState } from "react";
import {
  NAV_WIDTH,
  navShows,
  navToggleTitle,
  readNavCollapse,
  toggleNavCollapse,
  writeNavCollapse,
  type NavCollapse,
} from "../lib/navcollapse";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { Logo, PRODUCT_TAGLINE, Tagline } from "../brand";
import { useAuth } from "../lib/auth";
import { useResendVerification } from "../lib/useResendVerification";
import { Button } from "./ui";
import { HealthStatus } from "./HealthStatus";
import { IdentityBadges } from "./IdentityBadges";
import { OrgSwitcher } from "./OrgSwitcher";
import { useLayoutCapability } from "./ComposeGate";
import { CommandPalette } from "./CommandPalette";
import { useNavCounts } from "../lib/useNavCounts";
import { Icon, type IconName } from "./Icon";
import { badgeText, gatewayBadgeText, type NavCounts } from "../lib/navcounts";

// S14.2 — THE NAV, GROUPED. The wireframe groups destinations NETWORK / ACCESS / OBSERVE / OPERATE / SETTINGS,
// and that grouping is preserved at EVERY width; only its PRESENTATION changes.
//
// ⛔ RESPONSIVE MAY RE-ARRANGE, NEVER REMOVE. Every destination is in the DOM at every width. A CSS-hidden
// destination is a navigation surface that exists for some users and not others, DECIDED BY VIEWPORT RATHER
// THAN BY PERMISSION — and permission is a render decision while width never is (docs/laws.md).
//
// Sites (S8.3) and Kubernetes (S10.3) are shown to everyone: each page owns its own edition upsell (the Access
// precedent, D5), so a non-enterprise org sees the entry and a clear explanation rather than a dead link.
export const NAV_GROUPS: Array<{
  group: string;
  items: Array<{ to: string; label: string; icon: IconName }>;
}> = [
  {
    group: "",
    items: [{ to: "/dashboard", label: "Overview", icon: "layout-dashboard" }],
  },
  {
    group: "NETWORK",
    items: [
      // S14.6: Gateways leads NETWORK, as the handoff's nav does. It was a component inside Devices with no
      // route and no entry here — working fleet management an operator could only reach by scrolling another
      // screen.
      { to: "/gateways", label: "Gateways", icon: "server" },
      { to: "/sites", label: "Sites", icon: "network" },
      // S14.7: Routed Ranges was BUILD, not REDESIGN — `/routed-ranges` has been served since S8.5 and
      // nothing rendered it. The answer to "does my LAN traffic go down the tunnel" was reachable only by
      // reading a device's AllowedIPs.
      { to: "/routed-ranges", label: "Routed ranges", icon: "route" },
      { to: "/kubernetes", label: "Kubernetes", icon: "boxes" },
      // ⛔ S15.3 — AI agents is a TOP-LEVEL DESTINATION, beside Kubernetes, and the placement is the
      // ruling. It was first built as a section inside Devices on the premise that the schema says an
      // agent is a devices row — and the measurement broke that premise: an agent is a GATEWAY, enrolled
      // on Gateways, that ACQUIRES a device row. The row is an artifact of attribution, not the thing.
      // ⚠ NETWORK is where things you ENROL live, which is exactly what an agent now is.
      { to: "/agents", label: "AI agents", icon: "bot" },
    ],
  },
  {
    group: "ACCESS",
    items: [
      { to: "/access", label: "Access Policies", icon: "shield" },
      { to: "/devices", label: "Devices", icon: "laptop" },
      { to: "/users", label: "Users & Roles", icon: "users" },
    ],
  },
  {
    group: "OBSERVE",
    items: [
      {
        to: "/access-events",
        label: "Access Events",
        icon: "arrow-right-left",
      },
      { to: "/audit", label: "Audit Log", icon: "file-text" },
    ],
  },
  {
    group: "SETTINGS",
    items: [{ to: "/settings", label: "Org Settings", icon: "settings" }],
  },
];

/** Flat destination list — the invariant the responsive contract asserts is identical at every width. */
export const NAV_DESTINATIONS = NAV_GROUPS.flatMap((g) => g.items);

/** The triage set — the surfaces mobile exists FOR (read health, work the approval queue, act on devices). */
const TRIAGE_SET = ["/dashboard", "/devices", "/access"];

/**
 * The badge for a destination, or `null`.
 *
 * ⛔ `null` MEANS RENDER NOTHING. Not an empty string, not a dash, and never `0` — see lib/navcounts.ts for
 * why this surface is stricter than any other in the app.
 */
function badgeFor(to: string, c: NavCounts): string | null {
  // ⛔ THE GATEWAY RATIO BELONGS ON /gateways, and it was on /dashboard because /gateways DID NOT EXIST.
  //
  // Overview rendered `1/6` — the online-of-total GATEWAY count — on a nav item that is not about gateways,
  // while the Gateways item carried nothing. The handoff binds `3/7` to Gateways. Moved now that slice 1
  // gave the fleet a route of its own.
  //
  // A BADGE PARKED ON THE NEAREST AVAILABLE ITEM OUTLIVES THE REASON IT WAS PARKED THERE.
  if (to === "/gateways")
    return gatewayBadgeText(c.gatewaysTotal, c.gatewayCeiling);
  if (to === "/sites") return badgeText(c.sites);
  if (to === "/devices") return badgeText(c.devices);
  return null;
}

function NavGroups({
  onNavigate,
  counts,
  collapsed = false,
}: {
  onNavigate?: () => void;
  counts: NavCounts;
  collapsed?: boolean;
}) {
  const shows = navShows(collapsed ? "closed" : "open");
  return (
    <>
      {NAV_GROUPS.map((g) => (
        <div key={g.group || "root"} className="mb-3">
          {/* ⛔ HEADERS GO, DESTINATIONS STAY. A rail that dropped a destination would make it
              unreachable rather than compact — the collapse is a presentation, never a filter. */}
          {g.group && shows.sectionHeaders && (
            <p className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-600">
              {g.group}
            </p>
          )}
          <ul className="space-y-1">
            {g.items.map((item) => (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  onClick={onNavigate}
                  title={collapsed ? item.label : undefined}
                  aria-label={collapsed ? item.label : undefined}
                  className={({ isActive }) =>
                    // README: nav item = flex, gap 10, padding 7px 12px, radius 9, 14px icon + 12.5px label,
                    // right-aligned badge. Active = accent at 13%; hover nudges 2px right.
                    `relative flex items-center gap-2.5 rounded-nav text-nav transition-colors ${
                      // The design's own padding/justification pair: 9px 0 + centre when closed,
                      // 7px 12px + flex-start when open.
                      collapsed ? "justify-center py-[9px]" : "px-3 py-[7px]"
                    } ${
                      isActive
                        ? "bg-white/[.12] text-ink-heading"
                        : "text-ink-body hover:translate-x-[2px] hover:bg-white/[.06] hover:text-ink-primary"
                    }`
                  }
                >
                  <Icon name={item.icon} size={14} className="shrink-0" />
                  {/* The label is the only thing the rail drops. `title` keeps it reachable to a
                      pointer, and the aria-label keeps it reachable to a screen reader — a rail of
                      unlabelled icons is not a compact nav, it is a quiz. */}
                  {shows.labels && (
                    <span className="truncate">{item.label}</span>
                  )}
                  {/* ⛔ The badge is RIGHT-ALIGNED and CONDITIONAL; the destination never is. `null` means
                      render nothing — never 0, never a dash (lib/navcounts.ts). */}
                  {(() => {
                    const b = badgeFor(item.to, counts);
                    // Badges survive the collapse — they are the reason to glance at a rail at all.
                    if (collapsed) {
                      return b === null ? null : (
                        <span className="absolute right-1 top-1 h-1.5 w-1.5 rounded-full bg-accent-400" />
                      );
                    }
                    return b === null ? null : (
                      <span className="ml-auto font-mono text-badge tracking-[.1em] text-ink-secondary">
                        {b}
                      </span>
                    );
                  })()}
                </NavLink>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </>
  );
}

/**
 * SidebarNav renders every destination in every nav mode. `navMode` changes how the groups are PRESENTED — a
 * drawer behind a menu button, a compact rail, or the full labelled rail — and never WHICH destinations exist.
 *
 * ⚠ THE DRAWER IS `hidden` WHEN CLOSED, DELIBERATELY, and that is not a contradiction of "never remove".
 * An off-canvas panel whose links stay in the accessible tree is a keyboard trap: tab order walks through
 * destinations the user cannot see. So the closed drawer is genuinely absent — and the invariant it must
 * satisfy is that OPENING it yields the SAME destination set as the widest rail. That is what the responsive
 * contract asserts: it clicks the menu button at `triage` and compares the set. A destination dropped from the
 * narrow build fails there.
 */
function SidebarNav() {
  const { navMode } = useLayoutCapability();
  const counts = useNavCounts();
  const [drawerOpen, setDrawerOpen] = useState(false);
  // ⛔ USER-CONTROLLED, AND PERSISTED AT THE DESIGNER'S OWN KEY. `navMode` narrows the rail when the
  // VIEWPORT is small; this is the operator narrowing it on a wide screen and having it remembered.
  // Read once at mount so the first paint is already correct — a sidebar that expands and then
  // snaps shut is worse than one that never remembered.
  const [collapse, setCollapse] = useState<NavCollapse>(() =>
    readNavCollapse(typeof window === "undefined" ? null : window.localStorage),
  );
  const toggle = () => {
    const next = toggleNavCollapse(collapse);
    setCollapse(next);
    writeNavCollapse(
      typeof window === "undefined" ? null : window.localStorage,
      next,
    );
  };
  // The narrow-viewport rail already has no room for labels, so it reads as collapsed regardless
  // of the preference — the preference governs the WIDE case, which is what it was missing.
  const collapsed = navMode === "rail" || collapse === "closed";

  if (navMode === "drawer") {
    return (
      <>
        <button
          type="button"
          aria-expanded={drawerOpen}
          aria-controls="main-nav"
          onClick={() => setDrawerOpen((o) => !o)}
          className="absolute left-4 top-4 rounded-md border border-white/10 px-3 py-2 text-sm text-slate-300"
        >
          Menu
        </button>
        <nav
          id="main-nav"
          aria-label="Main"
          hidden={!drawerOpen}
          className="absolute inset-y-0 left-0 z-20 w-[228px] border-r border-line bg-bg p-2.5"
        >
          <NavGroups onNavigate={() => setDrawerOpen(false)} counts={counts} />
        </nav>
      </>
    );
  }

  // rail (compose) and full (operate+) differ in width and label treatment, not in content.
  return (
    // ⛔ THE BRAND HEADER SITS OUTSIDE <nav>, AND THE RESPONSIVE CONTRACT IS WHY.
    //
    // The wordmark links to /dashboard, so putting it inside `#main-nav` added a SECOND link to a
    // destination that was already there — and the contract, which compares the nav's destination
    // SET across breakpoints, caught it immediately (10 where it expected 9).
    //
    // It was right to. A brand mark that happens to navigate is not a nav destination, and
    // counting it as one would have quietly changed what "every destination" means. <nav> now
    // contains the destination list and nothing else, which is also what the landmark is for.
    <div
      style={{ width: collapsed ? NAV_WIDTH.closed : NAV_WIDTH.open }}
      className="flex shrink-0 flex-col border-r border-line p-2.5 transition-[width] duration-200"
    >
      {/* ⛔ TWO TARGETS, TWO MEANINGS. The MARK toggles the rail; the WORDMARK goes to Overview.
          One combined click-target would have to pick one, and whichever it picked would surprise
          half the people who clicked it. Collapsed, only the mark remains — and it is still the
          toggle, which is the only way back out. */}
      <div className="mb-3 flex items-center gap-2.5 px-1">
        <button
          type="button"
          onClick={toggle}
          title={navToggleTitle(collapsed ? "closed" : "open")}
          aria-label={navToggleTitle(collapsed ? "closed" : "open")}
          aria-expanded={!collapsed}
          aria-controls="main-nav"
          className="shrink-0 rounded-lg transition-transform hover:scale-105"
        >
          <Logo size={26} markOnly />
        </button>
        {navShows(collapsed ? "closed" : "open").wordmark && (
          <NavLink
            to="/dashboard"
            className="min-w-0 leading-none"
            // ⛔ NOT "Overview" — the nav already has a link to /dashboard with that exact name, so
            // two links shared one accessible name and a screen reader announced them identically.
            // Playwright's strict mode caught it as an ambiguous locator, which is the same defect
            // wearing a test's clothes. The brand is a HOME affordance, not the destination's label.
            aria-label="Tunnex home"
          >
            <Logo size={26} wordmarkOnly />
            {/* The design sets the tagline directly under the wordmark, 8.5px/1.6. Shared with the
                desktop client through brand.tsx — one definition, so it cannot drift. */}
            <Tagline className="mt-1" />
          </NavLink>
        )}
      </div>

      <nav
        id="main-nav"
        aria-label="Main"
        className="min-h-0 flex-1 overflow-y-auto"
      >
        <NavGroups counts={counts} collapsed={collapsed} />
      </nav>
    </div>
  );
}

/**
 * The triage bottom bar: the on-call subset, one tap away, at `triage` only.
 *
 * It is a SECOND surface carrying destinations that already exist in the drawer, so it is derived from
 * NAV_DESTINATIONS rather than re-listed — a hand-written copy is how the two drift apart.
 */
function TriageBar() {
  const items = NAV_DESTINATIONS.filter((i) => TRIAGE_SET.includes(i.to));
  return (
    <nav
      aria-label="Triage"
      className="sticky bottom-0 flex justify-around border-t border-white/5 bg-ink-950 px-2 py-2"
    >
      {items.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          className="px-3 py-1 text-xs text-slate-400"
        >
          {item.label}
        </NavLink>
      ))}
    </nav>
  );
}

/** AppShell is the authenticated layout: header (brand + user + logout), sidebar
 * nav, and the routed page in the main area. */
export function AppShell() {
  const { state, logout } = useAuth();
  const { navMode, columns } = useLayoutCapability();
  const navigate = useNavigate();
  const email = state.status === "authed" ? state.user.email : "";

  async function onLogout() {
    // ⛔ THE DESKTOP ARM IS GONE (S14.20 step 4) — this shell is dashboard chrome and the client
    // never mounts it. Signing out of the CLIENT is `auth.logout()` on its own Settings pane, which
    // is where the credential and the keychain actually live.
    await logout();
    navigate("/login", { replace: true });
  }

  return (
    <div className="flex min-h-full flex-col bg-transparent">
      {/* Mounted on the SHELL, not per screen: ⌘K must work wherever the user is. */}
      <CommandPalette />
      {/* README: TOP BAR, h:56px — search (opens the palette), spacer, then identity. */}
      {/* README: TOP BAR, h:56px. `min-w-0` on both children and `truncate` on the email are load-bearing:
          without them a long address (owner@demo.tunnex.local) pushes the row past the viewport and the whole
          PAGE scrolls sideways — the overflow the viewport leg caught at 390px, 65px wide and constant.
          Flex items default to `min-width: auto`, so they refuse to shrink below their content. That is the
          single most common cause of horizontal overflow in a flex row, and it is invisible until something
          inside is long enough. */}

      {/* ⛔ TWO LOGOS, AND THE LAYOUT WAS THE REASON. The topbar spanned the FULL WIDTH — above the
          sidebar — and carried its own <Logo>, so once the sidebar gained the brand there were two
          marks stacked in the same corner.
          The design has the sidebar FULL-HEIGHT with the topbar beside it, which is why it has one:
          there is only one place the brand can sit. Removing the duplicate without moving the
          topbar would have left a blank 56px strip above the sidebar instead. */}
      <div className="relative flex min-h-0 flex-1">
        <SidebarNav />
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="flex h-[56px] shrink-0 items-center justify-end gap-2 border-b border-line px-4">
            <div className="flex min-w-0 items-center gap-3">
              {/* The search field IS the command-palette affordance (S14.3 built the palette; this is its
              discoverable entry point, since a shortcut nobody sees is a shortcut nobody uses). */}
              <button
                type="button"
                onClick={() =>
                  window.dispatchEvent(
                    new KeyboardEvent("keydown", {
                      key: "k",
                      metaKey: true,
                      bubbles: true,
                    }),
                  )
                }
                className="hidden items-center gap-2 rounded-input border border-line bg-surface-inset px-3 py-[7px] text-cell text-ink-secondary hover:text-ink-body md:flex"
              >
                <Icon name="search" size={13} />
                <span>Search users, devices, gateways, sites…</span>
                <span className="ml-2 font-mono text-badge text-ink-secondary">
                  ⌘K
                </span>
              </button>
              {/* Badges and the address are IDENTITY CONTEXT, not controls. Below `sm` the row belongs to the
              action, so they step aside rather than squeezing it — the destination is never removed, only the
              decoration around it (S14.2's rule, applied to the top bar). */}
              <OrgSwitcher />
              <span className="hidden sm:flex">
                <IdentityBadges />
              </span>
              <span className="hidden min-w-0 truncate text-cell text-ink-body sm:block">
                {email}
              </span>
              <Button variant="ghost" className="shrink-0" onClick={onLogout}>
                Log out
              </Button>
            </div>
          </header>

          {/* ⛔ NO max-width. README: "Page body max content width: none — grids fill available width."
            The previous `max-w-3xl` capped EVERY screen at 768px, which is why S14.2's `columns` budget was
            computed, asserted, and never consumable — dormant machinery in our own new code (docs/laws.md).
            Padding and gap are the README's: 20px 24px 28px, flex column, gap 14. */}
          <main
            className="tnx-page flex flex-1 flex-col gap-3.5 px-6 pb-[30px] pt-[34px]"
            data-columns={columns}
          >
            {/* data-columns publishes the column BUDGET so a page grid can consume it — which nothing could do
              while this element capped the width at 768px. */}
            {state.status === "authed" && !state.user.email_verified && (
              <VerifyEmailBanner />
            )}
            <Outlet />
          </main>
        </div>
      </div>

      {navMode === "drawer" && <TriageBar />}

      <footer className="flex items-center justify-between border-t border-white/5 px-6 py-3 text-xs text-slate-600">
        <HealthStatus />
        <span>{PRODUCT_TAGLINE}</span>
      </footer>
    </div>
  );
}

// VerifyEmailBanner nudges an unverified user (login is allowed unverified, but
// org-mutating actions are gated server-side). Resend goes through the real
// mailer flow (POST /auth/verify-email/resend) via the shared hook.
function VerifyEmailBanner() {
  const { state, resend } = useResendVerification();
  return (
    <div className="mb-6 flex items-center justify-between rounded-lg border border-warn/40 bg-warn/5 px-4 py-3">
      <span className="text-sm text-slate-300">
        Verify your email to unlock all actions.
        {/* Success feedback uses the accent, not green: green is reserved for
            liveness ("alive right now"), not "the action worked" (S4.4 decision f). */}
        {state === "sent" && (
          <span className="ml-1 text-accent-400">Sent. Check your inbox.</span>
        )}
        {state === "error" && (
          <span className="ml-1 text-danger">
            Couldn&rsquo;t send. Try again.
          </span>
        )}
      </span>
      {state !== "sent" && (
        <Button variant="ghost" onClick={resend} disabled={state === "busy"}>
          {state === "busy" ? "Sending…" : "Resend verification"}
        </Button>
      )}
    </div>
  );
}
