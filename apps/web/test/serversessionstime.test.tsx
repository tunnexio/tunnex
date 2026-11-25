import { afterEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { ServerSessions } from "../src/components/ServerSessions";
import { compactDateTime } from "../src/lib/format";
import { stripCssComments } from "./support/source";
import type { components } from "@tunnex/shared";
type Session = components["schemas"]["ServerAccessSession"];
afterEach(cleanup);

const server = { id: "server-1", name: "Target" } as components["schemas"]["ServerAccessServer"];
const session = (id: string, overrides: Partial<Session> = {}) => ({ id, kind: "terminal", status: "ended", reason: "", server_id: server.id, user_id: "user-1", account: "ubuntu", created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 3600000).toISOString(), recording_enabled: true, ...overrides }) as Session;
const renderSessions = (sessions: Session[]) => render(<MemoryRouter><ServerSessions sessions={sessions} servers={[server]} members={[]} disabled={false} onRefresh={vi.fn()} onEnd={vi.fn()} onReplay={vi.fn()} importControl={null} /></MemoryRouter>);
// Expected strings come from the same Intl options, so the tests hold under any LANG/TZ.
const fmt = (iso: string, options: Intl.DateTimeFormatOptions) => new Intl.DateTimeFormat(undefined, options).format(new Date(iso));
const seconds = /\d{1,2}:\d{2}:\d{2}/;

// SA-UX-4 bug 1: the Started column was a blank 40px column with a date wrapping 2–3 characters per line.
describe("compactDateTime", () => {
  const now = new Date(2026, 10, 25, 15, 0, 0);
  it("shows only the time on the same day", () => {
    const iso = new Date(2026, 10, 25, 12, 32, 2).toISOString();
    expect(compactDateTime(iso, now)).toBe(fmt(iso, { hour: "numeric", minute: "2-digit" }));
    expect(compactDateTime(iso, now)).not.toMatch(seconds);
  });
  it("shows day, month and time earlier in the same year, without the year", () => {
    const iso = new Date(2026, 2, 4, 9, 5, 0).toISOString();
    expect(compactDateTime(iso, now)).toBe(fmt(iso, { day: "numeric", month: "short", hour: "numeric", minute: "2-digit" }));
    expect(compactDateTime(iso, now)).not.toContain("2026");
  });
  it("adds the year for another year", () => {
    const iso = new Date(2025, 11, 31, 23, 59, 0).toISOString();
    expect(compactDateTime(iso, now)).toBe(fmt(iso, { year: "numeric", day: "numeric", month: "short", hour: "numeric", minute: "2-digit" }));
  });
  it("is empty for a missing or invalid time", () => {
    expect(compactDateTime("", now)).toBe("");
    expect(compactDateTime("not a date", now)).toBe("");
  });
});

describe("Server sessions time columns", () => {
  it("names every column header, including Started and Duration or expiry", () => {
    renderSessions([session("rec00001")]);
    const headers = screen.getAllByRole("columnheader").map(h => h.textContent?.trim());
    expect(headers).toEqual(["Server", "User", "Status", "Recording", "Started", "Duration or expiry", "Actions"]);
  });
  it("renders Started as a compact, non-wrapping time with the exact time on hover", () => {
    const created = "2026-11-25T10:00:00Z";
    renderSessions([session("rec00001", { created_at: created, ended_at: "2026-11-25T10:12:00Z" })]);
    const row = screen.getAllByRole("row")[1];
    const time = row.querySelector(`time[datetime="${created}"]`) as HTMLElement;
    expect(time).toBeTruthy();
    expect(time.classList.contains("sa-time")).toBe(true);
    expect(time.textContent).toBe(compactDateTime(created));
    expect(time.textContent).not.toMatch(seconds);
    expect(time.getAttribute("title")).toBe(new Date(created).toLocaleString());
    expect(within(row).getByText("12 min").classList.contains("sa-time")).toBe(true);
  });
  it("renders a live session's expiry with the same compact, non-wrapping time", () => {
    const expires = new Date(Date.now() + 3600000).toISOString();
    renderSessions([session("live0001", { status: "connected", expires_at: expires })]);
    const time = screen.getAllByRole("row")[1].querySelector(`time[datetime="${expires}"]`) as HTMLElement;
    expect(time.classList.contains("sa-time")).toBe(true);
    expect(time.textContent).toBe(compactDateTime(expires));
    const cell = time.parentElement as HTMLElement;
    expect(cell.classList.contains("sa-time")).toBe(true);
    expect(cell.textContent).toBe(`Expires ${compactDateTime(expires)}`);
  });
  it("shows full start and end times in Details", () => {
    const created = "2026-11-25T10:00:00Z", ended = "2026-11-25T10:12:00Z";
    renderSessions([session("rec00001", { created_at: created, ended_at: ended })]);
    const trigger = screen.getByRole("button", { name: "Session actions for rec00001" });
    fireEvent.click(trigger);
    fireEvent.click(within(screen.getByRole("menu", { name: "Session actions for rec00001" })).getByRole("menuitem", { name: "Details" }));
    const dialog = screen.getByRole("dialog", { name: "Session details" });
    expect(within(dialog).getByText(new Date(created).toLocaleString())).toBeTruthy();
    const facts = [...dialog.querySelectorAll("dd")].map(dd => dd.textContent);
    expect(facts).toContain(`${new Date(ended).toLocaleString()} (12 min)`);
    expect(dialog.querySelector(`time[datetime="${ended}"]`)).toBeTruthy();
  });
});

// jsdom applies no stylesheet, so the original bug (a shared nth-child rule hiding the 5th header) needs a
// stylesheet guard: the sessions table must never inherit the grants table's positional widths again.
describe("Server sessions stylesheet", () => {
  const css = stripCssComments(readFileSync(join(__dirname, "..", "src", "server-access-workspace.css"), "utf8"));
  const rules = [...css.matchAll(/([^{}]+)\{([^}]*)\}/g)].map(m => ({ selector: m[1].trim(), body: m[2] }));
  const sessionRules = rules.filter(r => r.selector.includes(".sa-session-table"));
  it("never hides a session column header or shares grants column widths", () => {
    expect(sessionRules.length).toBeGreaterThan(0);
    for (const r of sessionRules) {
      expect(r.body.replace(/\s/g, "")).not.toContain("font-size:0");
      expect(r.selector).not.toContain(".sa-grants-table");
    }
  });
  it("sizes all seven session columns and keeps time values on one line", () => {
    for (const key of ["user", "status", "recording", "started", "time", "actions"]) expect(sessionRules.some(r => r.selector.includes(`th[data-column="${key}"]`))).toBe(true);
    const time = rules.find(r => /\.sa-time\b/.test(r.selector));
    expect(time?.body.replace(/\s/g, "")).toContain("white-space:nowrap");
  });
});
