import { describe, expect, it, vi, beforeEach } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const { setUser, get } = vi.hoisted(() => ({ setUser: vi.fn(), get: vi.fn() }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ setUser }) }));
vi.mock("../src/lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: get, POST: vi.fn() } };
});

import Login from "../src/pages/Login";

// `window.location.href = ...` is how the page hands off to the IdP; jsdom refuses a real
// navigation, so the assignment is captured instead of performed.
function captureNavigation(): { url: string | null } {
  const seen: { url: string | null } = { url: null };
  Object.defineProperty(window, "location", {
    configurable: true,
    value: {
      ...window.location,
      host: "localhost",
      set href(v: string) {
        seen.url = v;
      },
      get href() {
        return seen.url ?? "";
      },
    },
  });
  return seen;
}

// Routes by PATH, not by call order: the page fetches /api/v1/meta on mount, and a queue keyed on
// order silently fed that meta response to the first SSO click instead — the click then saw a
// success shape with no redirect_url and no error, so the ambiguity branch never ran.
function metaThen(...starts: unknown[]) {
  get.mockReset();
  let i = 0;
  get.mockImplementation(async (path: string) => {
    if (path === "/api/v1/meta") {
      return { data: { sso_providers: ["google", "microsoft"] } };
    }
    // ⛔ /healthz MUST BE ROUTED, NOT LEFT TO THE QUEUE. AuthLayout renders HealthStatus, which GETs
    // /healthz on mount — so an unrouted path fell through to `starts[i++]` and ATE the SSO response the
    // test had queued. The click then saw a health payload, and four tests failed for a reason that had
    // nothing to do with SSO. Routing by path is the whole point of this stub; every path the page actually
    // calls has to be named.
    if (path === "/healthz") {
      return { data: { status: "ok" } };
    }
    return starts[i++] ?? { error: { error: { code: "unexpected_extra_call" } } };
  });
}

function renderLogin() {
  return render(
    <MemoryRouter initialEntries={["/login"]}>
      <Login />
    </MemoryRouter>,
  );
}

describe("SSO sign-in without an organization field", () => {
  // This suite renders the same page repeatedly; without an explicit unmount every query matches
  // the previous test's DOM too, and "multiple elements found" masks what is actually being asserted.
  beforeEach(() => {
    cleanup();
    get.mockReset();
  });

  // ⛔ THE POINT OF THE WHOLE CHANGE. A person clicking "Continue with Google" must never be asked
  // for a tenant slug, so the request must carry NO `org` query at all — an empty string is a slug
  // the server would try to look up and fail on.
  it("starts SSO with no org query and follows the IdP redirect", async () => {
    const nav = captureNavigation();
    metaThen({ data: { redirect_url: "https://accounts.google.com/o/oauth2/v2/auth?x=1" } });
    renderLogin();

    expect(screen.queryByLabelText("Organization slug")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /continue with google/i }));

    await waitFor(() =>
      expect(nav.url).toBe("https://accounts.google.com/o/oauth2/v2/auth?x=1"),
    );
    const startCall = get.mock.calls.find(
      (c: unknown[]) => c[0] === "/api/v1/auth/sso/{provider}/start",
    );
    expect(startCall?.[1]).toEqual({
      params: { path: { provider: "google" }, query: undefined },
    });
  });

  // A failure that is NOT the person's to fix must not sprout a field that implies they typed
  // something wrong — sso_not_configured is an operator's problem, not theirs.
  it("does not reveal the org field when SSO is simply not configured", async () => {
    metaThen({
      error: {
        error: {
          code: "sso_not_configured",
          message: "single sign-on is not configured for this provider",
        },
      },
    });
    renderLogin();
    fireEvent.click(screen.getByRole("button", { name: /continue with google/i }));

    await screen.findByText(/not configured for this provider/i);
    expect(screen.queryByLabelText("Organization slug")).toBeNull();
  });

  // ⛔ THE ESCAPE HATCH, END TO END. The server answers sso_org_ambiguous with "specify your
  // organization to continue"; the page must then offer a field AND a way to submit it, and the
  // retry must carry the slug. Without the retry assertion this test would pass on a dead-end form.
  it("reveals the org field on ambiguity and retries with the typed slug", async () => {
    const nav = captureNavigation();
    metaThen(
      {
        error: {
          error: {
            code: "sso_org_ambiguous",
            message: "more than one organization uses this provider",
          },
        },
      },
      { data: { redirect_url: "https://accounts.google.com/o/oauth2/v2/auth?x=2" } },
    );
    renderLogin();

    fireEvent.click(screen.getByRole("button", { name: /continue with google/i }));
    const field = await screen.findByLabelText("Organization slug");
    expect(screen.getByText(/press enter to continue/i)).toBeTruthy();

    fireEvent.change(field, { target: { value: " demo-sandbox " } });
    fireEvent.keyDown(field, { key: "Enter" });

    await waitFor(() =>
      expect(nav.url).toBe("https://accounts.google.com/o/oauth2/v2/auth?x=2"),
    );
    const retry = get.mock.calls
      .filter((c: unknown[]) => c[0] === "/api/v1/auth/sso/{provider}/start")
      .at(-1);
    // Trimmed — a slug pasted with surrounding whitespace is the same slug.
    expect(retry?.[1]).toEqual({
      params: { path: { provider: "google" }, query: { org: "demo-sandbox" } },
    });
  });

  // Enter on an EMPTY field must not fire a request: that would re-send the org-less call that just
  // failed and read as the page ignoring what the person typed (nothing).
  it("ignores Enter while the org field is empty", async () => {
    metaThen({
      error: { error: { code: "sso_org_ambiguous", message: "ambiguous" } },
    });
    renderLogin();
    fireEvent.click(screen.getByRole("button", { name: /continue with google/i }));
    const field = await screen.findByLabelText("Organization slug");

    const before = get.mock.calls.length;
    fireEvent.keyDown(field, { key: "Enter" });
    await new Promise((r) => setTimeout(r, 0));
    expect(get.mock.calls.length).toBe(before);
  });
});
