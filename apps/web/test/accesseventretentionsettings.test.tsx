import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { AccessEventRetentionResource } from "../src/components/AccessEventRetentionSettings";

const RETENTION_PATH = "/api/v1/organizations/{orgId}/access-event-retention";
const PRUNE_PATH =
  "/api/v1/organizations/{orgId}/access-event-retention/actions/prune";

function retention(
  over: Partial<AccessEventRetentionResource> = {},
): AccessEventRetentionResource {
  return {
    retention_days: 30,
    cleanup_interval_minutes: 60,
    row_cap: 500_000,
    revision: 7,
    next_run_at: "2026-09-04T00:00:00Z",
    ...over,
  };
}

type RetentionRun = NonNullable<AccessEventRetentionResource["last_run"]>;

let current = retention();
let getMode: "success" | "error" | "reject" = "success";
let conflictOnce = false;
let postFailures = 0;
let postRunStatus: "succeeded" | "failed" = "succeeded";
let postOutcomeRun: RetentionRun | null = null;
let postReplayed = false;
let deferGets = false;
const deferredGets = new Map<
  string,
  (result: { data: AccessEventRetentionResource }) => void
>();

vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>(
    "../src/lib/api",
  );
  return {
    ...actual,
    api: {
      GET: vi.fn(
        async (
          path: string,
          request: { params?: { path?: { orgId?: string } } },
        ) => {
          expect(path).toBe(RETENTION_PATH);
          const orgId = request.params?.path?.orgId ?? "";
          if (deferGets) {
            return new Promise<{ data: AccessEventRetentionResource }>(
              (resolve) => deferredGets.set(orgId, resolve),
            );
          }
          if (getMode === "reject") throw new Error("offline");
          if (getMode === "error") {
            return {
              error: {
                error: {
                  code: "retention_unavailable",
                  message: "Retention unavailable",
                },
              },
            };
          }
          return { data: current };
        },
      ),
      PUT: vi.fn(
        async (
          path: string,
          request: {
            params?: { path?: { orgId?: string } };
            body?: {
              retention_days?: number;
              cleanup_interval_minutes?: number;
              expected_revision?: number;
            };
          },
        ) => {
          expect(path).toBe(RETENTION_PATH);
          if (conflictOnce) {
            conflictOnce = false;
            current = retention({ retention_days: 31, revision: 8 });
            return {
              error: {
                error: {
                  code: "access_event_retention_revision_conflict",
                  message: "Revision changed",
                },
              },
            };
          }
          current = retention({
            retention_days: request.body?.retention_days ?? 30,
            cleanup_interval_minutes:
              request.body?.cleanup_interval_minutes ?? 60,
            revision: (request.body?.expected_revision ?? 0) + 1,
          });
          return { data: current };
        },
      ),
      POST: vi.fn(
        async (
          path: string,
          _request: { body?: { idempotency_key?: string } },
        ) => {
          expect(path).toBe(PRUNE_PATH);
          if (postFailures > 0) {
            postFailures -= 1;
            return {
              error: {
                error: {
                  code: "prune_unavailable",
                  message: "Prune unavailable",
                },
              },
            };
          }
          const run: RetentionRun =
            postOutcomeRun ?? {
              id: "run-1",
              trigger: "manual",
              status: postRunStatus,
              started_at: "2026-09-03T00:00:00Z",
              completed_at: "2026-09-03T00:00:02Z",
              deleted_rows: postRunStatus === "failed" ? 12 : 42,
              batches: 2,
              more_pending: false,
              ...(postRunStatus === "failed"
                ? { error_code: "database_timeout" }
                : {}),
            };
          if (!postOutcomeRun) {
            current = retention({ ...current, last_run: run });
          }
          return {
            data: { retention: current, run, replayed: postReplayed },
          };
        },
      ),
    },
  };
});

import { AccessEventRetentionSettings } from "../src/components/AccessEventRetentionSettings";
import { api } from "../src/lib/api";

function view(orgId = "org-a") {
  return (
    <MemoryRouter>
      <AccessEventRetentionSettings orgId={orgId} canEdit />
    </MemoryRouter>
  );
}

beforeEach(() => {
  current = retention();
  getMode = "success";
  conflictOnce = false;
  postFailures = 0;
  postRunStatus = "succeeded";
  postOutcomeRun = null;
  postReplayed = false;
  deferGets = false;
  deferredGets.clear();
  vi.mocked(api.GET).mockClear();
  vi.mocked(api.PUT).mockClear();
  vi.mocked(api.POST).mockClear();
});

afterEach(cleanup);

describe("access-event retention settings", () => {
  it("loads authoritative policy data and saves only editable fields with its revision", async () => {
    render(view());

    expect(await screen.findByText(/30 days · every 1 hour/i)).toBeTruthy();
    expect(screen.getByText("500,000 rows")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Access-event evidence" }).getAttribute("href")).toBe(
      "/access-events",
    );

    fireEvent.click(screen.getByRole("button", { name: "Edit policy" }));
    fireEvent.change(screen.getByLabelText("Retention duration (days)"), {
      target: { value: "45" },
    });
    fireEvent.change(screen.getByLabelText("Cleanup interval (minutes)"), {
      target: { value: "120" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Save retention policy" }),
    );

    expect(await screen.findByText(/45 days · every 2 hours/i)).toBeTruthy();
    const [, request] = vi.mocked(api.PUT).mock.calls[0] as unknown as [
      string,
      { body: Record<string, unknown> },
    ];
    expect(request.body).toEqual({
      retention_days: 45,
      cleanup_interval_minutes: 120,
      expected_revision: 7,
    });
    expect(request.body).not.toHaveProperty("row_cap");
  });

  it("enforces server bounds before mutation", async () => {
    render(view());
    await screen.findByText(/30 days · every 1 hour/i);
    fireEvent.click(screen.getByRole("button", { name: "Edit policy" }));

    fireEvent.change(screen.getByLabelText("Retention duration (days)"), {
      target: { value: "0" },
    });
    expect(screen.getByText(/whole number from 1 to 3650 days/i)).toBeTruthy();
    expect(
      screen.getByRole("button", { name: "Save retention policy" }).hasAttribute("disabled"),
    ).toBe(true);

    fireEvent.change(screen.getByLabelText("Retention duration (days)"), {
      target: { value: "30" },
    });
    fireEvent.change(screen.getByLabelText("Cleanup interval (minutes)"), {
      target: { value: "1441" },
    });
    expect(screen.getByText(/whole number from 5 to 1440 minutes/i)).toBeTruthy();
    expect(api.PUT).not.toHaveBeenCalled();
  });

  it("reloads after a revision conflict and retries against the new revision", async () => {
    conflictOnce = true;
    render(view());
    await screen.findByText(/30 days · every 1 hour/i);
    fireEvent.click(screen.getByRole("button", { name: "Edit policy" }));
    fireEvent.change(screen.getByLabelText("Retention duration (days)"), {
      target: { value: "32" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Save retention policy" }),
    );

    expect(await screen.findByText(/changed after it was loaded/i)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Reload current policy" }));
    expect(await screen.findByText(/31 days · every 1 hour/i)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: "Edit policy" }));
    fireEvent.change(screen.getByLabelText("Retention duration (days)"), {
      target: { value: "32" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Save retention policy" }),
    );
    expect(await screen.findByText(/32 days · every 1 hour/i)).toBeTruthy();

    const requests = vi.mocked(api.PUT).mock.calls.map(
      (call) => (call[1] as { body: { expected_revision: number } }).body,
    );
    expect(requests.map((request) => request.expected_revision)).toEqual([7, 8]);
  });

  it("retries manual policy-only pruning with the same idempotency key", async () => {
    postFailures = 1;
    render(view());
    await screen.findByText(/30 days · every 1 hour/i);
    fireEvent.click(screen.getByRole("button", { name: "Run pruning now" }));

    expect(screen.getByRole("dialog", { name: "Run access-event pruning now?" })).toBeTruthy();
    expect(screen.getByText(/older than 30 days or exceed its 500,000-row cap/i)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Run policy-bound prune" }));
    expect(await screen.findByText("Prune unavailable")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Retry pruning" }));
    expect(await screen.findByText(/42 rows deleted in 2 batches/i)).toBeTruthy();

    const calls = vi.mocked(api.POST).mock.calls as unknown as Array<[
      string,
      { body: Record<string, unknown> },
    ]>;
    expect(calls).toHaveLength(2);
    expect(Object.keys(calls[0][1].body)).toEqual(["idempotency_key"]);
    expect(calls[1][1].body).toEqual(calls[0][1].body);
  });

  it("treats a confirmed failed run as failure and starts its retry with a new key", async () => {
    postRunStatus = "failed";
    render(view());
    await screen.findByText(/30 days · every 1 hour/i);
    fireEvent.click(screen.getByRole("button", { name: "Run pruning now" }));
    fireEvent.click(screen.getByRole("button", { name: "Run policy-bound prune" }));

    const failure = await screen.findByRole("alert");
    expect(failure.textContent).toMatch(/pruning failed \(database_timeout\)/i);
    expect(failure.textContent).toMatch(/after deleting 12 rows/i);
    expect(screen.queryByRole("dialog")).toBeNull();

    const firstBody = (vi.mocked(api.POST).mock.calls[0][1] as {
      body: { idempotency_key: string };
    }).body;
    postRunStatus = "succeeded";
    fireEvent.click(screen.getByRole("button", { name: "Run pruning now" }));
    fireEvent.click(screen.getByRole("button", { name: "Run policy-bound prune" }));
    await screen.findByText(/42 rows deleted in 2 batches/i);
    const secondBody = (vi.mocked(api.POST).mock.calls[1][1] as {
      body: { idempotency_key: string };
    }).body;
    expect(secondBody.idempotency_key).not.toBe(firstBody.idempotency_key);
  });

  it("reports the exact replayed run while retaining the newer overview", async () => {
    current = retention({
      last_run: {
        id: "run-newer",
        trigger: "scheduled",
        status: "succeeded",
        started_at: "2026-09-03T02:00:00Z",
        completed_at: "2026-09-03T02:00:02Z",
        deleted_rows: 99,
        batches: 1,
        more_pending: false,
      },
    });
    postOutcomeRun = {
      id: "run-original",
      trigger: "manual",
      status: "succeeded",
      started_at: "2026-09-03T00:00:00Z",
      completed_at: "2026-09-03T00:00:02Z",
      deleted_rows: 3,
      batches: 1,
      more_pending: false,
    };
    postReplayed = true;

    render(view());
    await screen.findByText(/99 rows deleted in 1 batch/i);
    fireEvent.click(screen.getByRole("button", { name: "Run pruning now" }));
    fireEvent.click(screen.getByRole("button", { name: "Run policy-bound prune" }));

    expect(await screen.findByText(/pruning completed\. 3 rows deleted/i)).toBeTruthy();
    expect(screen.getByText(/99 rows deleted in 1 batch/i)).toBeTruthy();
  });

  it("shows a rejected load as retryable instead of default settings", async () => {
    getMode = "reject";
    render(view());
    expect(await screen.findByText(/could not reach the api/i)).toBeTruthy();
    expect(screen.queryByText(/30 days · every 1 hour/i)).toBeNull();

    getMode = "success";
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText(/30 days · every 1 hour/i)).toBeTruthy();
  });

  it("cancels stale organization loads", async () => {
    deferGets = true;
    const rendered = render(view("org-a"));
    expect(screen.getByRole("status").textContent).toMatch(/loading retention policy/i);

    rendered.rerender(view("org-b"));
    await waitFor(() => expect(deferredGets.has("org-b")).toBe(true));
    await act(async () => {
      deferredGets.get("org-b")?.({
        data: retention({ retention_days: 45, revision: 2 }),
      });
    });
    expect(await screen.findByText(/45 days · every 1 hour/i)).toBeTruthy();

    await act(async () => {
      deferredGets.get("org-a")?.({
        data: retention({ retention_days: 10, revision: 1 }),
      });
    });
    await waitFor(() => {
      expect(screen.getByText(/45 days · every 1 hour/i)).toBeTruthy();
      expect(screen.queryByText(/10 days · every 1 hour/i)).toBeNull();
    });
  });

  it("surfaces failed pruning status and the operator-safe error code", async () => {
    current = retention({
      last_run: {
        id: "run-failed",
        trigger: "scheduled",
        status: "failed",
        started_at: "2026-09-03T00:00:00Z",
        completed_at: "2026-09-03T00:00:03Z",
        deleted_rows: 12,
        batches: 1,
        more_pending: true,
        error_code: "database_timeout",
      },
    });
    render(view());
    expect(await screen.findByText(/failed · database_timeout · 12 rows deleted before failure/i)).toBeTruthy();
  });
});
