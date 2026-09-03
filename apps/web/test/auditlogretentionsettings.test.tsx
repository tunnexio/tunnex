import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { AuditLogRetentionResource } from "../src/components/AuditLogRetentionSettings";

const RETENTION_PATH =
  "/api/v1/organizations/{orgId}/audit-log-retention";
const PRUNE_PATH =
  "/api/v1/organizations/{orgId}/audit-log-retention/actions/prune";

function retention(
  over: Partial<AuditLogRetentionResource> = {},
): AuditLogRetentionResource {
  return {
    retention_days: null,
    cleanup_interval_minutes: 60,
    batch_size: 1_000,
    revision: 0,
    ...over,
  };
}

type RetentionRun = NonNullable<AuditLogRetentionResource["last_run"]>;

let current = retention();
let conflictOnce = false;
let postFailures = 0;

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
          expect(request.params?.path?.orgId).toBe("org-a");
          return { data: current };
        },
      ),
      PUT: vi.fn(
        async (
          path: string,
          request: {
            params?: { path?: { orgId?: string } };
            body?: {
              retention_days?: number | null;
              cleanup_interval_minutes?: number;
              expected_revision?: number;
            };
          },
        ) => {
          expect(path).toBe(RETENTION_PATH);
          expect(request.params?.path?.orgId).toBe("org-a");
          if (conflictOnce) {
            conflictOnce = false;
            current = retention({
              retention_days: 45,
              cleanup_interval_minutes: 60,
              revision: 8,
            });
            return {
              error: {
                error: {
                  code: "audit_log_retention_revision_conflict",
                  message: "Revision changed",
                },
              },
            };
          }
          current = retention({
            retention_days: request.body?.retention_days ?? null,
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
          request: {
            params?: { path?: { orgId?: string } };
            body?: { idempotency_key?: string };
          },
        ) => {
          expect(path).toBe(PRUNE_PATH);
          expect(request.params?.path?.orgId).toBe("org-a");
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
          const run: RetentionRun = {
            id: "run-1",
            trigger: "manual",
            status: "succeeded",
            started_at: "2026-09-03T00:00:00Z",
            completed_at: "2026-09-03T00:00:02Z",
            deleted_rows: 42,
            batches: 2,
            more_pending: false,
          };
          current = retention({ ...current, last_run: run });
          return {
            data: { retention: current, run, replayed: false },
          };
        },
      ),
    },
  };
});

import { AuditLogRetentionSettings } from "../src/components/AuditLogRetentionSettings";
import { api } from "../src/lib/api";

function view(canEdit = true) {
  return (
    <MemoryRouter>
      <AuditLogRetentionSettings orgId="org-a" canEdit={canEdit} />
    </MemoryRouter>
  );
}

beforeEach(() => {
  current = retention();
  conflictOnce = false;
  postFailures = 0;
  vi.mocked(api.GET).mockClear();
  vi.mocked(api.PUT).mockClear();
  vi.mocked(api.POST).mockClear();
});

afterEach(cleanup);

describe("audit-log retention settings", () => {
  it("keeps the default policy Forever and offers no deletion or manual prune", async () => {
    render(view());

    expect(await screen.findByText("Forever")).toBeTruthy();
    expect(screen.getByText("No deletion")).toBeTruthy();
    expect(
      screen.getByText("Disabled while retention is Forever"),
    ).toBeTruthy();
    expect(
      screen.getByRole("button", { name: "Run audit-log pruning now" }).hasAttribute("disabled"),
    ).toBe(true);
    expect(
      screen.getByRole("link", { name: "Control-plane audit evidence" }).getAttribute("href"),
    ).toBe("/audit");
    expect(api.POST).not.toHaveBeenCalled();
  });

  it("confirms Forever-to-bounded before persisting and saves Forever without a destructive prompt", async () => {
    render(view());
    await screen.findByText("Forever");

    fireEvent.click(
      screen.getByRole("button", { name: "Edit audit-log policy" }),
    );
    fireEvent.change(screen.getByLabelText("Retention mode"), {
      target: { value: "bounded" },
    });
    fireEvent.change(screen.getByLabelText("Retention duration (days)"), {
      target: { value: "45" },
    });
    fireEvent.change(screen.getByLabelText("Cleanup interval (minutes)"), {
      target: { value: "120" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Save audit-log policy" }),
    );

    expect(api.PUT).not.toHaveBeenCalled();
    expect(
      screen.getByRole("dialog", {
        name: "Change audit-log retention to 45 days?",
      }),
    ).toBeTruthy();
    expect(
      screen.getByText(
        /enables the server scheduler to permanently delete retention-eligible audit rows older than 45 days/i,
      ),
    ).toBeTruthy();
    fireEvent.click(
      screen.getByRole("button", { name: "Save 45-day retention" }),
    );

    expect(await screen.findByText(/45 days · every 2 hours/i)).toBeTruthy();
    const firstRequest = vi.mocked(api.PUT).mock.calls[0][1] as {
      body: Record<string, unknown>;
    };
    expect(firstRequest.body).toEqual({
      retention_days: 45,
      cleanup_interval_minutes: 120,
      expected_revision: 0,
    });

    fireEvent.click(
      screen.getByRole("button", { name: "Edit audit-log policy" }),
    );
    fireEvent.change(screen.getByLabelText("Retention mode"), {
      target: { value: "forever" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Save audit-log policy" }),
    );

    await waitFor(() => {
      expect(screen.getByText("No deletion")).toBeTruthy();
      expect(
        screen.getByRole("button", { name: "Run audit-log pruning now" }).hasAttribute("disabled"),
      ).toBe(true);
    });
    expect(
      screen.queryByRole("dialog", {
        name: /change audit-log retention/i,
      }),
    ).toBeNull();
    const secondRequest = vi.mocked(api.PUT).mock.calls[1][1] as {
      body: Record<string, unknown>;
    };
    expect(secondRequest.body).toEqual({
      retention_days: null,
      cleanup_interval_minutes: 120,
      expected_revision: 1,
    });
  });

  it("enforces bounded-age and cleanup-interval limits before mutation", async () => {
    render(view());
    await screen.findByText("Forever");
    fireEvent.click(
      screen.getByRole("button", { name: "Edit audit-log policy" }),
    );
    fireEvent.change(screen.getByLabelText("Retention mode"), {
      target: { value: "bounded" },
    });
    fireEvent.change(screen.getByLabelText("Retention duration (days)"), {
      target: { value: "0" },
    });

    const daysInput = screen.getByLabelText("Retention duration (days)");
    const daysError = screen.getByText(/whole number from 1 to 3650 days/i);
    expect(daysInput.getAttribute("aria-invalid")).toBe("true");
    expect(daysInput.getAttribute("aria-describedby")).toBe(daysError.id);
    expect(
      screen.getByRole("button", { name: "Save audit-log policy" }).hasAttribute("disabled"),
    ).toBe(true);

    fireEvent.change(screen.getByLabelText("Retention duration (days)"), {
      target: { value: "30" },
    });
    fireEvent.change(screen.getByLabelText("Cleanup interval (minutes)"), {
      target: { value: "1441" },
    });
    const intervalInput = screen.getByLabelText(
      "Cleanup interval (minutes)",
    );
    const intervalError = screen.getByText(
      /whole number from 5 to 1440 minutes/i,
    );
    expect(intervalInput.getAttribute("aria-invalid")).toBe("true");
    expect(intervalInput.getAttribute("aria-describedby")).toBe(
      intervalError.id,
    );
    expect(api.PUT).not.toHaveBeenCalled();
  });

  it("confirms a shorter bounded window before mutation", async () => {
    current = retention({ retention_days: 90, revision: 7 });
    render(view());
    await screen.findByText(/90 days · every 1 hour/i);

    fireEvent.click(
      screen.getByRole("button", { name: "Edit audit-log policy" }),
    );
    fireEvent.change(screen.getByLabelText("Retention duration (days)"), {
      target: { value: "30" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Save audit-log policy" }),
    );

    expect(api.PUT).not.toHaveBeenCalled();
    expect(
      screen.getByRole("dialog", {
        name: "Change audit-log retention to 30 days?",
      }),
    ).toBeTruthy();
    fireEvent.click(
      screen.getByRole("button", { name: "Save 30-day retention" }),
    );
    expect(await screen.findByText(/30 days · every 1 hour/i)).toBeTruthy();
    expect(api.PUT).toHaveBeenCalledTimes(1);
  });

  it("resets a canceled or dismissed draft to the current policy", async () => {
    current = retention({ retention_days: 90, revision: 7 });
    render(view());
    await screen.findByText(/90 days · every 1 hour/i);

    fireEvent.click(
      screen.getByRole("button", { name: "Edit audit-log policy" }),
    );
    fireEvent.change(screen.getByLabelText("Retention duration (days)"), {
      target: { value: "30" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    fireEvent.click(
      screen.getByRole("button", { name: "Edit audit-log policy" }),
    );
    expect(
      (screen.getByLabelText("Retention duration (days)") as HTMLInputElement)
        .value,
    ).toBe("90");

    fireEvent.change(screen.getByLabelText("Retention duration (days)"), {
      target: { value: "45" },
    });
    fireEvent.keyDown(screen.getByLabelText("Retention duration (days)"), {
      key: "Escape",
    });

    fireEvent.click(
      screen.getByRole("button", { name: "Edit audit-log policy" }),
    );
    expect(
      (screen.getByLabelText("Retention duration (days)") as HTMLInputElement)
        .value,
    ).toBe("90");
    expect(api.PUT).not.toHaveBeenCalled();
  });

  it("reloads after a CAS conflict and retries against the authoritative revision", async () => {
    current = retention({ retention_days: 30, revision: 7 });
    conflictOnce = true;
    render(view());
    await screen.findByText(/30 days · every 1 hour/i);

    fireEvent.click(
      screen.getByRole("button", { name: "Edit audit-log policy" }),
    );
    fireEvent.change(screen.getByLabelText("Retention duration (days)"), {
      target: { value: "31" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Save audit-log policy" }),
    );

    expect(await screen.findByText(/changed after it was loaded/i)).toBeTruthy();
    fireEvent.click(
      screen.getByRole("button", { name: "Reload audit-log policy" }),
    );
    expect(await screen.findByText(/45 days · every 1 hour/i)).toBeTruthy();

    fireEvent.click(
      screen.getByRole("button", { name: "Edit audit-log policy" }),
    );
    fireEvent.change(screen.getByLabelText("Retention duration (days)"), {
      target: { value: "46" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Save audit-log policy" }),
    );
    expect(await screen.findByText(/46 days · every 1 hour/i)).toBeTruthy();

    const revisions = vi.mocked(api.PUT).mock.calls.map(
      (call) =>
        (call[1] as { body: { expected_revision: number } }).body
          .expected_revision,
    );
    expect(revisions).toEqual([7, 8]);
  });

  it("requires confirmation and reuses the same idempotency key after an unknown prune outcome", async () => {
    current = retention({ retention_days: 30, revision: 7 });
    postFailures = 1;
    render(view());
    await screen.findByText(/30 days · every 1 hour/i);

    fireEvent.click(
      screen.getByRole("button", { name: "Run audit-log pruning now" }),
    );
    expect(api.POST).not.toHaveBeenCalled();
    expect(
      screen.getByRole("dialog", { name: "Run audit-log pruning now?" }),
    ).toBeTruthy();
    expect(
      screen.getByText(/older than 30 days, in batches of at most 1,000 rows/i),
    ).toBeTruthy();
    fireEvent.click(
      screen.getByRole("button", { name: "Run audit-log policy prune" }),
    );
    expect(await screen.findByText("Prune unavailable")).toBeTruthy();
    fireEvent.click(
      screen.getByRole("button", { name: "Retry audit-log pruning" }),
    );
    expect(
      await screen.findByText(/Audit-log pruning completed\. 42 rows deleted/i),
    ).toBeTruthy();

    const calls = vi.mocked(api.POST).mock.calls as unknown as Array<[
      string,
      { body: { idempotency_key: string } },
    ]>;
    expect(calls).toHaveLength(2);
    expect(Object.keys(calls[0][1].body)).toEqual(["idempotency_key"]);
    expect(calls[1][1].body).toEqual(calls[0][1].body);
  });

  it("disables every retention mutation for an unverified operator", async () => {
    current = retention({ retention_days: 30, revision: 7 });
    render(view(false));
    await screen.findByText(/30 days · every 1 hour/i);

    expect(
      screen.getByRole("button", { name: "Edit audit-log policy" }).hasAttribute("disabled"),
    ).toBe(true);
    expect(
      screen.getByRole("button", { name: "Run audit-log pruning now" }).hasAttribute("disabled"),
    ).toBe(true);
    expect(
      screen.getByRole("status").textContent,
    ).toMatch(/verify your email before changing retention/i);
    expect(api.PUT).not.toHaveBeenCalled();
    expect(api.POST).not.toHaveBeenCalled();
  });
});
