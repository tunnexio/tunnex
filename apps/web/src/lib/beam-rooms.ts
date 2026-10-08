import { createTunnexClient } from "@tunnex/shared";
import { apiErrorCode, apiErrorMessage } from "./api";
import type { paths, components } from "./beam-api";
import type { BeamResult } from "./beam";

export type BeamProject = components["schemas"]["BeamProject"];
export type BeamProjectInput = components["schemas"]["BeamProjectInput"];
export type BeamFeedback = components["schemas"]["BeamFeedback"];
export type BeamFeedbackInput = components["schemas"]["BeamFeedbackInput"];
export type BeamNotification = components["schemas"]["BeamNotification"];
const client = createTunnexClient<paths>("/");
async function request<T>(call: () => Promise<{ data?: T; error?: unknown; response?: Response }>): Promise<BeamResult<T>> {
  try {
    const result = await call();
    if (result.error || result.data === undefined) return { ok: false, error: apiErrorMessage(result.error, "Could not complete the Local Sharing request."), code: apiErrorCode(result.error) };
    return { ok: true, data: result.data, server_time: result.response?.headers.get("Date") ?? undefined };
  } catch { return { ok: false, error: "Could not reach the server. Refresh to check the current state before trying again." }; }
}
export const beamRoomsApi = {
  projects: (orgId: string, offset = 0, limit = 20) => request(() => client.GET("/api/v1/organizations/{orgId}/beam/projects", { params: { path: { orgId }, query: { limit, offset } } })),
  saveProject: (orgId: string, input: BeamProjectInput, project?: BeamProject) => project
    ? request(() => client.PUT("/api/v1/organizations/{orgId}/beam/projects/{id}", { params: { path: { orgId, id: project.id } }, body: { ...input, expected_version: project.version } }))
    : request(() => client.POST("/api/v1/organizations/{orgId}/beam/projects", { params: { path: { orgId } }, body: input })),
  sessions: (orgId: string, id: string, offset = 0, scope?: "active" | "history", limit = 20) => request(() => client.GET("/api/v1/organizations/{orgId}/beam/projects/{id}/sessions", { params: { path: { orgId, id }, query: { limit, offset, ...(scope ? { scope } : {}) } } })),
  feedback: (orgId: string, id: string, offset = 0, limit = 20) => request(() => client.GET("/api/v1/organizations/{orgId}/beam/shares/{id}/feedback", { params: { path: { orgId, id }, query: { limit, offset } } })),
  addFeedback: (orgId: string, id: string, input: BeamFeedbackInput) => request(() => client.POST("/api/v1/organizations/{orgId}/beam/shares/{id}/feedback", { params: { path: { orgId, id } }, body: input })),
  notifications: (orgId: string, offset = 0, limit = 20) => request(() => client.GET("/api/v1/organizations/{orgId}/beam/notifications", { params: { path: { orgId }, query: { limit, offset } } })),
};

// API-owned authenticated path only. Never load an arbitrary attachment URL.
export function beamScreenshotURL(orgId: string, shareId: string, feedback: BeamFeedback): string | null {
  const expected = `/api/v1/organizations/${encodeURIComponent(orgId)}/beam/shares/${encodeURIComponent(shareId)}/feedback/${encodeURIComponent(feedback.id)}/screenshot`;
  return feedback.screenshot_url === expected ? expected : null;
}
