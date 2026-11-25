// SA-UX-2 audit A1/A2/A5/A6: App Access states in words, never the stored value.
export const checkStatusText: Record<string, string> = { passed: "Passed", failed: "Failed", pending: "Checking", queued: "Checking", checking: "Checking", skipped: "Not checked", "": "Not checked" };
export const operationStatusText: Record<string, string> = { queued: "Requested", checking: "Checking", activated: "Live", failed: "Failed", cancelled: "Cancelled", expired: "Expired" };
export const grantStatusText: Record<string, string> = { active: "Active", scheduled: "Scheduled", expired: "Expired", disabled: "Disabled", revoked: "Revoked", subject_unavailable: "Person or group removed" };
export const subjectKindText: Record<string, string> = { user: "Person", group: "Group" };
export const words = (map: Record<string, string>, value: string | undefined | null, fallback = "Unknown") => map[value ?? ""] ?? fallback;
