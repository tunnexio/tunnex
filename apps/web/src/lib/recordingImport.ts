import type { components } from "@tunnex/shared";
export type LocalRecording = Pick<components["schemas"]["ServerAccessRecording"], "status" | "events">;
export const MAX_RECORDING_FILE_BYTES = 32 * 1024 * 1024;
const MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
const MAX_EVENT_BYTES = 16 * 1024;
const MAX_MILLIS = 24 * 60 * 60 * 1000;
function object(value: unknown): value is Record<string, unknown> { return !!value && typeof value === "object" && !Array.isArray(value); }
function invalid(): never { throw new Error("Invalid recording JSON. Use a Tunnex Manual download with ordered output/resize events; raw archive chunks and manifests are not supported."); }
export function parseRecordingImport(text: string): LocalRecording {
 if (new TextEncoder().encode(text).length > MAX_RECORDING_FILE_BYTES) throw new Error("Recording file exceeds the 32 MiB limit.");
 let value: unknown; try { value = JSON.parse(text); } catch { return invalid(); }
 if (!object(value)) return invalid();
 // Current Manual Download is the unversioned v1 ServerAccessRecording JSON.
 // Accept an explicit v1 marker, but never guess how to read a future format.
 if (value.version !== undefined && value.version !== 1) throw new Error("Unsupported recording version. Only recording JSON version 1 is supported.");
 if (value.format !== undefined && value.format !== "tunnex-terminal-recording") return invalid();
 if (typeof value.session_id !== "string" || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(value.session_id) || typeof value.expires_at !== "string" || !Number.isFinite(Date.parse(value.expires_at))) return invalid();
 if (!["available", "archived", "incomplete", "capturing"].includes(value.status as string) || !Array.isArray(value.events) || value.events.length > 4096) return invalid();
 const events: LocalRecording["events"] = []; let previous = 0; let bytes = 0;
 for (const [seq, raw] of value.events.entries()) {
  if (!object(raw) || raw.seq !== seq || !Number.isSafeInteger(raw.millis) || (raw.millis as number) < previous || (raw.millis as number) > MAX_MILLIS || typeof raw.data !== "string") return invalid();
  if (raw.type === "output") {
   if (raw.rows !== 0 || raw.cols !== 0 || raw.data.length > Math.ceil(MAX_EVENT_BYTES / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(raw.data)) return invalid();
   let decoded: string; try { decoded = atob(raw.data); } catch { return invalid(); }
   if (decoded.length > MAX_EVENT_BYTES || btoa(decoded) !== raw.data) return invalid();
   bytes += decoded.length; if (bytes > MAX_OUTPUT_BYTES) throw new Error("Recording output exceeds the 16 MiB limit.");
  } else if (raw.type === "resize") {
   if (raw.data !== "" || !Number.isInteger(raw.rows) || !Number.isInteger(raw.cols) || (raw.rows as number) < 1 || (raw.rows as number) > 400 || (raw.cols as number) < 1 || (raw.cols as number) > 400) return invalid();
  } else return invalid();
  previous = raw.millis as number;
  events.push({seq, millis: previous, type: raw.type, data: raw.data, rows: raw.rows as number, cols: raw.cols as number});
 }
 // Strip all file-supplied identity, timestamps, archive/audit and extra fields.
 // A local file cannot establish server provenance or current authorization.
 return {status: value.status === "capturing" ? "incomplete" : value.status as LocalRecording["status"], events};
}

export type ImportedRecording = {recording: LocalRecording; name: string; source: "json" | "encrypted-package"};
const PACKAGE_MAGIC = "TUNNEX-RECORDING-V2\n";
export function encodeRecordingPackage(bytes: Uint8Array): string {
 if (bytes.byteLength > MAX_RECORDING_FILE_BYTES) throw new Error("Recording file exceeds the 32 MiB limit.");
 if (new TextDecoder().decode(bytes.subarray(0, PACKAGE_MAGIC.length)) !== PACKAGE_MAGIC) throw new Error("Invalid encrypted recording package. Import a complete .tunnex-recording package, not raw chunks or an archive manifest.");
 const pieces: string[] = [];
 for (let offset=0; offset<bytes.length; offset+=16384) pieces.push(String.fromCharCode(...bytes.subarray(offset, offset+16384)));
 return btoa(pieces.join(""));
}
