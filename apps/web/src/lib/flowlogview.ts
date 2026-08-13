// Flow logs — the view-model.
//
// ⛔ THE FOURTH UNREACHABLE-SURFACE INSTANCE. `GET …/access-events` and `…/access-log/health`
// shipped in S7.5.1 and `apps/web` rendered NEITHER — same class as the five idp-sync endpoints
// S14.14 closed. Neither the old page census nor the founder's list found it; only running the
// census against the DESIGN did.
//
// ⛔ AND THE DESIGN SHOWS A COLUMN THE SERVER DELIBERATELY REFUSES TO FILL. Its SOURCE column reads
// `alice · 100.90.4.11` — a person and an address. The schema says, in its own words:
//
//     GRANT-level attribution (rule_id -> resource/group). device/user are DEFERRED (nil) —
//     never derived from a racy src_ip lookup.
//
// So the user half is not missing data, it is a REFUSED INFERENCE: an IP maps to a device only via
// a lease that may have moved, and naming the wrong person in a security feed is worse than naming
// nobody. We render what the server attributes and say why the rest is absent.

export type Decision =
  "allow" | "deny" | "deny_aggregate" | "terminated" | "gap";

export type AccessEvent = {
  id: string;
  created_at: string;
  seq: number;
  occurred_at: string;
  decision: Decision;
  rule_id?: string | null;
  node_id?: string | null;
  src_ip: string;
  dst_ip: string;
  dst_resource_id?: string | null;
  dst_group_id?: string | null;
  protocol: string;
  dst_port?: number | null;
  deny_count?: number | null;
  window_end?: string | null;
};

/**
 * ⛔ `gap` IS A FIRST-CLASS VERDICT AND IT IS THE MOST IMPORTANT ONE.
 *
 * `seq` is a per-org monotonic sequence for tamper-evidence. A `gap` marker means events are
 * MISSING — the feed is not complete — and `deny_count` carries how many. A security feed that
 * rendered a gap as just another row, or dropped it because the design's chip list does not mention
 * it, would present an incomplete log as a complete one. The design's five chips are
 * allow/deny/deny_aggregate/terminated; the SCHEMA has five decisions including `gap`.
 */
export function decisionLabel(d: Decision): string {
  switch (d) {
    case "allow":
      return "ALLOW";
    case "deny":
      return "DENY";
    case "deny_aggregate":
      return "DENY_AGG";
    case "terminated":
      return "TERMINATED";
    case "gap":
      return "GAP";
  }
}

export function decisionTone(d: Decision): "ok" | "warn" | "bad" | "gap" {
  switch (d) {
    case "allow":
      return "ok";
    case "deny":
      return "bad";
    case "deny_aggregate":
      return "warn";
    case "terminated":
      return "warn";
    case "gap":
      return "gap";
  }
}

/**
 * The RULE / CAUSE cell — what the server can actually say about why.
 *
 * ⚠ NAMES COME FROM A LOOKUP THE CALLER OWNS. `rule_id`, `dst_resource_id` and `dst_group_id` are
 * UUIDs; resolving them is the page's job, and an unresolved id renders as an id rather than as a
 * blank — an empty cause cell reads as "no reason", which is a different and untrue claim.
 */
export function causeFor(
  e: AccessEvent,
  ruleName: (id: string) => string | null,
): string {
  if (e.decision === "gap") {
    const n = e.deny_count ?? 0;
    return n > 0
      ? `${n} events missing from the log — sequence gap`
      : "sequence gap — events are missing from the log";
  }
  if (e.decision === "deny_aggregate") {
    const n = e.deny_count ?? 0;
    return n > 0 ? `${n} denies aggregated` : "denies aggregated";
  }
  if (e.rule_id) {
    const name = ruleName(e.rule_id);
    return name ? `rule: ${name}` : `rule: ${e.rule_id.slice(0, 8)}`;
  }
  // No rule matched. This is the DEFAULT-DENY answer and it is the most common deny reason.
  // ⛔ NOT an em-dash. `placeholderglyph.test.ts` bans it as a VALUE — a dash reads as data that
  // happens to be short, and "n/a" reads as an answer. Caught by that guard on this file's first run.
  return e.decision === "deny" ? "no matching grant" : "n/a";
}

/** DESTINATION — address plus port, protocol only where it adds something. */
export function destinationFor(e: AccessEvent): string {
  const port = e.dst_port ? `:${e.dst_port}` : "";
  return `${e.dst_ip}${port}`;
}

/**
 * ⛔ SOURCE IS AN ADDRESS, NOT A PERSON — see the header. The design pairs a name with the IP; the
 * server refuses to derive one. This returns only what was attributed.
 */
export function sourceFor(e: AccessEvent): string {
  return e.src_ip;
}

export const ATTRIBUTION_NOTE =
  "Events are attributed to a source ADDRESS, not to a person. An address maps to a device only through a lease that may since have moved, so naming a user here would be a guess — and a wrong name in a security log is worse than no name.";

/**
 * ⛔ THE KEYSET CURSOR IS THE INGEST CLOCK, NOT THE OBSERVATION CLOCK — and the schema warns about
 * exactly this: `occurred_at` is the agent's clock and is explicitly "NOT the pagination clock".
 *
 * Paginating on `occurred_at` would skew: an agent with a slow clock inserts events that sort
 * before rows already shown, so a page boundary could skip them forever. The cursor is
 * `(created_at, id)`.
 */
export function nextCursor(
  page: AccessEvent[],
): { cursor_ts: string; cursor_id: string } | null {
  const last = page[page.length - 1];
  return last ? { cursor_ts: last.created_at, cursor_id: last.id } : null;
}

/** A short page means the end — the API documents it, so the client must not ask again. */
export function isLastPage(page: AccessEvent[], limit: number): boolean {
  return page.length < limit;
}

/**
 * ⛔ WHAT WAS CUT FROM THIS SCREEN, AND WHY — each measured against the spec, not judged.
 *
 * Kept as data so the panel can SAY what it does not show. A screen that silently omits four of
 * the design's controls looks unfinished; one that names them looks decided.
 */
export const FLOW_LOG_CUTS: readonly { what: string; why: string }[] = [
  {
    what: "JSONL export",
    why: "DEFERRED with the on-disk JSONL writer (S7.5.1b) — the spec says so in a comment where the endpoint would be. The wireframe labels it deferred too.",
  },
  {
    what: "Per-verdict filter chips (allow / deny / deny_aggregate / terminated)",
    why: "the API has ONE filter, `denies_only`. Filtering a keyset page client-side would hide events on OTHER pages while looking like a complete filter — a feed that under-reports is worse than one that does not filter.",
  },
  {
    what: "The verdict timeline and its totals (allow 528 · deny 68 · …)",
    why: "there is no aggregate endpoint. Those totals span far more than one page, so computing them from the rows in hand would state a number the server never counted.",
  },
] as const;

/** The one filter the server actually has. */
export type FlowFilter = { deniesOnly: boolean };

/**
 * Retention health, from `/access-log/health`.
 *
 * ⛔ `retention_failed` MEANS THE HOT WINDOW MAY BE GROWING — the schema says so. That is a
 * disk-exhaustion warning wearing a housekeeping name, so it renders loud rather than as a stat.
 */
export type AccessLogHealth = {
  retention_last_sweep?: string | null;
  retention_dropped: number;
  retention_failed: boolean;
};

export function retentionNote(h: AccessLogHealth): {
  text: string;
  loud: boolean;
} {
  if (h.retention_failed) {
    return {
      text: "The last retention sweep failed — old events may not have been dropped, so the hot window can keep growing. Check the control-plane logs.",
      loud: true,
    };
  }
  return {
    text: `Last sweep dropped ${h.retention_dropped.toLocaleString()} event${h.retention_dropped === 1 ? "" : "s"}.`,
    loud: false,
  };
}
