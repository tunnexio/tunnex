import { describe, expect, it } from "vitest";
import {
  ATTRIBUTION_NOTE,
  FLOW_LOG_CUTS,
  causeFor,
  decisionLabel,
  decisionTone,
  destinationFor,
  isLastPage,
  nextCursor,
  retentionNote,
  sourceFor,
  type AccessEvent,
} from "../src/lib/flowlogview";

const ev = (over: Partial<AccessEvent> = {}): AccessEvent => ({
  id: "e1",
  created_at: "2026-08-03T14:22:41.208Z",
  seq: 1,
  occurred_at: "2026-08-03T14:22:41.100Z",
  decision: "allow",
  src_ip: "100.90.4.11",
  dst_ip: "10.2.0.9",
  protocol: "tcp",
  ...over,
});

// ⛔ `gap` IS A FIRST-CLASS VERDICT AND THE DESIGN'S CHIP LIST DOES NOT MENTION IT.
//
// `seq` is a per-org monotonic sequence for tamper-evidence; a `gap` marker means events are
// MISSING. Rendering it as an ordinary row — or dropping it because the wireframe lists only four
// verdicts — would present an INCOMPLETE security log as a complete one.
describe("decision handling", () => {
  it("labels and tones every decision the SCHEMA has, not just the four the design draws", () => {
    for (const d of [
      "allow",
      "deny",
      "deny_aggregate",
      "terminated",
      "gap",
    ] as const) {
      expect(decisionLabel(d)).toBeTruthy();
      expect(decisionTone(d)).toBeTruthy();
    }
    expect(decisionLabel("gap")).toBe("GAP");
  });

  it("⛔ gives `gap` its OWN tone — never the same as an ordinary allow", () => {
    expect(decisionTone("gap")).not.toBe(decisionTone("allow"));
    expect(decisionTone("gap")).toBe("gap");
  });

  it("⛔ a gap SAYS events are missing, and how many when it knows", () => {
    expect(
      causeFor(ev({ decision: "gap", deny_count: 12 }), () => null),
    ).toMatch(/12 events missing/i);
    expect(causeFor(ev({ decision: "gap" }), () => null)).toMatch(
      /missing from the log/i,
    );
  });
});

describe("causeFor", () => {
  it("names the rule when there is one, and falls back to its id rather than a blank", () => {
    expect(causeFor(ev({ rule_id: "r-1" }), () => "eng → gitlab")).toBe(
      "rule: eng → gitlab",
    );
    expect(causeFor(ev({ rule_id: "abcdef01-2345" }), () => null)).toBe(
      "rule: abcdef01",
    );
  });

  it("⛔ says DEFAULT-DENY in words — the most common deny reason", () => {
    expect(causeFor(ev({ decision: "deny" }), () => null)).toBe(
      "no matching grant",
    );
  });

  it("⛔ uses n/a, never an em-dash — a dash reads as short data, n/a reads as an answer", () => {
    // Caught by placeholderglyph.test.ts on this file's first run.
    const c = causeFor(ev({ decision: "allow" }), () => null);
    expect(c).toBe("n/a");
    expect(c).not.toContain("—");
  });

  it("reports an aggregate's count", () => {
    expect(
      causeFor(ev({ decision: "deny_aggregate", deny_count: 412 }), () => null),
    ).toBe("412 denies aggregated");
  });
});

// ⛔ SOURCE IS AN ADDRESS, NOT A PERSON — a refused inference, not missing data.
describe("sourceFor + ATTRIBUTION_NOTE", () => {
  it("renders only what the server attributed", () => {
    expect(sourceFor(ev())).toBe("100.90.4.11");
  });

  it("explains WHY there is no name", () => {
    expect(ATTRIBUTION_NOTE).toMatch(/not to a person/i);
    expect(ATTRIBUTION_NOTE).toMatch(/lease that may since have moved/i);
    expect(ATTRIBUTION_NOTE).toMatch(/wrong name/i);
  });
});

describe("destinationFor", () => {
  it("appends the port only when there is one", () => {
    expect(destinationFor(ev({ dst_port: 443 }))).toBe("10.2.0.9:443");
    expect(destinationFor(ev())).toBe("10.2.0.9");
  });
});

// ⛔ THE CURSOR IS THE INGEST CLOCK. `occurred_at` is the agent's clock and the schema says in so
// many words that it is NOT the pagination clock — an agent with a slow clock would insert rows
// that sort before ones already shown, and a page boundary could skip them forever.
describe("nextCursor", () => {
  it("takes created_at + id from the LAST row", () => {
    const page = [
      ev({ id: "a" }),
      ev({ id: "z", created_at: "2026-08-03T10:00:00Z" }),
    ];
    expect(nextCursor(page)).toEqual({
      cursor_ts: "2026-08-03T10:00:00Z",
      cursor_id: "z",
    });
  });

  it("⛔ never paginates on occurred_at", () => {
    const page = [
      ev({
        id: "a",
        created_at: "2026-08-03T12:00:00Z",
        occurred_at: "1999-01-01T00:00:00Z",
      }),
    ];
    expect(nextCursor(page)?.cursor_ts).toBe("2026-08-03T12:00:00Z");
  });

  it("is null on an empty page — there is nothing to page from", () => {
    expect(nextCursor([])).toBeNull();
  });
});

describe("isLastPage", () => {
  it("a short page is the last page; a full one is not", () => {
    expect(isLastPage(new Array(99).fill(ev()), 100)).toBe(true);
    expect(isLastPage(new Array(100).fill(ev()), 100)).toBe(false);
    expect(isLastPage([], 100)).toBe(true);
  });
});

// ⛔ `retention_failed` IS A DISK WARNING WEARING A HOUSEKEEPING NAME.
describe("retentionNote", () => {
  it("is LOUD on failure and says what it means", () => {
    const r = retentionNote({ retention_dropped: 0, retention_failed: true });
    expect(r.loud).toBe(true);
    expect(r.text).toMatch(/keep growing/i);
  });

  it("is quiet and factual on success", () => {
    const r = retentionNote({
      retention_dropped: 1234,
      retention_failed: false,
    });
    expect(r.loud).toBe(false);
    expect(r.text).toMatch(/1,?234/);
  });
});

// ⛔ THE CUTS ARE DATA SO THE SCREEN CAN SAY THEM. A screen that silently omits four of the
// design's controls looks unfinished; one that names them looks decided.
describe("FLOW_LOG_CUTS", () => {
  it("names each cut with a reason, not just a label", () => {
    expect(FLOW_LOG_CUTS.length).toBeGreaterThanOrEqual(3);
    for (const c of FLOW_LOG_CUTS) {
      expect(c.what.length).toBeGreaterThan(5);
      expect(c.why.length).toBeGreaterThan(40);
    }
  });

  it("⛔ explains WHY per-verdict chips cannot be client-side on a keyset feed", () => {
    const chips = FLOW_LOG_CUTS.find((c) => /chips/i.test(c.what));
    expect(chips?.why).toMatch(/other pages/i);
  });
});
