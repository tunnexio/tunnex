import { describe, expect, it } from "vitest";
import {
  agentConnectCommand,
  agentSummary,
  attributionNote,
  NO_AGENTS,
  sortAgents,
  agentLiveness,
  livenessLabel,
  formatTraffic,
  type AgentRow,
} from "../src/lib/agentview";

describe("the agent surface — S15.3", () => {
  const row = (o: Partial<AgentRow> = {}): AgentRow => ({
    device_id: o.device_id ?? "d1",
    name: o.name ?? "agent-a",
    owner_email:
      "owner_email" in o ? (o.owner_email ?? null) : "owner@demo.tunnex.local",
    unattributable: o.unattributable ?? false,
    address: "address" in o ? (o.address ?? null) : "10.99.0.4",
    gateway_name: o.gateway_name ?? "gw-1",
    status: o.status ?? "active",
  });

  it("⛔ UNATTRIBUTABLE SORTS FIRST — the one state found nowhere else", () => {
    const sorted = sortAgents([
      row({ device_id: "d1", name: "aaa-normal" }),
      row({ device_id: "d2", name: "zzz-normal" }),
      row({
        device_id: "d3",
        name: "mmm-orphan",
        unattributable: true,
        owner_email: null,
      }),
    ]);
    // ⚠ Must not depend on a name: alphabetically this order would be aaa, mmm, zzz.
    expect(sorted.map((r) => r.name)).toEqual([
      "mmm-orphan",
      "aaa-normal",
      "zzz-normal",
    ]);
  });

  it("⛔ THE ABSENCES ARE FIRST-CLASS — no owner and no address stay null, never a guess", () => {
    const [r] = sortAgents([
      row({ owner_email: null, address: null, unattributable: true }),
    ]);
    expect(r.owner_email).toBeNull();
    expect(r.address).toBeNull();
  });

  describe("the attribution note", () => {
    it("names the gap and says the agent KEEPS RUNNING", () => {
      const n = attributionNote({ unattributable: true })!;
      expect(n.label).toMatch(/unattributable/i);
      expect(n.detail).toMatch(/keeps running/i);
      expect(n.detail).toMatch(/audit trail, not in access control/i);
    });

    it("⚠ TONE IS warn, NEVER danger — a logging gap is not an access-control failure", () => {
      expect(attributionNote({ unattributable: true })!.tone).toBe("warn");
    });

    it("is absent for an attributable agent — without this the note could be a constant", () => {
      expect(attributionNote({ unattributable: false })).toBeNull();
    });
  });

  // ⛔ THE RENDER FLOOR, ENFORCED ON THE COPY ITSELF. These are the two claims the product cannot keep.
  it("⛔ NO DETECTION AND NO PER-TOOL LANGUAGE anywhere in the surface's copy", () => {
    const copy = [
      NO_AGENTS,
      attributionNote({ unattributable: true })!.label,
      attributionNote({ unattributable: true })!.detail,
    ].join(" ");
    for (const forbidden of [
      /\bdetect\w*/i,
      /\bblocks?\b/i,
      /\bprevent\w*/i,
      /\bprompt injection\b/i,
      /\btool\b/i,
      /\bper-tool\b/i,
      /\bsecure\b/i,
      /\bprotected\b/i,
    ]) {
      expect(copy).not.toMatch(forbidden);
    }
  });
});

// ⛔ THE UNDETERMINED STATE'S WORDS ARE PINNED THE WAY THE RENDER FLOOR IS PINNED.
//
// The ruling: undetermined means *we do not know what this was enrolled as, because the fact was not
// recorded at the time and cannot be recovered*. It is NOT "not an agent" (a fact nobody has), NOT "agent"
// (the defect the marker fixed), and NOT a fault (these nodes work correctly).
//
// > **"UNKNOWN" SOFTENING INTO "NONE" IS EXACTLY HOW THE PHRASE WOULD DRIFT INTO A VERDICT** — one is an
// > absence of knowledge, the other is a claim about the world.
describe("the Overview card — S15.3", () => {
  const r = (u: boolean) => ({ unattributable: u });

  it("counts, and names the gap only when it exists", () => {
    expect(agentSummary([r(false), r(false)])).toMatchObject({
      total: 2,
      unattributable: 0,
      note: null,
    });
    const s = agentSummary([r(true), r(false), r(true)]);
    expect(s).toMatchObject({ total: 3, unattributable: 2 });
    expect(s.note).toMatch(/cannot be attributed to a person/i);
  });

  // ⛔ §0 BINDS HARDEST AT CARD SIZE — this is where copy gets shortened until it implies things.
  it("⛔ the card's copy makes no detection, per-tool or health claim", () => {
    const copy = agentSummary([r(true)]).note ?? "";
    for (const forbidden of [
      /\bdetect\w*/i,
      /\bblocks?\b/i,
      /\bprevent\w*/i,
      /\btool\b/i,
      /\bsecure\b/i,
      /\bprotected\b/i,
      /\ball good\b/i,
      /\bhealthy\b/i,
    ]) {
      expect(copy).not.toMatch(forbidden);
    }
  });
});

describe("the connect command — S15.3", () => {
  const conf =
    "[Interface]\nPrivateKey = k+ey/with$dollar=\nAddress = 10.99.0.7/32\n";

  it("⛔ ONE COMMAND, not a file to save and then a command to run", () => {
    const c = agentConnectCommand(conf);
    expect(c).toMatch(/tee \/etc\/wireguard\/tunnex\.conf/);
    expect(c).toMatch(/wg-quick up tunnex/);
  });

  it("⛔ THE HEREDOC IS QUOTED — an unquoted one would let the shell mangle a key containing $", () => {
    const c = agentConnectCommand(conf);
    expect(c).toContain("<<'TUNNEXEOF'");
    // the key survives verbatim
    expect(c).toContain("k+ey/with$dollar=");
  });

  it("⚠ the config is chmod 600 — a private key must not be world-readable", () => {
    expect(agentConnectCommand(conf)).toMatch(/chmod 600/);
  });
});

/**
 * ⛔ AGENT LIVENESS — the five states, and the precedence between two of them.
 *
 * The whole point of this block is the ONE ordering rule: `unknown` outranks `offline`. Everything else is
 * a straightforward mapping; that rule is the one a refactor silently breaks, and breaking it produces a
 * screen that confidently blames an agent for its gateway's silence.
 */
describe("agent liveness — S15.3", () => {
  const now = new Date("2026-08-05T12:00:00Z");
  const ago = (s: number) => new Date(now.getTime() - s * 1000).toISOString();
  const live = (o: Partial<AgentRow> = {}): AgentRow => ({
    device_id: "d1",
    name: "agent-a",
    owner_email: "o@x.com",
    unattributable: false,
    address: "10.99.0.2",
    gateway_name: "gw-1",
    status: "active",
    config_issued: true,
    gateway_reporting: true,
    ...o,
  });

  it("⭐ REVOKED OUTRANKS EVERYTHING — a dead credential must never be told to reconnect", () => {
    // ⛔ THE EXACT ROW THE LIVE RIG PRODUCED. Revocation keeps the row and the key (config_issued stays
    // true) and SWEEPS the telemetry (last_handshake_at goes null) — which lands a revoked agent in
    // `never`, whose copy sends the operator to run the connect command on a machine that is fine, for a
    // credential that was deliberately destroyed.
    const a = live({
      status: "revoked",
      online: false,
      last_handshake_at: null,
    });
    expect(agentLiveness(a)).toBe("revoked");
    expect(livenessLabel(a, now).label).toBe("revoked");
    expect(livenessLabel(a, now).detail).not.toMatch(/Run the command/);
    // ⚠ And it outranks the reporter check too: a revoked agent on a silent gateway is still revoked,
    // not unknown — that fact does not depend on anyone reporting.
    expect(
      agentLiveness(live({ status: "revoked", gateway_reporting: false })),
    ).toBe("revoked");
    // ⚠ NOT `danger`. A revoked credential is the system doing what it was told.
    expect(livenessLabel(a, now).tone).not.toBe("danger");
  });

  it("an ACTIVE agent with the same shape still reads never-connected — revoked is doing the work", () => {
    // Without this, the assertion above would pass on a function that returned "revoked" for everything.
    expect(
      agentLiveness(
        live({ status: "active", online: false, last_handshake_at: null }),
      ),
    ).toBe("never");
  });

  it("online when the gateway reports a recent handshake", () => {
    const a = live({ online: true, last_handshake_at: ago(20) });
    expect(agentLiveness(a)).toBe("online");
    expect(livenessLabel(a, now).label).toBe("connected");
    expect(livenessLabel(a, now).tone).toBe("ok");
  });

  it("⛔ NEVER-CONNECTED IS NOT OFFLINE — a command issued and never run is a different fact", () => {
    const a = live({ online: false, last_handshake_at: null });
    expect(agentLiveness(a)).toBe("never");
    expect(livenessLabel(a, now).label).toBe("never connected");
    // ⚠ And it must be ACTIONABLE. This is the most likely state for a new agent, so the detail has to
    // tell the operator what to do rather than merely restate the badge.
    expect(livenessLabel(a, now).detail).toMatch(
      /Run the command on the agent host/,
    );
  });

  it("offline, with honest recency rather than a bare word", () => {
    const a = live({ online: false, last_handshake_at: ago(600) });
    expect(agentLiveness(a)).toBe("offline");
    expect(livenessLabel(a, now).label).toBe("last seen 10m ago");
  });

  it("⭐ UNKNOWN OUTRANKS OFFLINE — a silent gateway must never be reported as a dead agent", () => {
    // Same row as the offline case in every respect EXCEPT the reporter's own liveness. If the precedence
    // were reversed this would read "last seen 10m ago" — a confident claim about an agent nobody has
    // heard from OR about, sending an operator to debug the wrong machine.
    const a = live({
      online: false,
      last_handshake_at: ago(600),
      gateway_reporting: false,
    });
    expect(agentLiveness(a)).toBe("unknown");
    expect(livenessLabel(a, now).label).toBe("liveness unknown");
    // ⛔ AND IT NAMES THE GATEWAY AS THE SUSPECT.
    expect(livenessLabel(a, now).detail).toContain("gw-1");
    expect(livenessLabel(a, now).detail).toMatch(/Check the gateway first/);
  });

  it("⛔ AND UNKNOWN OUTRANKS ONLINE-LOOKING DATA TOO — a stale `online` must not survive a dead reporter", () => {
    // The server derives `online` from a handshake it may have recorded before the gateway went quiet.
    // If the reporter is silent, that derivation is stale by construction and must not be rendered as fact.
    const a = live({
      online: true,
      last_handshake_at: ago(10),
      gateway_reporting: false,
    });
    expect(agentLiveness(a)).toBe("unknown");
  });

  it("no config issued is distinct from never connected", () => {
    // ⚠ Nothing was handed over, so there is no command to re-run — the "never connected" advice would be
    // wrong here, which is why these are two states and not one.
    const a = live({ config_issued: false });
    expect(agentLiveness(a)).toBe("not-issued");
    expect(livenessLabel(a, now).label).toBe("no config issued");
  });

  it("⛔ NO LIVENESS STATE IS `danger` — a down agent is not a security event", () => {
    // Fail-closed means a disconnected agent reaches NOTHING. Painting it red claims an incident that has
    // not occurred, and over-alarming is the same defect as under-alarming, facing the other way.
    for (const a of [
      live({ online: true, last_handshake_at: ago(5) }),
      live({ online: false, last_handshake_at: null }),
      live({ online: false, last_handshake_at: ago(9999) }),
      live({ gateway_reporting: false }),
      live({ config_issued: false }),
    ]) {
      expect(livenessLabel(a, now).tone).not.toBe("danger");
    }
  });

  it("traffic: an unreported counter renders as absent, never as zero", () => {
    // ⛔ A device the gateway has never reported has NULL counters. Rendering "0 B" would claim we measured
    // no traffic, when in fact we measured nothing at all.
    expect(formatTraffic(null, null)).toBeNull();
    expect(formatTraffic(undefined, undefined)).toBeNull();
    expect(formatTraffic(0, 0)).toBe("↓ 0 B · ↑ 0 B");
    expect(formatTraffic(2048, 1048576)).toBe("↓ 2.0 KB · ↑ 1.0 MB");
    expect(formatTraffic(15_728_640, 0)).toBe("↓ 15 MB · ↑ 0 B");
  });
});
