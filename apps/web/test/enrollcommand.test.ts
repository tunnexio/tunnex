import { describe, it, expect } from "vitest";
import {
  enrollCommand,
  remoteEnrollCommand,
  cpEndpoints,
  GATEWAY_IMAGE,
} from "../src/components/Gateways";

// S8.2c D4: the emitted remote-gateway command is the ZERO-TOUCH artifact — pasted verbatim on a clean VM
// it must reach agent_ready on real WireGuard with NO edits. These reds encode tonight's double
// paste-failure: it must be a SINGLE `docker run` (no compose, no line breaks) with EVERY piece the demo
// added by hand baked in.

// The CP's AUTHORITATIVE public base URL (meta.public_base_url), not the dashboard origin (review #1).
// cpEndpoints returns a discriminated result; a valid URL narrows to the ok branch (spreadable into opts).
function okBase(url: string | undefined, fallback: string) {
  const e = cpEndpoints(url, fallback);
  if (!e.ok) throw new Error(`expected ok endpoints, got: ${e.reason}`);
  return e;
}

describe("remoteEnrollCommand — the one true zero-touch docker run", () => {
  const base = okBase("https://cp.example.com", "https://ignored.example");

  it("is a SINGLE docker run — no compose, no newlines (the paste-mismatch is structurally impossible)", () => {
    const cmd = remoteEnrollCommand({
      token: "TKN",
      name: "gw-aws",
      endpoint: "203.0.113.7:51820",
      ...base,
      image: GATEWAY_IMAGE,
    });
    expect(cmd.startsWith("docker run ")).toBe(true);
    expect(cmd).not.toContain("docker compose");
    expect(cmd).not.toContain("\n");
    expect(cmd).not.toContain("tunnex.yml");
  });

  it("bakes in EVERY hand-fixed piece from the demo (host net, wgctrl, tun, token, CP urls, servername, image)", () => {
    const cmd = remoteEnrollCommand({
      token: "TKN",
      name: null,
      endpoint: null,
      ...base,
      image: GATEWAY_IMAGE,
    });
    for (const piece of [
      "--network host",
      "--cap-add NET_ADMIN",
      "--device /dev/net/tun",
      "-e TUNNEX_WG_BACKEND=wgctrl",
      "-e TUNNEX_JOIN_TOKEN=TKN",
      // The CP urls are shell-quoted too (re-review #3 — they now come from operator config, not the browser).
      '-e TUNNEX_API_URL="https://cp.example.com"',
      '-e TUNNEX_AGENT_URL="https://cp.example.com:8443"',
      '-e TUNNEX_AGENT_SERVERNAME="tunnex-control"',
      GATEWAY_IMAGE,
    ]) {
      expect(cmd, `missing: ${piece}`).toContain(piece);
    }
  });

  it("endpoint present → TUNNEX_NODE_ENDPOINT set (hub); absent → omitted (NAT'd spoke)", () => {
    expect(
      remoteEnrollCommand({
        token: "T",
        name: null,
        endpoint: "1.2.3.4:51820",
        ...base,
        image: GATEWAY_IMAGE,
      }),
    ).toContain('-e TUNNEX_NODE_ENDPOINT="1.2.3.4:51820"');
    expect(
      remoteEnrollCommand({
        token: "T",
        name: null,
        endpoint: null,
        ...base,
        image: GATEWAY_IMAGE,
      }),
    ).not.toContain("TUNNEX_NODE_ENDPOINT");
  });

  it("a name is shell-quoted (a space can't truncate it into a node_name_mismatch loop)", () => {
    expect(
      remoteEnrollCommand({
        token: "T",
        name: "my gw",
        endpoint: null,
        ...base,
        image: GATEWAY_IMAGE,
      }),
    ).toContain('-e TUNNEX_NODE_NAME="my gw"');
  });

  it("an endpoint is shell-quoted too (review #3 — a space/metachar can't corrupt the zero-touch command)", () => {
    expect(
      remoteEnrollCommand({
        token: "T",
        name: null,
        endpoint: "1.2.3.4:51820 --privileged",
        ...base,
        image: GATEWAY_IMAGE,
      }),
    ).toContain('-e TUNNEX_NODE_ENDPOINT="1.2.3.4:51820 --privileged"');
  });

  it("cpEndpoints prefers the CP's configured public base URL over the fallback origin (review #1)", () => {
    // An admin opening the dashboard via a tunnel/alias must NOT bake that origin into the emitted command.
    const e = okBase("https://cp.example.com", "https://tunnel.internal:9999");
    expect(e.apiURL).toBe("https://cp.example.com");
    expect(e.agentURL).toBe("https://cp.example.com:8443");
    expect(e.serverName).toBe("tunnex-control");
    expect(e.usedFallback).toBe(false);
  });

  it("uses the deployment gateway control URL when configured", () => {
    const e = cpEndpoints(
      "https://cp.example.com",
      "https://ignored.example",
      "https://agent.example.com:8443",
    );
    if (!e.ok) throw new Error(e.reason);
    expect(e.apiURL).toBe("https://cp.example.com");
    expect(e.agentURL).toBe("https://agent.example.com:8443");
  });

  it("refuses a gateway control URL with a path or non-https scheme", () => {
    expect(cpEndpoints("https://cp.example.com", "https://ignored.example", "http://agent.example.com:8443").ok).toBe(false);
    expect(cpEndpoints("https://cp.example.com", "https://ignored.example", "https://agent.example.com/control").ok).toBe(false);
  });

  it("cpEndpoints falls back to the dashboard origin ONLY when the CP has no configured public URL", () => {
    const e = okBase(undefined, "http://40.65.63.141");
    expect(e.apiURL).toBe("http://40.65.63.141");
    expect(e.agentURL).toBe("https://40.65.63.141:8443");
    expect(e.serverName).toBe("tunnex-control");
    expect(e.usedFallback).toBe(true); // signal the caller uses to caveat a fetch-failure fallback (#2)
    // An empty/whitespace configured URL is treated as unset (falls back).
    expect(okBase("   ", "http://40.65.63.141").apiURL).toBe(
      "http://40.65.63.141",
    );
  });

  it("WF-2: the command uses the CP-configured (digest-pinnable) image, not a hardcoded :latest", () => {
    const digest = "ghcr.io/tunnexio/tunnex-node-agent@sha256:abc123";
    const cmd = remoteEnrollCommand({
      token: "T",
      name: null,
      endpoint: null,
      ...base,
      image: digest,
    });
    expect(cmd.endsWith(digest)).toBe(true);
    expect(cmd).not.toContain(":latest");
  });

  it("cpEndpoints REFUSES an unparseable configured URL (re-review #1 — never a silently-broken command)", () => {
    // A non-blank configured value the browser can't parse is an operator APP_BASE_URL typo — the caller
    // blocks the one-time-token mint on this, rather than emitting a command with an empty agent URL.
    const bad = cpEndpoints("cp.example.com", "http://40.65.63.141"); // no scheme → new URL() throws
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.reason).toMatch(/not a valid URL/);
  });
});

describe("enrollCommand — compose enrollment pins the CP agent image", () => {
  it("passes the exact configured digest to compose instead of using its :latest default", () => {
    const digest = "ghcr.io/tunnexio/tunnex-node-agent@sha256:abc123";
    const cmd = enrollCommand("TKN", "gw-1", digest);
    expect(cmd).toContain(`TUNNEX_NODE_AGENT_IMAGE="${digest}"`);
    expect(cmd).toContain("docker compose -f tunnex.yml up -d --force-recreate node-agent");
    expect(cmd).not.toContain(":latest");
  });

  it("keeps the pinned node name and shell-quotes image metacharacters", () => {
    const cmd = enrollCommand("TKN", "my gw", 'registry.example/agent@sha256:abc$def');
    expect(cmd).toContain('TUNNEX_NODE_NAME="my gw"');
    expect(cmd).toContain('TUNNEX_NODE_AGENT_IMAGE="registry.example/agent@sha256:abc\\$def"');
  });
});
