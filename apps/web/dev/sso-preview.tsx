import React from "react";
import { createRoot } from "react-dom/client";
import {
  SsoConnections,
  type SsoConnectionTransport,
} from "../src/components/SsoConnections";
import type { components } from "@tunnex/shared";
import "@fontsource-variable/inter";
type Connection = components["schemas"]["SsoConnection"];
const org = "11111111-1111-4111-8111-111111111111";
let items: Connection[] = [
  {
    id: "22222222-2222-4222-8222-222222222222",
    org_id: org,
    name: "Acme workforce",
    provider: "okta",
    issuer_url: "https://acme.okta.com",
    client_id: "sample-client-id",
    enabled: false,
    revision: 1,
    verified: false,
    updated_at: new Date().toISOString(),
    callback_url: location.origin + "/api/v1/auth/sso-connections/callback",
    login_url:
      location.origin +
      "/login?connection=22222222-2222-4222-8222-222222222222",
  },
];
const transport: SsoConnectionTransport = {
  async list() {
    return structuredClone(items);
  },
  async save(org_id, id, d) {
    const old = items.find((c) => c.id === id);
    const c: Connection = {
      id,
      org_id,
      name: d.name,
      provider: d.provider,
      issuer_url: d.issuer_url,
      client_id: d.client_id,
      enabled: false,
      verified: false,
      revision: (old?.revision ?? 0) + 1,
      updated_at: new Date().toISOString(),
      callback_url: location.origin + "/api/v1/auth/sso-connections/callback",
      login_url: location.origin + "/login?connection=" + id,
    };
    items = [...items.filter((c) => c.id !== id), c];
    return c;
  },
  async test(_, id) {
    items = items.map((c) =>
      c.id === id
        ? { ...c, verified: true, tested_at: new Date().toISOString() }
        : c,
    );
    return "#simulated-test";
  },
  async activate(_, c, enabled) {
    if (enabled && !c.verified) throw Error("Test sign-in first");
    const next = { ...c, enabled };
    items = items.map((v) => (v.id === c.id ? next : v));
    return next;
  },
};
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <div
      style={{ maxWidth: 1000, margin: "0 auto", padding: "32px 30px 60px" }}
    >
      <header
        style={{
          fontFamily: "Inter, sans-serif",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          borderBottom: "1px solid #242a34",
          paddingBottom: 24,
          color: "#e9edf3",
        }}
      >
        <strong style={{ fontSize: 22, letterSpacing: 2 }}>
          TUNN<span style={{ color: "#b53a4d" }}>EX</span>
        </strong>
        <span style={{ fontSize: 12, color: "#7e899a" }}>
          Acme workspace / Settings / Authentication
        </span>
      </header>
      <div
        style={{
          fontFamily: "Inter,sans-serif",
          margin: "30px 0",
          color: "#e9edf3",
        }}
      >
        <h1 style={{ fontSize: 28, letterSpacing: -1, marginBottom: 8 }}>
          Authentication
        </h1>
        <p style={{ fontSize: 13, color: "#8d98a9" }}>
          Manage how your team signs in to Tunnex.
        </p>
        <div style={{ display: "flex", gap: 12, marginTop: 24 }}>
          {["Google", "Microsoft Entra ID"].map((s) => (
            <div
              key={s}
              style={{
                flex: 1,
                border: "1px solid #2b3039",
                borderRadius: 10,
                padding: 18,
                fontSize: 13,
              }}
            >
              {s}
              <span style={{ float: "right", color: "#8d98a9", fontSize: 11 }}>
                Existing setup
              </span>
            </div>
          ))}
        </div>
        <SsoConnections orgId={org} canEdit transport={transport} preview />
      </div>
    </div>
  </React.StrictMode>,
);
