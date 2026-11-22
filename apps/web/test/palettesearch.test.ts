import { describe, expect, it } from "vitest";
import { entityResults } from "../src/lib/palettesearch";

const inventory = {
  gateways: [{ id: "g1", name: "gke-gw-a", endpoint: "35.244.118.52" }, { id: "g2", name: "onprem-gw-a" }],
  devices: [{ id: "d1", name: "ops-laptop", owner_email: "ops@example.test" }],
  people: [{ user_id: "u1", name: "Ops Lead", email: "ops@example.test" }],
  clusters: [{ id: "c1", name: "gke" }],
};

describe("palette entity search", () => {
  it("finds nothing below two characters, so one keystroke never floods the list", () => {
    expect(entityResults("g", inventory)).toEqual([]);
  });
  it("matches names, addresses and e-mails, and links each kind to where it is managed", () => {
    expect(entityResults("gke", inventory).map(r => [r.kind, r.to])).toEqual([
      ["Gateway", "/gateways/g1"], ["Cluster", "/kubernetes?cluster=c1"],
    ]);
    expect(entityResults("35.244", inventory).map(r => r.label)).toEqual(["gke-gw-a"]);
    expect(entityResults("ops@", inventory).map(r => [r.kind, r.to])).toEqual([
      ["Device", "/devices?q=ops-laptop"], ["Person", "/users?q=ops%40example.test"],
    ]);
  });
  it("caps each kind at five and survives an inventory that did not load", () => {
    const many = { gateways: Array.from({ length: 9 }, (_, i) => ({ id: `g${i}`, name: `edge-${i}` })) };
    expect(entityResults("edge", many)).toHaveLength(5);
    expect(entityResults("edge", {})).toEqual([]);
  });
});
