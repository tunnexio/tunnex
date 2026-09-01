import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ManagedOrganizationSelector,
  NoOrganizationError,
  OrganizationSelectionConflictError,
  OrganizationSelectionRequiredError,
  organizationSelectionKey,
  type LiveOrganization,
  type OrganizationSelectionPersistence,
} from "../src/main/orgselection";

const ORGS: LiveOrganization[] = [
  { id: "00000000-0000-4000-8000-000000000311", name: "Alpha", slug: "alpha" },
  { id: "00000000-0000-4000-8000-000000000312", name: "Beta", slug: "beta" },
];

function memoryPersistence(): OrganizationSelectionPersistence & { values: Map<string, string> } {
  const values = new Map<string, string>();
  return {
    values,
    get: (key) => values.get(key) ?? "",
    set: (key, organizationId) => { values.set(key, organizationId); },
  };
}

test("organization selection is keyed by canonical origin and current user", () => {
  assert.equal(
    organizationSelectionKey(" HTTPS://CP.Example/ ", "00000000-0000-4000-8000-000000000301"),
    organizationSelectionKey("https://cp.example", "00000000-0000-4000-8000-000000000301"),
  );
  assert.notEqual(
    organizationSelectionKey("https://cp.example", "00000000-0000-4000-8000-000000000301"),
    organizationSelectionKey("https://cp.example", "00000000-0000-4000-8000-000000000302"),
  );
});

test("zero organizations refuses and a sole live membership auto-selects without persisting", () => {
  const persistence = memoryPersistence();
  const selector = new ManagedOrganizationSelector(persistence);
  assert.throws(
    () => selector.requireFreshEnrollment("https://cp.example", "00000000-0000-4000-8000-000000000301", []),
    NoOrganizationError,
  );

  const sole = ORGS.slice(0, 1);
  assert.equal(selector.requireFreshEnrollment("https://cp.example", "00000000-0000-4000-8000-000000000301", sole), "00000000-0000-4000-8000-000000000311");
  assert.deepEqual(selector.organizations("https://cp.example", "00000000-0000-4000-8000-000000000301", sole, null, false), {
    organizations: [{ ...ORGS[0], selected: true }],
    enrollmentLocked: false,
  });
  assert.equal(persistence.values.has(organizationSelectionKey("https://cp.example", "00000000-0000-4000-8000-000000000301")), false);
});

test("multiple organizations require an explicit live choice and revalidate saved membership", () => {
  const persistence = memoryPersistence();
  const selector = new ManagedOrganizationSelector(persistence);
  assert.throws(
    () => selector.requireFreshEnrollment("https://cp.example", "00000000-0000-4000-8000-000000000301", ORGS),
    OrganizationSelectionRequiredError,
  );
  assert.equal(selector.organizations("https://cp.example", "00000000-0000-4000-8000-000000000301", ORGS, null, false).organizations.every((org) => !org.selected), true);

  const selected = selector.select("https://cp.example", "00000000-0000-4000-8000-000000000301", ORGS, "00000000-0000-4000-8000-000000000312", null, false);
  assert.equal(selected.organizations.find((org) => org.id === "00000000-0000-4000-8000-000000000312")?.selected, true);
  assert.equal(selector.requireFreshEnrollment("https://cp.example", "00000000-0000-4000-8000-000000000301", ORGS), "00000000-0000-4000-8000-000000000312");

  // The persisted id is only a preference. Once it disappears from the fresh list,
  // it is stale and cannot authorize enrollment in another tenant.
  const changed = [ORGS[0], { id: "00000000-0000-4000-8000-000000000313", name: "Gamma", slug: "gamma" }];
  assert.throws(
    () => selector.requireFreshEnrollment("https://cp.example", "00000000-0000-4000-8000-000000000301", changed),
    OrganizationSelectionRequiredError,
  );
  assert.equal(selector.organizations("https://cp.example", "00000000-0000-4000-8000-000000000301", changed, null, false).organizations.every((org) => !org.selected), true);
});

test("selection does not bleed between users on the same origin", () => {
  const selector = new ManagedOrganizationSelector(memoryPersistence());
  selector.select("https://cp.example", "00000000-0000-4000-8000-000000000301", ORGS, "00000000-0000-4000-8000-000000000312", null, false);
  assert.equal(selector.requireFreshEnrollment("https://cp.example", "00000000-0000-4000-8000-000000000301", ORGS), "00000000-0000-4000-8000-000000000312");
  assert.throws(
    () => selector.requireFreshEnrollment("https://cp.example", "00000000-0000-4000-8000-000000000302", ORGS),
    OrganizationSelectionRequiredError,
  );
});

test("an enrolled config is authoritative until confirmed removal", () => {
  const persistence = memoryPersistence();
  const selector = new ManagedOrganizationSelector(persistence);
  selector.select("https://cp.example", "00000000-0000-4000-8000-000000000301", ORGS, "00000000-0000-4000-8000-000000000312", null, false);
  const before = new Map(persistence.values);

  const view = selector.organizations("https://cp.example", "00000000-0000-4000-8000-000000000301", ORGS, "00000000-0000-4000-8000-000000000311", true);
  assert.deepEqual(view, {
    organizations: [
      { id: "00000000-0000-4000-8000-000000000311", name: "Alpha", slug: "alpha", selected: true },
      { id: "00000000-0000-4000-8000-000000000312", name: "Beta", slug: "beta", selected: false },
    ],
    enrollmentLocked: true,
  });
  assert.deepEqual(persistence.values, before);
  assert.throws(
    () => selector.select("https://cp.example", "00000000-0000-4000-8000-000000000301", ORGS, "00000000-0000-4000-8000-000000000311", "00000000-0000-4000-8000-000000000311", true),
    OrganizationSelectionConflictError,
  );
  assert.throws(
    () => selector.select("https://cp.example", "00000000-0000-4000-8000-000000000301", ORGS, "00000000-0000-4000-8000-000000000312", "00000000-0000-4000-8000-000000000311", true),
    OrganizationSelectionConflictError,
  );
  assert.equal(persistence.values.get(organizationSelectionKey("https://cp.example", "00000000-0000-4000-8000-000000000301")), "00000000-0000-4000-8000-000000000312");

  // If the enrolled org is no longer a live membership, do not make another org
  // look selected while the old credential still exists locally.
  const staleView = selector.organizations("https://cp.example", "00000000-0000-4000-8000-000000000301", ORGS.slice(1), "00000000-0000-4000-8000-000000000311", true);
  assert.equal(staleView.enrollmentLocked, true);
  assert.equal(staleView.organizations[0].selected, false);
  assert.throws(
    () => selector.select("https://cp.example", "00000000-0000-4000-8000-000000000301", ORGS.slice(1), "00000000-0000-4000-8000-000000000312", "00000000-0000-4000-8000-000000000311", true),
    OrganizationSelectionConflictError,
  );
});

test("a legacy stored record with no organization stays locked without inventing a selected row", () => {
  const persistence = memoryPersistence();
  const selector = new ManagedOrganizationSelector(persistence);
  selector.select("https://cp.example", "00000000-0000-4000-8000-000000000301", ORGS, "00000000-0000-4000-8000-000000000312", null, false);
  const before = new Map(persistence.values);

  const view = selector.organizations(
    "https://cp.example",
    "00000000-0000-4000-8000-000000000301",
    ORGS,
    null,
    true,
  );
  assert.equal(view.enrollmentLocked, true);
  assert.equal(view.organizations.every((organization) => !organization.selected), true);
  assert.deepEqual(persistence.values, before, "a locked legacy view must not persist a tenant guess");
  assert.throws(
    () => selector.select("https://cp.example", "00000000-0000-4000-8000-000000000301", ORGS, "00000000-0000-4000-8000-000000000311", null, true),
    OrganizationSelectionConflictError,
  );
  assert.deepEqual(persistence.values, before);
});
