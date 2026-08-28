import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { stripJsComments } from "./support/source";

const app = stripJsComments(
  readFileSync(fileURLToPath(new URL("../src/App.tsx", import.meta.url)), "utf8"),
);
const fixture = stripJsComments(
  readFileSync(fileURLToPath(new URL("../src/pages/K8sEnrollmentLocalReview.tsx", import.meta.url)), "utf8"),
);
const scopeFixture = stripJsComments(
  readFileSync(fileURLToPath(new URL("../src/pages/K8sScopeLocalReview.tsx", import.meta.url)), "utf8"),
);

describe("the Kubernetes enrollment local review route", () => {
  it("is explicit, lazy, build-flagged off, and selected before product auth", () => {
    expect(app).toMatch(/import\.meta\.env\.VITE_K8S_ENROLLMENT_LOCAL_REVIEW === "1"/);
    expect(app).toMatch(/lazy\(\(\) => import\("\.\/pages\/K8sEnrollmentLocalReview"\)\)/);
    expect(app).toContain('path="/__local-review/kubernetes-enrollment"');
    expect(app).toMatch(/<Route path="\*" element=\{<ProductApp \/>\} \/>/);
    expect(app).toMatch(/function ProductApp\(\) \{\s*return \(\s*<AuthProvider>/);
  });

  it("has no committed default-on environment setting", () => {
    for (const file of [".env", ".env.production", ".env.local"]) {
      let contents = "";
      try {
        contents = readFileSync(fileURLToPath(new URL(`../${file}`, import.meta.url)), "utf8");
      } catch {
        continue;
      }
      expect(contents).not.toMatch(/VITE_K8S_ENROLLMENT_LOCAL_REVIEW\s*=\s*1/);
    }
  });

  it("keeps enrollment and legacy metadata correction fixture-only with no API client", () => {
    expect(fixture).toContain("ProviderFirstEnrollmentModal");
    expect(fixture).toContain("ProviderMetadataCorrectionModal");
    expect(fixture).toContain('name: "prod-k8s-connector"');
    expect(fixture).not.toContain("eks-prod-connector");
    expect(fixture).toMatch(/initialProvider="unknown"/);
    expect(fixture).not.toMatch(/\bapi\.(GET|POST|PUT|DELETE|PATCH)\b/);
  });

  it("keeps the scope preview lazy, build-flagged, labelled, and transport-restoring", () => {
    expect(app).toMatch(/lazy\(\(\) => import\("\.\/pages\/K8sScopeLocalReview"\)\)/);
    expect(app).toContain('path="/__local-review/kubernetes-scopes"');
    expect(scopeFixture).toContain("LOCAL FIXTURE — NO CLUSTER OR POLICY MUTATION");
    expect(scopeFixture).toContain("mutable.GET = original.GET");
    expect(scopeFixture).toContain("mutable.POST = original.POST");
    expect(scopeFixture).toContain("mutable.PUT = original.PUT");
    expect(scopeFixture).toContain("mutable.DELETE = original.DELETE");
  });
});
