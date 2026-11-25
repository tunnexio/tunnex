import { expect, it } from "vitest";
import { checkStatusText, grantStatusText, operationStatusText, subjectKindText, words } from "../src/lib/appAccessLabels";

it("maps every App Access state shown in badges to words (SA-UX-2 audit A1/A2/A5/A6)", () => {
  for (const map of [checkStatusText, grantStatusText, operationStatusText, subjectKindText]) {
    for (const [code, text] of Object.entries(map)) {
      expect(text, code).not.toMatch(/_/);
      expect(text.charAt(0), code).toBe(text.charAt(0).toUpperCase());
    }
  }
  for (const status of ["active", "scheduled", "expired", "disabled", "revoked", "subject_unavailable"]) expect(grantStatusText[status]).toBeTruthy();
  for (const status of ["queued", "checking", "activated", "failed", "cancelled", "expired"]) expect(operationStatusText[status]).toBeTruthy();
  expect(words(checkStatusText, "something_new")).toBe("Unknown");
});
