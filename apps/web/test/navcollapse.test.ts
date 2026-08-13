import { describe, expect, it } from "vitest";
import {
  NAV_STORAGE_KEY,
  NAV_WIDTH,
  navShows,
  navToggleTitle,
  readNavCollapse,
  toggleNavCollapse,
  writeNavCollapse,
} from "../src/lib/navcollapse";

// ⛔ THE KEY AND ITS VALUES ARE THE DESIGNER'S, TRANSCRIBED — not chosen here.
//
//     localStorage.setItem('tnx-nav', c ? 'closed' : 'open')
//
// I previously reported that `tnx-nav` was undocumented. It is documented — in the wireframe's own
// JS, which is not our README, and I had only grepped the README. **"Not in our README" is not the
// same as "not documented", and reporting the first as the second sent the decision the wrong way.**
describe("the persisted key", () => {
  it("is the designer's key and values, verbatim", () => {
    expect(NAV_STORAGE_KEY).toBe("tnx-nav");
    const store = new Map<string, string>();
    writeNavCollapse({ setItem: (k, v) => store.set(k, v) }, "closed");
    expect(store.get("tnx-nav")).toBe("closed");
    writeNavCollapse({ setItem: (k, v) => store.set(k, v) }, "open");
    expect(store.get("tnx-nav")).toBe("open");
  });

  it("carries the design's widths", () => {
    expect(NAV_WIDTH.open).toBe("228px");
    expect(NAV_WIDTH.closed).toBe("64px");
  });
});

// ⛔ ABSENT IS NOT A PREFERENCE. A user in private mode gets the full sidebar, not a mystery icon
// rail they never chose — the same absent-until-known rule the nav counts and the edition seam use.
describe("readNavCollapse", () => {
  it("defaults OPEN when nothing is stored", () => {
    expect(readNavCollapse({ getItem: () => null })).toBe("open");
  });

  it("defaults OPEN when storage itself throws", () => {
    // Safari private mode throws on ACCESS, not just on write.
    expect(
      readNavCollapse({
        getItem: () => {
          throw new Error("SecurityError");
        },
      }),
    ).toBe("open");
  });

  it("defaults OPEN for any value that is not exactly 'closed'", () => {
    // A half-written or foreign value must not collapse the nav.
    for (const v of ["", "true", "collapsed", "CLOSED", "0"]) {
      expect(readNavCollapse({ getItem: () => v })).toBe("open");
    }
  });

  it("honours a stored 'closed'", () => {
    expect(readNavCollapse({ getItem: () => "closed" })).toBe("closed");
  });

  it("survives a null store (SSR / no window)", () => {
    expect(readNavCollapse(null)).toBe("open");
  });
});

describe("writeNavCollapse", () => {
  it("⛔ never throws when storage refuses — the toggle must still work", () => {
    // A failed write loses the preference on reload; it must not break the click that made it.
    expect(() =>
      writeNavCollapse(
        {
          setItem: () => {
            throw new Error("QuotaExceededError");
          },
        },
        "closed",
      ),
    ).not.toThrow();
    expect(() => writeNavCollapse(null, "open")).not.toThrow();
  });
});

describe("toggleNavCollapse", () => {
  it("is its own inverse", () => {
    expect(toggleNavCollapse("open")).toBe("closed");
    expect(toggleNavCollapse("closed")).toBe("open");
    expect(toggleNavCollapse(toggleNavCollapse("open"))).toBe("open");
  });
});

// ⛔ COLLAPSING IS A PRESENTATION, NEVER A FILTER.
describe("navShows", () => {
  it("hides the wordmark, the section headers and the labels — and nothing else", () => {
    expect(navShows("closed")).toEqual({
      wordmark: false,
      sectionHeaders: false,
      labels: false,
    });
    expect(navShows("open")).toEqual({
      wordmark: true,
      sectionHeaders: true,
      labels: true,
    });
  });
});

describe("navToggleTitle", () => {
  it("names the ACTION, not the state", () => {
    // "Collapsed" would describe what is; the control must say what clicking does.
    expect(navToggleTitle("closed")).toBe("Expand sidebar");
    expect(navToggleTitle("open")).toBe("Collapse sidebar");
  });
});
