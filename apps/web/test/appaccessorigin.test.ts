import { describe, expect, it } from "vitest";
import { suggestedOriginRange } from "../src/lib/appaccessorigin";

describe("suggestedOriginRange", () => {
  it.each([
    ["http://10.0.0.5:8080", [], { address: "10.0.0.5", range: "10.0.0.5/32", covered: false }],
    ["https://172.16.4.1/", [], { address: "172.16.4.1", range: "172.16.4.1/32", covered: false }],
    ["http://192.168.1.10", ["10.0.0.0/8"], { address: "192.168.1.10", range: "192.168.1.10/32", covered: false }],
    ["http://192.168.1.10", ["192.168.0.0/16"], { address: "192.168.1.10", range: "192.168.1.10/32", covered: true }],
    ["http://[fd00::12]:8080", [], { address: "fd00::12", range: "fd00::12/128", covered: false }],
  ])("suggests the single-host range for private literal %s", (url, allowed, want) => {
    expect(suggestedOriginRange(url, allowed)).toEqual(want);
  });
  it.each(["https://wiki.corp.internal", "http://8.8.8.8", "http://127.0.0.1", "http://169.254.169.254", "http://172.32.0.1", "not a url", ""])("never suggests a range the policy would refuse or cannot know: %s", url => {
    expect(suggestedOriginRange(url, [])).toBeNull();
  });
});
