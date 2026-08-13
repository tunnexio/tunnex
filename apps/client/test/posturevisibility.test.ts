import { test } from "node:test";
import assert from "node:assert/strict";

import {
  postureBlockedOverridesTransport,
  postureVisibilityChanged,
  postureVisibilityFor,
  postureWarningOverridesTransport,
} from "../src/main/posturevisibility";

test("posture visibility keeps warn-mode noncompliance distinct from a healthy tunnel", () => {
  assert.equal(postureVisibilityFor({ state: "compliant", blocked: false }), "clear");
  assert.equal(postureVisibilityFor({ state: "noncompliant", blocked: false }), "warning");
  assert.equal(postureVisibilityFor({ state: "noncompliant", blocked: true }), "blocked");
});

test("posture visibility only notifies on a verdict transition", () => {
  assert.equal(postureVisibilityChanged("clear", "warning"), true);
  assert.equal(postureVisibilityChanged("warning", "warning"), false);
  assert.equal(postureVisibilityChanged("warning", "blocked"), true);
  assert.equal(postureVisibilityChanged("blocked", "clear"), true);
});

test("a posture block remains visible across gateway peer withdrawal transport state", () => {
  assert.equal(postureBlockedOverridesTransport("up"), true);
  assert.equal(postureBlockedOverridesTransport("down"), true);
  assert.equal(postureBlockedOverridesTransport("failed"), false);
  assert.equal(postureBlockedOverridesTransport("revoked"), false);
});

test("a posture warning remains visible across routine healthy heartbeats", () => {
  assert.equal(postureWarningOverridesTransport("up"), true);
  assert.equal(postureWarningOverridesTransport("down"), false);
  assert.equal(postureWarningOverridesTransport("failed"), false);
});
