import { readFileSync } from "node:fs";
import { join } from "node:path";
import assert from "node:assert/strict";
import { test } from "node:test";

const source = readFileSync(
  join(__dirname, "..", "src", "main", "index.ts"),
  "utf8",
);

test("desktop client shell uses the compact fixed surface", () => {
  assert.match(source, /width:\s*400,/);
  assert.match(source, /height:\s*740,/);
  assert.match(source, /resizable:\s*false,/);
});
