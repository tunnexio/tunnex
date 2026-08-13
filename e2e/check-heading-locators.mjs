import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const roots = ["e2e/tests", "e2e/walk"];
const files = [];
for (const root of roots) {
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (entry.isFile() && entry.name.endsWith(".ts")) {
      files.push(join(root, entry.name));
    }
  }
}

const broadGatewayHeading =
  /getByRole\(\s*["']heading["']\s*,\s*\{\s*name:\s*["']Gateways["']\s*\}\s*\)/g;
const pageTitleGatewayHeading =
  /getByRole\(\s*["']heading["']\s*,\s*\{\s*name:\s*["']Gateways["']\s*,\s*level:\s*1\s*\}\s*\)/g;

const broad = [];
let scoped = 0;
for (const file of files) {
  const source = readFileSync(file, "utf8");
  if (broadGatewayHeading.test(source)) broad.push(file);
  scoped += [...source.matchAll(pageTitleGatewayHeading)].length;
  broadGatewayHeading.lastIndex = 0;
}

if (broad.length > 0) {
  console.error(
    `Ambiguous Gateways heading locator in: ${broad.join(", ")}. ` +
      `The page has both an h1 and h2 named Gateways; use level: 1 for the page title.`,
  );
  process.exit(1);
}

if (scoped < 3) {
  console.error(
    `Expected at least 3 semantically scoped Gateways page-title locators; found ${scoped}. ` +
      `The census may have lost its subjects.`,
  );
  process.exit(1);
}

console.log(`Gateways heading locator contract: PASS (${scoped} scoped locators)`);
