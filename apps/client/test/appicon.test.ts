import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { inflateSync } from "node:zlib";

const ROOT = join(__dirname, "..", "..", "..");
const ICON = join(__dirname, "..", "build", "icon.png");
const TRAY_DIR = join(__dirname, "..", "build", "tray");

function readTrayPixels(file: string): { width: number; height: number; pixels: Buffer } {
  const source = readFileSync(file);
  let offset = 8;
  let width = 0;
  let height = 0;
  const data: Buffer[] = [];
  while (offset < source.length) {
    const length = source.readUInt32BE(offset);
    const type = source.subarray(offset + 4, offset + 8).toString("ascii");
    const chunk = source.subarray(offset + 8, offset + 8 + length);
    if (type === "IHDR") {
      width = chunk.readUInt32BE(0);
      height = chunk.readUInt32BE(4);
    }
    if (type === "IDAT") data.push(chunk);
    offset += length + 12;
  }
  assert.ok(width > 0 && height > 0 && data.length > 0, `${file} has no readable PNG image data`);
  const rows = inflateSync(Buffer.concat(data));
  const pixels = Buffer.alloc(width * height * 4);
  for (let y = 0; y < height; y += 1) {
    const from = y * (width * 4 + 1);
    assert.equal(rows[from], 0, `${file} must use no-filter PNG rows for this portable pixel proof`);
    rows.copy(pixels, y * width * 4, from + 1, from + 1 + width * 4);
  }
  return { width, height, pixels };
}

// ⛔ THE APP SHIPPED WITH ELECTRON'S OWN ICON, AND THE FIX HAD A SECOND HALF THAT NEARLY GOT LOST.
//
// Generating the icon was the easy part. `.gitignore` carries an UNANCHORED `build/`, which matches
// `apps/client/build/` — the electron-builder buildResources directory, full of AUTHORED files. The
// four already in git are there only because somebody ran `git add -f`. The icon would have been
// the fifth: correct on the machine that generated it, absent on every fresh clone, and the
// packaged app would have gone back to Electron's atom with nothing failing.
//
// > **THIS REPO HAS ALREADY PAID FOR THIS EXACT PATTERN** — an unanchored `secrets/` kept
// > `apps/api/internal/secrets` SOURCE out of git, building locally and breaking every clone.

test("the app icon exists and is a square PNG big enough for every target", () => {
  assert.ok(existsSync(ICON), "apps/client/build/icon.png is missing — run `pnpm --filter @tunnex/client icon`");
  const buf = readFileSync(ICON);
  // PNG signature, then IHDR: width and height are big-endian u32 at offsets 16 and 20.
  assert.equal(buf.subarray(1, 4).toString("ascii"), "PNG");
  const w = buf.readUInt32BE(16);
  const h = buf.readUInt32BE(20);
  assert.equal(w, h, `the icon is ${w}x${h} — a non-square icon is stretched by every OS that shows it`);
  // electron-builder derives .icns and .ico from this one file; below 512 they come out blurred.
  assert.ok(w >= 512, `the icon is ${w}px — too small to generate .icns/.ico cleanly`);
});

test("⛔ the icon is not swallowed by the unanchored `build/` ignore rule", () => {
  // ⚠ `git check-ignore` IS THE WRONG INSTRUMENT AND IT ANSWERED "IGNORED" FOR A FILE THAT IS NOT.
  // Its exit status is 0 when ANY pattern matches — including a NEGATION — so an un-ignored file
  // reports the same status as an ignored one. The question is not "does a rule match" but "would
  // git add this", and only `ls-files --others --exclude-standard` answers that.
  const tracked = execFileSync("git", ["ls-files", "apps/client/build/icon.png"], {
    cwd: ROOT,
    encoding: "utf8",
  }).trim();
  const addable = execFileSync(
    "git",
    ["ls-files", "--others", "--exclude-standard", "apps/client/build/icon.png"],
    { cwd: ROOT, encoding: "utf8" },
  ).trim();
  assert.ok(
    tracked !== "" || addable !== "",
    "apps/client/build/icon.png is neither tracked nor addable — .gitignore is swallowing it, and " +
      "the packaged app will fall back to Electron's icon on a fresh clone",
  );
});

test("the generated helper binary stays OUT of git", () => {
  // The same directory holds a real build artefact. Un-ignoring the directory must not drag it in.
  const addable = execFileSync(
    "git",
    ["ls-files", "--others", "--exclude-standard", "apps/client/build/helper/"],
    { cwd: ROOT, encoding: "utf8" },
  ).trim();
  assert.equal(addable, "", "the staged helper binary became addable — it is a build output");
});

test("tray icons are shipped as explicit normal and Retina PNG resources", () => {
  for (const name of [
    "connected.png", "connected@2x.png", "idle.png", "idle@2x.png",
    "connected-win.png", "connected-win@2x.png", "idle-win.png", "idle-win@2x.png",
  ]) {
    const file = join(TRAY_DIR, name);
    assert.ok(existsSync(file), `${name} is missing — macOS tray may render blank`);
    assert.equal(readFileSync(file).subarray(1, 4).toString("ascii"), "PNG", `${name} is not a PNG`);
  }
  const yml = readFileSync(join(__dirname, "..", "electron-builder.yml"), "utf8");
  assert.match(yml, /from: build\/tray/);
  assert.match(yml, /to: tray/);
});

test("tray PNGs are centred transparent assets, not opaque SVG thumbnail canvases", () => {
  for (const name of [
    "connected.png", "connected@2x.png", "idle.png", "idle@2x.png",
    "connected-win.png", "connected-win@2x.png", "idle-win.png", "idle-win@2x.png",
  ]) {
    const { width, height, pixels } = readTrayPixels(join(TRAY_DIR, name));
    const opaque: Array<[number, number]> = [];
    for (let y = 0; y < height; y += 1) for (let x = 0; x < width; x += 1) {
      if (pixels[(y * width + x) * 4 + 3] > 0) opaque.push([x, y]);
    }
    assert.equal(pixels[3], 0, `${name} has an opaque top-left canvas — the mark will render as a square`);
    assert.ok(opaque.length > 0, `${name} has no visible mark`);
    const xs = opaque.map(([x]) => x);
    const ys = opaque.map(([, y]) => y);
    const minX = Math.min(...xs), maxX = Math.max(...xs), minY = Math.min(...ys), maxY = Math.max(...ys);
    assert.ok(minX >= 1 && minY >= 1 && maxX <= width - 2 && maxY <= height - 2, `${name} touches the canvas edge`);
    assert.ok(maxX - minX + 1 >= Math.floor(width * 0.6), `${name} mark is too small for a status item`);
    assert.ok(Math.abs((minX + maxX + 1) / 2 - width / 2) <= 1, `${name} mark is not horizontally centred`);
    assert.ok(Math.abs((minY + maxY + 1) / 2 - height / 2) <= 1, `${name} mark is not vertically centred`);
  }
});

test("macOS and Windows tray assets use their native footprints with the same centred mark", () => {
  const expected = {
    "connected.png": [16, 16],
    "connected@2x.png": [32, 32],
    "idle.png": [16, 16],
    "idle@2x.png": [32, 32],
    "connected-win.png": [20, 20],
    "connected-win@2x.png": [40, 40],
    "idle-win.png": [20, 20],
    "idle-win@2x.png": [40, 40],
  } as const;
  for (const [name, [width, height]] of Object.entries(expected)) {
    const image = readTrayPixels(join(TRAY_DIR, name));
    assert.equal(image.width, width, `${name} has the wrong native tray width`);
    assert.equal(image.height, height, `${name} has the wrong native tray height`);
  }
});

// ── S14.20 step 4: the dashboard is not shipped ─────────────────────────────────────────────────
test("⛔ the packaged bundle EXCLUDES the dashboard entry, and keeps the shared brand chunk", () => {
  // The vite build emits two entries. The client loads client.html and cannot reach index.html at
  // all, so shipping it put the whole admin dashboard — 352 KB of JS plus its CSS — inside the
  // client as code that cannot execute but can be read.
  //
  // ⚠ `brand-*` is SHARED and must survive: client.html references brand.css and brand.js. Verified
  // against the built HTML, not guessed — which is why this asserts the keep as well as the drop.
  const yml = readFileSync(join(__dirname, "..", "electron-builder.yml"), "utf8");
  assert.match(yml, /!index\.html/, "index.html is still shipped to the client");
  assert.match(yml, /!assets\/index-\*/, "the dashboard chunk is still shipped to the client");
  assert.ok(!/!assets\/brand-/.test(yml), "brand-* must NOT be excluded — the client renders it");
});

test("⛔ the app:// fallback serves the CLIENT entry, not the dashboard's", () => {
  // It served index.html for any extension-less path. That was right while the client loaded the
  // dashboard; now index.html is not even packaged, so the fallback would 404 on "/".
  const src = readFileSync(join(__dirname, "..", "src", "main", "index.ts"), "utf8")
    .replace(/^\s*\/\/.*$/gm, " ")
    .replace(/\/\*[\s\S]*?\*\//g, " ");
  const fallback = /const serveIndex = \(\) => \{[\s\S]*?\n    \};/.exec(src)?.[0] ?? "";
  assert.ok(fallback.length > 0, "serveIndex not found — this test is measuring nothing");
  assert.ok(!/index\.html/.test(fallback), "the fallback still points at the dashboard entry");
  assert.match(fallback, /CLIENT_ENTRY/);
});
