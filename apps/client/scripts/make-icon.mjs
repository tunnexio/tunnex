// Generate the app icon from the brand mark.
//
// ⛔ RENDERED BY CHROMIUM, BECAUSE NOTHING ELSE ON THE BOX CAN RENDER THIS SVG. There is no
// rsvg-convert, inkscape, ImageMagick or cairosvg here, and `sips` does not read SVG. The mark uses
// gradients and a sheen, so a hand-rolled rasteriser would drop exactly the parts that make it look
// like the brand. Electron is already a dependency and ships the same engine that draws the app —
// so the icon is rendered by the renderer, which also means it cannot disagree with what the app
// shows.
//
// ⛔ PADDING AND A PLATE, DELIBERATELY. The asset's glyph runs corner to corner with a baked
// `#0A0A0A` rectangle behind it, which is why it reads as a cropped tile at small sizes. Here the
// glyph is drawn at 58% of the canvas, centred, on a rounded square of the same brand black — so
// the mark has room on every side and the ROUNDING is ours rather than the OS clipping a square.
//
//   macOS draws no mask: whatever the file contains is what appears in the Dock. A square PNG shows
//   as a square. The 22.37% corner radius below is Apple's own for the Big Sur icon grid.
//
// Run: pnpm --filter @tunnex/client icon
import { app, BrowserWindow } from "electron";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const SVG = join(here, "..", "..", "web", "src", "assets", "tunnex-logo.svg");
const OUT = join(here, "..", "build", "icon.png");

const SIZE = 1024;
const GLYPH = 0.58; // fraction of the canvas the mark occupies — the rest is padding
const RADIUS = 0.2237; // Apple's Big Sur corner radius, as a fraction of the side

app.disableHardwareAcceleration();

app.whenReady().then(async () => {
  const svg = readFileSync(SVG, "utf8");
  // ⚠ THE ASSET'S OWN BACKGROUND PLATE IS REMOVED. It is a full-bleed <rect> sized to the artboard;
  // leaving it in would paint a hard-edged square on top of the rounded one and undo the padding.
  const glyph = svg.replace(
    /<rect\s+width="577"\s+height="551"\s+fill="#0A0A0A"\s*>\s*<\/rect>|<rect\s+width="577"\s+height="551"\s+fill="#0A0A0A"\s*\/>/,
    "",
  );
  if (glyph === svg) {
    // Loud, not silent: a changed asset must not quietly produce an icon with a square inside it.
    console.error("make-icon: the artboard rect was NOT found — the asset changed shape.");
    console.error("Re-check the <rect> in tunnex-logo.svg before shipping this icon.");
    app.exit(1);
    return;
  }

  const html = `<!doctype html><meta charset="utf-8"><style>
    html,body{margin:0;padding:0;background:transparent}
    .plate{
      width:${SIZE}px;height:${SIZE}px;border-radius:${SIZE * RADIUS}px;
      background:#0A0A0A;
      display:flex;align-items:center;justify-content:center;
      box-shadow:inset 0 0 0 1px rgba(255,255,255,.06);
    }
    .glyph{width:${SIZE * GLYPH}px;height:auto;display:block}
    .glyph svg{width:100%;height:auto;display:block}
  </style><div class="plate"><div class="glyph">${glyph}</div></div>`;

  const win = new BrowserWindow({
    width: SIZE,
    height: SIZE,
    show: false,
    frame: false,
    transparent: true,
    backgroundColor: "#00000000",
    webPreferences: { offscreen: true },
  });
  await win.loadURL("data:text/html;charset=utf-8," + encodeURIComponent(html));
  // One frame is not enough for a gradient-heavy SVG on some machines; wait for paint.
  await new Promise((r) => setTimeout(r, 400));
  const img = await win.webContents.capturePage();
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, img.toPNG());
  const { width, height } = img.getSize();
  console.log(`make-icon: wrote ${OUT} (${width}x${height})`);
  // ⚠ ON A RETINA DISPLAY THE CAPTURE COMES BACK AT DEVICE PIXELS — 2048 for a 1024 window. That is
  // MORE detail, not a scaling bug, and electron-builder downsamples happily. What must hold is
  // that it is SQUARE and at least the target: a non-square icon is stretched by every OS that
  // shows it, and an undersized one is blurred by all of them.
  if (width !== height || width < SIZE) {
    console.error(`make-icon: expected a square of at least ${SIZE}px, got ${width}x${height}.`);
    app.exit(1);
    return;
  }
  app.exit(0);
});
