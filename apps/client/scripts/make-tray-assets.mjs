// Generate the small, transparent status-bar assets used by Electron's native Tray.
//
// Do not rasterise through Quick Look or SVG data URLs: both put a 64px SVG preview in
// the top-left of a requested 16/32px canvas. That is exactly how RC21 shipped a tiny
// mark inside an opaque white square. This tiny dependency-free rasteriser owns the
// output pixels, keeps the badge centred, and is safe to run without launching Electron.
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { deflateSync } from "node:zlib";

const here = dirname(new URL(import.meta.url).pathname);
const out = join(here, "..", "build", "tray");
const SCALE = 4;

const crcTable = Array.from({ length: 256 }, (_, i) => {
  let value = i;
  for (let bit = 0; bit < 8; bit += 1) value = (value & 1) ? (value >>> 1) ^ 0xedb88320 : value >>> 1;
  return value >>> 0;
});

function crc32(data) {
  let value = 0xffffffff;
  for (const byte of data) value = (value >>> 8) ^ crcTable[(value ^ byte) & 0xff];
  return (value ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const kind = Buffer.from(type, "ascii");
  const result = Buffer.alloc(data.length + 12);
  result.writeUInt32BE(data.length, 0);
  kind.copy(result, 4);
  data.copy(result, 8);
  result.writeUInt32BE(crc32(Buffer.concat([kind, data])), data.length + 8);
  return result;
}

function png(width, height, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // depth
  ihdr[9] = 6; // RGBA
  const rows = Buffer.alloc((width * 4 + 1) * height);
  for (let y = 0; y < height; y += 1) {
    const target = y * (width * 4 + 1);
    rows[target] = 0; // explicit no-filter rows make the asset proof portable in Node
    rgba.copy(rows, target + 1, y * width * 4, (y + 1) * width * 4);
  }
  return Buffer.concat([
    Buffer.from("89504e470d0a1a0a", "hex"),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(rows)),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

function render(size, connected) {
  const edge = size * SCALE;
  const pixels = new Uint8Array(edge * edge * 4);
  const paint = (inside, color) => {
    for (let y = 0; y < edge; y += 1) for (let x = 0; x < edge; x += 1) {
      if (!inside((x + 0.5) / SCALE, (y + 0.5) / SCALE)) continue;
      const at = (y * edge + x) * 4;
      pixels[at] = color[0]; pixels[at + 1] = color[1]; pixels[at + 2] = color[2]; pixels[at + 3] = color[3];
    }
  };
  const roundedRect = (x, y, width, height, radius) => (px, py) => {
    const cx = Math.max(x + radius, Math.min(px, x + width - radius));
    const cy = Math.max(y + radius, Math.min(py, y + height - radius));
    return (px - cx) ** 2 + (py - cy) ** 2 <= radius ** 2;
  };
  const polygon = (points) => (px, py) => {
    let hit = false;
    for (let i = 0, j = points.length - 1; i < points.length; j = i, i += 1) {
      const [xi, yi] = points[i], [xj, yj] = points[j];
      if ((yi > py) !== (yj > py) && px < ((xj - xi) * (py - yi)) / (yj - yi) + xi) hit = !hit;
    }
    return hit;
  };
  const badge = [23, 23, 25, 255];
  const outline = connected ? [73, 73, 79, 255] : [96, 96, 103, 255];
  const mark = connected ? [238, 29, 54, 255] : [215, 215, 218, 255];
  const black = [8, 8, 10, 255];
  const white = [255, 255, 255, 255];
  const unit = size / 32;
  const u = (value) => value * unit;

  // A compact centred badge with the established Tunnex T and diagonal cut.
  paint(roundedRect(u(4.25), u(4.25), u(23.5), u(23.5), u(6.75)), outline);
  paint(roundedRect(u(5), u(5), u(22), u(22), u(6)), badge);
  paint(roundedRect(u(10), u(11), u(12), u(3.75), u(1.15)), mark);
  paint(polygon([[u(13), u(14)], [u(19), u(14)], [u(19), u(21.35)], [u(16), u(25.4)], [u(13), u(21.35)]]), mark);
  paint(polygon([[u(14.25), u(11)], [u(15.85), u(11)], [u(14.25), u(14.75)], [u(12.65), u(14.75)]]), black);
  paint(polygon([[u(11.3), u(13)], [u(20.7), u(13)], [u(16), u(16.9)]]), black);
  paint(roundedRect(u(15.35), u(16.1), u(1.3), u(5.55), u(0.2)), black);
  // Node circles intentionally use a little more weight than the source SVG at 16px.
  for (const [x, y] of [[11.3, 13], [20.7, 13], [16, 16.9], [16, 22.45]]) {
    paint((px, py) => (px - u(x)) ** 2 + (py - u(y)) ** 2 <= u(1.15) ** 2, white);
  }

  // Downsample supersampled pixels. Transparent padding is preserved, unlike the RC21 export.
  const rgba = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y += 1) for (let x = 0; x < size; x += 1) {
    const sums = [0, 0, 0, 0];
    for (let dy = 0; dy < SCALE; dy += 1) for (let dx = 0; dx < SCALE; dx += 1) {
      const at = ((y * SCALE + dy) * edge + x * SCALE + dx) * 4;
      for (let channel = 0; channel < 4; channel += 1) sums[channel] += pixels[at + channel];
    }
    const at = (y * size + x) * 4;
    for (let channel = 0; channel < 4; channel += 1) rgba[at + channel] = Math.round(sums[channel] / (SCALE * SCALE));
  }
  return png(size, size, rgba);
}

mkdirSync(out, { recursive: true });
for (const [name, size, connected] of [
  ["connected.png", 16, true], ["connected@2x.png", 32, true],
  ["idle.png", 16, false], ["idle@2x.png", 32, false],
  ["connected-win.png", 20, true], ["connected-win@2x.png", 40, true],
  ["idle-win.png", 20, false], ["idle-win@2x.png", 40, false],
]) writeFileSync(join(out, name), render(size, connected));

console.log(`tray assets: wrote 8 centred transparent PNGs to ${out}`);
