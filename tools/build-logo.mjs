#!/usr/bin/env node
// fwscope: draws the logo emblem (scope ring, dotted world map, brick wall, hit dots)
// from the world map already embedded in index.html, then writes:
//   assets/logo.svg      full-detail emblem on a dark tile (README, sharing)
//   assets/favicon.svg   coarse version for 16-32px
//   index.html           the header emblem (theme-aware, uses the page's CSS colors)
//                        and the favicon, between the LOGO / FAVICON markers
// Run after tools/build-map.mjs:  node tools/build-logo.mjs

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const indexPath = path.join(root, 'index.html');
let html = await readFile(indexPath, 'utf8');
const MAP = JSON.parse(/const MAP = (\{.*\});/.exec(html)[1]);

// ---- same Equal Earth projection as build-map.mjs, for placing the hit dots
const A1 = 1.340264, A2 = -0.081106, A3 = 0.000893, A4 = 0.003796, M = Math.sqrt(3) / 2;
function project(lon, lat) {
  const lam = lon * Math.PI / 180, l = Math.asin(M * Math.sin(lat * Math.PI / 180)), l2 = l * l, l6 = l2 * l2 * l2;
  return [lam * Math.cos(l) / (M * (A1 + 3 * A2 * l2 + l6 * (7 * A3 + 9 * A4 * l2))), l * (A1 + A2 * l2 + l6 * (A3 + A4 * l2))];
}
const xMax = project(180, 0)[0], yMax = project(0, 90)[1], S = MAP.w / (2 * xMax);
const toMap = (lon, lat) => { const [x, y] = project(lon, lat); return [(x + xMax) * S, (yMax - y) * S]; };

// ---- land test on the embedded country outlines
const polys = [];
for (const d of Object.values(MAP.shapes)) for (const ring of d.split('Z')) {
  const pts = ring.replace(/^M/, '').split('L').filter(Boolean).map(p => p.trim().split(/ (?=-?\d)/).map(Number));
  if (pts.length > 2) polys.push(pts);
}
function land(x, y) {
  let inside = false;
  for (const p of polys) for (let i = 0, j = p.length - 1; i < p.length; j = i++) {
    const [xi, yi] = p[i], [xj, yj] = p[j];
    if ((yi > y) !== (yj > y) && x < (xj - xi) * (y - yi) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}

// ---- emblem geometry, in a 100 x 100 box
const C = 50, R = 42, INNER = 38.5;
const K = 76 / MAP.w;                         // map width 76 units, so the whole world fits in the scope
const MAPTOP = 41 - (MAP.h - MAP.y0) * K / 2; // map centered a little above the middle
const fromLogo = (x, y) => [(x - 12) / K, (y - MAPTOP) / K + MAP.y0];
const toLogo = (mx, my) => [12 + mx * K, MAPTOP + (my - MAP.y0) * K];
const inCircle = (x, y, r) => (x - C) ** 2 + (y - C) ** 2 <= r * r;
const f = n => +n.toFixed(2);
const HITS = [[-74, 40.7], [8.7, 50], [116.4, 40], [-46.6, -23.5], [103.8, 1.35], [-97, 33], [0, 51.5], [37.6, 55.8], [51.4, 35.7], [4.9, 52.4], [-74, 4.6], [151.2, -33.9]]; // spread first: the small sizes only use the first few

function emblem(col, { spacing, hitR, hits, bg }) {
  const out = [];
  if (bg) out.push(`<rect width="100" height="100" rx="18" fill="${bg}"/>`);
  // dotted world map, clipped to the scope and kept above the wall
  const dots = [], r = spacing * 0.34;
  for (let y = 12 + spacing / 2; y < 63; y += spacing) for (let x = 10 + spacing / 2; x < 90; x += spacing) {
    if (!inCircle(x, y, INNER - r)) continue;
    const [mx, my] = fromLogo(x, y);
    if (land(mx, my)) dots.push(`M${f(x - r)} ${f(y)}a${f(r)} ${f(r)} 0 1 0 ${f(2 * r)} 0a${f(r)} ${f(r)} 0 1 0 ${f(-2 * r)} 0`);
  }
  out.push(`<path fill="${col.map}" d="${dots.join('')}"/>`);
  // brick wall across the bottom of the scope
  const bricks = [];
  for (let row = 0, y = 65; y < 92; row++, y += 6.6) for (let x = 6 - (row % 2) * 5.8; x < 94; x += 11.6) {
    const half = Math.min(Math.sqrt(Math.max(0, INNER ** 2 - (y - C) ** 2)), Math.sqrt(Math.max(0, INNER ** 2 - (y + 5 - C) ** 2)));
    const x0 = Math.max(x, C - half + 0.8), x1 = Math.min(x + 10, C + half - 0.8);
    if (x1 - x0 > 2.5) bricks.push(`M${f(x0)} ${f(y)}h${f(x1 - x0)}v5h${f(x0 - x1)}z`);
  }
  out.push(`<path fill="${col.ring}" d="${bricks.join('')}"/>`);
  // crosshair: fine lines with ticks, heavy posts at the edges
  const ticks = [];
  for (let d = -21; d <= 21; d += 7) if (d) { ticks.push(`M${C + d} ${C - 1.6}v3.2`, `M${C - 1.6} ${C + d}h3.2`); }
  out.push(`<path stroke="${col.ring}" stroke-width="0.9" fill="none" d="M24 ${C}H76M${C} 24V76${ticks.join('')}"/>`);
  out.push(`<path stroke="${col.ring}" stroke-width="4.2" stroke-linecap="butt" fill="none" d="M${C} 8V24M${C} 76V92M8 ${C}H24M76 ${C}H92"/>`);
  // hit dots with a soft halo
  for (const [lon, lat] of HITS.slice(0, hits)) {
    const [x, y] = toLogo(...toMap(lon, lat));
    if (!inCircle(x, y, INNER - hitR * 2)) continue;
    out.push(`<circle cx="${f(x)}" cy="${f(y)}" r="${f(hitR * 1.8)}" fill="${col.hit}" opacity="0.3"/><circle cx="${f(x)}" cy="${f(y)}" r="${f(hitR)}" fill="${col.hit}"/>`);
  }
  // scope ring, lit on the right
  out.push(`<circle cx="${C}" cy="${C}" r="${R}" fill="none" stroke="${col.ring}" stroke-width="5"/>`);
  out.push(`<path d="M${C} ${C - R}A${R} ${R} 0 0 1 ${C} ${C + R}" fill="none" stroke="${col.hi}" stroke-width="5"/>`);
  return out.join('');
}

const FIXED = { map: '#3987e5', ring: '#6b7a85', hi: '#b7d3f6', hit: '#d55181' };
const THEMED = { map: 'var(--accent)', ring: 'var(--logo-ring)', hi: 'var(--logo-hi)', hit: 'var(--a-block)' };
const svg = (body, attrs = '') => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"${attrs}>${body}</svg>`;

const full = svg(emblem(FIXED, { spacing: 2.1, hitR: 1.5, hits: 12, bg: '#1a1a19' }));
const fav = svg(emblem(FIXED, { spacing: 3.9, hitR: 2.6, hits: 5, bg: '#1a1a19' }));
const header = svg(emblem(THEMED, { spacing: 2.9, hitR: 2, hits: 8 }), ' class="logo" aria-hidden="true" focusable="false"');

await mkdir(path.join(root, 'assets'), { recursive: true });
await writeFile(path.join(root, 'assets', 'logo.svg'), full + '\n');
await writeFile(path.join(root, 'assets', 'favicon.svg'), fav + '\n');

const put = (name, value) => {
  const re = new RegExp(`(<!--${name}-->)[\\s\\S]*?(<!--END-${name}-->)`);
  if (!re.test(html)) throw new Error(`${name} markers not found in index.html`);
  html = html.replace(re, `$1${value}$2`);
};
put('FAVICON', `<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,${encodeURIComponent(fav)}">`);
put('LOGO', header);
await writeFile(indexPath, html);
console.log(`logo: header ${(header.length / 1024).toFixed(1)} KB, favicon ${(fav.length / 1024).toFixed(1)} KB, logo.svg ${(full.length / 1024).toFixed(1)} KB`);
