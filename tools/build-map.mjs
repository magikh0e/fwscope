#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 magikh0e
// fwscope: builds the world map that index.html embeds, and writes it between the
// MAP-DATA markers in index.html.
//
//   node tools/build-map.mjs            downloads the sources from jsDelivr
//   node tools/build-map.mjs <dir>      reads countries-110m.json, codes.json and en.json from <dir>
//
// Sources: Natural Earth 1:110m countries (public domain) via the world-atlas
// package, and ISO 3166 codes + English names from i18n-iso-countries (MIT).
// Projection: Equal Earth. Antarctica is dropped.

import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const indexPath = path.join(here, '..', 'index.html');
const SRC = {
  'countries-110m.json': 'https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json',
  'codes.json': 'https://cdn.jsdelivr.net/npm/i18n-iso-countries@7.11.0/codes.json',
  'en.json': 'https://cdn.jsdelivr.net/npm/i18n-iso-countries@7.11.0/langs/en.json',
};
async function load(name) {
  if (process.argv[2]) return JSON.parse(await readFile(path.join(process.argv[2], name), 'utf8'));
  const r = await fetch(SRC[name]);
  if (!r.ok) throw new Error(`${SRC[name]}: HTTP ${r.status}`);
  return r.json();
}
const [topo, codes, en] = await Promise.all(Object.keys(SRC).map(load));

// ---- Equal Earth projection (Šavrič, Patterson & Jenny 2018)
const A1 = 1.340264, A2 = -0.081106, A3 = 0.000893, A4 = 0.003796, M = Math.sqrt(3) / 2;
function project([lon, lat]) {
  const lam = lon * Math.PI / 180, phi = lat * Math.PI / 180;
  const l = Math.asin(M * Math.sin(phi)), l2 = l * l, l6 = l2 * l2 * l2;
  return [lam * Math.cos(l) / (M * (A1 + 3 * A2 * l2 + l6 * (7 * A3 + 9 * A4 * l2))), l * (A1 + A2 * l2 + l6 * (A3 + A4 * l2))];
}
const W = 1000;
const xMax = project([180, 0])[0], yMax = project([0, 90])[1];
const S = W / (2 * xMax);
const toPx = p => { const [x, y] = project(p); return [(x + xMax) * S, (yMax - y) * S]; };

// ---- TopoJSON decode
const { scale, translate } = topo.transform;
const arcs = topo.arcs.map(arc => { let x = 0, y = 0; return arc.map(([dx, dy]) => { x += dx; y += dy; return [x * scale[0] + translate[0], y * scale[1] + translate[1]]; }); });
function ring(ids) {
  const pts = [];
  for (const id of ids) {
    const a = id < 0 ? arcs[~id].slice().reverse() : arcs[id];
    pts.push(...(pts.length ? a.slice(1) : a));
  }
  return pts;
}

const num2a2 = Object.fromEntries(codes.map(([a2, , num]) => [num, a2]));
const PICK = { CD: 'DR Congo', CG: 'Congo', CD_: 0 };
const name = a2 => {
  if (PICK[a2]) return PICK[a2];
  const v = en.countries[a2];
  if (!Array.isArray(v)) return v;
  return ['GB', 'KR', 'NL', 'AE'].includes(a2) ? v[0] : v[1];
};

let minY = Infinity, maxY = -Infinity;
const shapes = {};
for (const g of topo.objects.countries.geometries) {
  const a2 = num2a2[g.id];
  if (!a2 || a2 === 'AQ') continue;
  const polys = g.type === 'Polygon' ? [g.arcs] : g.arcs;
  let d = shapes[a2] || '';
  for (const poly of polys) for (const r of poly) {
    let prev = '';
    let seg = '';
    for (const p of ring(r)) {
      const [x, y] = toPx(p);
      minY = Math.min(minY, y); maxY = Math.max(maxY, y);
      const s = `${x.toFixed(1)} ${y.toFixed(1)}`;
      if (s === prev) continue;
      seg += (seg ? 'L' : 'M') + s; prev = s;
    }
    d += seg + 'Z';
  }
  shapes[a2] = d.replace(/ -/g, '-').replace(/\.0(?=[ LMZ-])/g, '');
}

// Small countries the 1:110m map has no shape for get a dot at roughly their
// center, so the busiest scan sources (Singapore, Hong Kong, ...) still show up.
const DOTS = {
  SG: [103.82, 1.35], HK: [114.17, 22.32], MO: [113.54, 22.19], MT: [14.45, 35.9], BH: [50.56, 26.07], AD: [1.52, 42.55],
  MC: [7.42, 43.74], LI: [9.55, 47.16], SM: [12.46, 43.94], VA: [12.45, 41.9], MU: [57.55, -20.3], MV: [73.22, 3.2],
  BB: [-59.55, 13.19], SC: [55.45, -4.68], AG: [-61.8, 17.07], DM: [-61.37, 15.41], GD: [-61.68, 12.12], KN: [-62.75, 17.33],
  LC: [-60.98, 13.91], VC: [-61.2, 13.25], TO: [-175.2, -21.18], WS: [-172.1, -13.76], KI: [173.0, 1.87], FM: [158.2, 6.92],
  MH: [171.2, 7.1], PW: [134.58, 7.5], NR: [166.93, -0.52], TV: [179.2, -8.52], ST: [6.61, 0.19], CV: [-23.6, 15.1],
  KM: [43.87, -11.88], BM: [-64.75, 32.31], KY: [-81.25, 19.31], GI: [-5.35, 36.14], IM: [-4.55, 54.24], JE: [-2.13, 49.21],
  GG: [-2.58, 49.45], FO: [-6.91, 62.0], AW: [-69.97, 12.52], CW: [-68.99, 12.17], SX: [-63.05, 18.04], VG: [-64.62, 18.42],
  VI: [-64.9, 18.34], GU: [144.79, 13.44], MP: [145.67, 15.1], AS: [-170.7, -14.27], RE: [55.54, -21.12], GP: [-61.55, 16.25],
  MQ: [-61.02, 14.64], PF: [-149.4, -17.65], YT: [45.15, -12.83], AI: [-63.07, 18.22], MS: [-62.19, 16.74], TC: [-71.8, 21.69],
  XK: [20.9, 42.6], BL: [-62.83, 17.9], MF: [-63.08, 18.07], PM: [-56.3, 46.9], AX: [19.95, 60.18], CK: [-159.78, -21.24], NU: [-169.87, -19.05],
};
const dots = {};
for (const [a2, ll] of Object.entries(DOTS)) if (!shapes[a2]) dots[a2] = toPx(ll).map(v => +v.toFixed(1));

const names = {};
for (const [a2] of codes) if (en.countries[a2]) names[a2] = name(a2);
names.XK = 'Kosovo'; // user-assigned code used by most GeoIP databases

const H = Math.ceil(maxY + 2);
const data = { w: W, h: H, y0: Math.floor(minY - 2), shapes, dots, names };
const js = `const MAP = ${JSON.stringify(data)};`;

const html = await readFile(indexPath, 'utf8');
const re = /(\/\*MAP-DATA\*\/)[\s\S]*?(\/\*END-MAP-DATA\*\/)/;
if (!re.test(html)) throw new Error('MAP-DATA markers not found in index.html');
await writeFile(indexPath, html.replace(re, `$1\n${js}\n$2`));
const missing = codes.map(c => c[0]).filter(a2 => !shapes[a2] && !dots[a2]);
console.log(`map: ${Object.keys(shapes).length} shapes, ${Object.keys(dots).length} dots, ${(js.length / 1024).toFixed(0)} KB embedded`);
console.log(`no shape or dot (tiny territories, listed but not drawn): ${missing.join(' ')}`);
