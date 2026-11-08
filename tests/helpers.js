// Loads index.html in jsdom with its script running, so the tests drive the real page code.
import { JSDOM, VirtualConsole } from 'jsdom';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const PAGE = readFileSync(fileURLToPath(new URL('../index.html', import.meta.url)), 'utf8');

// A fixed "now" so year-less syslog stamps and relative windows are predictable.
export const NOW = Date.UTC(2026, 10, 7, 12, 0, 0);

export function openPage({ url = 'http://localhost/?tz=UTC' } = {}) {
  const errors = [], alerts = [];
  const vc = new VirtualConsole();
  vc.on('jsdomError', e => errors.push(e.message || String(e)));
  vc.on('error', (...a) => errors.push(a.join(' ')));
  const dom = new JSDOM(PAGE, {
    url, runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: vc,
    beforeParse(w) {
      w.alert = m => alerts.push(String(m));
      w.confirm = () => true;
      w.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} });
      w.HTMLCanvasElement.prototype.getContext = () => new Proxy({}, { get: (t, k) => k === 'measureText' ? () => ({ width: 10 }) : k === 'createLinearGradient' || k === 'createRadialGradient' ? () => ({ addColorStop() {} }) : k === 'getImageData' ? () => ({ data: new Uint8ClampedArray(4) }) : typeof k === 'string' ? () => {} : undefined, set: () => true });
      w.HTMLDialogElement && (w.HTMLDialogElement.prototype.showModal = function () { this.open = true; }, w.HTMLDialogElement.prototype.close = function () { this.open = false; });
      w.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };
      w.IntersectionObserver = class { observe() {} unobserve() {} disconnect() {} };
      w.scrollTo = () => {};
      // jsdom lacks these; the page uses them for files and gzip
      for (const k of ['TextDecoder', 'TextEncoder', 'TextDecoderStream', 'TransformStream', 'ReadableStream', 'DecompressionStream', 'CompressionStream', 'structuredClone']) if (!w[k]) w[k] = globalThis[k];
    },
  });
  const w = dom.window;
  const g = expr => w.eval(expr); // reaches top-level const/let too, which aren't window properties
  return {
    w, g, errors, alerts,
    async load(name, text, ref = NOW) { await w.loadText(name, text, ref); return g('D'); },
    // every row as a plain object, easier to assert on
    rows() {
      return JSON.parse(g(`JSON.stringify(Array.from({ length: D ? D.n : 0 }, (_, i) => {
        const c = D.c;
        return { ts: c.ts[i], act: D.act.list[c.act[i]], group: D.actGroup[c.act[i]], proto: D.proto.list[c.proto[i]],
          src: D.ip.list[c.src[i]], dst: D.ip.list[c.dst[i]], spt: c.spt[i], dpt: c.dpt[i], host: D.host.list[c.host[i]],
          rule: D.rule.list[c.rule[i]], iin: D.iface.list[c.iin[i]], iout: D.iface.list[c.iout[i]] };
      }))`));
    },
    close() { w.close(); },
  };
}
