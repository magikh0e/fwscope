// The background parser is built from the page's own script (the parts between the W markers). Run that code
// with no page around it, as a worker would, and check it parses files and hands back a usable store.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { openPage } from './helpers.js';

const PAGE = readFileSync(fileURLToPath(new URL('../index.html', import.meta.url)), 'utf8');
const script = PAGE.slice(PAGE.indexOf('<script>') + 8, PAGE.lastIndexOf('</script>'));

function workerSource() {
  const parts = [...script.matchAll(/\/\*W>\*\/([\s\S]*?)\/\*<W\*\//g)].map(m => m[1]);
  const main = /function workerMain\(\) \{[\s\S]*?\n\}\n/.exec(script)[0];
  return "'use strict';\n" + parts.join('\n') + `\n(${main})();\n`;
}

function startWorker() {
  const sent = [];
  const ctx = vm.createContext({
    postMessage: (m, transfer) => sent.push(structuredClone(m, { transfer })),
    setTimeout, clearTimeout, performance, Intl, TextDecoder, TextEncoder, TextDecoderStream, TransformStream, DecompressionStream, structuredClone, console,
  });
  ctx.self = ctx;
  vm.runInContext(workerSource(), ctx);
  return { ctx, sent, send: m => ctx.onmessage({ data: structuredClone(m) }) };
}

test('the worker code runs without a page (no document, window or storage)', () => {
  const w = startWorker();
  w.send({ type: 'ping' });
  assert.deepEqual(w.sent, [{ type: 'pong' }]);
});

test('the worker parses files into the store it is given and hands it back', async () => {
  const page = openPage();
  page.g('resetStore()');
  const store = page.g('D');
  const w = startWorker();
  const ufw = new File(['Nov  7 10:00:01 web kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.5 DST=192.0.2.10 LEN=60 PROTO=TCP SPT=1 DPT=22\n'], 'ufw.log', { lastModified: Date.UTC(2026, 10, 7, 12) });
  const eve = new File([JSON.stringify({ timestamp: '2026-11-07T10:00:00.000000+0000', flow_id: 1, event_type: 'alert', src_ip: '198.51.100.9', src_port: 1, dest_ip: '192.0.2.1', dest_port: 3389, proto: 'TCP', alert: { action: 'allowed', signature_id: 1, signature: 'test' } }) + '\n'], 'eve.json');
  await w.ctx.onmessage({ data: { type: 'parse', files: [ufw, eve], load: { tz: 'UTC', chatter: false, blocksOnly: false }, D: structuredClone(page.w.eval('D')) } });
  const done = w.sent.find(m => m.type === 'done');
  assert.ok(done, 'done message');
  assert.equal(done.error, null);
  assert.equal(done.D.n, 2);
  assert.deepEqual(done.D.files.map(f => f.name), ['ufw.log', 'eve.json']);
  // back on the page: revive it and finish as usual
  page.w.__fromWorker = done.D;
  page.g('D = reviveStore(window.__fromWorker); finish()');
  assert.deepEqual(page.errors, []);
  assert.equal(page.g('D.ip.id("203.0.113.5")') > 0, true, 'interned strings work again');
  assert.equal(page.g('D.act.list.join()'), 'BLOCK,IDS ALERT');
  assert.ok(store);
});
