// The page as a whole: it starts cleanly, the sample renders, and filters, views and block suggestions behave.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openPage } from './helpers.js';

const until = async (cond, ms = 15000) => { const end = Date.now() + ms; while (!cond()) { if (Date.now() > end) throw new Error('timed out'); await new Promise(r => setTimeout(r, 25)); } };

test('the script starts without errors (nothing used before it is defined)', () => {
  const p = openPage();
  assert.deepEqual(p.errors, []);
  for (const f of ['loadText', 'compileQuery', 'filterRows', 'addToken', 'renderAll', 'blockCandidates', 'makeSample'])
    assert.equal(p.g(`typeof ${f}`), 'function', f);
  assert.ok(p.w.document.querySelector('#drop'), 'start screen is there');
});

test('?demo loads the generated sample and every card renders', async () => {
  const p = openPage({ url: 'http://localhost/?demo&tz=UTC' });
  await until(() => p.g('typeof D !== "undefined" && D && D.n > 0 && D.order'));
  await new Promise(r => setTimeout(r, 300));
  assert.deepEqual(p.errors, []);
  assert.deepEqual(p.alerts, []);
  assert.ok(p.g('D.n') > 1000, 'sample has events');
  assert.ok(p.g('D.waf'), 'sample includes WAF events');
  assert.ok(p.g('SEL.length') > 0, 'something is selected');
  const doc = p.w.document;
  assert.equal(doc.querySelector('#empty').hidden, true, 'start screen hidden');
  assert.equal(doc.querySelector('#dash').hidden, false, 'dashboard shown');
  assert.ok(doc.querySelectorAll('#ev tr').length > 10, 'events table has rows');
  assert.ok(doc.querySelectorAll('#blockTable tr').length > 1, 'block suggestions listed');
});

const LINES = [
  'Nov  7 10:00:01 web kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.5 DST=192.0.2.10 LEN=60 PROTO=TCP SPT=40000 DPT=22',
  'Nov  7 10:00:02 web kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.6 DST=192.0.2.10 LEN=60 PROTO=TCP SPT=40001 DPT=23',
  'Nov  7 10:00:03 web kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.7 DST=192.0.2.10 LEN=60 PROTO=UDP SPT=40002 DPT=161',
  'Nov  7 10:00:04 web kernel: [UFW ALLOW] IN=eth0 OUT= SRC=198.51.100.8 DST=192.0.2.10 LEN=60 PROTO=TCP SPT=40003 DPT=443',
  'Nov  7 10:00:05 web kernel: [UFW AUDIT] IN=eth0 OUT= SRC=2001:db8::1 DST=2001:db8::2 LEN=60 PROTO=TCP SPT=40004 DPT=8080',
];

test('filter language', async () => {
  const p = openPage();
  await p.load('ufw.log', LINES.join('\n'));
  const count = q => p.g(`F.preds = compileQuery(${JSON.stringify(q)}); filterRows(null).length`);
  assert.equal(count(''), 5);
  assert.equal(count('dpt:22'), 1);
  assert.equal(count('22'), 1, 'a bare number is a port');
  assert.equal(count('dpt:20-25'), 2, 'port range');
  assert.equal(count('dpt:22,161'), 2, 'port list');
  assert.equal(count('-dpt:22'), 4, 'exclude');
  assert.equal(count('!dpt:22'), 4, 'exclude with !');
  assert.equal(count('src:203.0.113.0/24'), 2, 'CIDR');
  assert.equal(count('203.0.113.0/24'), 2, 'a bare address range');
  assert.equal(count('src:203.0.113.*'), 2, 'wildcard');
  assert.equal(count('src:2001:db8::/32'), 1, 'IPv6 range');
  assert.equal(count('src:2001:db8:0:0::1'), 1, 'IPv6 written the long way matches the short form');
  assert.equal(count('proto:udp'), 1);
  assert.equal(count('act:block'), 3);
  assert.equal(count('act:block dpt:22'), 1, 'terms AND together');
  assert.throws(() => p.g('compileQuery("nosuchfield:1 dpt:abc")'));
});

test('clicking a second value of the same field replaces the first (not AND)', async () => {
  const p = openPage();
  await p.load('ufw.log', LINES.join('\n'));
  p.g('setQuery("src:203.0.113.5 dpt:22")');
  p.g('addToken("src:203.0.113.6", false)');
  assert.equal(p.g('$("#q").value'), 'dpt:22 src:203.0.113.6');
  p.g('addToken("dpt:22", true)');
  p.g('addToken("dpt:23", true)');
  assert.equal(p.g('$("#q").value'), 'src:203.0.113.6 -dpt:22 -dpt:23', 'excludes add up, and replace the same term shown');
});

test('views round-trip through the address', async () => {
  const p = openPage();
  await p.load('ufw.log', LINES.join('\n'));
  p.g('F.q = "dpt:22 -src:198.51.100.0/24"; F.preset = "7d"; F.hideNoise = true; F.sort = "-dpt"; F.cmpWin = "7d"');
  const s = p.g('viewString(false)');
  const v = JSON.parse(p.g(`JSON.stringify(readView(${JSON.stringify(s)}))`));
  assert.equal(v.q, 'dpt:22 -src:198.51.100.0/24');
  assert.equal(v.preset, '7d'); assert.equal(v.hideNoise, true); assert.equal(v.sort, '-dpt'); assert.equal(v.cmpWin, '7d');
  const bad = JSON.parse(p.g('JSON.stringify(readView("#s=x%3Balert(1)&cw=99y&d=nope"))'));
  assert.notEqual(bad.sort, 'x;alert(1)'); assert.notEqual(bad.cmpWin, '99y');
});

// WAF events in detection-only mode: attacks that reached the site
function wafEvents(src, n, { host = '192.0.2.10', path = i => '/wp-admin/x' + i + '.php?f=../../etc/passwd' } = {}) {
  return Array.from({ length: n }, (_, i) => JSON.stringify({ transaction: { client_ip: src, time_stamp: `Sat Nov  7 10:${String(10 + (i % 40)).padStart(2, '0')}:${String(i % 60).padStart(2, '0')} 2026`, client_port: 40000 + i, host_ip: host, host_port: 443, unique_id: src + '-' + i,
    request: { method: 'GET', uri: path(i), headers: { Host: 'example.com', 'User-Agent': 'Mozilla/5.0 zgrab' } }, response: { http_code: 404 },
    messages: [{ message: 'Path Traversal Attack (/../)', details: { ruleId: '930100', severity: '2', tags: ['attack-lfi'] } }, { message: 'OS File Access Attempt', details: { ruleId: '930120', severity: '2', tags: ['attack-lfi'] } }] } }));
}

test('block suggestions: WAF attackers that reached the site, even if the server once talked to them', async () => {
  const p = openPage();
  await p.load('ufw.log', [
    ...LINES,
    // the web server made an outbound connection to the attacker (e.g. a DNS or update lookup): that doesn't make it "your server"
    'Nov  7 09:00:00 web kernel: [UFW ALLOW] IN= OUT=eth0 SRC=192.0.2.10 DST=203.0.113.40 LEN=60 PROTO=TCP SPT=50000 DPT=443',
  ].join('\n'));
  await p.load('modsec_audit.log', [...wafEvents('203.0.113.40', 40), ...wafEvents('198.51.100.44', 1)].join('\n'));
  p.g('SEL = filterRows(null)');
  const list = JSON.parse(p.g('JSON.stringify(blockCandidates().map(x => ({ key: x.key, score: x.score, reached: x.reached })))'));
  const hit = list.find(x => x.key === '203.0.113.40');
  assert.ok(hit, 'the attacker is suggested: ' + JSON.stringify(list));
  assert.equal(hit.reached, 40);
  assert.ok(!list.some(x => x.key === '192.0.2.10'), 'own server never suggested');
  assert.ok(!list.some(x => x.key === '203.0.113.5'), 'firewall-dropped traffic alone is not a reason');
});

test('block suggestions: requests Cloudflare already blocked did not reach the site', async () => {
  const p = openPage();
  const ev = i => JSON.stringify({ Action: 'block', ClientIP: '203.0.113.20', ClientRequestHost: 'example.com', ClientRequestMethod: 'GET', ClientRequestPath: '/.env' + i, Datetime: `2026-11-07T10:00:${String(i).padStart(2, '0')}Z`, RayID: 'ray' + i, RuleID: 'r1', Source: 'firewallCustom' });
  await p.load('cf.json', Array.from({ length: 30 }, (_, i) => ev(i)).join('\n'));
  p.g('SEL = filterRows(null)');
  const list = JSON.parse(p.g('JSON.stringify(blockCandidates().map(x => ({ key: x.key, reached: x.reached })))'));
  const hit = list.find(x => x.key === '203.0.113.20');
  assert.ok(!hit || hit.reached === 0, JSON.stringify(list));
});

test('fail2ban: seen:f2b, caught / missed marks, and fail2ban lines are not firewall traffic', async () => {
  const p = openPage();
  // 120 hits on one port: "hammering" in the Scans card
  const ssh = (src, k) => `Nov  7 1${Math.floor(k / 60)}:${String(k % 60).padStart(2, '0')}:00 web kernel: [UFW LIMIT BLOCK] IN=eth0 OUT= SRC=${src} DST=192.0.2.10 LEN=60 PROTO=TCP SPT=${40000 + k} DPT=22`;
  await p.load('ufw.log', [...Array.from({ length: 120 }, (_, k) => ssh('203.0.113.5', k)), ...Array.from({ length: 120 }, (_, k) => ssh('203.0.113.9', k))].join('\n'));
  await p.load('fail2ban.log', [
    '2026-11-07 10:05:00,000 fail2ban.actions        [811]: NOTICE  [sshd] Ban 203.0.113.5',
    '2026-11-07 10:06:00,000 fail2ban.filter         [811]: INFO    [sshd] Found 198.51.100.77 - 2026-11-07 10:06:00',
  ].join('\n'));
  const count = q => p.g(`F.preds = compileQuery(${JSON.stringify(q)}); filterRows(null).length`);
  assert.equal(count('seen:f2b'), 121, 'every event from the banned source, plus the ban itself');
  assert.equal(p.g('D.ipSeen[D.ip.map.get("198.51.100.77")]'), 0, 'found by fail2ban only: not seen by the firewall');
  p.g('setQuery("dpt:22")'); p.g('F.preset = "all"; apply()');
  const marks = [...p.w.document.querySelectorAll('#scan tr')].map(tr => tr.textContent);
  assert.ok(marks.some(t => t.includes('203.0.113.5') && t.includes('fail2ban banned')), marks.join('\n'));
  assert.ok(marks.some(t => t.includes('203.0.113.9') && t.includes('not banned')), marks.join('\n'));
});

test('a fail2ban filter without a fail2ban log explains itself', async () => {
  const p = openPage();
  await p.load('ufw.log', LINES.join('\n'));
  assert.throws(() => p.g('compileQuery("seen:f2b")'), /fail2ban/);
});

test('the rate-limit chip is named after what is in it', async () => {
  const p = openPage();
  await p.load('cf.json', JSON.stringify({ Action: 'managed_challenge', ClientIP: '203.0.113.20', ClientRequestPath: '/', Datetime: '2026-11-07T10:00:00Z', RayID: 'r', RuleID: 'x', Source: 'bic' }));
  assert.equal(p.g('GROUPS[1].name'), 'CHALLENGE');
  await p.load('ufw.log', 'Nov  7 10:00:01 web kernel: [UFW LIMIT BLOCK] IN=eth0 OUT= SRC=203.0.113.5 DST=192.0.2.10 LEN=60 PROTO=TCP SPT=1 DPT=22');
  assert.equal(p.g('GROUPS[1].name'), 'LIMIT/CHALLENGE');
  assert.match(p.w.document.querySelector('#foot').textContent, /1 events are from Cloudflare's own firewall/);
  assert.doesNotMatch(p.w.document.querySelector('#foot').textContent, /CF-Connecting-IP/);
});

test('the saved report names the tool version and its author', async () => {
  const p = openPage();
  await p.load('ufw.log', LINES.join('\n'));
  p.w.URL.createObjectURL = () => 'blob:x'; p.w.URL.revokeObjectURL = () => {};
  const html = p.g('saveReport()');
  const v = p.g('document.querySelector("meta[name=version]").content');
  assert.match(v, /^\d+\.\d+\.\d+$/);
  assert.ok(html.includes(`<meta name="generator" content="fwscope ${v}">`));
  assert.ok(html.includes(`fwscope ${v} by`) && html.includes('magikh0e'));
});

test('files can be added to what is loaded, one at a time', async () => {
  const p = openPage();
  await p.load('web1.log', LINES.slice(0, 3).join('\n'));
  assert.equal(p.g('$("#btnOpen").textContent'), 'Add logs');
  p.g('BLOCKSEL.add("203.0.113.40")');
  await p.load('web2.log', LINES.slice(2).join('\n')); // one line repeats
  assert.equal(p.g('D.n'), 5);
  assert.equal(p.g('D.files.length'), 2);
  assert.match(p.g('$("#toast").textContent'), /^Added web2\.log: 2 new events, 1 duplicate skipped\. 2 files loaded\./);
  assert.ok(p.g('BLOCKSEL.has("203.0.113.40")'), 'block ticks survive an added file');
  p.g('$("#btnClear").click()');
  assert.equal(p.g('$("#btnOpen").textContent'), 'Open logs');
});

test('pasting real lines replaces the sample instead of mixing with it', async () => {
  const p = openPage({ url: 'http://localhost/?demo&tz=UTC' });
  await until(() => p.g('typeof D !== "undefined" && D && D.n > 0 && D.order'));
  assert.equal(p.g('$("#btnOpen").textContent'), 'Open logs');
  await p.w.loadText('pasted text', LINES.join('\n'));
  assert.equal(p.g('D.n'), 5);
  assert.equal(p.g('$("#toast").hidden'), true, 'a replacement is not an "added" message');
});
