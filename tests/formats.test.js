// Each log format fwscope reads, from small hand-written samples (documentation addresses only).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openPage } from './helpers.js';

async function rowsOf(name, text) {
  const p = openPage();
  await p.load(name, text);
  assert.deepEqual(p.errors, [], 'no script errors');
  const rows = p.rows();
  return { p, rows };
}

test('UFW lines, with the duplicate copy in kern.log skipped', async () => {
  const line = 'Nov  7 10:00:01 web kernel: [ 1234.567890] [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 SRC=203.0.113.5 DST=192.0.2.10 LEN=60 TOS=0x00 PREC=0x00 TTL=50 ID=1 DF PROTO=TCP SPT=40000 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0';
  const p = openPage();
  await p.load('ufw.log', line + '\n' + line.replace('10:00:01', '10:00:02').replace('BLOCK', 'ALLOW').replace('DPT=22', 'DPT=443'));
  await p.load('kern.log', line);
  const rows = p.rows();
  assert.equal(rows.length, 2);
  const [b, a] = rows.sort((x, y) => x.ts - y.ts);
  assert.equal(b.act, 'BLOCK'); assert.equal(b.group, 0);
  assert.equal(b.src, '203.0.113.5'); assert.equal(b.dst, '192.0.2.10');
  assert.equal(b.spt, 40000); assert.equal(b.dpt, 22); assert.equal(b.proto, 'TCP'); assert.equal(b.iin, 'eth0'); assert.equal(b.host, 'web');
  assert.equal(b.ts, Date.UTC(2026, 10, 7, 10, 0, 1)); // ?tz=UTC: zone-less syslog read as UTC
  assert.equal(a.act, 'ALLOW'); assert.equal(a.group, 2);
  assert.equal(p.g('D.dupes'), 1);
});

test('UFW from journalctl -o json', async () => {
  const { rows } = await rowsOf('ufw.json', JSON.stringify({ __REALTIME_TIMESTAMP: '1794045601000000', _HOSTNAME: 'web', MESSAGE: '[UFW LIMIT BLOCK] IN=eth0 OUT= SRC=198.51.100.9 DST=192.0.2.10 LEN=60 PROTO=TCP SPT=1 DPT=22' }));
  assert.equal(rows.length, 1);
  assert.equal(rows[0].act, 'LIMIT BLOCK'); assert.equal(rows[0].group, 1); assert.equal(rows[0].host, 'web');
  assert.equal(rows[0].ts, 1794045601000);
});

test('generic netfilter: nftables / iptables / firewalld prefixes become actions', async () => {
  const { rows } = await rowsOf('kern.log', [
    'Nov  7 10:00:01 gw kernel: [12345.678901] nft-drop: IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 SRC=203.0.113.5 DST=192.0.2.10 LEN=60 TTL=50 PROTO=TCP SPT=40000 DPT=22 SYN URGP=0',
    '2026-11-07T10:00:02.123456+00:00 gw kernel: FINAL_REJECT: IN=eth0 OUT= SRC=198.51.100.7 DST=192.0.2.10 LEN=40 PROTO=UDP SPT=5353 DPT=161 LEN=20',
    'Nov  7 10:00:03 gw kernel: IPTables-Accepted: IN= OUT=eth0 SRC=192.0.2.10 DST=203.0.113.9 LEN=40 PROTO=TCP SPT=5000 DPT=443',
    'Nov  7 10:00:04 gw kernel: [  99.000001] IN=eth0 OUT= SRC=2001:db8::1 DST=2001:db8::2 LEN=80 PROTO=ICMPv6 TYPE=128 CODE=0',
  ].join('\n'));
  assert.deepEqual(rows.map(r => [r.act, r.group]), [['NFT-DROP', 0], ['FINAL REJECT', 0], ['IPTABLES-ACCEPTED', 2], ['LOG', 3]]);
  assert.equal(rows[0].dpt, 22); assert.equal(rows[0].host, 'gw');
  assert.equal(rows[1].ts, Date.UTC(2026, 10, 7, 10, 0, 2, 123));
  assert.equal(rows[2].iout, 'eth0');
  assert.equal(rows[3].src, '2001:db8::1');
});

test('fail2ban log: ban, found and unban per jail', async () => {
  const { p, rows } = await rowsOf('fail2ban.log', [
    '2026-11-07 10:00:04,123 fail2ban.actions        [811]: NOTICE  [sshd] Ban 203.0.113.5',
    '2026-11-07 10:00:05,001 fail2ban.filter         [811]: INFO    [nginx-botsearch] Found 203.0.113.6 - 2026-11-07 10:00:05',
    '2026-11-07 10:10:04,123 fail2ban.actions        [811]: NOTICE  [sshd] Unban 203.0.113.5',
    '2026-11-07 10:10:05,000 fail2ban.actions        [811]: NOTICE  [sshd] Restore Ban 203.0.113.7',
    '2026-11-07 10:10:06,000 fail2ban.server         [811]: INFO    Starting Fail2ban v1.1.0',
  ].join('\n'));
  assert.deepEqual(rows.map(r => [r.act, r.group, r.src, r.rule]), [
    ['F2B BAN', 0, '203.0.113.5', 'sshd'], ['F2B FOUND', 3, '203.0.113.6', 'nginx-botsearch'],
    ['F2B UNBAN', 2, '203.0.113.5', 'sshd'], ['F2B BAN', 0, '203.0.113.7', 'sshd']]);
  assert.equal(rows[0].ts, Date.UTC(2026, 10, 7, 10, 0, 4, 123));
  assert.equal(p.g('D.kinds.f2b'), 1);
});

test('OPNsense filterlog CSV', async () => {
  const { rows } = await rowsOf('filter_20261107.log', [
    '<134>1 2026-11-07T10:00:00-10:00 opnsense.localdomain filterlog 123 - [meta sequenceId="1"] 12,,,02f4bab031b57d1e30553ce08e0ec131,vtnet0,match,block,in,4,0x0,,64,1234,0,DF,6,tcp,60,203.0.113.60,192.0.2.1,40000,22,0,S,123,,64240,,mss',
    '2026-11-07T10:00:01-10:00 opnsense filterlog[99]: 5,,,abc,vtnet1,match,pass,out,6,0x00,0x00000,64,udp,17,40,2001:db8::10,2001:db8::53,5353,53,40',
  ].join('\n'));
  assert.equal(rows.length, 2);
  assert.equal(rows[0].act, 'BLOCK'); assert.equal(rows[0].src, '203.0.113.60'); assert.equal(rows[0].dpt, 22); assert.equal(rows[0].proto, 'TCP');
  assert.equal(rows[0].ts, Date.UTC(2026, 10, 7, 20, 0, 0));
  assert.equal(rows[1].act, 'PASS'); assert.equal(rows[1].group, 2); assert.equal(rows[1].dst, '2001:db8::53'); assert.equal(rows[1].iout, 'vtnet1');
});

test('Windows Firewall pfirewall.log', async () => {
  const { rows } = await rowsOf('office-pc.log', [
    '#Version: 1.5', '#Software: Microsoft Windows Firewall', '#Time Format: Local',
    '#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid',
    '2026-11-07 10:00:00 DROP TCP 203.0.113.70 192.0.2.20 50000 3389 52 S 1 0 64240 - - - RECEIVE 4',
    '2026-11-07 10:00:01 ALLOW UDP 192.0.2.20 198.51.100.53 5000 53 0 - - - - - - - SEND 4',
  ].join('\n'));
  assert.deepEqual(rows.map(r => [r.act, r.group, r.dpt, r.host]), [['DROP', 0, 3389, 'office-pc'], ['ALLOW', 2, 53, 'office-pc']]);
  assert.equal(rows[0].ts, Date.UTC(2026, 10, 7, 10, 0, 0));
});

const v3 = (o = {}) => JSON.stringify({ transaction: { client_ip: '203.0.113.40', time_stamp: 'Sat Nov  7 10:00:00 2026', client_port: 5555, host_ip: '192.0.2.10', host_port: 443, unique_id: 'u' + Math.random(),
  request: { method: 'GET', uri: "/?id=1'or'1", headers: { Host: 'example.com', 'User-Agent': 'sqlmap/1.8' } }, response: { http_code: 403 },
  messages: [{ message: 'SQL Injection Attack Detected via libinjection', details: { ruleId: '942100', severity: '2', tags: ['attack-sqli'] } }], intervention: { status: 403 }, ...o } });

test('ModSecurity v3 JSON audit log', async () => {
  const { p, rows } = await rowsOf('modsec_audit.log', v3());
  assert.equal(rows.length, 1);
  assert.equal(rows[0].act, 'WAF BLOCK'); assert.equal(rows[0].proto, 'HTTP'); assert.equal(rows[0].src, '203.0.113.40'); assert.equal(rows[0].dpt, 443);
  assert.equal(p.g('D.wcatOf.get("942100")'), 'SQLi');
  assert.equal(p.g('D.uri.list[D.c.uri[0]]'), "/?id=1'or'1");
});

test('mod_security2 JSON behind Cloudflare: CF-Connecting-IP trusted only from Cloudflare, and the "--1000" zone', async () => {
  const ev = (remote, id) => JSON.stringify({
    transaction: { time: '07/Nov/2026:10:00:00.123456 --1000', transaction_id: id, remote_address: remote, remote_port: 1234, local_address: '192.0.2.10', local_port: 443 },
    request: { request_line: 'GET /wp-login.php HTTP/1.1', headers: { Host: 'example.com', 'CF-Connecting-IP': '203.0.113.50', 'User-Agent': 'Mozilla/5.0' } },
    response: { status: 200 },
    audit_data: { messages: ['Warning. Matched phrase "wp-login" at REQUEST_FILENAME. [file "x.conf"] [line "1"] [id "930130"] [msg "Restricted File Access Attempt"] [severity "CRITICAL"] [tag "attack-lfi"]'] } });
  const { p, rows } = await rowsOf('modsec_audit.log', ev('173.245.48.5', 't1') + '\n' + ev('198.51.100.66', 't2'));
  assert.equal(rows.length, 2);
  const [viaCf, spoofed] = rows;
  assert.equal(viaCf.src, '203.0.113.50', 'unwrapped: the connection came from a Cloudflare range');
  assert.equal(spoofed.src, '198.51.100.66', 'not unwrapped: anyone can send the header');
  assert.deepEqual([...Object.values(JSON.parse(p.g('JSON.stringify(D.c.via.slice(0, 2))')))], [1, 0]);
  assert.equal(viaCf.ts, Date.UTC(2026, 10, 7, 20, 0, 0, 123), 'a zone written as --1000 is UTC-10');
  assert.equal(viaCf.act, 'WAF DETECT');
});

test('ModSecurity native audit log, behind a LAN proxy (X-Forwarded-For)', async () => {
  const { rows } = await rowsOf('modsec_audit.log', [
    '--a1b2c3d4-A--', '[07/Nov/2026:10:00:00.000000 +0000] YxAbC 192.168.1.5 50000 192.0.2.10 80',
    '--a1b2c3d4-B--', 'GET /cgi-bin/.%2e/.%2e/bin/sh HTTP/1.1', 'Host: example.com', 'X-Forwarded-For: 203.0.113.80, 192.168.1.5', 'User-Agent: zgrab/0.x',
    '--a1b2c3d4-F--', 'HTTP/1.1 403 Forbidden',
    '--a1b2c3d4-H--', 'Message: Access denied with code 403 (phase 2). [id "930100"] [msg "Path Traversal Attack (/../)"] [severity "CRITICAL"] [tag "attack-lfi"]',
    'Action: Intercepted (phase 2)',
    '--a1b2c3d4-Z--', '',
  ].join('\n'));
  assert.equal(rows.length, 1);
  assert.equal(rows[0].src, '203.0.113.80');
  assert.equal(rows[0].act, 'WAF BLOCK');
  assert.equal(rows[0].ts, Date.UTC(2026, 10, 7, 10, 0, 0));
});

test('Apache and nginx error logs: ModSecurity lines grouped per request, "[" start is not JSON', async () => {
  const { rows } = await rowsOf('error.log', [
    '[Sat Nov 07 10:00:00.123456 2026] [security2:error] [pid 1] [client 203.0.113.90:51000] [client 203.0.113.90] ModSecurity: Warning. Pattern match [id "920350"] [msg "Host header is a numeric IP address"] [severity "WARNING"] [tag "attack-protocol"] [hostname "192.0.2.10"] [uri "/"] [unique_id "AAA"]',
    '[Sat Nov 07 10:00:00.123456 2026] [security2:error] [pid 1] [client 203.0.113.90:51000] [client 203.0.113.90] ModSecurity: Warning. Pattern match [id "913100"] [msg "Found User-Agent associated with security scanner"] [severity "CRITICAL"] [tag "attack-reputation-scanner"] [hostname "192.0.2.10"] [uri "/"] [unique_id "AAA"]',
    '2026/11/07 10:00:01 [error] 10#10: *1 [client 198.51.100.91] ModSecurity: Access denied with code 403 (phase 2). [id "941100"] [msg "XSS Attack Detected"] [severity "2"] [unique_id "BBB"], client: 198.51.100.91, server: example.com, request: "GET /?q=<script> HTTP/1.1", host: "example.com"',
  ].join('\n'));
  assert.equal(rows.length, 2, 'two requests');
  assert.equal(rows[0].src, '203.0.113.90'); assert.equal(rows[0].spt, 51000); assert.equal(rows[0].act, 'WAF DETECT');
  assert.equal(rows[1].src, '198.51.100.91'); assert.equal(rows[1].act, 'WAF BLOCK');
});

test('Cloudflare firewall events: Logpush NDJSON', async () => {
  const { p, rows } = await rowsOf('cf-logpush.json', [
    { Action: 'block', ClientIP: '203.0.113.20', ClientRequestHost: 'example.com', ClientRequestMethod: 'GET', ClientRequestPath: '/wp-login.php', ClientRequestQuery: '', Datetime: '2026-11-07T10:00:00Z', RayID: 'ray1', RuleID: 'efb7b8c949ac4650a09736fc376e9aee', Source: 'firewallManaged', Description: 'WordPress login', EdgeResponseStatus: 403, ClientRequestUserAgent: 'curl/8' },
    { Action: 'managed_challenge', ClientIP: '198.51.100.30', ClientRequestHost: 'example.com', ClientRequestMethod: 'POST', ClientRequestPath: '/xmlrpc.php', ClientRequestQuery: '?a=1', Datetime: '2026-11-07T10:01:00Z', RayID: 'ray2', RuleID: 'r2', Source: 'firewallCustom', EdgeResponseStatus: 403 },
    { Action: 'log', ClientIP: '2001:db8::5', ClientRequestHost: 'example.com', ClientRequestMethod: 'GET', ClientRequestPath: '/', Datetime: '2026-11-07T10:02:00Z', RayID: 'ray3', RuleID: 'r3', Source: 'rateLimit' },
    { Action: 'skip', ClientIP: '192.0.2.99', ClientRequestHost: 'example.com', ClientRequestMethod: 'GET', ClientRequestPath: '/api', Datetime: '2026-11-07T10:03:00Z', RayID: 'ray4', RuleID: 'r4', Source: 'firewallCustom' },
  ].map(o => JSON.stringify(o)).join('\n'));
  assert.deepEqual(rows.map(r => [r.act, r.group, r.host]), [['WAF BLOCK', 0, 'cloudflare'], ['WAF CHALLENGE', 1, 'cloudflare'], ['WAF DETECT', 3, 'cloudflare'], ['WAF ALLOW', 2, 'cloudflare']]);
  assert.equal(rows[0].ts, Date.UTC(2026, 10, 7, 10, 0, 0));
  assert.equal(p.g('D.wmsg.get("efb7b8c949ac4650a09736fc376e9aee")'), 'WordPress login');
  assert.equal(p.g('D.wcatOf.get("r3")'), 'CF rate limiting');
  assert.equal(p.g('D.uri.list[D.c.uri[1]]'), '/xmlrpc.php?a=1');
  assert.equal(p.g('D.c.score[0]'), -1, 'no made-up anomaly score');
  assert.equal(p.g('blockDefaultFmt()'), 'cloudflare');
});

test('Cloudflare firewall events: GraphQL response, and its errors', async () => {
  const body = { data: { viewer: { zones: [{ firewallEventsAdaptive: [
    { action: 'block', clientIP: '203.0.113.21', clientRequestHTTPHost: 'example.com', clientRequestHTTPMethodName: 'GET', clientRequestPath: '/.env', clientRequestQuery: '', datetime: '2026-11-07T11:00:00Z', rayName: 'r1', ruleId: 'x1', source: 'firewallCustom', userAgent: 'zgrab', edgeResponseStatus: 403 },
    { action: 'jschallenge', clientIP: '203.0.113.22', clientRequestHTTPHost: 'example.com', clientRequestHTTPMethodName: 'GET', clientRequestPath: '/', clientRequestQuery: '', datetime: '2026-11-07T11:01:00Z', rayName: 'r2', ruleId: '', source: 'bic' }] }] } }, errors: null };
  const { rows } = await rowsOf('cf-events.json', JSON.stringify(body, null, 2));
  assert.deepEqual(rows.map(r => [r.act, r.src]), [['WAF BLOCK', '203.0.113.21'], ['WAF CHALLENGE', '203.0.113.22']]);
  const p = openPage();
  await p.load('cf-events.json', JSON.stringify({ data: null, errors: [{ message: 'zone not found' }] }));
  assert.ok(p.alerts.some(a => a.includes('zone not found')), 'the API error is shown');
});
