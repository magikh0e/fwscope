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
    '2026-11-07 10:10:07,000 fail2ban.actions        [811]: WARNING [sshd] 203.0.113.7 already banned',
    '2026-11-07 10:10:08,000 fail2ban.filter         [811]: INFO    [sshd] Ignore 192.0.2.1 by ip',
  ].join('\n'));
  assert.deepEqual(rows.map(r => [r.act, r.group, r.src, r.rule]), [
    ['F2B BAN', 0, '203.0.113.5', 'sshd'], ['F2B FOUND', 3, '203.0.113.6', 'nginx-botsearch'],
    ['F2B UNBAN', 2, '203.0.113.5', 'sshd'], ['F2B BAN', 0, '203.0.113.7', 'sshd'], ['F2B REPEAT', 3, '203.0.113.7', 'sshd']]);
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

test('Suricata eve.json: alerts only, signature as the rule, blocked in IPS mode', async () => {
  const eve = (o) => JSON.stringify({ timestamp: '2026-11-07T10:00:00.123456+0000', flow_id: Math.floor(Math.random() * 1e15), in_iface: 'igb0', event_type: 'alert',
    src_ip: '203.0.113.5', src_port: 40000, dest_ip: '192.0.2.1', dest_port: 22, proto: 'TCP',
    alert: { action: 'allowed', gid: 1, signature_id: 2001219, rev: 20, signature: 'ET SCAN Potential SSH Scan', category: 'Attempted Information Leak', severity: 2 }, ...o });
  const { p, rows } = await rowsOf('opnsense-eve.json', [
    eve(),
    eve({ timestamp: '2026-11-07T10:00:01.000000-1000', src_ip: '2001:db8::7', dest_ip: '2001:db8::1', proto: 'IPv6-ICMP', icmp_type: 128, icmp_code: 0, src_port: undefined, dest_port: undefined,
      alert: { action: 'blocked', signature_id: 2100366, signature: 'GPL ICMP_INFO PING *NIX' } }),
    JSON.stringify({ timestamp: '2026-11-07T10:00:02.000000+0000', flow_id: 1, event_type: 'flow', src_ip: '203.0.113.5', dest_ip: '192.0.2.1', proto: 'TCP' }),
    'Nov  7 10:00:03 opnsense suricata[4242]: {"timestamp":"2026-11-07T10:00:03.000000+0000","flow_id":7,"event_type":"alert","src_ip":"198.51.100.9","src_port":5555,"dest_ip":"192.0.2.1","dest_port":3389,"proto":"TCP","alert":{"action":"allowed","signature_id":2023753,"signature":"ET SCAN MS Terminal Server Traffic on Non-standard Port"}}',
  ].join('\n'));
  assert.deepEqual(rows.map(r => [r.act, r.group, r.src, r.dpt, r.rule, r.host]), [
    ['IDS ALERT', 3, '203.0.113.5', 22, 'sid:2001219', 'opnsense-eve'],
    ['IDS DROP', 0, '2001:db8::7', -1, 'sid:2100366', 'opnsense-eve'],
    ['IDS ALERT', 3, '198.51.100.9', 3389, 'sid:2023753', 'opnsense-eve']]);
  assert.equal(rows[0].ts, Date.UTC(2026, 10, 7, 10, 0, 0, 123));
  assert.equal(rows[1].ts, Date.UTC(2026, 10, 7, 20, 0, 1));
  assert.equal(rows[1].proto, 'ICMPv6'); assert.equal(rows[0].iin, 'igb0');
  assert.equal(p.g('ruleName("sid:2001219")'), 'ET SCAN Potential SSH Scan');
  const count = q => p.g(`F.preds = compileQuery(${JSON.stringify(q)}); filterRows(null).length`);
  assert.equal(count('seen:ids'), 3);
  assert.equal(count('rule:sid:2001219'), 1);
});

test('Suricata fast.log', async () => {
  const { rows } = await rowsOf('fast.log', [
    '11/07/2026-10:00:00.123456  [**] [1:2001219:20] ET SCAN Potential SSH Scan [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 203.0.113.5:40000 -> 192.0.2.1:22',
    '11/07/2026-10:00:01.000000  [Drop] [**] [1:2100366:8] GPL ICMP_INFO PING *NIX [**] [Classification: Misc activity] [Priority: 3] {ICMP} 203.0.113.6:8 -> 192.0.2.1:0',
    '11/07/2026-10:00:02.000000  [**] [1:2210000:1] SURICATA STREAM test [**] [Classification: Generic Protocol Command Decode] [Priority: 3] {TCP} [2001:db8::5]:443 -> [2001:db8::1]:51000',
  ].join('\n'));
  assert.deepEqual(rows.map(r => [r.act, r.src, r.spt, r.dst, r.dpt, r.rule, r.host]), [
    ['IDS ALERT', '203.0.113.5', 40000, '192.0.2.1', 22, 'sid:2001219', ''],
    ['IDS DROP', '203.0.113.6', -1, '192.0.2.1', -1, 'sid:2100366', ''],
    ['IDS ALERT', '2001:db8::5', 443, '2001:db8::1', 51000, 'sid:2210000', '']]);
  assert.equal(rows[0].ts, Date.UTC(2026, 10, 7, 10, 0, 0, 123));
});

test('OpenWrt: fw4 and fw3 log prefixes, from logread or remote syslog', async () => {
  const { p, rows } = await rowsOf('logread.txt', [
    'Sat Nov  7 10:00:01 2026 kern.warn kernel: [12345.678901] drop wan in: IN=eth1 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 SRC=203.0.113.5 DST=192.0.2.10 LEN=60 TOS=0x00 PREC=0x00 TTL=50 ID=1 DF PROTO=TCP SPT=40000 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0',
    'Sat Nov  7 10:00:02 2026 kern.warn kernel: [12346.000001] reject lan forward: IN=br-lan OUT=eth1 SRC=192.168.1.20 DST=198.51.100.9 LEN=60 PROTO=TCP SPT=50000 DPT=25',
    'Sat Nov  7 10:00:03 2026 kern.warn kernel: [12347.000001] DROP(src wan)IN=eth0.2 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:08:00 SRC=203.0.113.6 DST=192.0.2.10 LEN=40 PROTO=TCP SPT=4000 DPT=23',
    'Sat Nov  7 10:00:04 2026 kern.warn kernel: [12348.000001] ACCEPT(dest wan)IN=br-lan OUT=eth0.2 SRC=192.168.1.20 DST=198.51.100.10 LEN=40 PROTO=UDP SPT=5000 DPT=53',
    'Sat Nov  7 10:00:05 2026 daemon.info dnsmasq[1]: query[A] example.com from 192.168.1.20',
    'Nov  7 10:00:06 router kernel: [12349.000001] drop wan in: IN=eth1 OUT= SRC=198.51.100.11 DST=192.0.2.10 LEN=60 PROTO=TCP SPT=1 DPT=3389',
  ].join('\n'));
  assert.deepEqual(rows.map(r => [r.act, r.group, r.rule, r.src, r.dpt, r.iin, r.iout, r.host]), [
    ['DROP', 0, 'wan_in', '203.0.113.5', 22, 'eth1', '', 'openwrt'],
    ['REJECT', 0, 'lan_forward', '192.168.1.20', 25, 'br-lan', 'eth1', 'openwrt'],
    ['DROP', 0, 'src_wan', '203.0.113.6', 23, 'eth0.2', '', 'openwrt'],
    ['ACCEPT', 2, 'dest_wan', '192.168.1.20', 53, 'br-lan', 'eth0.2', 'openwrt'],
    ['DROP', 0, 'wan_in', '198.51.100.11', 3389, 'eth1', '', 'router']]);
  assert.equal(rows[0].ts, Date.UTC(2026, 10, 7, 10, 0, 1));
  assert.equal(p.g('D.kinds.openwrt'), 1);
});

test('OpenWrt logread saved under the router\'s name shows that name', async () => {
  const { rows } = await rowsOf('gl-ax1800.log', 'Sat Nov  7 10:00:01 2026 kern.warn kernel: [1.000001] drop wan in: IN=eth1 OUT= SRC=203.0.113.5 DST=192.0.2.10 LEN=60 PROTO=TCP SPT=1 DPT=22');
  assert.equal(rows[0].host, 'gl-ax1800');
});

test('AWS VPC Flow Logs: default format, custom header, CloudWatch export', async () => {
  const { rows } = await rowsOf('vpc.log', [
    'version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status',
    '2 123456789012 eni-0a1b2c3d4e5f60718 203.0.113.5 192.0.2.10 40000 22 6 3 180 1794045600 1794045660 REJECT OK',
    '2 123456789012 eni-0a1b2c3d4e5f60718 198.51.100.7 192.0.2.10 5353 443 6 10 4200 1794045610 1794045670 ACCEPT OK',
    '2 123456789012 eni-0a1b2c3d4e5f60718 - - - - - - - 1794045620 1794045680 - NODATA',
  ].join('\n'));
  assert.deepEqual(rows.map(r => [r.act, r.group, r.src, r.dpt, r.proto, r.iin, r.host]), [
    ['REJECT', 0, '203.0.113.5', 22, 'TCP', 'eni-0a1b2c3d4e5f60718', 'aws 123456789012'],
    ['ACCEPT', 2, '198.51.100.7', 443, 'TCP', 'eni-0a1b2c3d4e5f60718', 'aws 123456789012']]);
  assert.equal(rows[0].ts, 1794045600000);

  const custom = await rowsOf('vpc-custom.log', [
    '${vpc-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${start} ${action} ${flow-direction} ${interface-id}',
    'vpc-0abc 203.0.113.9 192.0.2.10 1 3389 6 1794045600 REJECT ingress eni-1',
    'vpc-0abc 192.0.2.10 198.51.100.9 50000 443 6 1794045601 ACCEPT egress eni-1',
  ].join('\n'));
  assert.deepEqual(custom.rows.map(r => [r.act, r.src, r.dpt, r.host, r.iin, r.iout]), [
    ['REJECT', '203.0.113.9', 3389, 'vpc-0abc', 'eni-1', ''], ['ACCEPT', '192.0.2.10', 443, 'vpc-0abc', '', 'eni-1']]);

  const cw = await rowsOf('cloudwatch.txt', '2026-11-07T10:00:00.000Z 2 123456789012 eni-0a1b2c3d4e5f60718 203.0.113.6 192.0.2.10 1 23 6 1 40 1794045600 1794045660 REJECT OK');
  assert.deepEqual(cw.rows.map(r => [r.act, r.src, r.dpt]), [['REJECT', '203.0.113.6', 23]]);
});

test('Azure NSG and VNet flow logs: begin records and denies, rule names, the NSG as host', async () => {
  const nsg = { records: [{ time: '2026-11-07T10:00:00Z', category: 'NetworkSecurityGroupFlowEvent', macAddress: '000D3AF87856',
    resourceId: '/SUBSCRIPTIONS/00000000-0000-0000-0000-000000000000/RESOURCEGROUPS/RG/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WEB-NSG',
    properties: { Version: 2, flows: [
      { rule: 'DefaultRule_DenyAllInBound', flows: [{ mac: '000D3AF87856', flowTuples: ['1794045600,203.0.113.5,10.0.0.4,40000,22,T,I,D,B,,,,'] }] },
      { rule: 'UserRule_AllowHttps', flows: [{ mac: '000D3AF87856', flowTuples: ['1794045601,198.51.100.7,10.0.0.4,50000,443,T,I,A,B,,,,', '1794045660,198.51.100.7,10.0.0.4,50000,443,T,I,A,E,10,800,8,4000'] }] }] } }] };
  const a = await rowsOf('PT1H.json', JSON.stringify(nsg, null, 2));
  assert.deepEqual(a.rows.map(r => [r.act, r.group, r.rule, r.src, r.dpt, r.host, r.iin]), [
    ['DENY', 0, 'DefaultRule_DenyAllInBound', '203.0.113.5', 22, 'web-nsg', 'inbound'],
    ['ALLOW', 2, 'UserRule_AllowHttps', '198.51.100.7', 443, 'web-nsg', 'inbound']]);
  assert.equal(a.rows[0].ts, 1794045600000);
  assert.equal(a.p.g('ruleName("DefaultRule_DenyAllInBound")'), 'DefaultRule DenyAllInBound');

  const vnet = { records: [{ time: '2026-11-07T10:00:00Z', flowLogVersion: 4, category: 'FlowLogFlowEvent', macAddress: '00224871C205',
    targetResourceID: '/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/prod-vnet',
    flowRecords: { flows: [{ aclID: 'x', flowGroups: [{ rule: 'BlockSSH', flowTuples: ['1794045600599,203.0.113.8,10.0.0.6,40000,22,6,I,D,NX,0,0,0,0', '1794045601000,10.0.0.6,198.51.100.180,23956,443,6,O,B,NX,0,0,0,0'] }] }] } }] };
  const b = await rowsOf('PT1H.json', JSON.stringify(vnet));
  assert.deepEqual(b.rows.map(r => [r.act, r.src, r.dpt, r.host, r.iout]), [['DENY', '203.0.113.8', 22, 'prod-vnet', ''], ['ALLOW', '10.0.0.6', 443, 'prod-vnet', 'outbound']]);
  assert.equal(b.rows[0].ts, 1794045600599);
});
