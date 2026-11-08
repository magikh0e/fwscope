#!/usr/bin/env python3
# fwscope-pull: gather firewall, WAF and IDS logs for fwscope onto this computer.
# Copyright (C) 2026 magikh0e
# SPDX-License-Identifier: GPL-3.0-or-later
"""Gather logs for fwscope onto the computer you run fwscope on.

It only reads. Remote machines (servers, OPNsense / pfSense, OpenWrt) are reached over SSH with the ssh
client your system already has, so nothing is installed on them and they don't need Python. Cloud logs
come from Cloudflare's API, or through the aws / az tools. Everything lands in one folder: drop that
folder on fwscope.

Examples:
  python3 fwscope-pull.py local --days 7
  python3 fwscope-pull.py ssh admin@web1 --sudo
  python3 fwscope-pull.py opnsense root@192.168.1.1 --days 2
  python3 fwscope-pull.py openwrt root@192.168.1.1
  CF_API_TOKEN=... python3 fwscope-pull.py cloudflare --zone ZONE_ID --since 2026-11-01
  python3 fwscope-pull.py aws --bucket my-flow-logs --account 123456789012 --region us-east-1
  python3 fwscope-pull.py azure --storage-account myflowlogs
  python3 fwscope-pull.py gui            (a page in your browser instead of the command line)
"""
import argparse
import datetime as dt
import getpass
import glob
import gzip
import hmac
import http.server
import json
import os
import platform
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

VERSION = '1.0.0'
CREDIT = f'fwscope-pull {VERSION} by magikh0e - https://github.com/magikh0e/fwscope - GPL-3.0-or-later'
DAY = 86400

# ---------------------------------------------------------------------------------------------- helpers

def safe(name):
    """A file-name-safe version of a host or label."""
    return re.sub(r'[^A-Za-z0-9._-]+', '_', name).strip('._') or 'host'


def host_of(target):
    """'root@192.168.1.1' -> '192.168.1.1'; refuse anything ssh would read as an option."""
    if not target or target.startswith('-') or any(c in target for c in ' \t\n;|&$`'):
        raise SystemExit(f'not a usable ssh target: {target!r}')
    return target.split('@', 1)[-1]


def out_dir(args, label):
    d = args.out or os.path.join('fwscope-logs', f'{safe(label)}-{dt.datetime.now():%Y%m%d-%H%M}')
    os.makedirs(d, exist_ok=True)
    return d


class Report:
    """What was collected and what was skipped, printed at the end."""
    def __init__(self):
        self.files, self.notes = [], []

    def add(self, path):
        if os.path.exists(path) and os.path.getsize(path) > 0:
            self.files.append(path)
        elif os.path.exists(path):
            os.remove(path)

    def note(self, text):
        self.notes.append(text)

    def show(self, folder):
        total = sum(os.path.getsize(f) for f in self.files)
        for f in self.files:
            print(f'  {os.path.relpath(f, folder):<48} {os.path.getsize(f) / 1e6:9.1f} MB')
        for n in self.notes:
            print(f'  note: {n}')
        if self.files:
            print(f'\n{len(self.files)} file(s), {total / 1e6:.1f} MB in {os.path.abspath(folder)}')
            print('Open fwscope and drop that folder on it (or use Open logs > Open a folder).')
        else:
            print('\nNothing collected.')
        return 0 if self.files else 1


def ssh_cmd(args, target, remote, tty=False):
    batch = 'yes' if os.environ.get('FWSCOPE_BATCH') else 'no'  # set by the gui, which can't answer ssh prompts
    cmd = ['ssh', '-o', f'BatchMode={batch}', '-o', 'ConnectTimeout=15']
    if getattr(args, 'port', None):
        cmd += ['-p', str(args.port)]
    if getattr(args, 'identity', None):
        # only this key: otherwise ssh offers every key it knows first, and servers cut that off after a few tries
        cmd += ['-i', os.path.expanduser(args.identity), '-o', 'IdentitiesOnly=yes']
    if tty:
        cmd.append('-t')
    return cmd + [target, remote]


def run_ssh(args, target, remote, dest, password=None):
    """Run a remote command and write its output to dest. Returns the exit code."""
    if not shutil.which('ssh'):
        raise SystemExit('ssh was not found. On Windows: Settings > System > Optional features > OpenSSH Client.')
    # say what's happening as it happens: big logs can take a while, and the helper page shows these lines live
    name = os.path.basename(dest)
    if name.startswith('.'):
        print(f'  asking {host_of(target)} what it has ...', flush=True)
    else:
        print(f'  fetching {name} ...', flush=True)
    t0 = time.time()
    with open(dest, 'wb') as fh:
        p = subprocess.Popen(ssh_cmd(args, target, remote), stdin=subprocess.PIPE, stdout=fh, stderr=subprocess.PIPE)
        _, err = p.communicate((password + '\n').encode() if password is not None else None)
    if not name.startswith('.'):
        print(f'    {os.path.getsize(dest) / 1e6:.1f} MB in {time.time() - t0:.0f} s', flush=True)
    msg = err.decode(errors='replace').strip()
    if p.returncode and msg:
        print(f'  ssh: {msg.splitlines()[-1]}', file=sys.stderr)
        if os.environ.get('FWSCOPE_BATCH') and re.search(r'Permission denied|Host key verification|passphrase', msg):
            print('  (the helper page needs SSH key login, and the host already known: connect once with ssh in a terminal first)', file=sys.stderr)
    return p.returncode


def sudo_password(args):
    """Asked once per run when --sudo is given. It is sent to sudo on stdin, never on a command line."""
    if not getattr(args, 'sudo', False):
        return None
    pw = os.environ.get('FWSCOPE_SUDO_PASSWORD')
    return pw if pw is not None else getpass.getpass('sudo password on the remote machine (Enter if none needed): ')


def wrap(args, script):
    """A remote shell script, run through sudo when asked."""
    inner = 'sh -c ' + shlex.quote(script)
    return "sudo -S -p '' " + inner if getattr(args, 'sudo', False) else inner


# ---------------------------------------------------------------------------------------------- what to look for
# Linux log files fwscope reads. Globs include rotated copies (.1, .2.gz ...). Error logs are filtered down to
# their ModSecurity lines, so a big web server's error log doesn't come along whole.
LINUX_FILES = [
    '/var/log/ufw.log*', '/var/log/kern.log*', '/var/log/messages*', '/var/log/firewalld*',
    '/var/log/fail2ban.log*',
    '/var/log/suricata/eve.json*', '/var/log/suricata/fast.log*',
    '/var/log/modsec_audit.log*', '/var/log/apache2/modsec_audit.log*', '/var/log/httpd/modsec_audit.log*',
    '/var/log/nginx/modsec_audit.log*', '/var/log/modsecurity/*audit*.log*',
]
LINUX_ERROR_LOGS = ['/var/log/apache2/*error*.log*', '/var/log/httpd/*error_log*', '/var/log/nginx/error.log*']


def recent(paths, days, now=None):
    """Files changed in the last `days` days (rotated logs older than that are skipped)."""
    cut = (now or time.time()) - days * DAY
    return sorted(p for p in paths if os.path.isfile(p) and os.path.getmtime(p) >= cut)


def find_linux_logs(days, root='/'):
    """Matching log files under root (root is only changed by the tests)."""
    rel = lambda g: os.path.join(root, g.lstrip('/'))
    files = recent({f for g in LINUX_FILES for f in glob.glob(rel(g))}, days)
    errors = recent({f for g in LINUX_ERROR_LOGS for f in glob.glob(rel(g))}, days)
    # syslog only when nothing better holds the kernel lines (UFW writes the same line to ufw.log, kern.log and syslog)
    if not any(re.match(r'(ufw|kern)\.log', os.path.basename(f)) for f in files):
        files += recent(glob.glob(rel('/var/log/syslog*')), days)
    return files, errors


def open_any(path):
    return gzip.open(path, 'rb') if path.endswith('.gz') else open(path, 'rb')


# ---------------------------------------------------------------------------------------------- local

def cmd_local(args):
    host = safe(platform.node() or 'localhost')
    folder, rep = out_dir(args, host), Report()
    if os.name == 'nt':
        return local_windows(args, host, folder, rep)
    if sys.platform == 'darwin':
        rep.note('macOS pf logs are binary (pflog) captures, which fwscope does not read. Use the ssh command for your servers instead.')
        return rep.show(folder)
    files, errors = find_linux_logs(args.days)
    denied = 0
    for f in files:
        dest = os.path.join(folder, f'{host}-{os.path.basename(f)}')
        try:
            shutil.copy2(f, dest); rep.add(dest)
        except PermissionError:
            denied += 1
    if errors:
        dest = os.path.join(folder, f'{host}-modsecurity-errors.log')
        with open(dest, 'wb') as out:
            for f in errors:
                try:
                    with open_any(f) as fh:
                        for line in fh:
                            if b'ModSecurity: ' in line:
                                out.write(line)
                except PermissionError:
                    denied += 1
        rep.add(dest)
    if not any(re.search(r'(ufw|kern|messages|syslog)', f) for f in files) and shutil.which('journalctl'):
        dest = os.path.join(folder, f'{host}-kernel-journal.log')
        with open(dest, 'wb') as fh:
            subprocess.run(['journalctl', '-k', '-g', 'SRC=', '-o', 'short-iso', '--since', f'-{args.days}d', '--no-pager'], stdout=fh, stderr=subprocess.DEVNULL)
        rep.add(dest)
    if denied:
        rep.note(f'{denied} file(s) need root to read: run it again with sudo.')
    return rep.show(folder)


def local_windows(args, host, folder, rep):
    fw = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'LogFiles', 'Firewall')
    try:
        os.listdir(fw)
    except PermissionError:
        rep.note('the firewall log folder needs an administrator prompt: open one (Run as administrator) and run this again.')
        return rep.show(folder)
    except FileNotFoundError:
        pass
    for f in recent(glob.glob(os.path.join(fw, 'pfirewall.log*')), args.days):
        dest = os.path.join(folder, f'{host}-{os.path.basename(f)}')
        try:
            shutil.copy2(f, dest); rep.add(dest)
        except PermissionError:
            rep.note('the firewall log needs an administrator prompt: run it again as administrator.')
            break
    else:
        if not rep.files:
            rep.note('no pfirewall.log yet. Turn logging on (admin PowerShell): Set-NetFirewallProfile -All -LogBlocked True')
    if args.programs:
        dest = os.path.join(folder, f'{host}-wfp.json')
        ps = ("$s=(Get-Date).AddDays(-%d); Get-WinEvent -FilterHashtable @{LogName='Security';Id=5152,5156,5157;StartTime=$s} -ErrorAction SilentlyContinue | "
              "% { $x=[xml]$_.ToXml(); $d=[ordered]@{EventID=$_.Id;TimeCreated=$_.TimeCreated.ToUniversalTime().ToString('o');Computer=$_.MachineName}; "
              "$x.Event.EventData.Data | % { $d[$_.Name]=$_.'#text' }; $d | ConvertTo-Json -Compress }").replace('-%d)', f'-{args.days})')
        with open(dest, 'wb') as fh:
            subprocess.run(['powershell', '-NoProfile', '-Command', ps], stdout=fh, stderr=subprocess.DEVNULL)
        rep.add(dest)
        if not os.path.exists(dest):
            rep.note('no Security-log firewall events: auditing may be off (auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable).')
    return rep.show(folder)


# ---------------------------------------------------------------------------------------------- remote Linux

def remote_find_script(days):
    """A POSIX sh script that prints matching log files, one per line (no Python needed on the server)."""
    pats = ' '.join(LINUX_FILES)
    errs = ' '.join(LINUX_ERROR_LOGS)
    return (
        f'for f in {pats}; do [ -f "$f" ] && find "$f" -mtime -{days} -print; done; '
        f'if ! ls /var/log/ufw.log /var/log/kern.log >/dev/null 2>&1; then for f in /var/log/syslog*; do [ -f "$f" ] && find "$f" -mtime -{days} -print; done; fi; '
        f'for f in {errs}; do [ -f "$f" ] && find "$f" -mtime -{days} -print | sed "s/^/ERR /"; done'
    )


def cmd_ssh(args):
    host = host_of(args.target)
    folder, rep = out_dir(args, host), Report()
    listing = os.path.join(folder, '.list')
    pw = sudo_password(args)
    run_ssh(args, args.target, wrap(args, remote_find_script(args.days)), listing, pw)
    with open(listing, encoding='utf-8', errors='replace') as fh:
        lines = [l.strip() for l in fh if l.strip()]
    os.remove(listing)
    files = [l for l in lines if not l.startswith('ERR ')]
    errors = [l[4:] for l in lines if l.startswith('ERR ')]
    for f in files:
        dest = os.path.join(folder, f'{safe(host)}-{os.path.basename(f)}')
        run_ssh(args, args.target, wrap(args, 'cat ' + shlex.quote(f)), dest, pw)
        rep.add(dest)
    if errors:
        dest = os.path.join(folder, f'{safe(host)}-modsecurity-errors.log')
        quoted = ' '.join(shlex.quote(f) for f in errors)
        run_ssh(args, args.target, wrap(args, f'for f in {quoted}; do case "$f" in *.gz) gzip -dc "$f";; *) cat "$f";; esac; done | grep -F "ModSecurity: "'), dest, pw)
        rep.add(dest)
    if not any(re.search(r'(ufw|kern|messages|syslog)', f) for f in files):
        dest = os.path.join(folder, f'{safe(host)}-kernel-journal.log')
        run_ssh(args, args.target, wrap(args, f"command -v journalctl >/dev/null && journalctl -k -g 'SRC=' -o short-iso --since '-{args.days}d' --no-pager"), dest, pw)
        rep.add(dest)
    if not lines:
        rep.note('no log files found, or no permission to list them: try --sudo, or connect as root.')
    return rep.show(folder)


# ---------------------------------------------------------------------------------------------- OPNsense / pfSense

def cmd_opnsense(args):
    host = host_of(args.target)
    folder, rep = out_dir(args, host), Report()
    # OPNsense: /var/log/filter/filter_YYYYMMDD.log (+ latest.log); pfSense: /var/log/filter.log (+ rotated .bz2/.gz)
    listing = os.path.join(folder, '.list')
    find = f"find /var/log/filter /var/log -maxdepth 1 -name 'filter*' -type f -mtime -{args.days} 2>/dev/null; "
    if args.suricata:
        find += f"find /var/log/suricata -maxdepth 1 -name 'eve.json*' -type f -mtime -{args.days} 2>/dev/null; "
    run_ssh(args, args.target, find + 'true', listing)
    with open(listing, encoding='utf-8', errors='replace') as fh:
        files = sorted({l.strip() for l in fh if l.strip()})
    os.remove(listing)
    for f in files:
        base = os.path.basename(f)
        if base.endswith('.bz2'):
            dest = os.path.join(folder, f'{safe(host)}-{base[:-4]}')
            run_ssh(args, args.target, 'bzip2 -dc ' + shlex.quote(f), dest)
        else:
            dest = os.path.join(folder, f'{safe(host)}-{base}')
            run_ssh(args, args.target, 'cat ' + shlex.quote(f), dest)
        rep.add(dest)
    if not files:
        rep.note('no filter logs in the last days: check that rules have their Log box ticked, and that SSH login works.')
    return rep.show(folder)


# ---------------------------------------------------------------------------------------------- OpenWrt

def cmd_openwrt(args):
    host = host_of(args.target)
    folder, rep = out_dir(args, host), Report()
    name_file = os.path.join(folder, '.name')
    run_ssh(args, args.target, 'uci -q get system.@system[0].hostname || cat /proc/sys/kernel/hostname', name_file)
    with open(name_file, encoding='utf-8', errors='replace') as fh:
        name = safe(fh.read().strip() or host)
    os.remove(name_file)
    # OpenWrt's dropbear has no sftp, so everything is streamed over plain ssh rather than scp
    dest = os.path.join(folder, f'{name}.log')
    run_ssh(args, args.target, 'logread', dest)
    rep.add(dest)
    logfile = os.path.join(folder, '.logfile')
    run_ssh(args, args.target, 'uci -q get system.@system[0].log_file', logfile)
    with open(logfile, encoding='utf-8', errors='replace') as fh:
        lf = fh.read().strip()
    os.remove(logfile)
    if lf:
        dest2 = os.path.join(folder, f'{name}-{os.path.basename(lf)}')
        run_ssh(args, args.target, 'cat ' + shlex.quote(lf), dest2)
        rep.add(dest2)
    rep.note('logread holds only a small buffer. For history, send the log to a syslog server and pull it from there.')
    return rep.show(folder)


# ---------------------------------------------------------------------------------------------- Cloudflare

CF_FIELDS = ('action source ruleId description clientIP clientRequestHTTPHost clientRequestHTTPMethodName '
             'clientRequestPath clientRequestQuery userAgent edgeResponseStatus datetime rayName')
CF_QUERY = ('query($zone: String!, $since: Time!, $until: Time!, $limit: Int!) { viewer { zones(filter: {zoneTag: $zone}) { '
            'firewallEventsAdaptive(limit: $limit, orderBy: [datetime_ASC], filter: {datetime_geq: $since, datetime_lt: $until}) { '
            + CF_FIELDS + ' } } } }')
CF_URL = 'https://api.cloudflare.com/client/v4/graphql'


def iso(t):
    return t.strftime('%Y-%m-%dT%H:%M:%SZ')


def cf_post(token, variables, opener=urllib.request.urlopen, tries=5):
    body = json.dumps({'query': CF_QUERY, 'variables': variables}).encode()
    for n in range(tries):
        req = urllib.request.Request(CF_URL, data=body, headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json',
                                                                  'User-Agent': f'fwscope-pull/{VERSION}'})
        try:
            with opener(req, timeout=60) as r:
                res = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and n < tries - 1:
                time.sleep(2 ** n); continue
            raise SystemExit(f'Cloudflare API: HTTP {e.code}')
        if res.get('errors'):
            raise SystemExit('Cloudflare API: ' + '; '.join(e.get('message', '?') for e in res['errors']))
        zones = ((res.get('data') or {}).get('viewer') or {}).get('zones') or []
        if not zones:
            raise SystemExit('Cloudflare API: no such zone, or the token cannot read it')
        return zones[0].get('firewallEventsAdaptive') or []
    return []


def cf_pull(token, zone, since, until, write, window=dt.timedelta(hours=24), limit=10000, opener=urllib.request.urlopen):
    """All events from since to until. The API returns at most `limit` per request, so each window is walked forward
    from the last event's time; events at that same second come back again and are skipped by ray ID."""
    count, start = 0, since
    while start < until:
        end = min(start + window, until)
        cur, seen = start, set()
        while True:
            rows = cf_post(token, {'zone': zone, 'since': iso(cur), 'until': iso(end), 'limit': limit}, opener)
            fresh = [r for r in rows if (r.get('rayName'), r.get('ruleId'), r.get('datetime')) not in seen]
            for r in fresh:
                write(r)
            count += len(fresh)
            if len(rows) < limit or not fresh:
                break
            last = rows[-1]['datetime']
            seen = {(r.get('rayName'), r.get('ruleId'), r.get('datetime')) for r in rows if r.get('datetime') == last}
            cur = dt.datetime.strptime(last[:19], '%Y-%m-%dT%H:%M:%S')
        start = end
    return count


def cmd_cloudflare(args):
    token = os.environ.get(args.token_env)
    if not token:
        raise SystemExit(f'set your API token in the {args.token_env} environment variable (it needs Analytics read access for the zone)')
    since = dt.datetime.strptime(args.since, '%Y-%m-%d') if args.since else dt.datetime.utcnow() - dt.timedelta(days=args.days)
    until = dt.datetime.strptime(args.until, '%Y-%m-%d') if args.until else dt.datetime.utcnow()
    folder, rep = out_dir(args, 'cloudflare-' + args.zone[:8]), Report()
    dest = os.path.join(folder, f'cloudflare-{safe(args.name or args.zone[:8])}.json')
    with open(dest, 'w', encoding='utf-8') as fh:
        n = cf_pull(token, args.zone, since, until, lambda r: fh.write(json.dumps(r, separators=(',', ':')) + '\n'),
                    window=dt.timedelta(hours=args.window))
    rep.add(dest)
    print(f'{n:,} events from {iso(since)} to {iso(until)}')
    rep.note('how far back the API goes depends on your Cloudflare plan.')
    return rep.show(folder)


# ---------------------------------------------------------------------------------------------- AWS / Azure

def days_back(days):
    today = dt.datetime.utcnow().date()
    return [today - dt.timedelta(days=k) for k in range(days - 1, -1, -1)]


def need(tool, hint):
    if not shutil.which(tool):
        raise SystemExit(f'{tool} was not found. {hint}')


def cmd_aws(args):
    need('aws', 'Install the AWS CLI and run "aws configure" (or aws sso login) first.')
    folder, rep = out_dir(args, f'aws-{args.account}'), Report()
    prefix = (args.prefix.strip('/') + '/') if args.prefix else ''
    for d in days_back(args.days):
        src = f's3://{args.bucket}/{prefix}AWSLogs/{args.account}/vpcflowlogs/{args.region}/{d:%Y/%m/%d}/'
        dest = os.path.join(folder, f'{d:%Y-%m-%d}')
        print(f'  {src}')
        subprocess.run(['aws', 's3', 'sync', src, dest, '--only-show-errors'])
        for f in sorted(glob.glob(os.path.join(dest, '*'))):
            rep.add(f)
    return rep.show(folder)


def cmd_azure(args):
    need('az', 'Install the Azure CLI and run "az login" first.')
    folder, rep = out_dir(args, f'azure-{args.storage_account}'), Report()
    for d in days_back(args.days):
        dest = os.path.join(folder, f'{d:%Y-%m-%d}')
        os.makedirs(dest, exist_ok=True)
        print(f'  {args.container} y={d:%Y}/m={d:%m}/d={d:%d}')
        subprocess.run(['az', 'storage', 'blob', 'download-batch', '-d', dest, '-s', args.container, '--account-name', args.storage_account,
                        '--pattern', f'*y={d:%Y}/m={d:%m}/d={d:%d}/*', '--auth-mode', 'login', '--only-show-errors', '-o', 'none'])
        for f in sorted(glob.glob(os.path.join(dest, '**', '*.json'), recursive=True)):
            rep.add(f)
    return rep.show(folder)


# ---------------------------------------------------------------------------------------------- browser front end
# "gui" serves a small page on this computer only (127.0.0.1). Every request needs a random key, handed to the
# browser in the first address and kept in a strict same-site cookie, and the Host header must be the local
# address, so other websites can't drive it. Each pull runs this same script as a child process with a fixed
# argument list (no shell), so the form can't do anything the command line can't.

GUI_PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>fwscope-pull</title>
<link rel="icon" href="data:image/png;base64,__ICON__">
<style>
:root { --page:#f9f9f7; --surface:#fcfcfb; --surface-2:#f0efec; --ink:#0b0b0b; --ink-2:#52514e; --muted:#898781; --ring:rgba(11,11,11,.12); --accent:#2a78d6; --bad:#c43c6b; --good:#0a7d32; --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
@media (prefers-color-scheme: dark) { :root { --page:#121212; --surface:#1b1b1b; --surface-2:#262626; --ink:#f0efec; --ink-2:#c3c2b7; --muted:#898781; --ring:rgba(255,255,255,.12); --bad:#e87ba4; --good:#3ec26b; } }
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--page); color: var(--ink); font: 14px/1.5 system-ui, sans-serif; }
.wrap { max-width: 860px; margin: 0 auto; padding: 16px; }
h1 { font: 600 18px var(--mono); margin: 4px 0 2px; display: flex; align-items: center; gap: 10px; } h1 span { margin-left: -2px; } h1 span { color: var(--muted); font-weight: 400; }
.sub { color: var(--ink-2); margin: 0 0 14px; }
.card { background: var(--surface); border: 1px solid var(--ring); border-radius: 10px; padding: 14px 16px; margin-bottom: 14px; }
.tabs { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }
button, input, select { font: inherit; color: inherit; }
button { background: var(--surface); border: 1px solid var(--ring); border-radius: 6px; padding: 5px 12px; cursor: pointer; }
button:hover { background: var(--surface-2); } button:disabled { opacity: .5; cursor: default; }
.tabs button { border-radius: 14px; font-size: 13px; } .tabs button[aria-selected="true"], button.primary { background: var(--accent); color: #fff; border-color: transparent; }
label { display: block; margin: 8px 0 2px; color: var(--ink-2); font-size: 13px; }
input[type=text], input[type=password], input[type=number], input[type=date], select { width: 100%; max-width: 420px; padding: 6px 8px; border: 1px solid var(--ring); border-radius: 6px; background: var(--page); }
label.check { display: flex; gap: 8px; align-items: center; color: var(--ink); }
label:not(.check) > input, label > select { display: block; margin-top: 3px; }
.hint { color: var(--muted); font-size: 12.5px; margin: 6px 0 0; }
.row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-top: 12px; }
pre { background: var(--surface-2); border-radius: 6px; padding: 10px; font: 12.5px/1.45 var(--mono); white-space: pre-wrap; overflow-wrap: anywhere; max-height: 320px; overflow: auto; margin: 8px 0 0; }
.status { font-weight: 600; } .status.ok { color: var(--good); } .status.bad { color: var(--bad); }
[hidden] { display: none !important; }
a { color: var(--accent); }
.credit { color: var(--muted); font-size: 12px; text-align: center; margin: 22px 0 8px; } .credit a { color: inherit; }
</style></head><body><div class="wrap">
<h1><img src="data:image/png;base64,__ICON__" alt="" width="32" height="32">fwscope-pull <span>// gather logs for fwscope</span></h1>
<p class="sub">Runs on this computer only. Pick where the logs are, then open them in fwscope.</p>
<div class="card">
  <div class="tabs" role="tablist" id="tabs"></div>
  <form id="form" autocomplete="off"></form>
  <div class="row"><button class="primary" id="go">Pull logs</button><span id="state" class="status"></span></div>
</div>
<div class="card" id="out" hidden>
  <div class="row" style="margin-top:0"><b>Output</b><span class="hint" id="folder"></span></div>
  <pre id="log"></pre>
  <div class="row"><button class="primary" id="open" hidden>Open in fwscope</button><span class="hint" id="nofw" hidden>fwscope's index.html wasn't found next to this script: drop the folder above on fwscope instead.</span></div>
</div>
<p class="hint">Stop this helper with Ctrl+C in its terminal, or <a href="#" id="quit">quit it here</a>.</p>
<p class="credit">fwscope-pull __VERSION__ by <a href="https://magikh0e.pl/" target="_blank" rel="noopener">magikh0e</a> · <a href="https://github.com/magikh0e/fwscope" target="_blank" rel="noopener">source on GitHub</a> · <a href="https://github.com/magikh0e/fwscope/blob/main/LICENSE" target="_blank" rel="noopener">GPL-3.0-or-later</a> · <a href="https://buymeacoffee.com/magikh0e" target="_blank" rel="noopener">buy me a coffee</a></p>
</div>
<script>
const SOURCES = {
  ssh: { label: 'Linux server', fields: [['target', 'SSH login (user@host)', 'text', 'admin@web1'], ['port', 'SSH port (if not 22)', 'number'], ['identity', 'SSH key file (optional; default: your usual keys)', 'text', '~/.ssh/id_ed25519'], ['sudo', 'Read the logs with sudo', 'check'], ['sudopw', 'sudo password (sent to sudo only, not stored)', 'password']],
    hint: 'UFW / netfilter, fail2ban, Suricata and ModSecurity. The helper can\'t answer SSH prompts: use key login (a key with a passphrase needs ssh-agent), and connect once in a terminal first.' },
  opnsense: { label: 'OPNsense / pfSense', fields: [['target', 'SSH login', 'text', 'root@192.168.1.1'], ['port', 'SSH port (if not 22)', 'number'], ['identity', 'SSH key file (optional)', 'text', '~/.ssh/id_ed25519'], ['suricata', 'Also pull Suricata eve.json', 'check']], days: 2, hint: 'Filter logs over SSH (enable it under System > Settings > Administration). Key login needed.' },
  openwrt: { label: 'OpenWrt', fields: [['target', 'SSH login', 'text', 'root@192.168.1.1'], ['port', 'SSH port (if not 22)', 'number'], ['identity', 'SSH key file (optional)', 'text', '~/.ssh/id_ed25519']], hint: 'logread over SSH, saved under the router\'s name. Turn on logging for the zone first. Key login needed.' },
  local: { label: 'This computer', fields: [['programs', 'Windows: also program names (Security log)', 'check']], hint: 'Linux: start the helper with sudo to read /var/log. Windows: start it from an administrator prompt.' },
  cloudflare: { label: 'Cloudflare', fields: [['zone', 'Zone ID', 'text', '32 hex characters'], ['token', 'API token (Analytics read)', 'password'], ['since', 'From (optional; default: days back)', 'date']], hint: 'Pages past the 10,000-events-per-request limit. The token is only passed to this run.' },
  aws: { label: 'AWS VPC', fields: [['bucket', 'S3 bucket', 'text'], ['account', 'Account ID', 'text', '123456789012'], ['region', 'Region', 'text', 'us-east-1'], ['prefix', 'Key prefix (if set on the flow log)', 'text']], days: 1, hint: 'Uses the aws tool; run "aws configure" or "aws sso login" first.' },
  azure: { label: 'Azure', fields: [['storage_account', 'Storage account', 'text'], ['container', 'Container', 'select', ['insights-logs-flowlogflowevent', 'insights-logs-networksecuritygroupflowevent']]], days: 1, hint: 'Uses the az tool; run "az login" first. VNet flow logs, or the NSG container for NSG flow logs.' },
};
const $ = s => document.querySelector(s);
let src = localStorage.getItem('fwpull-src') || 'ssh'; if (!SOURCES[src]) src = 'ssh';
function draw() {
  $('#tabs').innerHTML = '';
  for (const [k, s] of Object.entries(SOURCES)) { const b = document.createElement('button'); b.type = 'button'; b.textContent = s.label; b.setAttribute('role', 'tab'); b.setAttribute('aria-selected', k === src); b.onclick = () => { src = k; localStorage.setItem('fwpull-src', k); draw(); }; $('#tabs').append(b); }
  const f = $('#form'); f.innerHTML = '';
  const saved = JSON.parse(localStorage.getItem('fwpull-' + src) || '{}');
  for (const [name, label, type, extra] of SOURCES[src].fields) {
    const l = document.createElement('label'); let i;
    if (type === 'select') { i = document.createElement('select'); for (const o of extra) i.append(new Option(o, o)); }
    else { i = document.createElement('input'); i.type = type === 'check' ? 'checkbox' : type; if (extra) i.placeholder = extra; }
    i.name = name;
    if (type === 'check') { l.className = 'check'; l.append(i, label); if (saved[name]) i.checked = true; }
    else { l.append(label, i); if (type !== 'password' && saved[name] != null) i.value = saved[name]; }
    f.append(l);
  }
  const dl = document.createElement('label'); dl.append('Days back');
  const d = document.createElement('input'); d.type = 'number'; d.name = 'days'; d.min = 1; d.max = 365; d.value = saved.days || SOURCES[src].days || 7; dl.append(d); f.append(dl);
  const h = document.createElement('p'); h.className = 'hint'; h.textContent = SOURCES[src].hint; f.append(h);
  const sp = f.querySelector('[name=sudopw]'); const su = f.querySelector('[name=sudo]');
  if (sp && su) { const sync = () => sp.parentElement.hidden = !su.checked; su.onchange = sync; sync(); }
}
draw();
function values() {
  const v = {}; for (const i of $('#form').elements) v[i.name] = i.type === 'checkbox' ? i.checked : i.value.trim();
  const keep = Object.fromEntries(Object.entries(v).filter(([k]) => !/pw|token/.test(k))); localStorage.setItem('fwpull-' + src, JSON.stringify(keep));
  return v;
}
async function api(path, body) {
  const r = await fetch(path, body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {});
  const j = await r.json().catch(() => ({ error: 'HTTP ' + r.status }));
  if (!r.ok) throw new Error(j.error || 'HTTP ' + r.status);
  return j;
}
$('#go').onclick = async () => {
  $('#go').disabled = true; $('#state').className = 'status'; $('#state').textContent = 'Pulling…'; $('#open').hidden = true; $('#nofw').hidden = true;
  $('#out').hidden = false; $('#log').textContent = ''; $('#folder').textContent = '';
  try {
    const { job } = await api('/api/pull', { source: src, fields: values() });
    for (;;) {
      const s = await api('/api/job/' + job);
      $('#log').textContent = s.log.join('\n'); $('#log').scrollTop = 1e9; $('#folder').textContent = s.folder;
      if (s.done) {
        const ok = s.files.length > 0; $('#state').className = 'status ' + (ok ? 'ok' : 'bad');
        $('#state').textContent = ok ? `${s.files.length} file(s) ready` : 'Nothing collected';
        if (ok) { if (s.fwscope) { $('#open').hidden = false; $('#open').onclick = () => window.open('/fwscope/?pull=' + job, '_blank', 'noopener'); } else $('#nofw').hidden = false; }
        break;
      }
      await new Promise(r => setTimeout(r, 700));
    }
  } catch (e) { $('#state').className = 'status bad'; $('#state').textContent = e.message; if (!$('#log').textContent) $('#out').hidden = true; }
  $('#go').disabled = false;
};
$('#quit').onclick = async e => { e.preventDefault(); try { await api('/api/quit', {}); } catch {} document.body.innerHTML = '<div class="wrap"><p>fwscope-pull has stopped. You can close this tab.</p></div>'; };
</script></body></html>
'''

# the fwscope-pull emblem, 64 px, so the page needs nothing but this file
ICON = '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'

RE_FIELD = {
    'target': re.compile(r'^[A-Za-z0-9._@:\[\]-]{1,200}$'),
    'zone': re.compile(r'^[0-9a-fA-F]{32}$'),
    'since': re.compile(r'^\d{4}-\d\d-\d\d$'),
    'bucket': re.compile(r'^[a-z0-9][a-z0-9.-]{1,62}$'),
    'account': re.compile(r'^\d{12}$'),
    'region': re.compile(r'^[a-z]{2}(-[a-z]+)+-\d$'),
    'prefix': re.compile(r'^[A-Za-z0-9!_.*\'()/-]{0,200}$'),
    'storage_account': re.compile(r'^[a-z0-9]{3,24}$'),
    'container': re.compile(r'^(insights-logs-flowlogflowevent|insights-logs-networksecuritygroupflowevent)$'),
}


def gui_job_argv(source, f, folder):
    """The command line for one pull from the form's values, checked field by field. Values are passed as
    --name=value so nothing in them can be read as another option. Returns (argv, extra environment)."""
    def val(name, required=True):
        v = str(f.get(name) or '').strip()
        if not v:
            if required:
                raise ValueError(f'{name.replace("_", " ")} is required')
            return ''
        if name in RE_FIELD and not RE_FIELD[name].match(v):
            raise ValueError(f'{name.replace("_", " ")} does not look right: {v[:60]}')
        return v
    try:
        days = int(f.get('days') or 7)
    except (TypeError, ValueError):
        raise ValueError('days must be a number')
    if not 1 <= days <= 365:
        raise ValueError('days must be 1 to 365')
    argv, env = [source], {'FWSCOPE_BATCH': '1'}
    if source in ('ssh', 'opnsense', 'openwrt'):
        argv.append(val('target'))
        host_of(argv[-1])
        key = str(f.get('identity') or '').strip()
        if key:
            path = os.path.abspath(os.path.expanduser(key))
            if not os.path.isfile(path):
                raise ValueError(f'SSH key file not found: {key[:120]}')
            argv.append(f'--identity={path}')
        if f.get('port'):
            port = int(f['port'])
            if not 1 <= port <= 65535:
                raise ValueError('port must be 1 to 65535')
            argv.append(f'--port={port}')
    if source == 'ssh' and f.get('sudo'):
        argv.append('--sudo')
        env['FWSCOPE_SUDO_PASSWORD'] = str(f.get('sudopw') or '')
    if source == 'opnsense' and f.get('suricata'):
        argv.append('--suricata')
    if source == 'local' and f.get('programs'):
        argv.append('--programs')
    if source == 'cloudflare':
        argv.append('--zone=' + val('zone'))
        if val('since', False):
            argv.append('--since=' + val('since'))
        token = str(f.get('token') or '').strip()
        if not token:
            raise ValueError('API token is required')
        env['CF_API_TOKEN'] = token
    if source == 'aws':
        argv += ['--bucket=' + val('bucket'), '--account=' + val('account'), '--region=' + val('region')]
        if val('prefix', False):
            argv.append('--prefix=' + val('prefix'))
    if source == 'azure':
        argv += ['--storage-account=' + val('storage_account'), '--container=' + (val('container', False) or 'insights-logs-flowlogflowevent')]
    if source not in ('ssh', 'opnsense', 'openwrt', 'local', 'cloudflare', 'aws', 'azure'):
        raise ValueError('unknown source')
    return argv + [f'--days={days}', f'--out={folder}'], env


def find_fwscope(path=None):
    """fwscope's index.html: given, next to this script's folder (a repo checkout), or here."""
    here = os.path.dirname(os.path.abspath(__file__))
    for p in ([path] if path else []) + [os.path.join(here, '..', 'index.html'), os.path.join(here, 'index.html'), 'index.html']:
        if p and os.path.isfile(p):
            with open(p, 'rb') as fh:
                if b'fwscope' in fh.read(4096):
                    return os.path.abspath(p)
    return None


class GuiState:
    def __init__(self, token, base, fwscope, port):
        self.token, self.base, self.fwscope, self.port = token, base, fwscope, port
        self.jobs, self.lock, self.server = {}, threading.Lock(), None

    def start(self, source, fields):
        jid = secrets.token_hex(6)
        label = safe(str(fields.get('target') or fields.get('zone') or fields.get('bucket') or fields.get('storage_account') or platform.node() or 'here').split('@')[-1])[:40]
        folder = os.path.abspath(os.path.join(self.base, f'{source}-{label}-{dt.datetime.now():%Y%m%d-%H%M%S}'))
        argv, extra = gui_job_argv(source, fields, folder)
        env = dict(os.environ, **extra, PYTHONUNBUFFERED='1', PYTHONIOENCODING='utf-8')
        job = {'log': [f'$ fwscope-pull {" ".join(a for a in argv if not a.startswith("--out="))}'], 'done': False, 'code': None, 'folder': folder}
        proc = subprocess.Popen([sys.executable, os.path.abspath(__file__)] + argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, env=env, text=True, encoding='utf-8', errors='replace')

        def pump():
            for line in proc.stdout:
                with self.lock:
                    job['log'].append(line.rstrip('\n'))
            proc.wait()
            with self.lock:
                job['done'], job['code'] = True, proc.returncode
        threading.Thread(target=pump, daemon=True).start()
        with self.lock:
            self.jobs[jid] = job
        return jid

    def files(self, jid):
        job = self.jobs.get(jid)
        if not job or not os.path.isdir(job['folder']):
            return []
        out = []
        for dirpath, _, names in os.walk(job['folder']):
            for n in sorted(names):
                if not n.startswith('.'):
                    out.append(os.path.join(dirpath, n))
        return sorted(out)


def make_handler(state):
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = 'fwscope-pull'

        def log_message(self, *a):
            pass

        def send(self, code, body=b'', ctype='application/json', headers=()):
            if isinstance(body, (dict, list)):
                body = json.dumps(body).encode()
            elif isinstance(body, str):
                body = body.encode()
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            for k, v in headers:
                self.send_header(k, v)
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)

        def allowed(self):
            # the Host header must be this computer (stops DNS-rebinding pages), and the key must match
            host = (self.headers.get('Host') or '').lower()
            if host not in (f'127.0.0.1:{state.port}', f'localhost:{state.port}'):
                return False
            cookie = self.headers.get('Cookie') or ''
            m = re.search(r'(?:^|;\s*)fwpull=([A-Za-z0-9_-]+)', cookie)
            return bool(m) and hmac.compare_digest(m.group(1), state.token)

        def do_GET(self):
            u = urllib.parse.urlsplit(self.path)
            q = urllib.parse.parse_qs(u.query)
            if u.path == '/' and q.get('key') and hmac.compare_digest(q['key'][0], state.token):
                # first visit: swap the key in the address for a cookie, and drop it from the address bar
                return self.send(303, '', 'text/plain', [('Set-Cookie', f'fwpull={state.token}; Path=/; HttpOnly; SameSite=Strict'), ('Location', '/')])
            if not self.allowed():
                return self.send(403, 'Open the address fwscope-pull printed in its terminal.', 'text/plain')
            if u.path == '/':
                return self.send(200, GUI_PAGE.replace('__VERSION__', VERSION).replace('__ICON__', ICON), 'text/html; charset=utf-8', [('Content-Security-Policy', "default-src 'self'; img-src data:; script-src 'unsafe-inline'; style-src 'unsafe-inline'")])
            if u.path in ('/fwscope', '/fwscope/'):
                if not state.fwscope:
                    return self.send(404, 'fwscope index.html not found', 'text/plain')
                with open(state.fwscope, 'rb') as fh:
                    return self.send(200, fh.read(), 'text/html; charset=utf-8')
            m = re.fullmatch(r'/api/job/([0-9a-f]{12})', u.path)
            if m:
                job = state.jobs.get(m.group(1))
                if not job:
                    return self.send(404, {'error': 'no such job'})
                with state.lock:
                    files = state.files(m.group(1)) if job['done'] else []
                    return self.send(200, {'log': job['log'][-400:], 'done': job['done'], 'code': job['code'], 'folder': job['folder'],
                                           'files': [os.path.relpath(f, job['folder']) for f in files], 'fwscope': bool(state.fwscope)})
            m = re.fullmatch(r'/api/job/([0-9a-f]{12})/files', u.path)
            if m:
                files = state.files(m.group(1))
                return self.send(200, {'files': [{'name': os.path.basename(f), 'url': f'/api/job/{m.group(1)}/file/{i}', 'mtime': int(os.path.getmtime(f) * 1000)} for i, f in enumerate(files)]})
            m = re.fullmatch(r'/api/job/([0-9a-f]{12})/file/(\d+)', u.path)
            if m:
                files = state.files(m.group(1))  # only files this job wrote, picked by number: no paths from the request
                i = int(m.group(2))
                if i >= len(files):
                    return self.send(404, {'error': 'no such file'})
                with open(files[i], 'rb') as fh:
                    return self.send(200, fh.read(), 'application/octet-stream')
            return self.send(404, {'error': 'not found'})

        def do_POST(self):
            if not self.allowed():
                return self.send(403, {'error': 'not allowed'})
            origin = self.headers.get('Origin')
            if origin and origin not in (f'http://127.0.0.1:{state.port}', f'http://localhost:{state.port}'):
                return self.send(403, {'error': 'wrong origin'})
            if (self.headers.get('Content-Type') or '').split(';')[0].strip() != 'application/json':
                return self.send(415, {'error': 'JSON only'})
            n = int(self.headers.get('Content-Length') or 0)
            if n > 65536:
                return self.send(413, {'error': 'too large'})
            try:
                body = json.loads(self.rfile.read(n) or b'{}')
            except ValueError:
                return self.send(400, {'error': 'bad JSON'})
            if self.path == '/api/pull':
                try:
                    jid = state.start(str(body.get('source')), body.get('fields') or {})
                except (ValueError, SystemExit) as e:
                    return self.send(400, {'error': str(e)})
                return self.send(200, {'job': jid})
            if self.path == '/api/quit':
                self.send(200, {'ok': True})
                threading.Thread(target=state.server.shutdown, daemon=True).start()
                return None
            return self.send(404, {'error': 'not found'})
    return Handler


class ExclusiveServer(http.server.ThreadingHTTPServer):
    """A port nobody else can share. Python's default lets a second server bind a busy port (on Windows that
    means two helpers answer on one address), so turn that off, and on Windows ask for exclusive use."""
    allow_reuse_address = False
    daemon_threads = True

    def server_bind(self):
        import socket
        if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def cmd_gui(args):
    token = secrets.token_urlsafe(24)
    fw = find_fwscope(args.fwscope)
    srv = None
    for port in [args.port] + ([] if args.port_fixed else list(range(args.port + 1, args.port + 20))):
        try:
            srv = ExclusiveServer(('127.0.0.1', port), None)
            break
        except OSError:
            continue
    if not srv:
        raise SystemExit(f'no free port from {args.port}')
    state = GuiState(token, args.out or 'fwscope-logs', fw, srv.server_address[1])
    srv.RequestHandlerClass = make_handler(state)
    state.server = srv
    url = f'http://127.0.0.1:{state.port}/?key={token}'
    print(CREDIT)
    print(f'fwscope-pull is running on this computer only: {url}')
    print('Opening it in your browser. Keep this window open; press Ctrl+C here to stop it.')
    if not fw:
        print('note: fwscope index.html was not found, so pulled logs can\'t open in fwscope directly (use --fwscope PATH).')
    if not args.no_browser:
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    srv.server_close()
    print('stopped')
    return 0


# ---------------------------------------------------------------------------------------------- command line

def parser():
    p = argparse.ArgumentParser(prog='fwscope-pull', description=__doc__.split('\n\n')[0], formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split('\n\n', 1)[1] + '\n' + CREDIT)
    p.add_argument('--version', action='version', version=CREDIT)
    sub = p.add_subparsers(dest='cmd', required=True)

    def common(sp, days=7):
        sp.add_argument('--days', type=int, default=days, help=f'how many days back (default {days})')
        sp.add_argument('-o', '--out', help='folder to write to (default: fwscope-logs/<source>-<time>)')

    def sshopts(sp):
        sp.add_argument('target', help='user@host, as you would give ssh')
        sp.add_argument('-p', '--port', type=int, help='SSH port')
        sp.add_argument('-i', '--identity', help='SSH private key file to log in with (only this key is tried)')

    s = sub.add_parser('local', help='this computer (Linux server or desktop, or Windows Firewall)'); common(s)
    s.add_argument('--programs', action='store_true', help='Windows: also export Security-log events with program names')
    s.set_defaults(fn=cmd_local)
    s = sub.add_parser('ssh', help='a Linux server over SSH: UFW / netfilter, fail2ban, Suricata, ModSecurity'); sshopts(s); common(s)
    s.add_argument('--sudo', action='store_true', help='read the logs with sudo (asks for the password; FWSCOPE_SUDO_PASSWORD also works)')
    s.set_defaults(fn=cmd_ssh)
    s = sub.add_parser('opnsense', help='OPNsense or pfSense firewall logs over SSH'); sshopts(s); common(s, days=2)
    s.add_argument('--suricata', action='store_true', help="also pull Suricata's eve.json")
    s.set_defaults(fn=cmd_opnsense)
    s = sub.add_parser('openwrt', help='OpenWrt logread over SSH'); sshopts(s); common(s)
    s.set_defaults(fn=cmd_openwrt)
    s = sub.add_parser('cloudflare', help='Cloudflare firewall events from the GraphQL API'); common(s)
    s.add_argument('--zone', required=True, help='zone ID (Overview page of the domain, right-hand side)')
    s.add_argument('--since', help='start date YYYY-MM-DD (default: --days back)')
    s.add_argument('--until', help='end date YYYY-MM-DD (default: now)')
    s.add_argument('--name', help='name for the output file (default: start of the zone ID)')
    s.add_argument('--window', type=int, default=24, help='hours per request window (default 24)')
    s.add_argument('--token-env', default='CF_API_TOKEN', help='environment variable holding the API token (default CF_API_TOKEN)')
    s.set_defaults(fn=cmd_cloudflare)
    s = sub.add_parser('aws', help='AWS VPC Flow Logs from S3 (uses the aws tool)'); common(s, days=1)
    s.add_argument('--bucket', required=True); s.add_argument('--account', required=True); s.add_argument('--region', required=True)
    s.add_argument('--prefix', help='key prefix set on the flow log, if any')
    s.set_defaults(fn=cmd_aws)
    s = sub.add_parser('azure', help='Azure VNet or NSG flow logs from a storage account (uses the az tool)'); common(s, days=1)
    s.add_argument('--storage-account', required=True)
    s.add_argument('--container', default='insights-logs-flowlogflowevent', help='insights-logs-flowlogflowevent (VNet, default) or insights-logs-networksecuritygroupflowevent (NSG)')
    s.set_defaults(fn=cmd_azure)
    s = sub.add_parser('gui', help='a page in your browser to run pulls and open them in fwscope')
    s.add_argument('--port', type=int, default=8765, help='local port (default 8765; a fixed port keeps fwscope\'s saved settings)')
    s.add_argument('--port-fixed', action='store_true', help='fail instead of trying the next ports when the port is busy')
    s.add_argument('--fwscope', help="path to fwscope's index.html (default: found next to this script)")
    s.add_argument('-o', '--out', help='folder for pulled logs (default: fwscope-logs)')
    s.add_argument('--no-browser', action='store_true', help='print the address instead of opening it')
    s.set_defaults(fn=cmd_gui)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    if getattr(args, 'days', 1) < 1:
        raise SystemExit('--days must be 1 or more')
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        print('\nstopped', file=sys.stderr)
        return 130


if __name__ == '__main__':
    sys.exit(main())
