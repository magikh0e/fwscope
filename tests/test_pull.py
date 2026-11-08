"""Tests for scripts/fwscope-pull.py. Run: python -m unittest discover -s tests -p "test_*.py" """
import datetime as dt
import importlib.util
import io
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fwscope_pull', HERE.parent / 'scripts' / 'fwscope-pull.py')
pull = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pull)


class Names(unittest.TestCase):
    def test_safe(self):
        self.assertEqual(pull.safe('web 1/../x'), 'web_1_.._x')
        self.assertEqual(pull.safe('192.168.1.1'), '192.168.1.1')

    def test_ssh_targets(self):
        self.assertEqual(pull.host_of('root@192.0.2.1'), '192.0.2.1')
        self.assertEqual(pull.host_of('web1'), 'web1')
        for bad in ['-oProxyCommand=touch x', 'a b', 'host;rm -rf /', '$(id)@x', '']:
            with self.assertRaises(SystemExit, msg=bad):
                pull.host_of(bad)


class LinuxDiscovery(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def touch(self, rel, age_days=0, data=b'x\n'):
        p = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'wb') as fh:
            fh.write(data)
        t = time.time() - age_days * 86400
        os.utime(p, (t, t))
        return p

    def test_recent_files_rotations_and_error_logs(self):
        ufw = self.touch('var/log/ufw.log')
        ufw1 = self.touch('var/log/ufw.log.1', 2)
        self.touch('var/log/ufw.log.4.gz', 30)  # too old
        self.touch('var/log/syslog')  # skipped: ufw.log already has the kernel lines
        eve = self.touch('var/log/suricata/eve.json')
        f2b = self.touch('var/log/fail2ban.log')
        err = self.touch('var/log/apache2/error.log')
        files, errors = pull.find_linux_logs(7, root=self.root)
        n = lambda xs: sorted(os.path.normpath(x) for x in xs)
        self.assertEqual(n(files), n([ufw, ufw1, eve, f2b]))
        self.assertEqual(n(errors), n([err]))

    def test_syslog_when_nothing_better(self):
        sl = self.touch('var/log/syslog')
        files, _ = pull.find_linux_logs(7, root=self.root)
        self.assertEqual([os.path.normpath(f) for f in files], [os.path.normpath(sl)])

    def test_remote_script_is_valid_sh(self):
        sh = shutil.which('sh')
        if not sh:
            self.skipTest('no sh here')
        r = subprocess.run([sh, '-n', '-c', pull.remote_find_script(7)], capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)


class FakeCloudflare:
    """Answers GraphQL like Cloudflare: events in [since, until), oldest first, at most `limit`."""
    def __init__(self, events, errors=None):
        self.events, self.errors, self.calls = events, errors, 0

    def __call__(self, req, timeout=None):
        self.calls += 1
        v = json.loads(req.data.decode())['variables']
        assert req.headers['Authorization'] == 'Bearer t0ken'
        rows = [e for e in self.events if v['since'] <= e['datetime'] < v['until']][:v['limit']]
        body = {'errors': self.errors} if self.errors else {'data': {'viewer': {'zones': [{'firewallEventsAdaptive': rows}]}}}
        return io.BytesIO(json.dumps(body).encode())


def events(n, start, per_second):
    out = []
    for k in range(n):
        t = start + dt.timedelta(seconds=k // per_second)
        out.append({'rayName': f'r{k}', 'ruleId': 'x', 'datetime': t.strftime('%Y-%m-%dT%H:%M:%SZ'), 'clientIP': '203.0.113.1', 'action': 'block'})
    return out


class CloudflarePaging(unittest.TestCase):
    def test_walks_past_the_per_request_limit_without_gaps_or_repeats(self):
        start = dt.datetime(2026, 11, 1)
        evs = events(2500, start, per_second=7)  # several events share each second, also across page edges
        fake, got = FakeCloudflare(evs), []
        n = pull.cf_pull('t0ken', 'zone', start, start + dt.timedelta(days=2), got.append, window=dt.timedelta(hours=6), limit=1000, opener=fake)
        self.assertEqual(n, 2500)
        self.assertEqual(sorted(e['rayName'] for e in got), sorted(e['rayName'] for e in evs))
        self.assertGreater(fake.calls, 3)

    def test_api_errors_are_reported(self):
        fake = FakeCloudflare([], errors=[{'message': 'zone not found'}])
        with self.assertRaises(SystemExit) as cm:
            pull.cf_pull('t0ken', 'zone', dt.datetime(2026, 11, 1), dt.datetime(2026, 11, 2), lambda r: None, opener=fake)
        self.assertIn('zone not found', str(cm.exception))


class CommandLine(unittest.TestCase):
    def test_days_must_be_positive(self):
        with self.assertRaises(SystemExit):
            pull.main(['local', '--days', '0'])

    def test_ssh_needs_a_target(self):
        with self.assertRaises(SystemExit):
            pull.main(['ssh'])


class GuiServer(unittest.TestCase):
    """The helper page: only this computer, only with the key, only the files a pull wrote."""
    def setUp(self):
        import http.client
        import http.server
        import threading
        self.http = http.client
        self.dir = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, self.dir)
        srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), None)
        self.port = srv.server_address[1]
        self.state = pull.GuiState('k3y_k3y_k3y', self.dir, None, self.port)
        srv.RequestHandlerClass = pull.make_handler(self.state)
        self.state.server = srv
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close); self.addCleanup(srv.shutdown)

    def req(self, method, path, body=None, cookie=True, host=None, headers=None):
        c = self.http.HTTPConnection('127.0.0.1', self.port, timeout=10)
        h = {'Host': host or f'127.0.0.1:{self.port}'}
        if cookie:
            h['Cookie'] = 'fwpull=k3y_k3y_k3y'
        if body is not None:
            h['Content-Type'] = 'application/json'
            body = json.dumps(body)
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, dict(r.getheaders()), data

    def test_key_becomes_a_strict_cookie(self):
        st, h, _ = self.req('GET', '/?key=k3y_k3y_k3y', cookie=False)
        self.assertEqual(st, 303)
        self.assertIn('HttpOnly', h['Set-Cookie']); self.assertIn('SameSite=Strict', h['Set-Cookie'])
        self.assertEqual(self.req('GET', '/?key=wrong', cookie=False)[0], 403)
        self.assertEqual(self.req('GET', '/', cookie=False)[0], 403)
        st, _, body = self.req('GET', '/')
        self.assertEqual(st, 200); self.assertIn(b'fwscope-pull', body)
        self.assertIn(f'fwscope-pull {pull.VERSION} by'.encode(), body)  # the credit line, with the version filled in
        self.assertNotIn(b'__VERSION__', body)

    def test_other_hosts_and_origins_are_refused(self):
        self.assertEqual(self.req('GET', '/', host=f'evil.example:{self.port}')[0], 403)  # DNS rebinding
        st, _, _ = self.req('POST', '/api/pull', {'source': 'local', 'fields': {}}, headers={'Origin': 'https://evil.example'})
        self.assertEqual(st, 403)
        c = self.http.HTTPConnection('127.0.0.1', self.port, timeout=10)
        c.request('POST', '/api/pull', body='source=local', headers={'Host': f'127.0.0.1:{self.port}', 'Cookie': 'fwpull=k3y_k3y_k3y', 'Content-Type': 'application/x-www-form-urlencoded'})
        self.assertEqual(c.getresponse().status, 415)  # a plain cross-site form can't post
        c.close()

    def test_bad_fields_are_rejected_before_anything_runs(self):
        for fields in [{'target': '-oProxyCommand=calc'}, {'target': 'a;b'}, {'target': 'root@h', 'port': '70000'}]:
            st, _, body = self.req('POST', '/api/pull', {'source': 'ssh', 'fields': fields})
            self.assertEqual(st, 400, fields)
        self.assertEqual(self.req('POST', '/api/pull', {'source': 'rm', 'fields': {}})[0], 400)
        self.assertEqual(self.state.jobs, {})

    def test_serves_only_the_files_a_pull_wrote(self):
        folder = os.path.join(self.dir, 'job1'); os.makedirs(folder)
        with open(os.path.join(folder, 'web1-ufw.log'), 'wb') as fh:
            fh.write(b'line\n')
        with open(os.path.join(folder, '.list'), 'w') as fh:
            fh.write('hidden\n')
        self.state.jobs['0123456789ab'] = {'log': [], 'done': True, 'code': 0, 'folder': folder}
        st, _, body = self.req('GET', '/api/job/0123456789ab/files')
        files = json.loads(body)['files']
        self.assertEqual([f['name'] for f in files], ['web1-ufw.log'])
        st, _, body = self.req('GET', files[0]['url'])
        self.assertEqual((st, body), (200, b'line\n'))
        self.assertEqual(self.req('GET', '/api/job/0123456789ab/file/5')[0], 404)
        self.assertEqual(self.req('GET', '/api/job/0123456789ab/file/..%2F..%2Fsecret')[0], 404)
        self.assertEqual(self.req('GET', '/api/job/0123456789ab/files', cookie=False)[0], 403)

    def test_a_pull_runs_and_finishes(self):
        st, _, body = self.req('POST', '/api/pull', {'source': 'local', 'fields': {'days': 1}})
        self.assertEqual(st, 200)
        job = json.loads(body)['job']
        for _ in range(200):
            s = json.loads(self.req('GET', f'/api/job/{job}')[2])
            if s['done']:
                break
            time.sleep(0.1)
        self.assertTrue(s['done'])
        self.assertTrue(s['log'][0].startswith('$ fwscope-pull local --days=1'))


class GuiPort(unittest.TestCase):
    def test_a_busy_port_is_not_shared(self):
        first = pull.ExclusiveServer(('127.0.0.1', 0), None)
        self.addCleanup(first.server_close)
        with self.assertRaises(OSError):
            pull.ExclusiveServer(('127.0.0.1', first.server_address[1]), None)


class GuiArguments(unittest.TestCase):
    def test_fields_become_name_value_arguments(self):
        argv, env = pull.gui_job_argv('aws', {'bucket': 'my-flow-logs', 'account': '123456789012', 'region': 'us-east-1', 'days': 2}, '/tmp/x')
        self.assertEqual(argv, ['aws', '--bucket=my-flow-logs', '--account=123456789012', '--region=us-east-1', '--days=2', '--out=/tmp/x'])
        argv, env = pull.gui_job_argv('ssh', {'target': 'admin@web1', 'sudo': True, 'sudopw': 'pw'}, '/tmp/x')
        self.assertEqual(argv[:3], ['ssh', 'admin@web1', '--sudo'])
        self.assertEqual(env['FWSCOPE_SUDO_PASSWORD'], 'pw')  # in the environment, never in the arguments
        self.assertNotIn('pw', ' '.join(argv))
        argv, env = pull.gui_job_argv('cloudflare', {'zone': 'a' * 32, 'token': 'secret'}, '/tmp/x')
        self.assertNotIn('secret', ' '.join(argv)); self.assertEqual(env['CF_API_TOKEN'], 'secret')

    def test_key_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            key = fh.name
        self.addCleanup(os.remove, key)
        argv, _ = pull.gui_job_argv('openwrt', {'target': 'root@192.0.2.1', 'identity': key}, '/tmp/x')
        self.assertIn(f'--identity={os.path.abspath(key)}', argv)
        with self.assertRaises(ValueError):
            pull.gui_job_argv('ssh', {'target': 'root@192.0.2.1', 'identity': key + '.missing'}, '/tmp/x')
        cmd = pull.ssh_cmd(pull.parser().parse_args(['ssh', 'root@192.0.2.1', '-i', key]), 'root@192.0.2.1', 'true')
        self.assertEqual(cmd[cmd.index('-i') + 1:cmd.index('-i') + 4], [key, '-o', 'IdentitiesOnly=yes'])

    def test_bad_values_are_refused(self):
        for src, f in [('aws', {'bucket': 'x --endpoint-url=http://evil', 'account': '1', 'region': 'us-east-1'}),
                       ('cloudflare', {'zone': 'nothex', 'token': 't'}), ('azure', {'storage_account': 'A_B'}),
                       ('local', {'days': 999}), ('cloudflare', {'zone': 'a' * 32})]:
            with self.assertRaises(ValueError, msg=(src, f)):
                pull.gui_job_argv(src, f, '/tmp/x')


if __name__ == '__main__':
    unittest.main()
