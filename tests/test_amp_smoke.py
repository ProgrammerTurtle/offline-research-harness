"""One-shot compatibility only: synthetic keys, mock children, no task effects."""
import copy
from contextlib import nullcontext
import ipaddress
import json
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from synthetic_harness import amp_protected as protected, sandbox
from synthetic_harness.amp_smoke import PROMPT, SmokeStream, safe_result
from synthetic_harness.login import CredentialStore
from test_amp_tls import SERVER


SESSION = 'T-00000000-0000-7000-8000-000000000001'
SECRET = 'PRIVATE-SYNTHETIC-CANARY'


def events():
    proposal = '{"op":"step","action":{"tool":"check","args":{}}}'
    return [
        {'type': 'system', 'subtype': 'init', 'session_id': SESSION, 'cwd': '/tmp',
         'tools': [SECRET], 'mcp_servers': [{'name': SECRET, 'status': 'connected'}],
         'subagents': [{'tool_use_id': SECRET, 'description': SECRET}],
         'agent_mode': 'openai/gpt-6-astra'},
        {'type': 'user', 'session_id': SESSION, 'parent_tool_use_id': None,
         'message': {'role': 'user', 'content': [{'type': 'text', 'text': PROMPT}]}},
        {'type': 'assistant', 'session_id': SESSION, 'parent_tool_use_id': None,
         'message': {'type': 'message', 'role': 'assistant', 'stop_reason': 'end_turn',
                     'content': [{'type': 'text', 'text': proposal}],
                     'usage': {'input_tokens': 13, 'output_tokens': 7}}},
        {'type': 'result', 'subtype': 'success', 'session_id': SESSION, 'is_error': False,
         'result': proposal, 'num_turns': 1, 'duration_ms': 17}]


class AmpSmokeTests(unittest.TestCase):
    def test_fixed_operation_success_failures_limits_and_one_shot(self):
        lines = [json.dumps(e) for e in events()]
        good = '\n'.join(lines) + '\n'
        tool = json.dumps({'type': 'assistant', 'session_id': SESSION, 'parent_tool_use_id': None,
                          'message': {'content': [{'type': 'tool_use', 'name': SECRET, 'input': {}}]}}) + '\n'
        cases = [
            ('success', good, '', 'compatible', 'awaiting_exit'),
            ('exact_total', ''.join(line.ljust(65535) + '\n' for line in lines), '', 'compatible', 'awaiting_exit'),
            ('exact_event', lines[0].ljust(65536) + '\n' + '\n'.join(lines[1:]) + '\n', '', 'compatible', 'awaiting_exit'),
            ('total_limit', ''.join(line.ljust(65536) + '\n' for line in lines), '', 'output_limit', 'awaiting_result'),
            ('event_limit', lines[0].ljust(65537) + '\n', '', 'output_limit', 'awaiting_init'),
            ('malformed', lines[0] + '\n' + SECRET + '\n', '', 'schema_rejected', 'awaiting_user'),
            ('truncated', good[:-2], '', 'schema_rejected', 'awaiting_result'),
            ('tool', '\n'.join(lines[:2]) + '\n' + tool, '', 'tool_activity', 'awaiting_assistant'),
            ('approval', json.dumps({'type': 'approval', 'secret': SECRET}) + '\n', '', 'tool_activity', 'awaiting_init'),
            ('late_tool', good + tool, '', 'tool_activity', 'awaiting_exit'),
            ('late_failure', good, 'sys.exit(7)', 'native_failed', 'awaiting_exit'),
            ('native_error', json.dumps({'type': 'system', 'subtype': 'error_during_execution', 'error': SECRET}) + '\n',
             '', 'native_error', 'awaiting_init'),
            ('forged_envelope', json.dumps({'op': 'smoke_result', 'result': {'state': 'compatible', 'secret': SECRET}}) + '\n',
             '', 'schema_rejected', 'awaiting_init'),
            ('interrupted', '', 'time.sleep(60)', 'interrupted', 'launch'),
            ('timeout', lines[0] + '\n', 'time.sleep(60)', 'timeout', 'awaiting_user')]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); (base/'audit').mkdir()
            for name, output, tail, expected, stage in cases:
                with self.subTest(name=name):
                    CredentialStore.create(base/name)
                    with CredentialStore(base/name) as store:
                        protected.provision(store, SECRET)
                        old = store.path/'home/check-used'; old.write_text('previous-auth-attempt')
                        with patch.object(protected, 'resolve_auth', return_value=(ipaddress.ip_address('93.184.216.34'),)):
                            egress = protected.AmpEgress(timeout=32)
                            again = protected.AmpEgress(timeout=32)
                        service = protected.ProtectedAmpService(base/'audit'/name, store, 'smoke', egress=egress)
                        # The real namespace/stream runner executes a fixed offline
                        # fixture in place of Amp; never a production command switch.
                        code = ("import os,sys,time\nassert sys.stdin.read()==''\n"
                                "assert not os.path.exists('/home/user/workspace')\n"
                                f"assert os.environ['AMP_API_KEY']=={SECRET!r}\n"
                                "print(os.environ['AMP_API_KEY'],file=sys.stderr)\n"
                                f"sys.stdout.write({output!r});sys.stdout.flush()\n{tail}\n")
                        # Oversized fixtures go in the source tmpfs, not oversized argv.
                        source = service.source().replace(b'    env=dict(os.environ)',
                            (f"    Path('/tmp/offline-child.py').write_text({code!r})\n    env=dict(os.environ)").encode())
                        native = repr(service.command()).encode()
                        source = source.replace(native, repr(['/usr/bin/python3.11', '-I', '-S', '/tmp/offline-child.py']).encode())
                        started = time.monotonic()
                        with patch.object(protected.AmpEgress, 'connect', side_effect=AssertionError('Network prohibited')), \
                                patch.object(service, 'source', return_value=source), \
                                (patch.object(service, 'read', side_effect=KeyboardInterrupt)
                                 if name == 'interrupted' else nullcontext()), service:
                            result = service.probe()
                        elapsed = time.monotonic() - started
                        self.assertLess(elapsed, 35)
                        self.assertEqual((result['state'], result['stage']), (expected, stage))
                        if expected == 'compatible':
                            self.assertTrue(result['proposal_validated'])
                            self.assertEqual(result['events'], dict(init=1, user=1, assistant=1, result=1,
                                                                  error=0, tool_activity=0, unknown=0))
                            self.assertEqual(result['init_counts'], dict(tools=1, mcp_servers=1, subagents=1))
                            self.assertEqual(result['usage'], {'input_tokens': 13, 'output_tokens': 7})
                            self.assertTrue(result['reported_mode_matches'])
                        if name == 'late_failure':
                            self.assertTrue(result['proposal_validated']); self.assertEqual(result['exit_code'], 7)
                        if name == 'timeout':
                            self.assertGreaterEqual(elapsed, 30)
                        for field in ('effective_model', 'effective_effort', 'effective_fast', 'native_retry_count'):
                            self.assertIsNone(result[field])
                        self.assertEqual(egress.opens, 0)
                        self.assertTrue(egress.closed)
                        self.assertFalse(list(sandbox.CGROUP.glob('service-*')))
                        self.assertEqual(old.read_text(), 'previous-auth-attempt')
                        self.assertTrue((store.path/'home/smoke-used').exists())
                        with self.assertRaises(FileExistsError):
                            with protected.ProtectedAmpService(base/'audit'/(name+'-again'), store, 'smoke', egress=again):
                                self.fail('Consumed operation launched twice')
                        self.assertEqual(again.opens, 0)
                        anchor = base/(name+'-anchor'); anchor.write_text(json.dumps({'root': service.receipt['root']}))
                        self.assertEqual(protected.verify(service.output, anchor)['outcome'], result)
                        journal = Path(str(service.output)+'.service.jsonl').read_text()
                        self.assertNotIn(SECRET, journal)
                        self.assertNotIn(PROMPT, journal)
                        anchor.write_text(json.dumps({'root': '0'*64}))
                        with self.assertRaises(ValueError): protected.verify(service.output, anchor)
                        print('offline-smoke', name, result['state'], result['stage'], flush=True)

    def test_pinned_native_smoke_rejecting_local_backend(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); (base/'audit').mkdir()
            cert, key = base/'fixture.pem', base/'fixture.key'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-subj', '/CN=ampcode.com', '-addext', 'subjectAltName=DNS:ampcode.com',
                            '-keyout', str(key), '-out', str(cert)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            record = base/'requests'
            server = subprocess.Popen([sys.executable, '-u', '-c', SERVER, str(cert), str(key), str(record), 'fixture'],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                      env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
            try:
                port = int(server.stdout.readline())
                CredentialStore.create(base/'store')
                with CredentialStore(base/'store') as store:
                    protected.provision(store, SECRET)
                    with patch.object(protected, 'resolve_auth', return_value=(ipaddress.ip_address('93.184.216.34'),)):
                        egress = protected.AmpEgress(timeout=32)
                    service = protected.ProtectedAmpService(base/'audit'/'native', store, 'smoke', egress=egress)
                    source = service.source().replace(b'    env=dict(os.environ)',
                        (f"    Path('/tmp/fixture-ca.pem').write_text({cert.read_text()!r})\n    env=dict(os.environ)").encode())
                    source = source.replace(b"NODE_EXTRA_CA_CERTS='/opt/public-ca.pem'", b"NODE_EXTRA_CA_CERTS='/tmp/fixture-ca.pem'")
                    def connect():
                        sock = socket.create_connection(('127.0.0.1', port), timeout=2)
                        sock.setblocking(False)
                        return sock
                    with patch.object(protected.AmpEgress, 'connect', side_effect=AssertionError('External network prohibited')), \
                            patch.object(egress, 'connect', side_effect=connect), patch.object(service, 'source', return_value=source), service:
                        result = service.probe()
                    self.assertEqual((result['state'], result['stage'], result['exit_code']), ('native_failed', 'awaiting_init', 1))
                    requests = json.loads(record.read_text())['requests']
                    self.assertIn('POST /api/internal?getUserInfo HTTP/1.1', requests)
                    self.assertLessEqual(set(requests), {'POST /api/internal?getUserInfo HTTP/1.1', 'POST /api/telemetry HTTP/1.1'})
                    self.assertFalse(result['proposal_validated'])
                    self.assertEqual(sum(result['events'].values()), 0)
                    anchor = base/'anchor'; anchor.write_text(json.dumps({'root': service.receipt['root']}))
                    self.assertEqual(protected.verify(service.output, anchor)['outcome'], result)
                    self.assertNotIn(SECRET, Path(str(service.output)+'.service.jsonl').read_text())
                    self.assertTrue(egress.closed)
                    self.assertFalse(list(sandbox.CGROUP.glob('service-*')))
            finally:
                server.terminate(); server.communicate(timeout=5)

    def test_stream_rejects_schema_drift_and_private_metadata(self):
        for index, field, value in ((0, 'session_id', SECRET), (0, 'session_id', None),
                                    (0, 'tools', None), (1, 'session_id', 'T-00000000-0000-7000-8000-000000000002'),
                                    (3, 'num_turns', True), (3, 'extra', SECRET)):
            fixture = events(); fixture[index][field] = value
            stream = SmokeStream()
            for e in fixture[:index]: self.assertTrue(stream.accept(json.dumps(e)))
            self.assertFalse(stream.accept(json.dumps(fixture[index])))
            self.assertEqual(stream.result['state'], 'schema_rejected')
            self.assertNotIn(SECRET, json.dumps(safe_result(stream.result)))
        for data in (b'{"type":"system","type":"user"}', b'\xff', b'['*10000, b'{"type":NaN}'):
            stream = SmokeStream(); self.assertFalse(stream.accept(data))
            self.assertEqual(stream.result['state'], 'schema_rejected')
        stream = SmokeStream()
        for e in events(): self.assertTrue(stream.accept(json.dumps(e)))
        for field, value in (('usage', {'input_tokens': SECRET, 'output_tokens': 0}),
                             ('session_id', SECRET), ('extra', SECRET), ('effective_fast', True)):
            unsafe = copy.deepcopy(stream.result); unsafe[field] = value
            with self.assertRaises(ValueError): safe_result(unsafe)

    def test_fresh_authorization_preserves_old_markers_and_is_single_use(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); (base/'audit').mkdir()
            CredentialStore.create(base/'store')
            with CredentialStore(base/'store') as store:
                protected.provision(store, SECRET)
                originals = {}
                for name in ('check-used', 'smoke-used'):
                    path = store.path/'home'/name
                    path.write_bytes(b'previous-consumed-authorization'); path.chmod(0o400)
                    originals[name] = (path.stat(), path.read_bytes())
                with patch.object(protected, 'resolve_auth', return_value=(ipaddress.ip_address('93.184.216.34'),)), \
                        patch.object(protected.AmpEgress, 'connect', side_effect=AssertionError('Network prohibited')):
                    for bad in ('', '../check-used', 'a'*31, 'A'*32, 'b'*33, 3):
                        with self.assertRaises(ValueError):
                            protected.ProtectedAmpService(base/'audit'/'bad', store, 'smoke',
                                egress=protected.AmpEgress(timeout=32), smoke_authorization=bad)
                    for ident, data, state in (
                            ('a'*32, '\n'.join(json.dumps(e) for e in events())+'\n', 'compatible'),
                            ('b'*32, 'malformed\n', 'schema_rejected')):
                        service = protected.ProtectedAmpService(base/'audit'/ident, store, 'smoke',
                            egress=protected.AmpEgress(timeout=32), smoke_authorization=ident)
                        command = ['/usr/bin/python3.11','-I','-S','-c',f'print({data!r},end="",flush=True)']
                        with patch.object(service, 'command', return_value=command), service:
                            result = service.probe()
                        self.assertEqual(result['state'], state)
                        self.assertTrue((store.path/'home'/f'smoke-{ident}-used').exists())
                        again = protected.ProtectedAmpService(base/'audit'/(ident+'-again'), store, 'smoke',
                            egress=protected.AmpEgress(timeout=32), smoke_authorization=ident)
                        with self.assertRaises(FileExistsError):
                            with again: self.fail('Authorization reused')
                        self.assertIsNone(again.process)
                        anchor = base/(ident+'-root'); anchor.write_text(json.dumps({'root':service.receipt['root']}))
                        self.assertEqual(protected.verify(service.output, anchor)['outcome'], result)
                    failed = protected.ProtectedAmpService(base/'audit'/'spawn-failure', store, 'smoke',
                        egress=protected.AmpEgress(timeout=32), smoke_authorization='c'*32)
                    with patch('synthetic_harness.trusted_service.subprocess.Popen', side_effect=OSError('fixture')):
                        with self.assertRaises(OSError):
                            with failed: self.fail('Spawn unexpectedly succeeded')
                    self.assertTrue((store.path/'home'/('smoke-'+'c'*32+'-used')).exists())
                    legacy = protected.ProtectedAmpService(base/'audit'/'legacy', store, 'smoke',
                        egress=protected.AmpEgress(timeout=32))
                    with self.assertRaises(FileExistsError):
                        with legacy: self.fail('Legacy authorization reused')
                    for name, (info, data) in originals.items():
                        path = store.path/'home'/name
                        self.assertEqual((path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes()),
                                         (info.st_ino, info.st_mtime_ns, data))
                    self.assertFalse(list(sandbox.CGROUP.glob('service-*')))

    def test_smoke_requires_own_explicit_gate(self):
        for args in (['smoke'], ['smoke', '--enable-check-egress'], ['check', '--enable-smoke-egress'],
                     ['probe', '--smoke-authorization', 'a'*32],
                     ['smoke', '--enable-smoke-egress', '--smoke-authorization', '../smoke-used']):
            result = subprocess.run([sys.executable, '-m', 'synthetic_harness.amp_protected', *args],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
