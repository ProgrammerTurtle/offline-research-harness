"""Offline envelope/polling diagnosis; production bounds are never raised."""
import ipaddress
import json
import socket
import tempfile
import time
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

from synthetic_harness import amp_protected as protected, sandbox
from synthetic_harness.amp_smoke import initial_result, safe_result
from synthetic_harness.login import CredentialStore
from synthetic_harness.trusted_service import ServiceBoundaryError

SECRET = 'PRIVATE-BOUNDARY-FIXTURE'


class AmpBoundaryTests(unittest.TestCase):
    def test_exact_envelope_boundary_and_secret_safe_categories(self):
        progress = initial_result(); progress['stage'] = 'awaiting_init'
        final = dict(progress, state='native_failed', exit_code=1)
        line = json.dumps({'op': 'smoke_progress', 'result': progress})
        terminal = json.dumps({'op': 'smoke_result', 'result': final})
        prefix = f'import sys,time\nprint({line!r},flush=True)\n'
        cases = [
            ('256', f'import sys\nfor _ in range(255): print({line!r},flush=True)\nprint({terminal!r},flush=True)', 'native_failed'),
            ('257', f'import sys\nfor _ in range(256): print({line!r},flush=True)\nprint({terminal!r},flush=True)', 'service_envelope_limit'),
            ('bytes', f'import sys\nfor _ in range(40): print({line!r}.ljust(65536),flush=True)', 'service_byte_limit'),
            ('buffer', prefix+f'sys.stdout.write({SECRET!r}+"x"*262144);sys.stdout.flush()', 'service_buffer_limit'),
            ('pipe', prefix, 'service_pipe_closed'),
            ('deadline', prefix+'time.sleep(60)', 'service_deadline'),
            ('stderr', prefix+f'sys.stderr.write({SECRET!r}+"x"*65536);sys.stderr.flush();time.sleep(60)', 'service_stderr_limit'),
            ('schema', prefix+f'print({SECRET!r},flush=True)', 'service_envelope_schema'),
            ('io', prefix+'time.sleep(60)', 'service_pipe_io')]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); (base/'audit').mkdir()
            for name, code, expected in cases:
                with self.subTest(name=name):
                    CredentialStore.create(base/name)
                    with CredentialStore(base/name) as store:
                        protected.provision(store, SECRET)
                        with patch.object(protected, 'resolve_auth', return_value=(ipaddress.ip_address('93.184.216.34'),)):
                            egress = protected.AmpEgress(timeout=32)
                        service = protected.ProtectedAmpService(base/'audit'/name, store, 'smoke', egress=egress)
                        self.assertEqual((service.max_frames, service.wire_bytes), (256, 2*1024*1024))
                        started = time.monotonic()
                        with patch.object(protected.AmpEgress, 'connect', side_effect=AssertionError('Network forbidden')), \
                                patch.object(service, 'source', return_value=code.encode()), service:
                            with (patch('synthetic_harness.trusted_service.os.read', side_effect=OSError(SECRET))
                                  if name == 'io' else nullcontext()):
                                result = service.probe()
                        elapsed = time.monotonic()-started
                        self.assertEqual(result['state'], expected)
                        self.assertLess(elapsed, 37)
                        counters = result['host_transport']
                        self.assertEqual(counters['egress_opens'], 0)
                        if name in ('256', '257'):
                            self.assertEqual(counters['received_envelopes'], int(name))
                            self.assertLess(counters['wire_bytes'], service.wire_bytes)
                        if name == 'bytes':
                            self.assertGreater(counters['wire_bytes'], service.wire_bytes)
                            self.assertLess(counters['received_envelopes'], 256)
                        if name == 'deadline':
                            self.assertGreaterEqual(counters['elapsed_ms'], 32000)
                        anchor = base/(name+'-anchor'); anchor.write_text(json.dumps({'root': service.receipt['root']}))
                        self.assertEqual(protected.verify(service.output, anchor)['outcome'], result)
                        records = [json.loads(x) for x in Path(str(service.output)+'.service.jsonl').read_text().splitlines()]
                        self.assertNotIn(SECRET, json.dumps(records))
                        if name in ('256', '257'):
                            self.assertEqual(sum(r['kind']=='receive' for r in records), 256)
                        self.assertTrue(egress.closed)
                        self.assertFalse(list(sandbox.CGROUP.glob('service-*')))
                        print('boundary-fixture', name, json.dumps({'state':result['state'], **counters}), flush=True)

    def test_unmodified_proxy_idle_polling_exhausts_budget_without_payload(self):
        # A client holds CONNECT open. No model, TLS or provider is involved.
        # The production Proxy and host relay perform all polling themselves.
        child = r'''import os,socket,time
from urllib.parse import urlparse
p=urlparse(os.environ['HTTPS_PROXY'])
s=socket.create_connection((p.hostname,p.port))
s.sendall(b'CONNECT ampcode.com:443 HTTP/1.1\r\nHost: ampcode.com:443\r\n\r\n')
data=b''
while b'\r\n\r\n' not in data: data+=s.recv(1)
assert b'200' in data
time.sleep(60)
'''
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); (base/'audit').mkdir()
            for mode, payload in (('idle', b''), ('one_payload', b'fixture')):
                CredentialStore.create(base/mode)
                with CredentialStore(base/mode) as store:
                    protected.provision(store, SECRET)
                    with patch.object(protected, 'resolve_auth', return_value=(ipaddress.ip_address('93.184.216.34'),)):
                        egress = protected.AmpEgress(timeout=32)
                    service = protected.ProtectedAmpService(base/'audit'/mode, store, 'smoke', egress=egress)
                    command = ['/usr/bin/python3.11', '-I', '-S', '-c', child]
                    left, right = socket.socketpair(); left.setblocking(False)
                    try:
                        if payload: right.sendall(payload)
                        with patch.object(protected.AmpEgress, 'connect', side_effect=AssertionError('External network forbidden')), \
                                patch.object(egress, 'connect', return_value=left), patch.object(service, 'command', return_value=command), service:
                            result = service.probe()
                        self.assertEqual(result['state'], 'service_envelope_limit')
                        self.assertEqual(result['stage'], 'awaiting_init')
                        counters = result['host_transport']
                        self.assertEqual(counters['received_envelopes'], 257)
                        self.assertEqual(counters['egress_opens'], 1)
                        self.assertEqual(counters['transfer_envelopes'], 254)
                        self.assertEqual(counters['idle_polls'], 254 if not payload else 253)
                        self.assertEqual(counters['sent_bytes'], 0)
                        self.assertEqual(counters['received_bytes'], len(payload))
                        self.assertLess(counters['elapsed_ms'], 30000)
                        self.assertLess(counters['wire_bytes'], 65536)
                        anchor = base/(mode+'-anchor'); anchor.write_text(json.dumps({'root':service.receipt['root']}))
                        self.assertEqual(protected.verify(service.output, anchor)['outcome'], result)
                        self.assertNotIn(SECRET, Path(str(service.output)+'.service.jsonl').read_text())
                        self.assertTrue(egress.closed)
                        self.assertFalse(list(sandbox.CGROUP.glob('service-*')))
                        print('proxy-polling', mode, json.dumps(counters), flush=True)
                    finally:
                        left.close(); right.close()

    def test_diagnostics_allowlist_and_old_evidence_compatibility(self):
        result = initial_result(); result['state'] = 'boundary_failed'
        self.assertEqual(safe_result(result), result)  # Old schema without counters.
        for reason in ServiceBoundaryError.codes:
            self.assertEqual(safe_result(dict(result, state=reason))['state'], reason)
        self.assertNotIn(SECRET, str(ServiceBoundaryError(SECRET)))
        for value in (dict(result, state=SECRET), dict(result, host_transport={'wire_bytes': SECRET})):
            with self.assertRaises(ValueError): safe_result(value)
