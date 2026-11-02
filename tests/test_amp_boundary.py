"""Offline envelope/polling diagnosis; production bounds are never raised."""
import ipaddress
import json
import socket
import subprocess
import sys
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
from test_amp_smoke import events

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

    def test_idle_backoff_traffic_fairness_deadline_flood_and_cancellation(self):
        # Real namespace/proxy/relay, synthetic child and local socket pairs only.
        child = r'''import os,socket,time,threading,sys
from urllib.parse import urlparse
p=urlparse(os.environ['HTTPS_PROXY'])
sockets=[]
for i in range(count):
    s=socket.create_connection((p.hostname,p.port))
    s.sendall(b'CONNECT ampcode.com:443 HTTP/1.1\r\nHost: ampcode.com:443\r\n\r\n')
    data=b''
    while b'\r\n\r\n' not in data: data+=s.recv(1)
    assert b'200' in data
    sockets.append(s)
if mode=='traffic':
    errors=[]
    def receive(s,expected):
        data=b''
        while len(data)<len(expected):
            chunk=s.recv(len(expected)-len(data))
            assert chunk
            data+=chunk
        assert data==expected
    def work(i,s):
        try:
            s.settimeout(6)
            time.sleep(3+i*.1)
            if i==0:
                for _ in range(20):
                    s.sendall(b'!'); receive(s,b'!'); time.sleep(.02)
            s.sendall(('client-'+str(i)).encode())
            receive(s,('server-'+str(i)).encode())
            s.sendall(('ack-'+str(i)).encode())
            receive(s,('done-'+str(i)).encode())
            s.close()
        except Exception:
            errors.append(True)
    workers=[threading.Thread(target=work,args=(i,s)) for i,s in enumerate(sockets)]
    for t in workers: t.start()
    for t in workers: t.join()
    assert not errors
elif mode=='flood':
    time.sleep(2); sys.stdout.write('x'*262145); sys.stdout.flush(); time.sleep(60)
else:
    time.sleep(60)
'''
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); (base/'audit').mkdir()
            for mode, count, expected in (('traffic', 4, 'compatible'), ('idle', 1, 'timeout'),
                    ('four_idle', 4, 'timeout'), ('flood', 4, 'output_limit'), ('cancel', 4, 'interrupted')):
                CredentialStore.create(base/mode)
                with CredentialStore(base/mode) as store:
                    protected.provision(store, SECRET)
                    with patch.object(protected, 'resolve_auth', return_value=(ipaddress.ip_address('93.184.216.34'),)):
                        egress = protected.AmpEgress(timeout=32)
                    service = protected.ProtectedAmpService(base/'audit'/mode, store, 'smoke', egress=egress)
                    good = '\n'.join(json.dumps(e) for e in events())+'\n'
                    code = f'count={count}\nmode={mode!r}\n'+child+f'print({good!r},end="",flush=True)\n'
                    command = ['/usr/bin/python3.11', '-I', '-S', '-c', code]
                    pairs = [socket.socketpair() for _ in range(count)]
                    for pair in pairs:
                        for sock in pair: sock.setblocking(False)
                    received = [b'']*count
                    challenge_at, client_at, ack_at = {}, {}, {}
                    ping_count = 0
                    original_exchange, original_read = egress.exchange, service.read
                    started = time.monotonic()
                    peer = None

                    def exchange(request):
                        nonlocal ping_count
                        if mode != 'traffic' or request['op'] != 'transfer':
                            return original_exchange(request)
                        i = request['connection']-1
                        right = pairs[i][1]
                        response = original_exchange(request)
                        if response['sent']:
                            data = right.recv(response['sent'])
                            # One busy tunnel exchanges 20 round trips while the
                            # other three independently wake from idle backoff.
                            if i == 0 and data == b'!':
                                right.sendall(data); ping_count += 1
                            else:
                                received[i] += data
                                if received[i].startswith(f'client-{i}'.encode()):
                                    client_at.setdefault(i, time.monotonic())
                                if received[i] == f'client-{i}ack-{i}'.encode() and i not in ack_at:
                                    ack_at[i] = time.monotonic()
                                    right.sendall(f'done-{i}'.encode())
                        return response

                    def read(deadline):
                        value = original_read(deadline)
                        if mode == 'cancel' and egress.opens == count and time.monotonic()-started > 2:
                            raise KeyboardInterrupt()
                        return value

                    try:
                        with patch.object(protected.AmpEgress, 'connect', side_effect=AssertionError('External network forbidden')), \
                                patch.object(egress, 'connect', side_effect=[p[0] for p in pairs]), \
                                patch.object(egress, 'exchange', side_effect=exchange), \
                                patch.object(service, 'read', side_effect=read), \
                                patch.object(service, 'command', return_value=command), service:
                            if mode == 'traffic':
                                # Independent timed upstream arrival, not a reply
                                # synthesized only when a polling request arrives.
                                sender = '''import json,socket,sys,time
sockets=[socket.socket(fileno=int(fd)) for fd in sys.argv[1:]]
time.sleep(7)
times=[]
for i,s in enumerate(sockets):
    times.append(time.monotonic()); s.sendall(('server-'+str(i)).encode()); time.sleep(.15)
print(json.dumps(times),flush=True)
'''
                                fds = [p[1].fileno() for p in pairs]
                                peer = subprocess.Popen([sys.executable, '-I', '-c', sender, *map(str,fds)],
                                    pass_fds=fds, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    env={'PATH':'/usr/bin','LANG':'C.UTF-8'})
                            result = service.probe()
                        elapsed = time.monotonic()-started
                        self.assertEqual(result['state'], expected, (ping_count, received, sorted(ack_at)))
                        counters = result['host_transport']
                        self.assertEqual((service.max_frames, service.wire_bytes), (256, 2*1024*1024))
                        self.assertLess(counters['received_envelopes'], 256)
                        self.assertEqual(counters['egress_opens'], count)
                        self.assertLess(counters['wire_bytes'], 65536)
                        if mode in ('idle', 'four_idle'):
                            self.assertEqual(counters['sent_bytes']+counters['received_bytes'], 0)
                            self.assertEqual(counters['idle_polls'], counters['transfer_envelopes'])
                            self.assertEqual(counters['received_envelopes'],
                                             counters['idle_polls']+count+2)  # Opens + progress + result.
                            self.assertGreaterEqual(counters['elapsed_ms'], 30000)
                            self.assertLess(elapsed, 35)
                        elif mode == 'traffic':
                            times, _ = peer.communicate(timeout=2)
                            self.assertEqual(peer.returncode, 0)
                            challenge_at = dict(enumerate(json.loads(times)))
                            self.assertEqual(received, [f'client-{i}ack-{i}'.encode() for i in range(count)])
                            self.assertEqual(ping_count, 20)
                            self.assertEqual(counters['sent_bytes'], 20+4*(8+5))
                            self.assertEqual(counters['received_bytes'], 20+4*(8+6))
                            self.assertEqual(egress.bytes, counters['sent_bytes']+counters['received_bytes'])
                            self.assertEqual(set(ack_at), set(range(count)))
                            self.assertTrue(all(ack_at[i]-challenge_at[i] < 2.5 for i in range(count)))
                            self.assertTrue(all(client_at[i]-started < 5 for i in (1,2,3)))
                        else:
                            self.assertLess(elapsed, 6)
                        anchor = base/(mode+'-anchor'); anchor.write_text(json.dumps({'root':service.receipt['root']}))
                        self.assertEqual(protected.verify(service.output, anchor)['outcome'], result)
                        self.assertNotIn(SECRET, Path(str(service.output)+'.service.jsonl').read_text())
                        self.assertTrue(egress.closed)
                        self.assertFalse(list(sandbox.CGROUP.glob('service-*')))
                        print('proxy-backoff', mode, json.dumps({'state':result['state'], **counters,
                              'ack_latency_ms':[round((ack_at[i]-challenge_at[i])*1000) for i in sorted(ack_at)]}), flush=True)
                    finally:
                        if peer is not None:
                            if peer.poll() is None: peer.terminate()
                            peer.communicate(timeout=2)
                        for pair in pairs:
                            for sock in pair: sock.close()

    def test_diagnostics_allowlist_and_old_evidence_compatibility(self):
        result = initial_result(); result['state'] = 'boundary_failed'
        self.assertEqual(safe_result(result), result)  # Old schema without counters.
        for reason in ServiceBoundaryError.codes:
            self.assertEqual(safe_result(dict(result, state=reason))['state'], reason)
        self.assertNotIn(SECRET, str(ServiceBoundaryError(SECRET)))
        for value in (dict(result, state=SECRET), dict(result, host_transport={'wire_bytes': SECRET})):
            with self.assertRaises(ValueError): safe_result(value)
