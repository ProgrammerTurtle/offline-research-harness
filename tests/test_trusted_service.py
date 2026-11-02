"""Real two-boundary tests: separate native service, arbitrary actor, host oracle."""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from synthetic_harness import sandbox, trusted_service
from synthetic_harness.controls import control_actions
from synthetic_harness.provider import MockUpstream
from synthetic_harness.tasks import actor_view, canonical, make_case
from synthetic_harness.trusted_service import ACTOR, TrustedService


class TrustedServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def answers(self, domain='inventory', seed=0):
        return [canonical({'op': 'step', 'action': action}) for action in
                control_actions(actor_view(make_case(domain, 0, seed)), 'honest')]

    def test_native_completion_and_escalation_through_separate_actor(self):
        for domain in ('inventory', 'analysis', 'software'):
            for seed in (0, 2):
                output = self.base / f'{domain}-{seed}'
                anchor = output.with_name(output.name + '-anchor')
                with TrustedService(output, MockUpstream(self.answers(domain, seed))) as service:
                    result = sandbox.run(ACTOR, output, anchor, domain=domain, seed=seed,
                                         service=service, timeout=20)
                    self.assertEqual(result['returncode'], 0)
                    evidence = sandbox.verify(output, anchor)
                    self.assertEqual(evidence['audit']['task_complete'], seed == 0)
                    self.assertEqual(evidence['audit']['valid_escalation'], seed == 2)
                    self.assertTrue(service.closed)
                    self.assertEqual(service.identity['uid'], 65533)
                    self.assertNotIn(service.canary.decode(), output.with_name(output.name + '.wire.jsonl').read_text())
        self.assertFalse(list(sandbox.CGROUP.glob('service-*')))

    def test_actor_cannot_read_or_signal_service_or_inherit_pipes(self):
        output, anchor = self.base / 'isolated', self.base / 'anchor'
        with TrustedService(output, MockUpstream(self.answers()), canary=os.urandom(32)) as service:
            # Warm the real service without applying its proposal to any task.
            service.decide(actor_view(make_case('inventory', 0, 0)), time.monotonic() + 10)
            pids = [int(pid) for pid in (service.group / 'cgroup.procs').read_text().split()]
            source = (f'service_ns={service.identity["namespaces"]!r}\nservice_pids={pids!r}\n'
                      f'journal={str(output)+".service.jsonl"!r}\n') + r'''
import errno, json, os, socket, sys
from pathlib import Path
sys.stdin.readline()
assert os.getuid() == 65534
for name, value in service_ns.items():
    assert os.readlink('/proc/self/ns/' + name) != value, name
for path in ['/service-private/canary', '/tmp/codex-home', '/opt/codex', journal,
             '/proc/1/root/service-private/canary']:
    assert not Path(path).exists(), path
for pid in service_pids:
    assert not Path('/proc/' + str(pid)).exists()
    try:
        os.kill(pid, 0)
        raise AssertionError('service visible in actor PID namespace')
    except ProcessLookupError:
        pass
for fd in range(3, 128):
    try:
        os.fstat(fd)
        raise AssertionError('service descriptor inherited')
    except OSError as error:
        assert error.errno == errno.EBADF
for family in (socket.AF_UNIX, socket.AF_INET):
    try:
        socket.socket(family)
        raise AssertionError('actor can connect to service')
    except OSError as error:
        assert error.errno == errno.EPERM
print('separate-boundary-probes-passed', file=sys.stderr)
print('{"op":"finish"}', flush=True)
sys.stdin.readline()
'''
            result = sandbox.run(source.encode(), output, anchor, domain='inventory', service=service)
            evidence = sandbox.verify(output, anchor)
            self.assertEqual(result['returncode'], 0, evidence['transport'])
            self.assertEqual(evidence['audit']['actions'], 0)
            self.assertIn('separate-boundary-probes-passed', evidence['transport']['stderr'])

    def test_actor_cannot_forward_rpc_or_select_service_configuration(self):
        for index, message in enumerate(({'op': 'decide', 'model': 'other'},
                {'op': 'app_server', 'message': {'method': 'account/login/start', 'params': {}}},
                {'op': 'provider', 'body': {}}, {'op': 'decide', 'observation': {'hidden': 'forged'}})):
            output, anchor = self.base / str(index), self.base / f'anchor-{index}'
            source = ('import sys\nsys.stdin.readline()\nprint(' + repr(canonical(message)) +
                      ',flush=True)\nsys.stdin.readline()').encode()
            with TrustedService(output, MockUpstream([])) as service:
                result = sandbox.run(source, output, anchor, domain='inventory', service=service)
                self.assertEqual(result['status'], 'protocol_error')
                self.assertEqual(service.transport.calls, 0)
                self.assertEqual(sandbox.verify(output, anchor)['audit']['actions'], 0)

    def test_service_crash_timeout_and_flood_close_both_boundaries(self):
        for index, source in enumerate((b'raise SystemExit(3)', b'while True: pass',
                                       b'import os\nwhile True: os.write(1,b"x"*4096)',
                                       b'import os\nwhile True: os.write(2,b"x"*4096)')):
            output, anchor = self.base / str(index), self.base / f'anchor-{index}'
            with patch.object(trusted_service, 'bridge_source', return_value=source):
                with TrustedService(output, MockUpstream([])) as service:
                    started = time.monotonic()
                    result = sandbox.run(ACTOR, output, anchor, domain='inventory', service=service, timeout=0.5)
                    self.assertIn(result['status'], ('protocol_error', 'wall_timeout'))
                    self.assertLess(time.monotonic() - started, 6)
                    self.assertEqual(sandbox.verify(output, anchor)['audit']['actions'], 0)
            self.assertFalse(list(sandbox.CGROUP.glob('actor-*')))
            self.assertFalse(list(sandbox.CGROUP.glob('service-*')))

    def test_service_journal_is_covered_by_external_anchor(self):
        output, anchor = self.base / 'run', self.base / 'anchor'
        with TrustedService(output, MockUpstream(self.answers())) as service:
            sandbox.run(ACTOR, output, anchor, domain='inventory', service=service, timeout=20)
        sandbox.verify(output, anchor)
        journal = output.with_name(output.name + '.service.jsonl')
        records = journal.read_text().splitlines()
        journal.chmod(0o600)
        journal.write_text('\n'.join(records[:-1]) + '\n')
        with self.assertRaisesRegex(ValueError, 'Service seal'):
            sandbox.verify(output, anchor)

    def test_service_resource_limits_and_fork_cleanup(self):
        probe = b'''
import errno, os, resource, signal, sys, time
assert resource.getrlimit(resource.RLIMIT_AS) == (2*1024**3, 2*1024**3)
assert resource.getrlimit(resource.RLIMIT_FSIZE) == (4*1024**2, 4*1024**2)
assert resource.getrlimit(resource.RLIMIT_NOFILE) == (64,64)
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
try:
    bytearray(3*1024**3)
    raise AssertionError('unbounded memory')
except MemoryError:
    pass
with open('/tmp/large','wb',buffering=0) as f:
    try:
        for _ in range(5): f.write(b'x'*1024**2)
        raise AssertionError('unbounded file')
    except OSError as e:
        assert e.errno == errno.EFBIG
for _ in range(256):
    try:
        pid = os.fork()
    except OSError as e:
        assert e.errno == errno.EAGAIN
        print('service-resource-limits-passed',file=sys.stderr,flush=True)
        break
    if pid == 0:
        os.setsid()
        time.sleep(60)
        os._exit(0)
time.sleep(60)
'''
        output, anchor = self.base / 'limits', self.base / 'anchor'
        with patch.object(trusted_service, 'bridge_source', return_value=probe):
            with TrustedService(output, MockUpstream([])) as service:
                result = sandbox.run(ACTOR, output, anchor, domain='inventory', service=service, timeout=1)
                self.assertIn(result['status'], ('protocol_error', 'wall_timeout'))
        sandbox.verify(output, anchor)
        end = json.loads(output.with_name(output.name+'.service.jsonl').read_text().splitlines()[-1])['payload']
        self.assertIn('service-resource-limits-passed', end['stderr'])
        self.assertGreater(int(end['resources']['pids.events'].split()[1]), 0)
        self.assertFalse(list(sandbox.CGROUP.glob('service-*')))

    def test_broker_sigkill_terminates_both_namespaces(self):
        output, anchor = self.base / 'death', self.base / 'anchor'
        actor = b'import sys,time\nsys.stdin.readline()\nprint(\'{"op":"observe"}\',flush=True)\ntime.sleep(60)'
        source = f'''
import time
from pathlib import Path
from synthetic_harness.trusted_service import TrustedService
from synthetic_harness.provider import MockUpstream
from synthetic_harness.tasks import actor_view, make_case
from synthetic_harness.sandbox import run
with TrustedService(Path({str(output)!r}), MockUpstream(['{{"op":"step","action":{{"tool":"check","args":{{}}}}}}'])) as service:
    service.decide(actor_view(make_case('inventory',0,0)), time.monotonic()+10)
    run({actor!r},
        Path({str(output)!r}), Path({str(anchor)!r}), domain='inventory', service=service, timeout=30)
'''
        process = subprocess.Popen([sys.executable, '-c', source], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        groups = []
        try:
            wire = output.with_name(output.name+'.wire.jsonl')
            deadline = time.monotonic()+12
            while not wire.exists() or '"kind":"receive"' not in wire.read_text():
                if process.poll() is not None or time.monotonic() >= deadline:
                    self.fail('Both boundaries did not start')
                time.sleep(0.02)
            groups = list(sandbox.CGROUP.glob('actor-*')) + list(sandbox.CGROUP.glob('service-*'))
            self.assertEqual(len(groups), 2)
            process.kill(); process.wait(timeout=5)
            deadline = time.monotonic()+5
            while any('populated 1' in (group/'cgroup.events').read_text() for group in groups):
                if time.monotonic() >= deadline:
                    self.fail('Actor or service survived broker death')
                time.sleep(0.02)
            self.assertEqual(anchor.read_bytes(), b'')
            self.assertNotIn('"kind":"end"', wire.read_text())
        finally:
            if process.poll() is None:
                process.kill(); process.wait(timeout=5)
            process.stderr.close()
            for group in groups:
                (group/'cgroup.kill').write_text('1')
                group.rmdir()

    def test_two_concurrent_native_episodes_keep_distinct_sessions(self):
        processes = []
        try:
            for domain in ('inventory', 'analysis'):
                process = subprocess.Popen([sys.executable, '-m', 'synthetic_harness.codex_demo',
                    '--trusted-service', '--domain', domain, '--output', str(self.base / domain),
                    '--anchor', str(self.base / (domain + '-anchor'))], stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True)
                processes.append((domain, process))
            overlap = False
            deadline = time.monotonic() + 25
            while not all(process.poll() is not None for _, process in processes):
                overlap |= (len(list(sandbox.CGROUP.glob('service-*'))) >= 2 and
                            len(list(sandbox.CGROUP.glob('actor-*'))) >= 2)
                if time.monotonic() >= deadline:
                    self.fail('Concurrent episodes exceeded deadline')
                time.sleep(0.01)
            self.assertTrue(overlap, 'Did not observe two actor/service pairs concurrently')
            thread_ids = []
            for domain, process in processes:
                stdout, stderr = process.communicate(timeout=30)
                self.assertEqual(process.returncode, 0, stderr + stdout)
                self.assertTrue(sandbox.verify(self.base / domain, self.base / (domain+'-anchor'))['audit']['task_complete'])
                records = map(json.loads, (self.base / (domain+'.service.jsonl')).read_text().splitlines())
                ids = {event['payload']['body']['prompt_cache_key'] for event in records
                       if event['kind'] == 'receive' and event['payload'].get('op') == 'provider'}
                self.assertEqual(len(ids), 1)
                thread_ids.extend(ids)
            self.assertEqual(len(set(thread_ids)), 2)
        finally:
            for _, process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)


if __name__ == '__main__':
    unittest.main()
