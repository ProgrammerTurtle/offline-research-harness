"""Separate, offline-only Codex service. No authentication or host home discovery.

The supervisor is trusted host code; only its frozen bridge/native CLI enters
the service namespace. Arbitrary actor code runs in a different sandbox.
"""

import hashlib
import os
import platform
import resource
import select
import subprocess
import tempfile
import threading
import time
from contextlib import ExitStack
from pathlib import Path

from . import sandbox
from .app_server import AppServerTransport, Gateway, bridge_source
from .codex_runtime import DEFAULT_RUNTIME, verify as verify_runtime
from .protocol import parse_request
from .runner import EventLog
from .tasks import canonical

# Native SQLite/runtime thread startup grows under CPU contention.
SERVICE_PIDS = 128

IDENTITY = b'''
import hashlib, json, os
from pathlib import Path
print(json.dumps({'op':'service_identity', 'uid':os.getuid(),
    'namespaces':{name:os.readlink('/proc/self/ns/'+name) for name in
        ('user','pid','mnt','net','ipc','uts','cgroup')},
    'private_canary_sha256':hashlib.sha256(Path('/service-private/canary').read_bytes()).hexdigest()}), flush=True)
'''

ACTOR = b'''
import json, sys
json.loads(sys.stdin.readline())
for _ in range(5):
    print('{"op":"decide"}', flush=True)
    action = json.loads(sys.stdin.readline())['action']
    print(json.dumps({'op':'step','action':action}), flush=True)
    json.loads(sys.stdin.readline())
    if action['tool'] in ('finish','escalate'):
        break
'''


class PublicObservation:
    """No oracle, fixture constructor, step method, or audit state."""
    def __init__(self, observation):
        self.observation = observation

    def observe(self):
        return self.observation


class TrustedService:
    log_type = EventLog
    max_frames = 256
    wire_bytes = 2 * 1024 * 1024
    cpu_seconds = 3

    def source(self):
        return IDENTITY + bridge_source()

    def mounts(self, private_fd):
        return ['--dir', '/service-private', '--ro-bind-data',
                str(private_fd), '/service-private/canary']

    def extra_fds(self):
        return ()

    def __init__(self, output, upstream, *, runtime=DEFAULT_RUNTIME, canary=b'offline-service-canary'):
        # Synthetic bytes only: never a path to an existing credential store.
        if type(canary) is not bytes or not 1 <= len(canary) <= 4096:
            raise ValueError('Expected bounded synthetic canary bytes')
        self.output = Path(output).absolute()
        self.runtime, self.canary = runtime, canary
        self.transport = AppServerTransport(upstream)
        self.gateway = Gateway(deferred=True)
        self.process = self.group = self.log = None
        self.stack = ExitStack()
        self.buffer = bytearray()
        self.stderr = bytearray()
        self.identity = None
        self.total = self.frames = 0
        self.started = False
        self.closed = False
        self.receipt = None
        self.configuration = None

    def __enter__(self):
        if self.started or self.closed:
            raise ValueError('Service instances are single-use')
        if os.geteuid() == 0 or platform.machine() != 'x86_64' or platform.system() != 'Linux' \
                or threading.active_count() != 1:
            raise RuntimeError('Requires single-threaded unprivileged Linux x86-64 host')
        runtime = verify_runtime(self.runtime)
        current = Path('/sys/fs/cgroup') / Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1].lstrip('/')
        if not current.is_relative_to(sandbox.CGROUP) or current == sandbox.CGROUP:
            raise RuntimeError('Enroll broker in delegated cgroup subtree first')
        try:
            self.group = Path(tempfile.mkdtemp(prefix='service-', dir=sandbox.CGROUP))
            for key, value in {'memory.max': sandbox.CODEX_MEMORY, 'memory.swap.max': 0,
                               'memory.oom.group': 1, 'pids.max': SERVICE_PIDS,
                               'cpu.max': '50000 100000'}.items():
                (self.group / key).write_text(str(value))
                if (self.group / key).read_text().strip() != str(value):
                    raise RuntimeError('Service cgroup control not applied')
            if not (self.group / 'cgroup.kill').exists():
                raise RuntimeError('cgroup.kill required')
            program = self.stack.enter_context(tempfile.TemporaryFile())
            bpf = self.stack.enter_context(tempfile.TemporaryFile())
            private = self.stack.enter_context(tempfile.TemporaryFile())
            source = self.source()
            program.write(source); program.seek(0)
            private.write(self.canary); private.seek(0)
            sandbox.seccomp_filter(bpf, codex=True, app_server=True)
            filter_hash = hashlib.sha256(bpf.read()).hexdigest(); bpf.seek(0)
            args = sandbox.command(program.fileno(), bpf.fileno(), self.runtime)
            args[args.index('--uid') + 1] = '65533'
            args[args.index('--gid') + 1] = '65533'
            args[args.index('--hostname') + 1] = 'offline-service'
            index = args.index('--remount-ro', args.index('--chdir'))
            args[index:index] = self.mounts(private.fileno())
            self.configuration = {'kind': 'separate-offline-service', 'runtime': runtime,
                'actor_sha256': hashlib.sha256(source).hexdigest(),
                'filter_sha256': filter_hash, 'private_canary_sha256': hashlib.sha256(self.canary).hexdigest(),
                'namespace_uid': 65533, 'memory_bytes': sandbox.CODEX_MEMORY,
                'pids': SERVICE_PIDS, 'file_bytes': 4 * 1024 * 1024,
                'tmp_bytes': sandbox.TMP_BYTES, 'max_frames': self.max_frames, 'wire_bytes': self.wire_bytes,
                'cpu_seconds': self.cpu_seconds,
                'provider': self.transport.configuration}
            self.log = self.log_type(self.output.with_name(self.output.name + '.service.jsonl'))
            self.log.append('configuration', self.configuration)

            def limits():
                (self.group / 'cgroup.procs').write_text(str(os.getpid()))
                for which, value in ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_NOFILE, 64),
                                     (resource.RLIMIT_FSIZE, 4 * 1024 * 1024),
                                     (resource.RLIMIT_AS, sandbox.CODEX_ADDRESS_SPACE), (resource.RLIMIT_CPU, self.cpu_seconds)):
                    resource.setrlimit(which, (value, value))

            self.process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True, cwd='/',
                env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'},
                pass_fds=(program.fileno(), bpf.fileno(), private.fileno()) + self.extra_fds(), preexec_fn=limits)
            os.set_blocking(self.process.stdin.fileno(), False)
            os.set_blocking(self.process.stdout.fileno(), False)
            os.set_blocking(self.process.stderr.fileno(), False)
            self.started = True
            return self
        except BaseException:
            self.finish()
            raise

    def write(self, message, deadline):
        data = (canonical(message) + '\n').encode()
        if len(data) > 256 * 1024:
            raise ValueError('Service write budget exceeded')
        self.log.append('send', message)
        while data:
            if time.monotonic() >= deadline or not select.select(
                    [], [self.process.stdin], [], max(0, deadline-time.monotonic()))[1]:
                raise ValueError('Service deadline expired')
            data = data[os.write(self.process.stdin.fileno(), data):]

    def read(self, deadline):
        while b'\n' not in self.buffer:
            readable = select.select([self.process.stdout, self.process.stderr], [], [],
                                     max(0, deadline-time.monotonic()))[0]
            if time.monotonic() >= deadline or not readable:
                raise ValueError('Service deadline expired')
            if self.process.stderr in readable:
                self.stderr.extend(os.read(self.process.stderr.fileno(), 4096)[:sandbox.MAX_STDERR-len(self.stderr)])
                if len(self.stderr) >= sandbox.MAX_STDERR:
                    raise ValueError('Service stderr budget exceeded')
            if self.process.stdout not in readable:
                continue
            data = os.read(self.process.stdout.fileno(), 4096)
            if not data:
                raise ValueError('Service closed its pipe')
            self.total += len(data)
            self.buffer.extend(data)
            if self.total > self.wire_bytes or len(self.buffer) > 256 * 1024:
                raise ValueError('Service output budget exceeded')
        line, _, remaining = self.buffer.partition(b'\n')
        self.buffer = bytearray(remaining)
        self.frames += 1
        if self.frames > self.max_frames:
            raise ValueError('Service frame budget exceeded')
        message = parse_request(line.decode('utf-8'), 256 * 1024)
        self.log.append('receive', message)
        return message

    def decide(self, observation, deadline):
        if not self.started or self.closed:
            raise ValueError('Service unavailable')
        public = PublicObservation(observation)
        try:
            if self.gateway.phase == 'ready':
                self.write({'service': 'offline'}, deadline)
            elif self.gateway.phase == 'awaiting_observation':
                self.write({'messages': [self.gateway.next_turn(public)], 'stop': False}, deadline)
            else:
                raise ValueError('Unexpected service phase')
            while True:
                message = self.read(deadline)
                if message.get('op') == 'service_identity':
                    if self.identity is not None or message.get('uid') != 65533 \
                            or message.get('private_canary_sha256') != self.configuration['private_canary_sha256']:
                        raise ValueError('Service identity mismatch')
                    namespaces = message.get('namespaces', {})
                    if set(namespaces) != {'user','pid','mnt','net','ipc','uts','cgroup'} or any(
                            value == os.readlink('/proc/self/ns/' + name) for name, value in namespaces.items()):
                        raise ValueError('Service namespace isolation missing')
                    self.identity = message
                    continue
                if self.identity is None:
                    raise ValueError('Service identity missing')
                if message.get('op') == 'provider':
                    reply = self.transport.exchange(message)
                elif message.get('op') == 'app_server':
                    reply = self.gateway.exchange(message, public)
                    if 'action' in reply:
                        self.log.append('proposal', reply)
                        # Leave the bridge waiting for its next host response.
                        # The actor never receives the service pipe or RPC IDs.
                        return reply
                else:
                    raise ValueError('Unknown service envelope')
                self.write(reply, deadline)
                if reply.get('stop'):
                    raise ValueError('Service declined request')
        except (ValueError, OSError) as error:
            self.log.append('failure', {'type': type(error).__name__})
            self.finish()
            raise ValueError('Trusted service failed closed') from error

    def finish(self):
        if self.closed:
            return self.receipt
        self.closed = True
        try:
            resources = {}
            if self.group is not None:
                (self.group / 'cgroup.kill').write_text('1')
                if self.process is not None:
                    self.process.wait(timeout=5)
                    self.stderr.extend(self.process.stderr.read(sandbox.MAX_STDERR-len(self.stderr)) or b'')
                deadline = time.monotonic() + 5
                while 'populated 1' in (self.group / 'cgroup.events').read_text():
                    if time.monotonic() >= deadline:
                        raise RuntimeError('Service descendants survived cleanup')
                    time.sleep(0.01)
                resources = {name: (self.group / name).read_text().strip()
                             for name in ('memory.events', 'pids.events', 'cpu.stat')}
                self.group.rmdir()
            if self.log is not None:
                self.log.append('end', {'resources': resources, 'frames': self.frames,
                    'provider_calls': self.transport.calls,
                    'stderr': self.stderr.decode('utf-8', errors='replace'),
                    'returncode': self.process.returncode if self.process else None})
                self.log.seal()
                self.receipt = {'root': self.log.root, 'provider_calls': self.transport.calls}
            return self.receipt
        finally:
            if self.process is not None:
                self.process.stdin.close(); self.process.stdout.close(); self.process.stderr.close()
            self.stack.close()

    def __exit__(self, *_):
        self.finish()
