"""Operator-only Amp credential boundary. No login or model commands enabled."""

import argparse
import getpass
import inspect
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

from .amp_execute import AmpRuntimeProbe, SETTINGS, AMP_SHA256
from .auth_egress import AuthEgress, resolve_auth
from .login import CredentialStore, verify as verify_chain
from .runner import EventLog
from .tasks import canonical
from .trusted_service import TrustedService


PROBE_STATES = frozenset({'runtime_ready', 'runtime_failed', 'timeout', 'interrupted', 'boundary_failed',
                          'authenticated', 'application_response_invalid', 'native_failed'})


def check_output(returncode, data):
    """Classify a bounded native list result without returning any metadata."""
    import json
    if returncode != 0:
        return 'native_failed'
    if len(data) > 65536:
        return 'application_response_invalid'
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError()
            result[key] = value
        return result
    try:
        value = json.loads(data, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if type(value) is not list or len(value) > 1:
            raise ValueError()
        for thread in value:
            # Native CLI owns the record fields. Validate the list contract,
            # not guessed fields or the content of private thread metadata.
            if type(thread) is not dict or not thread:
                raise ValueError()
    except (ValueError, TypeError, RecursionError):
        return 'application_response_invalid'
    return 'authenticated'


class AmpEgress(AuthEgress):
    """Opaque TCP to one public authority; not a URL-path or inference firewall."""
    authority = 'ampcode.com:443'

    def resolve(self):
        return resolve_auth('ampcode.com')

    def __init__(self, *, timeout=900, single_connection=False):
        self.single_connection = single_connection
        super().__init__(timeout=timeout)

    def _exchange(self, request):
        if self.single_connection and type(request) is dict and request.get('op') == 'open' and self.opens:
            raise ValueError('Check reconnect prohibited')
        return super()._exchange(request)


def provision(store, value):
    """Only explicitly supplied bytes; never search environment/home/keychains."""
    if store.fd is None or type(value) is not str or not 1 <= len(value) <= 4096 \
            or any(not 33 <= ord(char) <= 126 for char in value):
        raise ValueError('Credential input rejected')
    fd = os.open('amp-key', os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                 0o400, dir_fd=store.fd)
    with os.fdopen(fd, 'w') as target:
        target.write(value)
        target.flush()
        os.fsync(target.fileno())
    os.fsync(store.fd)


class ProtectedLog(EventLog):
    def append(self, kind, payload):
        if kind == 'configuration':
            safe = {'profile': 'amp-protected-offline', 'binary_sha256': AMP_SHA256,
                    'program_sha256': payload['actor_sha256'], 'filter_sha256': payload['filter_sha256']}
        elif kind in ('send', 'receive', 'end', 'failure'):
            safe = {}  # Never serialize bytes, exceptions, stderr, paths or account data.
        elif kind == 'probe_result':
            state = payload.get('state')
            safe = {'state': state if type(state) is str and state in
                    PROBE_STATES
                    else 'boundary_failed', 'authenticated': True if state == 'authenticated' else None}
        else:
            raise ValueError('Unknown protected event')
        super().append(kind, safe)


class ProtectedAmpService(AmpRuntimeProbe):
    log_type = ProtectedLog

    def __init__(self, output, store, operation='--version', *, egress=None):
        super().__init__(output, '--version' if operation == 'check' else operation)
        self.operation = operation
        if store.fd is None:
            raise ValueError('Exclusive explicit store lease required')
        audit = Path(output).absolute().parent.resolve()
        if audit.is_relative_to(store.path) or store.path.is_relative_to(audit):
            raise ValueError('Keep audit and credential directories separate')
        if egress is not None and (type(egress) is not AmpEgress or egress.closed):
            raise ValueError('Restricted Amp transport required')
        if operation == 'check' and (egress is None or not egress.single_connection):
            raise ValueError('Check requires explicit single-connection egress')
        self.store, self.egress, self.sequence = store, egress, 0
        self.key_fd = None

    def mounts(self, private_fd):
        mounts = super().mounts(private_fd)
        fd = os.open('amp-key', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.store.fd)
        self.key_fd = fd
        self.stack.callback(os.close, fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() \
                or stat.S_IMODE(info.st_mode) != 0o400 or info.st_nlink != 1 or not 1 <= info.st_size <= 4096:
            raise ValueError('Protected credential file rejected')
        if self.operation == 'check':
            # Reserve before launching native code. Failure/crash consumes this
            # store's check; never remove or automatically reset this marker.
            marker = os.open('check-used', os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                             0o400, dir_fd=self.store.fd)
            os.fsync(marker); os.close(marker); os.fsync(self.store.fd)
        return mounts + ['--ro-bind', f'/proc/self/fd/{fd}', '/service-private/amp-key']

    def extra_fds(self):
        return (self.key_fd,)

    def command(self):
        if self.operation == 'check':
            return ['/opt/amp','threads','list','--limit','1','--json',
                    '--settings-file','/tmp/amp-settings.json']
        return ['/opt/amp', self.operation, '--settings-file', '/tmp/amp-settings.json']

    def source(self):
        # Reuse only the bounded CONNECT relay, not the Codex RPC runner.
        bridge = Path(__file__).with_name('login_bridge.py').read_text()
        return (bridge + '\n' + inspect.getsource(check_output) + f'''
from pathlib import Path
import tempfile
os.umask(0o077)
Path('/tmp/amp-settings.json').write_text({canonical(SETTINGS)!r})
Proxy.authority='ampcode.com:443'
def responses():
    try:
        while True:
            line=sys.stdin.buffer.readline(65537)
            if not line.endswith(b'\\n') or len(line)>65536: raise ValueError()
            message=json.loads(line)
            if set(message)!={{'op','id','response'}} or message['op']!='egress': raise ValueError()
            with OUT: PENDING[message['id']].put_nowait(message['response'])
    except BaseException:
        os._exit(70)
threading.Thread(target=responses,daemon=True).start()
with Server(('127.0.0.1',0),Proxy) as server:
    proxy='http://127.0.0.1:'+str(server.server_port)
    os.environ.update(HTTPS_PROXY=proxy, HTTP_PROXY=proxy, ALL_PROXY=proxy,
                      https_proxy=proxy,http_proxy=proxy,all_proxy=proxy,NO_PROXY='',no_proxy='')
    threading.Thread(target=server.serve_forever,daemon=True).start()
    env=dict(os.environ)
    key=Path('/service-private/amp-key').read_text()
    if not 1<=len(key)<=4096 or any(not 33<=ord(c)<=126 for c in key): raise ValueError()
    env.update(AMP_API_KEY=key,AMP_URL='https://ampcode.com',NODE_EXTRA_CA_CERTS='/opt/public-ca.pem')
    try:
        with tempfile.TemporaryFile() as output:
            result=subprocess.run({self.command()!r},env=env,stdin=subprocess.DEVNULL,
                stdout=output,stderr=subprocess.DEVNULL,timeout=8,close_fds=True)
            if {self.operation == 'check'!r}:
                output.seek(0)
                state=check_output(result.returncode,output.read(65537))
            else:
                state='runtime_ready' if result.returncode==0 else 'runtime_failed'
    except subprocess.TimeoutExpired:
        state='timeout'
    emit({{'op':'probe_result','state':state}})
''').encode()

    def decide(self, *_):
        raise ValueError('Protected preparation service cannot serve actors')

    def probe(self):
        result = {'state': 'boundary_failed', 'authenticated': None}
        deadline = time.monotonic() + 12
        try:
            while True:
                message = self.read(deadline)
                if set(message) == {'op', 'state'} and message['op'] == 'probe_result' \
                        and message['state'] in (('authenticated','application_response_invalid','native_failed','timeout')
                            if self.operation == 'check' else ('runtime_ready', 'runtime_failed', 'timeout')):
                    result['state'] = message['state']
                    result['authenticated'] = True if message['state'] == 'authenticated' else None
                    break
                if self.egress is None or set(message) != {'op','id','request'} \
                        or message['op'] != 'egress' or type(message['id']) is not int \
                        or message['id'] != self.sequence + 1:
                    raise ValueError()
                self.sequence += 1
                response = self.egress.exchange(message['request'])
                self.write({'op':'egress','id':message['id'],'response':response}, deadline)
        except KeyboardInterrupt:
            result['state'] = 'interrupted'
        except (ValueError, OSError):
            pass
        finally:
            self.log.append('probe_result', result)
            self.finish()
        return result

    def finish(self):
        if self.egress is not None:
            self.egress.close()
        return TrustedService.finish(self)


def verify(output, anchor):
    result = verify_chain(output, anchor)
    outcome = result['outcome']
    if set(outcome) != {'state', 'authenticated'} \
            or type(outcome['state']) is not str or outcome['state'] not in PROBE_STATES:
        raise ValueError('Not protected Amp preparation evidence')
    if outcome['authenticated'] is not (True if outcome['state'] == 'authenticated' else None):
        raise ValueError('Inconsistent authentication outcome')
    result['scope'] = 'host-recorded native application result; no independent provider attestation'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('init-store','import-key','probe','verify','check'))
    parser.add_argument('--store', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--anchor', type=Path)
    parser.add_argument('--enable-check-egress', action='store_true')
    args = parser.parse_args()
    if args.enable_check_egress != (args.operation == 'check'):
        parser.error('Only check requires --enable-check-egress')
    if args.operation == 'verify':
        if args.output is None or args.anchor is None: parser.error('output and anchor required')
        print(canonical(verify(args.output, args.anchor))); return 0
    if args.store is None: parser.error('explicit store required')
    if args.operation == 'init-store':
        CredentialStore.create(args.store)
        print('{"state":"empty_store_created"}'); return 0
    with CredentialStore(args.store) as store:
        if args.operation == 'import-key':
            if not sys.stdin.isatty(): parser.error('private operator terminal required')
            # Explicit terminal avoids getpass's insecure echoed-input fallback.
            with open('/dev/tty','w') as terminal:
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter('error', getpass.GetPassWarning)
                    value = getpass.getpass('Amp API key (hidden; not an OpenAI key): ',stream=terminal)
                provision(store, value)
            print('{"state":"credential_stored_not_authenticated"}'); return 0
        if args.output is None or args.anchor is None: parser.error('output and anchor required')
        anchor = args.anchor.absolute()
        if anchor.resolve().is_relative_to(store.path) or anchor.resolve().is_relative_to(args.output.parent.resolve()):
            parser.error('anchor must be outside credential and audit directories')
        with anchor.open('x') as external:
            os.chmod(anchor,0o600)
            egress = AmpEgress(timeout=15,single_connection=True) if args.operation == 'check' else None
            try:
                with ProtectedAmpService(args.output,store,'check' if egress else '--version',egress=egress) as service:
                    result=service.probe()
            finally:
                if egress is not None: egress.close()
            external.write(canonical({'root':service.receipt['root']})+'\n')
            external.flush();os.fsync(external.fileno())
        os.chmod(anchor,0o400)
        print(canonical(result))
        return 0 if result['state'] in ('runtime_ready','authenticated') else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError, getpass.GetPassWarning):
        print('{"state":"boundary_failed","authenticated":null}',file=sys.stderr)
        raise SystemExit(1) from None
