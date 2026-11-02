"""Operator-only managed login, with explicit restricted-network opt-in."""

import argparse
import fcntl
import json
import os
import secrets
import stat
import subprocess
import sys
import time
from pathlib import Path

from .app_server import settings
from .auth_egress import AuthEgress
from .codex_runtime import DEFAULT_RUNTIME
from .runner import EventLog
from .tasks import canonical, digest
from .trusted_service import TrustedService


FAILURE_CATEGORIES = frozenset({'protocol_schema', 'rpc_request_rejected', 'rpc_error_unknown',
    'login_rejected', 'transport_or_framing', 'egress_failure',
    'status_confirmation', 'timeout', 'interrupted', 'unknown'})
FAILURE_STAGES = frozenset({'initialize', 'initial_status', 'start', 'display',
                           'wait', 'confirm_status', 'unknown'})


class LoginFailure(ValueError):
    def __init__(self, category):
        self.category = category if category in FAILURE_CATEGORIES else 'unknown'
        super().__init__('Login protocol rejected')


class CredentialStore:
    """Explicit new store, never the user's existing Codex home or keychain."""
    @staticmethod
    def create(path):
        path = Path(path).absolute()
        if path.parent.resolve() != path.parent:
            raise ValueError('Store parents must not be symlinks')
        path.mkdir(mode=0o700)
        (path / 'home').mkdir(mode=0o700)
        fd = os.open(path / 'lock', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)

    def __init__(self, path):
        self.path = Path(path).absolute()
        self.fd = self.lock = None

    def __enter__(self):
        if self.lock is not None:
            raise ValueError('Store already leased')
        try:
            for path in (self.path, self.path / 'home', self.path / 'lock'):
                info = path.lstat()
                directory = path != self.path / 'lock'
                if path.resolve() != path or info.st_uid != os.getuid() \
                        or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600) \
                        or (not stat.S_ISDIR(info.st_mode) if directory else
                            not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                    raise ValueError('Store ownership, type or permissions rejected')
            self.lock = os.open(self.path / 'lock', os.O_RDWR | os.O_NOFOLLOW)
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.fd = os.open(self.path / 'home', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            return self
        except BaseException:
            self.__exit__()
            raise

    def __exit__(self, *_):
        for name in ('fd', 'lock'):
            fd = getattr(self, name)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)


class LoginProtocol:
    """Narrow managed-login protocol; no caller-supplied RPC/params/tokens."""
    def __init__(self):
        self.phase, self.pending, self.login_id = 'new', None, None
        self.sequence = 0

    def request(self, operation):
        if self.pending or self.phase == 'failed':
            raise ValueError('Login protocol unavailable')
        if operation == 'initialize' and self.phase == 'new':
            method, params = 'initialize', {'clientInfo': {'name': 'offline_login_operator', 'version': '0.1'}}
        elif operation == 'status' and self.phase == 'ready':
            method, params = 'account/read', {'refreshToken': False}
        elif operation == 'start' and self.phase == 'ready':
            method, params = 'account/login/start', {'type': 'chatgptDeviceCode'}
        elif operation == 'cancel' and self.phase == 'waiting':
            method, params = 'account/login/cancel', {'loginId': self.login_id}
        elif operation == 'logout' and self.phase == 'ready':
            method, params = 'account/logout', {}
        else:
            raise ValueError('Operator operation prohibited')
        self.sequence += 1
        self.pending = operation
        return {'id': self.sequence, 'method': method, 'params': params}

    def accept(self, message):
        try:
            return self._accept(message)
        except LoginFailure:
            self.phase = 'failed'
            raise
        except (ValueError, KeyError, TypeError, AttributeError):
            self.phase = 'failed'
            raise LoginFailure('protocol_schema') from None

    def _accept(self, message):
        if self.phase == 'failed' or type(message) is not dict or len(canonical(message).encode()) > 65536:
            raise ValueError()
        if set(message) == {'id', 'error'} and type(message['id']) is int \
                and message['id'] == self.sequence and self.pending:
            error = message['error']
            if type(error) is not dict or set(error) - {'code', 'message', 'data'} \
                    or type(error.get('code')) is not int or type(error.get('message')) is not str:
                raise ValueError()
            # Never interpret free text/data as a TLS error or provider status.
            if error['code'] == -32600:
                raise LoginFailure('rpc_request_rejected')
            raise LoginFailure('protocol_schema' if error['code'] in
                               (-32700, -32601, -32602) else 'rpc_error_unknown')
        if 'id' not in message:
            if set(message) - {'method', 'params', 'emittedAtMs'}:
                raise ValueError()
            params = message['params']
            if message['method'] == 'account/login/completed' and self.phase == 'waiting' \
                    and self.pending is None and params['loginId'] == self.login_id \
                    and type(params['success']) is bool \
                    and set(params) <= {'loginId', 'success', 'error', 'onboardingEntrypoint'}:
                self.phase, self.login_id = 'ready', None
                return {'state': 'login_reported_complete' if params['success'] else 'login_failed'}
            # Notifications carry no authority to mark a login successful.
            if message['method'] == 'account/updated' and type(params) is dict \
                    and set(params) <= {'authMode', 'planType'}:
                return {'state': 'account_update'}
            if message['method'] == 'remoteControl/status/changed' and params.get('status') == 'disabled':
                return {'state': 'remote_control_disabled'}
            if message['method'] == 'configWarning' and params.get('summary', '').startswith(
                    'Codex could not find bubblewrap on PATH.'):
                return {'state': 'inner_sandbox_warning'}
            raise ValueError()
        if set(message) != {'id', 'result'} or type(message['id']) is not int \
                or message['id'] != self.sequence or not self.pending or type(message['result']) is not dict:
            raise ValueError()
        operation, result = self.pending, message['result']
        self.pending = None
        if operation == 'initialize':
            self.phase = 'ready'
            return {'state': 'initialized'}
        if operation == 'status':
            account = result['account']
            if set(result) - {'account', 'requiresOpenaiAuth', 'workspaceRouting'} \
                    or (account is not None and (type(account) is not dict or account.get('type') != 'chatgpt'
                        or set(account) - {'type', 'email', 'planType', 'workspaceName'})):
                raise ValueError()
            return {'state': 'status', 'authenticated': account is not None}
        if operation == 'start':
            if set(result) != {'type', 'loginId', 'verificationUrl', 'userCode'} \
                    or result['type'] != 'chatgptDeviceCode' \
                    or result['verificationUrl'] != 'https://auth.openai.com/codex/device' \
                    or type(result['loginId']) is not str or not 1 <= len(result['loginId']) <= 128 \
                    or type(result['userCode']) is not str or not 1 <= len(result['userCode']) <= 64 \
                    or any(not (c.isascii() and (c.isalnum() or c == '-')) for c in result['userCode']):
                raise ValueError()
            self.phase, self.login_id = 'waiting', result['loginId']
            # Private operator return value only; never feed this to EventLog.
            return {'state': 'waiting', 'verification_url': result['verificationUrl'], 'user_code': result['userCode']}
        if operation == 'cancel' and result not in ({'status': 'canceled'}, {'status': 'notFound'}):
            raise ValueError()
        if operation == 'logout' and result != {}:
            raise ValueError()
        self.phase, self.login_id = 'ready', None
        return {'state': 'cancel_not_found' if operation == 'cancel' and result['status'] == 'notFound' else operation}


class PrivateLog(EventLog):
    def append(self, kind, payload):
        # Allowlist event kinds, not redaction by secret patterns. Raw messages,
        # account details, paths, code URLs and stderr never enter the journal.
        if kind in {'send', 'receive'} and payload.get('op') == 'egress':
            return  # Only aggregate transport counters are retained, never bytes.
        if kind == 'configuration':
            safe = {'profile': 'offline-login-preparation', 'run_id': secrets.token_hex(16),
                    'runtime': payload['runtime'], 'program_sha256': payload['actor_sha256'],
                    'filter_sha256': payload['filter_sha256']}
        elif kind == 'send':
            method = payload.get('message', payload).get('method')
            safe = {'method': method if method in ('initialize', 'initialized', 'account/read',
                    'account/login/start', 'account/login/cancel', 'account/logout') else 'rejected'}
        elif kind == 'probe_result' and payload == {'authenticated': False}:
            safe = {'authenticated': False}
        elif kind == 'login_result' and payload.get('state') in (
                'authenticated', 'already_authenticated', 'login_failed', 'cancel',
                'cancel_not_found', 'interrupted_check_status', 'timed_out_check_status', 'failed_check_status'):
            safe = {'state': payload['state']}
            if 'category' in payload or 'stage' in payload:
                safe.update(category=payload.get('category') if type(payload.get('category')) is str
                            and payload['category'] in FAILURE_CATEGORIES else 'unknown',
                            stage=payload.get('stage') if type(payload.get('stage')) is str
                            and payload['stage'] in FAILURE_STAGES else 'unknown')
        elif kind == 'egress_summary':
            safe = {key: payload[key] for key in ('opens', 'bytes', 'frames')}
        elif kind in {'receive', 'failure', 'end'}:
            safe = {}
        else:
            raise ValueError('Unknown private audit event')
        super().append(kind, safe)


class LoginService(TrustedService):
    log_type = PrivateLog

    def __init__(self, output, store, *, runtime=DEFAULT_RUNTIME, egress=None):
        if store.fd is None:
            raise ValueError('Exclusive store lease required')
        audit = Path(output).absolute().parent.resolve()
        if audit.is_relative_to(store.path) or store.path.is_relative_to(audit):
            raise ValueError('Keep credential store outside audit directories')
        super().__init__(output, None, runtime=runtime)
        self.store = store
        self.egress = egress
        self.egress_sequence = 0
        self.protocol = LoginProtocol()
        if egress is not None:
            if not isinstance(egress, AuthEgress) or egress.closed:
                raise ValueError('Active restricted egress required')
            self.max_frames, self.wire_bytes, self.cpu_seconds = 40000, 64 * 1024 * 1024, 30

    def command(self):
        config = {k: v for k, v in settings(1).items() if k.startswith('features.')}
        config.update({'cli_auth_credentials_store': 'file', 'forced_login_method': 'chatgpt',
                       'mcp_servers': {}, 'analytics.enabled': False, 'web_search': 'disabled'})
        if self.egress is not None:
            config['features.respect_system_proxy'] = True
        args = ['/opt/codex', 'app-server', '--listen', 'stdio://', '--strict-config']
        for key, value in config.items():
            args += ['-c', key + '=' + json.dumps(value)]
        return args

    def source(self):
        setup = ("import os\nfrom pathlib import Path\nos.umask(0o077)\n"
                "Path('/tmp/work').mkdir()\n"
                "os.environ.update(CODEX_HOME='/tmp/codex-home', TMPDIR='/tmp/work')\n")
        if self.egress is None:
            return (setup + f"os.execv('/opt/codex', {self.command()!r})\n").encode()
        return (setup + Path(__file__).with_name('login_bridge.py').read_text()
                + f'\nrun({self.command()!r})\n').encode()

    def mounts(self, private_fd):
        return ['--bind', f'/proc/self/fd/{self.store.fd}', '/tmp/codex-home']

    def extra_fds(self):
        return (self.store.fd,)

    def decide(self, *_):
        raise ValueError('Login service cannot serve actors or model turns')

    def write(self, message, deadline):
        allowed = {'initialize': {'clientInfo': {'name': 'offline_login_operator', 'version': '0.1'}},
                   'account/read': {'refreshToken': False}, 'initialized': {}}
        if self.egress is not None:
            allowed.update({'account/login/start': {'type': 'chatgptDeviceCode'}, 'account/logout': {}})
            if self.protocol.login_id is not None:
                allowed['account/login/cancel'] = {'loginId': self.protocol.login_id}
        method = message.get('method')
        if method not in allowed or message.get('params') != allowed[method] \
                or set(message) != ({'method', 'params'} if method == 'initialized' else {'id', 'method', 'params'}) \
                or (method != 'initialized' and type(message['id']) is not int):
            raise ValueError('Login RPC prohibited')
        super().write({'op': 'rpc', 'message': message} if self.egress is not None else message, deadline)

    def read(self, deadline):
        if self.egress is None:
            return super().read(deadline)
        try:
            while True:
                message = super().read(deadline)
                if set(message) == {'op', 'category'} and message['op'] == 'failure':
                    if message['category'] not in ('protocol_schema', 'transport_or_framing'):
                        raise LoginFailure('protocol_schema')
                    raise LoginFailure(message['category'])
                if set(message) == {'op', 'message'} and message['op'] == 'rpc':
                    return message['message']
                if set(message) != {'op', 'id', 'request'} or message['op'] != 'egress' \
                        or type(message['id']) is not int or message['id'] != self.egress_sequence + 1:
                    raise LoginFailure('protocol_schema')
                self.egress_sequence = message['id']
                try:
                    response = self.egress.exchange(message['request'])
                except (ValueError, OSError):
                    raise LoginFailure('egress_failure') from None
                super().write({'op': 'egress', 'id': message['id'], 'response': response}, deadline)
        except (ValueError, OSError) as error:
            self.egress.close()
            raise LoginFailure(error.category if isinstance(error, LoginFailure)
                               else 'transport_or_framing') from None

    def rpc(self, operation, deadline):
        self.write(self.protocol.request(operation), deadline)
        while self.protocol.pending:
            result = self.protocol.accept(self.read(deadline))
        if operation == 'initialize':
            self.write({'method': 'initialized', 'params': {}}, deadline)
        return result

    def probe(self):
        """Only real RPCs enabled: initialize, initialized, non-refreshing read."""
        deadline = time.monotonic() + 15
        try:
            self.rpc('initialize', deadline)
            result = self.rpc('status', deadline)
            if result != {'state': 'status', 'authenticated': False}:
                raise ValueError('Offline probe requires unauthenticated store')
            self.log.append('probe_result', {'authenticated': False})
            return result
        except (ValueError, OSError):
            self.finish()
            raise ValueError('Offline login probe failed closed') from None

    def start_login(self, display=None, *, timeout=900):
        if self.egress is None or display is None or not 1 <= timeout <= 900:
            raise ValueError('Explicit restricted egress and private operator display required')
        deadline = min(self.egress.deadline, time.monotonic() + timeout)
        result = {'state': 'failed_check_status'}
        stage = 'initialize'
        try:
            self.rpc('initialize', deadline)
            stage = 'initial_status'
            if self.rpc('status', deadline)['authenticated']:
                result = {'state': 'already_authenticated'}
            else:
                stage = 'start'
                challenge = self.rpc('start', deadline)
                stage = 'display'
                display(challenge['verification_url'], challenge['user_code'])
                stage = 'wait'
                while True:
                    notification = self.protocol.accept(self.read(deadline))
                    if notification['state'] == 'login_failed':
                        result = dict(notification, category='login_rejected', stage=stage)
                        break
                    if notification['state'] == 'login_reported_complete':
                        stage = 'confirm_status'
                        if not self.rpc('status', deadline)['authenticated']:
                            raise LoginFailure('status_confirmation')
                        result = {'state': 'authenticated'}
                        break
        except (KeyboardInterrupt, ValueError, OSError) as error:
            category = ('interrupted' if isinstance(error, KeyboardInterrupt) else
                        'timeout' if time.monotonic() >= deadline else
                        error.category if isinstance(error, LoginFailure) else
                        'transport_or_framing' if isinstance(error, OSError) else 'unknown')
            result = {'state': 'interrupted_check_status' if isinstance(error, KeyboardInterrupt) else
                      'timed_out_check_status' if time.monotonic() >= deadline else 'failed_check_status',
                      'category': category, 'stage': stage}
            if self.protocol.phase == 'waiting' and self.protocol.pending is None:
                try:
                    result['state'] = self.rpc('cancel', time.monotonic() + 3)['state']
                except (ValueError, OSError, KeyboardInterrupt):
                    pass
        finally:
            self.log.append('login_result', result)
            self.finish()
        return result

    def finish(self):
        if not self.closed and self.egress is not None:
            self.egress.close()
            if self.log is not None:
                self.log.append('egress_summary', {key: getattr(self.egress, key) for key in ('opens', 'bytes', 'frames')})
        return super().finish()


def verify(output, anchor):
    trusted = json.loads(Path(anchor).read_text())
    records = [json.loads(line) for line in Path(str(output) + '.service.jsonl').read_text().splitlines()]
    previous = '0' * 64
    for index, record in enumerate(records):
        body = {key: record[key] for key in ('seq', 'previous', 'kind', 'payload')}
        if body['seq'] != index or body['previous'] != previous or digest(body) != record['hash']:
            raise ValueError('Broken login audit chain')
        previous = record['hash']
    if set(trusted) != {'root'} or trusted['root'] != previous or not records \
            or records[0]['kind'] != 'configuration' or records[-1]['kind'] != 'end' \
            or sum(record['kind'] in ('probe_result', 'login_result') for record in records) != 1:
        raise ValueError('Login seal or anchor mismatch')
    outcome = next(record['payload'] for record in records if record['kind'] in ('probe_result', 'login_result'))
    return {'verified': True, 'root': previous, 'outcome': outcome,
            'scope': 'host-recorded login outcome; not independent provider attestation'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('init-store', 'probe', 'verify', 'start'))
    parser.add_argument('--store', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--anchor', type=Path)
    parser.add_argument('--enable-auth-egress', action='store_true', help='Explicit operator opt-in; start only')
    args = parser.parse_args()
    if args.enable_auth_egress != (args.operation == 'start'):
        parser.error('start requires --enable-auth-egress; other operations forbid it')
    if args.operation == 'verify':
        if args.output is None or args.anchor is None:
            parser.error('verify requires --output and --anchor')
        print(canonical(verify(args.output, args.anchor)))
        return
    if args.store is None:
        parser.error('store path required; no default credential discovery')
    if args.operation == 'init-store':
        CredentialStore.create(args.store)
        print('{"state":"empty_store_created"}')
        return
    if args.output is None or args.anchor is None:
        parser.error('probe/start requires --output and --anchor')
    anchor = args.anchor.absolute()
    if anchor.resolve().is_relative_to(args.store.resolve()) or anchor.resolve().is_relative_to(args.output.parent.resolve()):
        parser.error('anchor must be outside credential and audit directories')
    terminal = None
    egress = None
    try:
        if args.operation == 'start':
            if not sys.stdin.isatty():
                parser.error('start requires an interactive operator terminal')
            terminal = open('/dev/tty', 'w')
        with anchor.open('x') as external:
            os.chmod(anchor, 0o600)
            with CredentialStore(args.store) as store:
                if args.operation == 'start':
                    egress = AuthEgress()
                with LoginService(args.output, store, egress=egress) as service:
                    def display(url, code):
                        terminal.write(f'Only continue if you initiated this login.\nOpen {url}\nCode: {code}\nCtrl-C cancels. Do not share this code.\n')
                        terminal.flush()
                    result = service.start_login(display) if egress is not None else service.probe()
                external.write(canonical({'root': service.receipt['root']}) + '\n')
                external.flush()
                os.fsync(external.fileno())
            os.chmod(anchor, 0o400)
    finally:
        if egress is not None:
            egress.close()
        if terminal is not None:
            terminal.close()
    print(canonical(result))
    return 0 if result.get('state') in ('status', 'authenticated', 'already_authenticated') else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.SubprocessError):
        print('{"state":"failed_check_status"}', file=sys.stderr)
        raise SystemExit(1) from None
