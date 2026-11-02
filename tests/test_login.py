"""Offline login preparation: synthetic secrets only, never a live login."""

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from synthetic_harness import sandbox
from synthetic_harness.login import CredentialStore, LoginProtocol, LoginService, PrivateLog, verify


class LoginTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.store = self.base / 'store'
        self.audit = self.base / 'audit'
        self.audit.mkdir()
        CredentialStore.create(self.store)

    def test_diagnostic_journal_allowlist_drops_untrusted_fields(self):
        marker = 'SYNTHETIC-SECRET-URL-token-code'
        for value in (marker, {'error': marker}, [marker], None):
            log = PrivateLog()
            log.append('login_result', {'state':'failed_check_status', 'category':value,
                                       'stage':value, 'message':marker, 'stderr':marker})
            self.assertEqual(log.snapshot()[0]['payload'], {
                'state':'failed_check_status', 'category':'unknown', 'stage':'unknown'})
            self.assertNotIn(marker, json.dumps(log.snapshot()))

    def ready(self):
        protocol = LoginProtocol()
        request = protocol.request('initialize')
        protocol.accept({'id': request['id'], 'result': {}})
        return protocol

    def started(self, **changes):
        protocol = self.ready()
        request = protocol.request('start')
        self.assertEqual(request['params'], {'type': 'chatgptDeviceCode'})
        result = {'type': 'chatgptDeviceCode', 'loginId': 'synthetic-id',
                  'verificationUrl': 'https://auth.openai.com/codex/device', 'userCode': 'FAKE-1234'}
        result.update(changes)
        reply = protocol.accept({'id': request['id'], 'result': result})
        return protocol, reply

    def test_mock_managed_login_cancel_completion_and_logout(self):
        protocol, reply = self.started()
        self.assertEqual(reply['user_code'], 'FAKE-1234')
        self.assertEqual(protocol.request('cancel')['params'], {'loginId': 'synthetic-id'})
        self.assertEqual(protocol.accept({'id': 3, 'result': {'status': 'canceled'}}), {'state': 'cancel'})
        protocol, _ = self.started()
        notice = {'method': 'account/login/completed', 'params': {
            'loginId': 'synthetic-id', 'success': True, 'error': None}}
        self.assertEqual(protocol.accept(notice), {'state': 'login_reported_complete'})
        self.assertEqual(protocol.request('status')['params'], {'refreshToken': False})
        reply = protocol.accept({'id': 3, 'result': {'account': {
            'type': 'chatgpt', 'email': 'synthetic@example.invalid', 'planType': 'pro'}}})
        self.assertEqual(reply, {'state': 'status', 'authenticated': True})
        protocol.request('logout')
        self.assertEqual(protocol.accept({'id': 4, 'result': {}}), {'state': 'logout'})
        with self.assertRaises(ValueError):
            protocol.accept(notice)

    def test_mock_protocol_rejects_forgery_tokens_and_redirects(self):
        for changes in ({'verificationUrl': 'https://auth.openai.com.evil.invalid/codex/device'},
                        {'verificationUrl': 'http://auth.openai.com/codex/device'},
                        {'userCode': 'FAKE\nINJECT'}, {'access_token': 'synthetic-secret'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.started(**changes)
        for method in ('thread/start', 'process/spawn', 'account/login/start', 'refresh', 'apiKey'):
            with self.assertRaises(ValueError):
                self.ready().request(method)
        for message in ({'id': 1, 'method': 'item/tool/call', 'params': {}},
                        {'method': 'account/login/completed', 'params': {
                            'loginId': 'other', 'success': True}},
                        {'id': 999, 'result': {}},
                        {'id': 2, 'error': {'message': 'synthetic-secret'}}):
            protocol, _ = self.started()
            with self.assertRaisesRegex(ValueError, '^Login protocol rejected$'):
                protocol.accept(message)
            with self.assertRaises(ValueError):
                protocol.request('status')

    def test_store_exclusivity_permissions_links_and_no_overwrite(self):
        with self.assertRaises(FileExistsError):
            CredentialStore.create(self.store)
        with CredentialStore(self.store):
            with self.assertRaises(BlockingIOError):
                with CredentialStore(self.store):
                    pass
        (self.store / 'home').chmod(0o755)
        with self.assertRaises(ValueError):
            with CredentialStore(self.store):
                pass
        (self.store / 'home').chmod(0o700)
        link = self.base / 'link'
        link.symlink_to(self.store)
        with self.assertRaises(ValueError):
            with CredentialStore(link):
                pass
        (self.store / 'lock').unlink()
        (self.store / 'lock').symlink_to(self.base / 'never-open')
        with self.assertRaises(ValueError):
            with CredentialStore(self.store):
                pass
        self.assertFalse((self.base / 'never-open').exists())

    def test_native_unauthenticated_probe_and_real_login_disabled(self):
        with CredentialStore(self.store) as store:
            for index in range(2):
                with LoginService(self.audit / str(index), store) as service:
                    self.assertEqual(service.probe(), {'state': 'status', 'authenticated': False})
                    with self.assertRaises(ValueError):
                        service.start_login()
                    for method, params in (('account/login/start', {'type': 'chatgptDeviceCode'}),
                                           ('account/read', {'refreshToken': True}), ('thread/start', {})):
                        with self.assertRaises(ValueError):
                            service.write({'id': 7, 'method': method, 'params': params}, time.monotonic()+1)
                records = [json.loads(line) for line in
                           (self.audit / f'{index}.service.jsonl').read_text().splitlines()]
                self.assertIn({'authenticated': False}, [record['payload'] for record in records])
                self.assertEqual(records[-1]['hash'], service.receipt['root'])
                anchor = self.base / f'probe-anchor-{index}'
                anchor.write_text(json.dumps({'root': service.receipt['root']}))
                self.assertTrue(verify(self.audit / str(index), anchor)['verified'])
                journal = self.audit / f'{index}.service.jsonl'
                journal.chmod(0o600)
                journal.write_text('\n'.join(journal.read_text().splitlines()[:-1]) + '\n')
                with self.assertRaises(ValueError):
                    verify(self.audit / str(index), anchor)
        self.assertFalse((self.store / 'home' / 'auth.json').exists())
        self.assertFalse(list(sandbox.CGROUP.glob('service-*')))

    def test_private_persistence_actor_isolation_and_log_non_disclosure(self):
        marker = 'SYNTHETIC-NOT-A-CREDENTIAL-7395'
        source = f'''
import errno, json, os, socket, sys, time
from pathlib import Path
os.umask(0o077)
assert os.getuid()==65533
assert not Path('/home/user/workspace').exists()
p=Path('/tmp/codex-home/offline-marker')
if p.exists(): assert p.read_text()=={marker!r}
else: p.write_text({marker!r})
try:
    socket.create_connection(('1.1.1.1',443),timeout=.1)
    raise AssertionError('network route available')
except OSError as error:
    assert error.errno in (errno.ENETUNREACH, errno.EPERM, errno.EACCES)
print(json.dumps({{'synthetic_secret':p.read_text()}}),flush=True)
print(p.read_text(),file=sys.stderr,flush=True)
time.sleep(10)
'''.encode()
        with CredentialStore(self.store) as store, patch.object(LoginService, 'source', return_value=source):
            for index in range(2):
                with LoginService(self.audit / f'private-{index}', store) as service:
                    self.assertEqual(service.read(time.monotonic()+5), {'synthetic_secret': marker})
                    actor = f'''
import os,sys
from pathlib import Path
sys.stdin.readline()
for path in ['/tmp/codex-home/offline-marker', {str(self.store/'home'/'offline-marker')!r}]:
    assert not Path(path).exists()
for fd in range(3,128):
    try: os.fstat(fd)
    except OSError: continue
    raise AssertionError('private descriptor inherited')
print('{{"op":"finish"}}',flush=True)
sys.stdin.readline()
'''.encode()
                    output = self.audit / f'actor-{index}'
                    result = sandbox.run(actor, output, self.base / f'anchor-{index}', domain='inventory')
                    self.assertEqual(result['returncode'], 0)
                for path in self.audit.rglob('*'):
                    if path.is_file():
                        self.assertNotIn(marker.encode(), path.read_bytes(), path)
        self.assertEqual((self.store / 'home' / 'offline-marker').read_text(), marker)
        self.assertEqual(os.stat(self.store / 'home' / 'offline-marker').st_mode & 0o777, 0o600)
        self.assertFalse(list(sandbox.CGROUP.glob('service-*')))
