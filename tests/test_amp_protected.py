"""Synthetic credentials only; no external DNS, login or model invocation."""

import ipaddress
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from synthetic_harness import amp_protected as protected, sandbox
from synthetic_harness.login import CredentialStore

SYNTHETIC = 'offline-amp-canary-NOT-A-REAL-KEY'


class ProtectedAmpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.store_path = self.base/'store'
        CredentialStore.create(self.store_path)
        (self.base/'audit').mkdir()
        self.output = self.base/'audit'/'probe'
        self.anchor = self.base/'anchor'
        self.addCleanup(patch.stopall)
        patch.object(protected, 'resolve_auth', return_value=(ipaddress.ip_address('93.184.216.34'),)).start()
        patch.object(protected.AmpEgress, 'connect', side_effect=AssertionError('External sockets forbidden')).start()

    def seal(self, service):
        self.anchor.write_text(json.dumps({'root':service.receipt['root']}))
        return protected.verify(self.output,self.anchor)

    def test_native_runtime_with_synthetic_key_and_sanitized_anchor(self):
        for index,operation in enumerate(('--version','--help')):
            self.output=self.base/'audit'/f'probe-{index}'
            with CredentialStore(self.store_path) as store:
                if index==0: protected.provision(store,SYNTHETIC)
                with protected.ProtectedAmpService(self.output,store,operation) as service:
                    self.assertEqual(service.probe(),{'state':'runtime_ready','authenticated':None})
            self.assertEqual(self.seal(service)['outcome']['authenticated'],None)
            journal=Path(str(self.output)+'.service.jsonl')
            self.assertNotIn(SYNTHETIC,journal.read_text())
            journal.chmod(0o600)
            journal.write_text(journal.read_text().replace('runtime_ready','runtime_failed'))
            with self.assertRaises(ValueError): protected.verify(self.output,self.anchor)
        self.assertFalse(list(sandbox.CGROUP.glob('service-*')))

    def test_native_child_receives_key_but_no_output_or_raw_error_escapes(self):
        source = '''
import os,sys
from pathlib import Path
assert os.environ['AMP_API_KEY']==Path('/service-private/amp-key').read_text()
assert os.environ['AMP_URL']=='https://ampcode.com'
assert not Path('/home/user/workspace').exists()
assert not Path('/tmp/.config/amp').exists()
print(os.environ['AMP_API_KEY'])
print(os.environ['AMP_API_KEY'],file=sys.stderr)
'''
        with CredentialStore(self.store_path) as store:
            protected.provision(store,SYNTHETIC)
            service=protected.ProtectedAmpService(self.output,store)
            command=['/usr/bin/python3.11','-I','-S','-c',source]
            with patch.object(service,'command',return_value=command),service:
                self.assertEqual(service.probe()['state'],'runtime_ready')
        self.seal(service)
        self.assertNotIn(SYNTHETIC,Path(str(self.output)+'.service.jsonl').read_text())
        self.assertEqual(service.stderr,b'')

    def test_store_rejections_and_no_cli_piped_secrets(self):
        with CredentialStore(self.store_path) as store:
            for bad in ('','x\ny','x'*4097,' key','é'):
                with self.assertRaises(ValueError): protected.provision(store,bad)
            protected.provision(store,SYNTHETIC)
            with self.assertRaises(FileExistsError): protected.provision(store,'replacement')
            for command in ('-x','login','account list'):
                with self.assertRaises(ValueError): protected.ProtectedAmpService(self.output,store,command)
            key=self.store_path/'home/amp-key'
            key.chmod(0o600)
            with self.assertRaises(ValueError):
                with protected.ProtectedAmpService(self.output,store): pass
            key.unlink();key.symlink_to(self.base/'absent')
            with self.assertRaises(OSError):
                with protected.ProtectedAmpService(self.output,store): pass
        result=subprocess.run([sys.executable,'-m','synthetic_harness.amp_protected','import-key',
            '--store',str(self.store_path)],input=SYNTHETIC,text=True,capture_output=True)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn(SYNTHETIC,result.stdout+result.stderr)

    def test_exact_amp_authority_and_secret_bearing_errors_fail_closed(self):
        for authority in ('auth.openai.com:443','ampcode.com:80','AMPCODE.COM:443',
                          'ampcode.com.evil:443','127.0.0.1:443','ampcode.com:443/'+SYNTHETIC):
            egress=protected.AmpEgress()
            with self.assertRaisesRegex(ValueError,'^Authentication egress rejected$'):
                egress.exchange({'op':'open','authority':authority})
            self.assertTrue(egress.closed)
            self.assertEqual(egress.opens,0)
        with CredentialStore(self.store_path) as store:
            protected.provision(store,SYNTHETIC)
            service=protected.ProtectedAmpService(self.output,store)
            source=('print('+repr(json.dumps({'op':'probe_result','state':SYNTHETIC}))+',flush=True)').encode()
            with patch.object(service,'source',return_value=source),service:
                self.assertEqual(service.probe()['state'],'boundary_failed')
        self.seal(service)
        self.assertNotIn(SYNTHETIC,Path(str(self.output)+'.service.jsonl').read_text())

    def test_namespace_connect_relay_with_mock_upstream(self):
        left,right=socket.socketpair()
        self.addCleanup(right.close)
        self.addCleanup(left.close)
        left.setblocking(False)
        right.sendall(b'offline-reply')
        source=r'''
import os,socket
from urllib.parse import urlsplit
p=urlsplit(os.environ['HTTPS_PROXY'])
with socket.create_connection((p.hostname,p.port),timeout=3) as s:
    s.sendall(b'CONNECT ampcode.com:443 HTTP/1.1\r\nHost: ampcode.com:443\r\n\r\n')
    data=b''
    while b'\r\n\r\n' not in data: data+=s.recv(1)
    assert b'200 Connection Established' in data
    s.sendall(b'offline-client')
    assert s.recv(13)==b'offline-reply'
'''
        with CredentialStore(self.store_path) as store:
            protected.provision(store,SYNTHETIC)
            egress=protected.AmpEgress()
            service=protected.ProtectedAmpService(self.output,store,egress=egress)
            with patch.object(egress,'connect',return_value=left), \
                    patch.object(service,'command',return_value=['/usr/bin/python3.11','-I','-S','-c',source]),service:
                self.assertEqual(service.probe()['state'],'runtime_ready')
        self.assertEqual(egress.opens,1)
        self.assertTrue(egress.closed)
        self.seal(service)
        self.assertNotIn('offline-client',Path(str(self.output)+'.service.jsonl').read_text())

    def test_child_failure_timeout_and_interrupt_are_sanitized_and_cleaned(self):
        for index,source in enumerate(('raise SystemExit(9)', 'import time; time.sleep(30)')):
            self.output=self.base/'audit'/f'failure-{index}'
            with CredentialStore(self.store_path) as store:
                if index==0: protected.provision(store,SYNTHETIC)
                service=protected.ProtectedAmpService(self.output,store)
                with patch.object(service,'command',return_value=['/usr/bin/python3.11','-I','-S','-c',source]),service:
                    self.assertEqual(service.probe()['state'],'runtime_failed' if index==0 else 'timeout')
            self.seal(service)
            self.assertFalse(list(sandbox.CGROUP.glob('service-*')))
        self.output=self.base/'audit'/'interrupt'
        with CredentialStore(self.store_path) as store:
            service=protected.ProtectedAmpService(self.output,store)
            with service,patch.object(service,'read',side_effect=KeyboardInterrupt):
                self.assertEqual(service.probe()['state'],'interrupted')
        self.seal(service)
        self.assertFalse(list(sandbox.CGROUP.glob('service-*')))

    def test_actor_cannot_read_credential_or_use_protected_service(self):
        source=b'''
import os,sys
from pathlib import Path
sys.stdin.readline()
assert 'AMP_API_KEY' not in os.environ
assert not Path('/service-private/amp-key').exists()
assert not Path('/proc/1/root/service-private/amp-key').exists()
print('{"op":"decide"}',flush=True)
sys.stdin.readline()
'''
        with CredentialStore(self.store_path) as store:
            protected.provision(store,SYNTHETIC)
            with protected.ProtectedAmpService(self.output,store) as service:
                result=sandbox.run(source,self.output,self.anchor,domain='inventory',service=service)
                self.assertEqual(result['status'],'protocol_error')
        self.assertEqual(sandbox.verify(self.output,self.anchor)['audit']['actions'],0)
        self.assertFalse(list(sandbox.CGROUP.glob('service-*')))
        self.assertFalse(list(sandbox.CGROUP.glob('actor-*')))
