"""Offline authentication gate checks; pinned native CLI, synthetic keys only."""
import ipaddress
import json
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from synthetic_harness import amp_protected as protected, sandbox
from synthetic_harness.login import CredentialStore
from test_amp_tls import SERVER


class AmpAuthenticationTests(unittest.TestCase):
    def test_native_application_result_and_single_use_gate(self):
        cases=[('empty','200 OK',[], 'authenticated'),
               # This is an incomplete server record, not a valid native list fixture.
               ('bad_record','200 OK',[{'error':'PRIVATE-THREAD-METADATA'}], 'native_failed'),
               ('denied','401 Unauthorized',[], 'native_failed'),
               ('server_error','500 Internal Server Error',[], 'native_failed'),
               ('redirect_same','200 OK',[], 'boundary_failed')]
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);(base/'audit').mkdir()
            root,key=base/'root.pem',base/'root.key'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                '-subj','/CN=ampcode.com','-addext','subjectAltName=DNS:ampcode.com',
                '-keyout',str(key),'-out',str(root)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            for name,status,threads,expected in cases:
                with self.subTest(case=name):
                    CredentialStore.create(base/name)
                    with CredentialStore(base/name) as store:
                        protected.provision(store,'offline-native-amp-fixture-not-a-key')
                        body={'ok':True,'result':{'threads':threads}}
                        server_code=SERVER.replace("body=b'PRIVATE-AMP-TLS-FIXTURE'",f'body={json.dumps(body).encode()!r}')
                        server_code=server_code.replace('404 Not Found',status+'\\r\\nContent-Type: application/json')
                        record=base/(name+'-record')
                        server=subprocess.Popen([sys.executable,'-u','-c',server_code,str(root),str(key),str(record),name],
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                            env={'PATH':'/usr/bin','LANG':'C.UTF-8'})
                        try:
                            port=int(server.stdout.readline())
                            with patch.object(protected,'resolve_auth',return_value=(ipaddress.ip_address('93.184.216.34'),)):
                                egress=protected.AmpEgress(timeout=15,single_connection=True)
                                again=protected.AmpEgress(timeout=15,single_connection=True)
                            service=protected.ProtectedAmpService(base/'audit'/name,store,'check',egress=egress)
                            source=service.source().replace(b'env=dict(os.environ)',
                                (f"Path('/tmp/fixture-ca.pem').write_text({root.read_text()!r})\n    env=dict(os.environ)").encode())
                            source=source.replace(b"NODE_EXTRA_CA_CERTS='/opt/public-ca.pem'",b"NODE_EXTRA_CA_CERTS='/tmp/fixture-ca.pem'")
                            def connect():
                                sock=socket.create_connection(('127.0.0.1',port),timeout=2);sock.setblocking(False);return sock
                            with patch.object(protected.AmpEgress,'connect',side_effect=AssertionError('Live transport forbidden')), \
                                    patch.object(egress,'connect',side_effect=connect),patch.object(service,'source',return_value=source),service:
                                result=service.probe()
                            self.assertEqual(result,{'state':expected,'authenticated':True if expected=='authenticated' else None})
                            self.assertEqual(egress.opens,1)
                            self.assertEqual(json.loads(record.read_text())['requests'],['POST /api/internal?listThreads HTTP/1.1'])
                            anchor=base/(name+'-anchor');anchor.write_text(json.dumps({'root':service.receipt['root']}))
                            self.assertEqual(protected.verify(service.output,anchor)['outcome'],result)
                            journal=Path(str(service.output)+'.service.jsonl').read_text()
                            for value in ('PRIVATE-THREAD-METADATA','offline-native-amp-fixture-not-a-key'):
                                self.assertNotIn(value,journal)
                            # Both successful and failed attempts consume the store.
                            with self.assertRaises(FileExistsError):
                                with protected.ProtectedAmpService(base/'audit'/(name+'-again'),store,'check',egress=again): pass
                            self.assertEqual(again.opens,0)
                            self.assertTrue((store.path/'home/check-used').exists())
                            self.assertFalse(list(sandbox.CGROUP.glob('service-*')))
                        finally:
                            if server.poll() is None: server.terminate()
                            server.communicate(timeout=5)

    def test_application_validator_rejects_false_success_without_leaking(self):
        self.assertEqual(protected.check_output(0,b'[]'),'authenticated')
        self.assertEqual(protected.check_output(0,b'[{"title":"PRIVATE-METADATA"}]'),'authenticated')
        self.assertEqual(protected.check_output(0,b'[]'+b' '*65534),'authenticated')
        self.assertEqual(protected.check_output(0,b'[]'+b' '*65535),'application_response_invalid')
        self.assertEqual(protected.check_output(1,b'[]'),'native_failed')
        for data in (b'',b'not json PRIVATE-ERROR',b'{}',b'{"error":"PRIVATE-ERROR"}',
                     b'[{}]',b'[null]',b'[NaN]',b'[{"id":"a","id":"b"}]',b'[{"id":1},{"id":2}]',
                     b'['*10000,b'x'*65537,b'\xff'):
            self.assertEqual(protected.check_output(0,data),'application_response_invalid')

    def test_mock_child_output_is_bounded_and_never_journaled(self):
        # Exercises wrapper behavior, not the native server's thread-record schema.
        cases=[('[{"title":"PRIVATE-METADATA"}]',0,'authenticated'),
               ('[{"id":1},{"id":2}]',0,'application_response_invalid'),
               ('PRIVATE-METADATA'*5000,0,'application_response_invalid'),
               ('[]',1,'native_failed')]
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);(base/'audit').mkdir()
            for index,(output,code,expected) in enumerate(cases):
                CredentialStore.create(base/str(index))
                with CredentialStore(base/str(index)) as store:
                    protected.provision(store,'offline-synthetic-key')
                    with patch.object(protected,'resolve_auth',return_value=(ipaddress.ip_address('93.184.216.34'),)):
                        egress=protected.AmpEgress(single_connection=True)
                    service=protected.ProtectedAmpService(base/'audit'/str(index),store,'check',egress=egress)
                    command=['/usr/bin/python3.11','-I','-S','-c',
                             f'import sys; print({output!r}); print("PRIVATE-STDERR",file=sys.stderr); sys.exit({code})']
                    with patch.object(protected.AmpEgress,'connect',side_effect=AssertionError('Network forbidden')), \
                            patch.object(service,'command',return_value=command),service:
                        result=service.probe()
                    self.assertEqual(result['state'],expected)
                    self.assertEqual(egress.opens,0)
                    anchor=base/(str(index)+'-anchor');anchor.write_text(json.dumps({'root':service.receipt['root']}))
                    self.assertEqual(protected.verify(service.output,anchor)['outcome'],result)
                    journal=Path(str(service.output)+'.service.jsonl').read_text()
                    for private in ('PRIVATE-METADATA','PRIVATE-STDERR','offline-synthetic-key'):
                        self.assertNotIn(private,journal)
                    self.assertFalse(list(sandbox.CGROUP.glob('service-*')))

    def test_operator_check_requires_explicit_egress_and_no_second_connection(self):
        for arguments in (['check'],['probe','--enable-check-egress']):
            result=subprocess.run([sys.executable,'-m','synthetic_harness.amp_protected',*arguments],
                capture_output=True,text=True)
            self.assertEqual(result.returncode,2)
        with patch.object(protected,'resolve_auth',return_value=(ipaddress.ip_address('93.184.216.34'),)):
            egress=protected.AmpEgress(single_connection=True)
        left,right=socket.socketpair()
        try:
            with patch.object(egress,'connect',return_value=left):
                self.assertEqual(egress.exchange({'op':'open','authority':'ampcode.com:443'}),{'connection':1})
                egress.exchange({'op':'close','connection':1})
                with self.assertRaises(ValueError): egress.exchange({'op':'open','authority':'ampcode.com:443'})
            self.assertEqual(egress.opens,1)
            self.assertTrue(egress.closed)
        finally:
            left.close();right.close()
