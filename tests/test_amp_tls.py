"""Pinned native Amp transport against local synthetic TLS only. Never -x."""

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
from synthetic_harness.login import CredentialStore


SERVER = r'''
import json,socket,ssl,sys,time
from pathlib import Path
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1],sys.argv[2])
record=Path(sys.argv[3]); mode=sys.argv[4]
evidence=dict(accepted=0,errors=0,requests=[],sni=[],key_seen=False)
def save(): record.write_text(json.dumps(evidence))
def sni(connection,name,ctx): evidence['sni'].append(name); save()
context.set_servername_callback(sni)
save()
with socket.socket() as listener:
 listener.bind(('127.0.0.1',0)); listener.listen(); listener.settimeout(20)
 print(listener.getsockname()[1],flush=True)
 while True:
  raw,_=listener.accept(); evidence['accepted']+=1; save(); raw.settimeout(3)
  if mode=='eof': raw.close(); continue
  if mode=='stall': time.sleep(15);raw.close();continue
  try:
   with context.wrap_socket(raw,server_side=True) as connection:
    data=b''
    while b'\r\n\r\n' not in data and len(data)<16384:
     chunk=connection.recv(4096)
     if not chunk: break
     data+=chunk
    evidence['requests'].append(data.split(b'\r\n')[0].decode('ascii'))
    evidence['key_seen'] |= b'offline-native-amp-fixture-not-a-key' in data
    save()
    body=b'PRIVATE-AMP-TLS-FIXTURE'
    destinations={'redirect':'https://blocked.invalid/', 'redirect_ip':'https://127.0.0.1/',
                  'redirect_http':'http://ampcode.com/redirect', 'redirect_same':'https://ampcode.com/redirect'}
    status=(b'HTTP/1.1 302 Found\r\nLocation: '+destinations[mode].encode()+b'\r\n'
            if mode in destinations and len(evidence['requests'])==1 else b'HTTP/1.1 404 Not Found\r\n')
    connection.sendall(status+b'Content-Length: '+str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body)
  except (ssl.SSLError,OSError): evidence['errors']+=1;save();raw.close()
'''


class AmpNativeTLSTests(unittest.TestCase):
    def test_native_tls_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory); (base/'audit').mkdir()
            def openssl(*args):
                subprocess.run(['openssl',*args],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            root,key=base/'root.pem',base/'root.key'
            openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                    '-subj','/CN=Offline Amp Root','-keyout',str(key),'-out',str(root))
            certificates={}
            for index,(name,hostname,days) in enumerate((('valid','ampcode.com','1'),
                    ('wrong','wrong.invalid','1'),('expired','ampcode.com','-1')),1):
                leaf,private,csr,ext=[base/(name+suffix) for suffix in ('.pem','.key','.csr','.ext')]
                ext.write_text(f'basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:{hostname}\nextendedKeyUsage=serverAuth\n')
                openssl('req','-new','-newkey','rsa:2048','-nodes','-subj',f'/CN={hostname}',
                        '-keyout',str(private),'-out',str(csr))
                openssl('x509','-req','-in',str(csr),'-CA',str(root),'-CAkey',str(key),
                        '-set_serial',str(index),'-days',days,'-extfile',str(ext),'-out',str(leaf))
                certificates[name]=(leaf,private)
            store_path=base/'store';CredentialStore.create(store_path)
            with CredentialStore(store_path) as store:
                protected.provision(store,'offline-native-amp-fixture-not-a-key')
                for mode in ('trusted','untrusted','hostname','expired','eof','stall',
                             'redirect','redirect_ip','redirect_http','redirect_same','no_proxy'):
                    with self.subTest(mode=mode):
                        leaf,private=certificates['wrong' if mode=='hostname' else 'expired' if mode=='expired' else 'valid']
                        record=base/(mode+'.json')
                        server=subprocess.Popen([sys.executable,'-u','-c',SERVER,str(leaf),str(private),str(record),mode],
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                        try:
                            port=int(server.stdout.readline())
                            with patch.object(protected,'resolve_auth',return_value=(ipaddress.ip_address('93.184.216.34'),)):
                                egress=protected.AmpEgress(timeout=15)
                            service=protected.ProtectedAmpService(base/'audit'/mode,store,egress=egress)
                            # Test-only command substitution: this is a supported read,
                            # not an agent/model/account mutation. Production still
                            # permits only native --version and --help.
                            command=['/opt/amp','threads','list','--limit','1','--json',
                                     '--settings-file','/tmp/amp-settings.json']
                            with patch.object(service,'command',return_value=command):
                                source=service.source()
                            if mode!='untrusted':
                                source=source.replace(b"env=dict(os.environ)",
                                    (f"Path('/tmp/fixture-ca.pem').write_text({root.read_text()!r})\n    env=dict(os.environ)").encode())
                                source=source.replace(b"NODE_EXTRA_CA_CERTS='/opt/public-ca.pem'",
                                                      b"NODE_EXTRA_CA_CERTS='/tmp/fixture-ca.pem'")
                            if mode=='no_proxy':
                                source=source.replace(b"env=dict(os.environ)",b"env={k:v for k,v in os.environ.items() if 'proxy' not in k.lower()}")
                            def connect():
                                sock=socket.create_connection(('127.0.0.1',port),timeout=2)
                                sock.setblocking(False)
                                return sock
                            started=time.monotonic()
                            # Guard the real transport class as well as this instance:
                            # accidental fallback can never reach a real endpoint.
                            with patch.object(protected.AmpEgress,'connect',side_effect=AssertionError('External egress prohibited')), \
                                    patch.object(egress,'connect',side_effect=connect), \
                                    patch.object(service,'source',return_value=source),service:
                                result=service.probe()
                            observed=json.loads(record.read_text())
                            print('native-amp-tls',mode,json.dumps({'result':result,**observed}),flush=True)
                            self.assertLess(time.monotonic()-started,14)
                            self.assertEqual(result['state'],'timeout' if mode=='stall' else 'runtime_failed')
                            self.assertEqual(observed['accepted'],egress.opens)
                            self.assertEqual(egress.opens,0 if mode=='no_proxy' else 2 if mode=='redirect_same' else 1)
                            if mode=='trusted' or mode.startswith('redirect'):
                                expected=['POST /api/internal?listThreads HTTP/1.1']
                                if mode=='redirect_same': expected.append('GET /redirect HTTP/1.1')
                                self.assertEqual(observed['requests'],expected)
                                self.assertTrue(observed['key_seen'])
                            else:
                                self.assertEqual(observed['requests'],[])
                                self.assertFalse(observed['key_seen'])
                            if mode not in ('eof','stall','no_proxy'):
                                self.assertEqual(observed['sni'],['ampcode.com']*egress.opens)
                            if mode in ('untrusted','hostname','expired'):
                                self.assertEqual(observed['errors'],1)
                            self.assertIsNone(result['authenticated'])
                            self.assertTrue(egress.closed)
                            self.assertFalse(list(sandbox.CGROUP.glob('service-*')))
                            anchor=base/(mode+'-anchor')
                            anchor.write_text(json.dumps({'root':service.receipt['root']}))
                            self.assertEqual(protected.verify(service.output,anchor)['outcome'],result)
                            journal=Path(str(service.output)+'.service.jsonl').read_text()
                            for secret in ('offline-native-amp-fixture-not-a-key','PRIVATE-AMP-TLS-FIXTURE'):
                                self.assertNotIn(secret,journal)
                        finally:
                            if server.poll() is None: server.terminate()
                            server.communicate(timeout=5)
