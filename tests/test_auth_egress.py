"""Restricted login transport tests. DNS and upstreams are local mocks only."""

import base64
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

from synthetic_harness import auth_egress, sandbox
from synthetic_harness.auth_egress import AUTHORITY, AuthEgress
from synthetic_harness.login import CredentialStore, LoginService, verify


def mock_command(mode='success', before_start=''):
    source = f'''
import json, sys
mode={mode!r}
done=False
for line in sys.stdin:
    message=json.loads(line)
    method=message['method']
    if method=='initialized': continue
    if method=='initialize': result={{}}
    elif method=='account/read':
        result={{'account':{{'type':'chatgpt','email':'private@example.invalid','planType':'pro'}} if done and mode!='false_claim' else None}}
    elif method=='account/login/start':
        exec({before_start!r})
        result={{'type':'chatgptDeviceCode','loginId':'fixture-id', 'verificationUrl':'https://auth.openai.com/codex/device','userCode':'FIXTURE-7395'}}
    elif method=='account/login/cancel': result={{'status':'canceled'}}
    else: raise AssertionError('Unexpected method')
    print(json.dumps({{'id':message['id'],'result':result}}),flush=True)
    if method=='account/login/start' and mode not in ('cancel','timeout'):
        done=True
        print(json.dumps({{'method':'account/login/completed','params':{{'loginId':'fixture-id','success':mode!='failure','error':None}}}}),flush=True)
'''
    return ['/usr/bin/python3.11', '-I', '-S', '-u', '-c', source]


class AuthEgressTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.dns = patch('synthetic_harness.auth_egress.resolve_auth',
                         return_value=(ipaddress.ip_address('93.184.216.34'),))
        self.dns.start()
        self.addCleanup(self.dns.stop)
        self.no_live_connect = patch.object(AuthEgress, 'connect', side_effect=AssertionError('Live connection prohibited in tests'))
        self.no_live_connect.start()
        self.addCleanup(self.no_live_connect.stop)

    def test_dns_policy_rejects_private_mixed_and_transition_addresses(self):
        self.dns.stop()
        for addresses in (['127.0.0.1'], ['169.254.169.254'], ['10.0.0.1'], ['::1'],
                          ['::ffff:8.8.8.8'], ['2002:0808:0808::1'], ['224.0.0.1'],
                          ['2606:4700:4700::1111%eth0'], [1234],
                          ['93.184.216.34','192.168.1.1'], []):
            with patch.object(auth_egress.subprocess, 'run', return_value=subprocess.CompletedProcess([],0,json.dumps(addresses).encode())), self.assertRaises(ValueError):
                auth_egress.resolve_auth()
        with patch.object(auth_egress.subprocess, 'run', return_value=subprocess.CompletedProcess([],0,b'["93.184.216.34"]')):
            self.assertEqual(auth_egress.resolve_auth(), (ipaddress.ip_address('93.184.216.34'),))

    def test_connection_uses_pinned_numeric_address(self):
        self.no_live_connect.stop()
        egress = AuthEgress()
        with patch.object(auth_egress.socket, 'socket') as factory, \
                patch.object(auth_egress, 'resolve_auth', side_effect=AssertionError('DNS relookup')):
            self.assertEqual(egress.exchange({'op':'open','authority':AUTHORITY}), {'connection':1})
            factory.return_value.connect.assert_called_once_with(('93.184.216.34',443))
            egress.close()

    def test_only_exact_authority_and_bounded_connection_ids(self):
        for authority in ('127.0.0.1:443','auth.openai.com:80','AUTH.OPENAI.COM:443',
                          'auth.openai.com.evil:443','auth.openai.com:443/path','user@auth.openai.com:443'):
            egress = AuthEgress()
            with self.assertRaises(ValueError):
                egress.exchange({'op':'open','authority':authority})
            self.assertTrue(egress.closed)
            self.assertEqual(egress.opens, 0)
        egress = AuthEgress()
        with self.assertRaises(ValueError):
            egress.exchange({'op':'transfer','connection':True,'data':''})

    def test_bidirectional_bytes_budgets_and_cleanup(self):
        left,right = socket.socketpair()
        left.setblocking(False)
        self.addCleanup(right.close)
        egress = AuthEgress()
        with patch.object(egress,'connect',return_value=left):
            self.assertEqual(egress.exchange({'op':'open','authority':AUTHORITY}), {'connection':1})
        right.sendall(b'upstream-unequal')
        reply=egress.exchange({'op':'transfer','connection':1,'data':base64.b64encode(b'client').decode()})
        self.assertEqual(right.recv(100), b'client')
        self.assertEqual(base64.b64decode(reply['data']),b'upstream-unequal')
        self.assertEqual(egress.bytes,22)
        with patch.object(auth_egress,'MAX_BYTES',22), self.assertRaises(ValueError):
            egress.exchange({'op':'transfer','connection':1,'data':'eA=='})
        self.assertEqual(left.fileno(), -1)
        self.assertTrue(egress.closed)

    def test_socket_count_lifetime_and_malformed_frames_fail_closed(self):
        egress=AuthEgress()
        peers=[]
        def pair():
            left,right=socket.socketpair(); peers.append(right)
            right.settimeout(1)
            self.addCleanup(right.close)
            return left
        with patch.object(egress,'connect',side_effect=pair):
            for _ in range(4): egress.exchange({'op':'open','authority':AUTHORITY})
            with self.assertRaises(ValueError): egress.exchange({'op':'open','authority':AUTHORITY})
        self.assertTrue(all(peer.recv(1)==b'' for peer in peers))
        egress=AuthEgress()
        with patch.object(auth_egress.time,'monotonic',return_value=egress.deadline+1), self.assertRaises(ValueError):
            egress.exchange({'op':'open','authority':AUTHORITY})
        egress=AuthEgress()
        with patch.object(egress,'connect',side_effect=pair):
            for ident in range(1,17):
                self.assertEqual(egress.exchange({'op':'open','authority':AUTHORITY}), {'connection':ident})
                egress.exchange({'op':'close','connection':ident})
            with self.assertRaises(ValueError): egress.exchange({'op':'open','authority':AUTHORITY})
        for data in ('!!', base64.b64encode(b'x' * (auth_egress.CHUNK+1)).decode()):
            egress=AuthEgress()
            with patch.object(egress,'connect',side_effect=pair):
                egress.exchange({'op':'open','authority':AUTHORITY})
            with self.assertRaises(ValueError):
                egress.exchange({'op':'transfer','connection':1,'data':data})
            self.assertTrue(egress.closed)

    def service(self, name, egress):
        store=self.base/(name+'-store'); audit=self.base/(name+'-audit'); audit.mkdir()
        CredentialStore.create(store)
        lease=CredentialStore(store).__enter__()
        self.addCleanup(lease.__exit__)
        return LoginService(audit/'run',lease,egress=egress)

    def test_native_cli_probe_with_proxy_enabled_never_connects(self):
        egress=AuthEgress()
        with self.service('native',egress) as service:
            self.assertEqual(service.probe(),{'state':'status','authenticated':False})
        self.assertEqual((egress.frames,egress.opens),(0,0))
        self.assertTrue(egress.closed)

    def test_operator_driver_success_failure_cancel_timeout_and_false_claim(self):
        for mode,expected in (('success','authenticated'),('failure','login_failed'),
                              ('false_claim','failed_check_status'),('cancel','cancel'),('timeout','cancel')):
            egress=AuthEgress()
            shown=[]
            def display(url,code):
                shown.append((url,code))
                if mode=='cancel': raise KeyboardInterrupt()
            with patch.object(LoginService,'command',return_value=mock_command(mode)):
                with self.service(mode,egress) as service:
                    result=service.start_login(display,timeout=1 if mode=='timeout' else 5)
            self.assertEqual(result['state'],expected,mode)
            if mode != 'success':
                self.assertEqual(result['category'], {'failure':'login_rejected',
                    'false_claim':'status_confirmation', 'cancel':'interrupted', 'timeout':'timeout'}[mode])
            self.assertEqual(shown,[('https://auth.openai.com/codex/device','FIXTURE-7395')])
            anchor=self.base/(mode+'-anchor'); anchor.write_text(json.dumps({'root':service.receipt['root']}))
            self.assertEqual(verify(service.output,anchor)['outcome'],result)
            log=Path(str(service.output)+'.service.jsonl').read_text()
            self.assertNotIn('FIXTURE-7395',log)
            self.assertNotIn('private@example.invalid',log)
            self.assertTrue(egress.closed)
        self.assertFalse(list(sandbox.CGROUP.glob('service-*')))

    def test_failure_categories_exclude_secret_bearing_rpc_and_broken_frames(self):
        marker = 'PRIVATE-CODE-token-email-https://secret.invalid'
        cases = [
            ({'code':-32603,'message':marker,'data':{'status':401,'tls':marker}}, 'rpc_error_unknown'),
            ({'code':-32600,'message':marker}, 'rpc_request_rejected'),
            ({'code':-32602,'message':marker}, 'protocol_schema'),
            ({'code':401,'message':marker}, 'rpc_error_unknown'),
            ({'code':True,'message':marker}, 'protocol_schema'),
            ({'code':-32603,'message':marker,'unexpected':marker}, 'protocol_schema'),
            ({'code':-32603,'message':marker * 2000}, 'transport_or_framing'),
        ]
        scripts = [(f"print(json.dumps({{'id':message['id'],'error':{error!r}}}),flush=True); sys.exit()", category)
                   for error,category in cases]
        scripts += [(f"sys.stdout.write({marker!r}); sys.stdout.flush(); sys.exit()", 'transport_or_framing'),
                    (f"print({marker!r},flush=True); sys.exit()", 'protocol_schema'),
                    ("print('null',flush=True); sys.exit()", 'protocol_schema')]
        for index,(script,category) in enumerate(scripts):
            with self.subTest(index=index), patch.object(LoginService,'command',return_value=mock_command(before_start=script)):
                with self.service(f'errors-{index}',AuthEgress()) as service:
                    result = service.start_login(lambda *_: self.fail('Must not display a code'),timeout=5)
            self.assertEqual(result, {'state':'failed_check_status','category':category,'stage':'start'})
            anchor=self.base/f'errors-{index}-anchor'
            anchor.write_text(json.dumps({'root':service.receipt['root']}))
            self.assertEqual(verify(service.output,anchor)['outcome'],result)
            journal=Path(str(service.output)+'.service.jsonl')
            self.assertNotIn(marker,journal.read_text())
            journal.chmod(0o600)
            journal.write_text(journal.read_text().replace(category, 'unknown'))
            with self.assertRaises(ValueError): verify(service.output,anchor)

    def test_native_device_start_faults_use_namespace_local_issuer(self):
        marker = 'SYNTHETIC-PRIVATE-PROVIDER-BODY'
        for index,(status,body,truncated,expected) in enumerate((
                (404,marker,False,'rpc_request_rejected'),
                (403,marker,False,'rpc_error_unknown'),
                (500,marker,False,'rpc_error_unknown'),
                (200,marker,False,'rpc_error_unknown'),
                (200,'{}',False,'rpc_error_unknown'),
                (200,marker,True,'rpc_error_unknown'))):
            # This test-only issuer lives inside the same network namespace.
            # No host listener, production authority change or live DNS/connect.
            fixture = f'''
import os, threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length',0)))
        with open('/tmp/codex-home/fixture-requests','a') as record:
            record.write(self.path+'\\n')
        body={body.encode()!r}
        self.send_response({status})
        self.send_header('Content-Length',str(len(body)+{10 if truncated else 0}))
        self.send_header('Connection','close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection=True
server=HTTPServer(('127.0.0.1',0),Fixture)
os.environ['CODEX_APP_SERVER_LOGIN_ISSUER']='http://127.0.0.1:'+str(server.server_port)
threading.Thread(target=server.serve_forever,daemon=True).start()
'''
            egress=AuthEgress()
            with self.subTest(status=status,body=body,truncated=truncated):
                service=self.service(f'native-fault-{index}',egress)
                native=service.command()
                wrapper=['/usr/bin/python3.11','-I','-S','-c',
                    "import os; os.environ.update(NO_PROXY='127.0.0.1',no_proxy='127.0.0.1'); "
                    +f"os.execv('/opt/codex',{native!r})"]
                with patch.object(service,'command',return_value=wrapper):
                    source=fixture.encode()+service.source()
                with patch.object(service,'source',return_value=source), service:
                    result=service.start_login(lambda *_: self.fail('No device code expected'),timeout=10)
                self.assertEqual(result,{'state':'failed_check_status','category':expected,'stage':'start'})
                self.assertEqual((egress.opens,egress.frames),(0,0))
                home=service.store.path/'home'
                self.assertEqual((home/'fixture-requests').read_text().splitlines(),
                                 ['/api/accounts/deviceauth/usercode'])
                self.assertFalse((home/'auth.json').exists())
                anchor=self.base/f'native-fault-anchor-{index}'
                anchor.write_text(json.dumps({'root':service.receipt['root']}))
                self.assertEqual(verify(service.output,anchor)['outcome'],result)
                self.assertNotIn(marker,Path(str(service.output)+'.service.jsonl').read_text())
                with LoginService(service.output.parent/'status',service.store) as probe:
                    self.assertEqual(probe.probe(),{'state':'status','authenticated':False})

    def test_native_tls_validation_through_restricted_relay(self):
        # Synthetic PKI only. Private keys stay at the local fixture server;
        # the native service receives only a test root certificate.
        def openssl(*args):
            subprocess.run(['openssl',*args],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        root,key=self.base/'root.pem',self.base/'root.key'
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                '-subj','/CN=Offline Test Root','-keyout',str(key),'-out',str(root))
        certificates={}
        for name,hostname in (('valid','auth.openai.com'),('wrong','wrong.invalid')):
            leaf,private,csr,ext=[self.base/(name+suffix) for suffix in ('.pem','.key','.csr','.ext')]
            ext.write_text(f'basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:{hostname}\nextendedKeyUsage=serverAuth\n')
            openssl('req','-new','-newkey','rsa:2048','-nodes','-subj',f'/CN={hostname}',
                    '-keyout',str(private),'-out',str(csr))
            openssl('x509','-req','-in',str(csr),'-CA',str(root),'-CAkey',str(key),
                    '-set_serial','1' if name=='valid' else '2','-days','1',
                    '-extfile',str(ext),'-out',str(leaf))
            certificates[name]=(leaf,private)
        server_code='''
import json,socket,ssl,sys,time
from pathlib import Path
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(sys.argv[1],sys.argv[2])
record=Path(sys.argv[3]); requests=[]; accepted=0; errors=0
def save(): record.write_text(json.dumps(dict(requests=requests,accepted=accepted,errors=errors)))
save()
with socket.socket() as listener:
 listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(20)
 print(listener.getsockname()[1],flush=True)
 while True:
  raw,_=listener.accept();accepted+=1;save();raw.settimeout(5)
  if sys.argv[4]=='eof': raw.close();continue
  if sys.argv[4]=='stall': time.sleep(20);raw.close();continue
  try:
   with ctx.wrap_socket(raw,server_side=True) as connection:
    data=b''
    while b'\\r\\n\\r\\n' not in data and len(data)<16384:
     chunk=connection.recv(4096)
     if not chunk: break
     data+=chunk
    requests.append(data.split(b'\\r\\n')[0].decode('ascii'));save()
    body=b'PRIVATE-NATIVE-TLS-FIXTURE'
    status=(b'HTTP/1.1 302 Found\\r\\nLocation: https://blocked.invalid/\\r\\n' if sys.argv[4]=='redirect'
            else b'HTTP/1.1 404 Not Found\\r\\n')
    connection.sendall(status+b'Content-Length: '+str(len(body)).encode()+b'\\r\\nConnection: close\\r\\n\\r\\n'+body)
  except (ssl.SSLError,OSError): errors+=1;save();raw.close()
'''
        for mode in ('trusted','untrusted','hostname','eof','stall','redirect'):
            with self.subTest(mode=mode):
                leaf,private=certificates['wrong' if mode=='hostname' else 'valid']
                record=self.base/(mode+'-tls-record.json')
                server=subprocess.Popen([sys.executable,'-u','-c',server_code,str(leaf),str(private),str(record),mode],
                                        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                try:
                    port=int(server.stdout.readline())
                    egress=AuthEgress()
                    service=self.service('native-tls-'+mode,egress)
                    source=service.source()
                    if mode!='untrusted':
                        source=("import os\nfrom pathlib import Path\n"
                                +f"Path('/tmp/codex-home/test-ca.pem').write_text({root.read_text()!r})\n"
                                +"os.environ['CODEX_CA_CERTIFICATE']='/tmp/codex-home/test-ca.pem'\n").encode()+source
                    def connect():
                        sock=socket.create_connection(('127.0.0.1',port),timeout=2)
                        sock.setblocking(False)
                        return sock
                    with patch.object(egress,'connect',side_effect=connect), \
                            patch.object(service,'source',return_value=source), service:
                        result=service.start_login(lambda *_: self.fail('No code expected'),timeout=2 if mode=='stall' else 10)
                    self.assertEqual(result,{'state':'timed_out_check_status' if mode=='stall' else 'failed_check_status','stage':'start',
                        'category':'timeout' if mode=='stall' else 'rpc_request_rejected' if mode=='trusted' else 'rpc_error_unknown'})
                    observed=json.loads(record.read_text())
                    self.assertGreater(observed['accepted'],0)
                    self.assertEqual(observed['requests'],
                        ['POST /api/accounts/deviceauth/usercode HTTP/1.1'] if mode in ('trusted','redirect') else [])
                    if mode=='redirect': self.assertEqual(egress.opens,1)
                    self.assertGreater(egress.bytes,0)
                    self.assertEqual(egress.opens,observed['accepted'])
                    self.assertTrue(egress.closed)
                    self.assertFalse((service.store.path/'home'/'auth.json').exists())
                    anchor=self.base/(mode+'-tls-anchor')
                    anchor.write_text(json.dumps({'root':service.receipt['root']}))
                    self.assertEqual(verify(service.output,anchor)['outcome'],result)
                    self.assertNotIn('PRIVATE-NATIVE-TLS-FIXTURE',Path(str(service.output)+'.service.jsonl').read_text())
                    with LoginService(service.output.parent/'status',service.store) as probe:
                        self.assertEqual(probe.probe(),{'state':'status','authenticated':False})
                finally:
                    if server.poll() is None: server.terminate()
                    server.communicate(timeout=5)

    def test_operator_cli_requires_explicit_opt_in_and_terminal(self):
        for flags in ([],['--enable-auth-egress']):
            result=subprocess.run([sys.executable,'-m','synthetic_harness.login','start',
                '--store',str(self.base/'not-created'), '--output',str(self.base/'audit'/'run'),
                '--anchor',str(self.base/'anchor'),*flags],capture_output=True,text=True)
            self.assertEqual(result.returncode,2)
            self.assertFalse((self.base/'anchor').exists())

    def test_tls_tunnel_through_real_namespace_without_external_network(self):
        key,cert=self.base/'key.pem',self.base/'cert.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-subj','/CN=auth.openai.com','-addext','subjectAltName=DNS:auth.openai.com',
            '-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        server_code='''
import socket,ssl,sys
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(sys.argv[1],sys.argv[2])
with socket.socket() as listener:
 listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(15)
 print(listener.getsockname()[1],flush=True)
 for _ in range(2):
  raw,_=listener.accept()
  try:
   with ctx.wrap_socket(raw,server_side=True) as connection:
    data=b''
    while b'\\r\\n\\r\\n' not in data: data+=connection.recv(4096)
    body=b'PRIVATE-TLS-FIXTURE'
    connection.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Length: 19\\r\\nConnection: close\\r\\n\\r\\n'+body)
  except ssl.SSLError: raw.close()
'''
        server=subprocess.Popen([sys.executable,'-u','-c',server_code,str(cert),str(key)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            port=int(server.stdout.readline())
            client='''
import http.client,os,ssl,urllib.parse
proxy=urllib.parse.urlparse(os.environ['HTTPS_PROXY'])
context=ssl.create_default_context(cadata=CERT)
connection=http.client.HTTPSConnection(proxy.hostname,proxy.port,context=context,timeout=5)
connection.set_tunnel('auth.openai.com',443)
connection.request('GET','/offline-fixture')
assert connection.getresponse().read()==b'PRIVATE-TLS-FIXTURE'
connection.close()
'''
            for index,trusted in enumerate((True,False)):
                # Second client does not trust the fixture CA: TLS must fail,
                # rather than allowing the proxy to bypass certificate checks.
                source='CERT='+repr(cert.read_text() if trusted else None)+'\n'+client
                egress=AuthEgress()
                def connect():
                    sock=socket.create_connection(('127.0.0.1',port),timeout=2)
                    sock.setblocking(False)
                    return sock
                with patch.object(egress,'connect',side_effect=connect), patch.object(LoginService,'command',return_value=mock_command(before_start=source)):
                    with self.service(f'tls-{index}',egress) as service:
                        result=service.start_login(lambda *_: None,timeout=10)
                self.assertEqual(result['state'],'authenticated' if trusted else 'failed_check_status')
                self.assertGreater(egress.bytes,0)
                self.assertEqual(egress.opens,1)
                log=Path(str(service.output)+'.service.jsonl').read_text()
                self.assertNotIn('PRIVATE-TLS-FIXTURE',log)
                self.assertNotIn('FIXTURE-7395',log)
            self.assertEqual(server.wait(timeout=5),0,server.stderr.read())
        finally:
            if server.poll() is None: server.terminate()
            server.communicate(timeout=5)
