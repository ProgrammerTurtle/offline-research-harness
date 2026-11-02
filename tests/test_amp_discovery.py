"""Native non-model discovery; synthetic credentials and loopback TLS only."""
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
from test_amp_tls import SERVER


class AmpDiscoveryTests(unittest.TestCase):
    def test_native_discovery_does_not_attest_auth_or_builtin_suppression(self):
        names_by_policy = {}
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);(base/'audit').mkdir()
            root,key=base/'root.pem',base/'root.key'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                '-subj','/CN=ampcode.com','-addext','subjectAltName=DNS:ampcode.com',
                '-keyout',str(key),'-out',str(root)],check=True,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            CredentialStore.create(base/'store')
            with CredentialStore(base/'store') as store:
                protected.provision(store,'offline-native-amp-fixture-not-a-key')
                for mode in ('baseline','wildcard','named','401','no_key',
                             'mcp_rejected','mcp_allowed','remote_rejected','remote_allowed','stall'):
                    with self.subTest(mode=mode):
                        record=base/(mode+'-record')
                        server_code=SERVER.replace('404 Not Found','401 Unauthorized') if mode=='401' else SERVER
                        server=subprocess.Popen([sys.executable,'-u','-c',server_code,str(root),str(key),str(record),mode],
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                            env={'PATH':'/usr/bin','LANG':'C.UTF-8'})
                        try:
                            port=int(server.stdout.readline())
                            with patch.object(protected,'resolve_auth',return_value=(ipaddress.ip_address('93.184.216.34'),)):
                                egress=protected.AmpEgress(timeout=15)
                            service=protected.ProtectedAmpService(base/'audit'/mode,store,egress=egress)
                            settings=dict(protected.SETTINGS)
                            if mode=='baseline': settings['amp.tools.disable']=[]
                            if mode=='named': settings['amp.tools.disable']=sorted(names_by_policy['baseline'])
                            if mode.startswith('mcp_'):
                                settings['amp.mcpServers']={'offline_canary':{'command':'/usr/bin/python3.11',
                                    'args':['-I','-S','-c',"from pathlib import Path; Path('/tmp/mcp-started').write_text('started')"]}}
                            if mode.startswith('remote_'):
                                settings['amp.mcpServers']={'offline_canary':{'url':'https://ampcode.com/offline-mcp'}}
                            if mode.endswith('_allowed'): settings['amp.mcpPermissions']=[]
                            # Test-only non-model command substitution; never expose a
                            # caller-selected command or fixture routing in production.
                            command=['/opt/amp','tools','list','--json','--mode','openai/gpt-6-astra',
                                     '--settings-file','/tmp/amp-settings.json']
                            with patch.object(service,'command',return_value=command),patch.object(protected,'SETTINGS',settings):
                                source=service.source()
                            source=source.replace(b'env=dict(os.environ)',
                                (f"Path('/tmp/fixture-ca.pem').write_text({root.read_text()!r})\n    env=dict(os.environ)").encode())
                            source=source.replace(b"NODE_EXTRA_CA_CERTS='/opt/public-ca.pem'",b"NODE_EXTRA_CA_CERTS='/tmp/fixture-ca.pem'")
                            if mode=='no_key': source=source.replace(b'env.update(AMP_API_KEY=key,',b'env.update(')
                            # Stdout contains only the synthetic registry; stderr stays
                            # discarded. This diagnostic envelope is test-only.
                            source=source.replace(b"state='runtime_ready' if result.returncode==0 else 'runtime_failed'",
                                b"output.seek(0)\n                emit({'offline_registry':json.loads(output.read(65537))})\n                state='runtime_ready' if result.returncode==0 else 'runtime_failed'")
                            source=source.replace(b"emit({'op':'probe_result','state':state})",
                                b"emit({'offline_marker':Path('/tmp/mcp-started').exists()})\n    emit({'op':'probe_result','state':state})")
                            read=service.read;diagnostics={}
                            def observe(deadline):
                                while True:
                                    reply=read(deadline)
                                    if set(reply) in ({'offline_registry'},{'offline_marker'}): diagnostics.update(reply)
                                    else: return reply
                            service.read=observe
                            def connect():
                                sock=socket.create_connection(('127.0.0.1',port),timeout=2);sock.setblocking(False);return sock
                            started=time.monotonic()
                            with patch.object(protected.AmpEgress,'connect',side_effect=AssertionError('External transport forbidden')), \
                                    patch.object(egress,'connect',side_effect=connect),patch.object(service,'source',return_value=source),service:
                                result=service.probe()
                            self.assertLess(time.monotonic()-started,14)
                            observed=json.loads(record.read_text());requests=observed['requests']
                            self.assertEqual(result,{'state':'timeout' if mode in ('no_key','stall') else 'runtime_ready',
                                                     'authenticated':None})
                            self.assertEqual(diagnostics['offline_marker'],mode=='mcp_allowed')
                            if mode=='stall':
                                self.assertEqual(requests,[])
                            elif mode=='no_key':
                                self.assertEqual(requests,['GET /api/auth/oauth-config HTTP/1.1'])
                                self.assertFalse(observed['key_seen'])
                            else:
                                names={item['name'] for item in diagnostics['offline_registry']}
                                self.assertIn('shell_command',names)
                                self.assertIn('POST /api/internal?getUserInfo HTTP/1.1',requests)
                                self.assertIn('POST /api/internal?loadPlugins HTTP/1.1',requests)
                                self.assertTrue(observed['key_seen'])
                                names_by_policy[mode]=names
                                mcp_requests=[line for line in requests if '/offline-mcp ' in line]
                                self.assertEqual(bool(mcp_requests),mode=='remote_allowed')
                                allowed={'POST /api/internal?getUserInfo HTTP/1.1',
                                         'POST /api/internal?loadPlugins HTTP/1.1','POST /api/telemetry HTTP/1.1'}
                                if mode=='remote_allowed': allowed|={'POST /offline-mcp HTTP/1.1','GET /offline-mcp HTTP/1.1'}
                                self.assertLessEqual(set(requests),allowed)
                            anchor=base/(mode+'-anchor');anchor.write_text(json.dumps({'root':service.receipt['root']}))
                            self.assertEqual(protected.verify(service.output,anchor)['outcome'],result)
                            journal=Path(str(service.output)+'.service.jsonl').read_text()
                            for private in ('offline-native-amp-fixture-not-a-key','PRIVATE-AMP-TLS-FIXTURE','offline_registry'):
                                self.assertNotIn(private,journal)
                            self.assertTrue(egress.closed)
                            self.assertFalse(list(sandbox.CGROUP.glob('service-*')))
                            print('native-discovery',mode,json.dumps({'state':result['state'],
                                'tools':len(diagnostics.get('offline_registry',[])),
                                'local_mcp_started':diagnostics['offline_marker']}),flush=True)
                        finally:
                            server.terminate();server.communicate(timeout=5)
        self.assertEqual(names_by_policy['baseline'],names_by_policy['wildcard'])
        self.assertEqual(names_by_policy['baseline'],names_by_policy['named'])
        self.assertEqual(names_by_policy['baseline'],names_by_policy['401'])
