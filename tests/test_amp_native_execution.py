"""Pinned native startup/extension probes. Every backend connection is local.

These characterize startup restrictions, not a successful agent turn. The mock
rejects thread creation/continuation; no real account, thread or model is used.
"""
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
from synthetic_harness.amp_execute import AmpExecuteService
from synthetic_harness.login import CredentialStore
from test_amp_tls import SERVER


THREAD = 'T-00000000-0000-7000-8000-000000000001'
MARKERS = ('module','init','registered','start','end','tool','synthetic-key','host-hidden','mcp')
# Lives only in the disposable service /tmp, never in an installed host plugin
# directory. Reports booleans, never reads a real key or copies key contents.
PLUGIN = """import {writeFileSync,readFileSync,existsSync} from 'node:fs';
export const description = 'Offline harmless lifecycle canary';
writeFileSync('/tmp/plugin-module','yes');
if (readFileSync('/service-private/amp-key','utf8') === 'offline-native-amp-fixture-not-a-key') writeFileSync('/tmp/plugin-synthetic-key','yes');
if (!existsSync('/home/user/workspace')) writeFileSync('/tmp/plugin-host-hidden','yes');
export default function(amp) {
  writeFileSync('/tmp/plugin-init','yes');
  amp.on('agent.start', () => {writeFileSync('/tmp/plugin-start','yes'); return {}});
  amp.on('agent.end', () => {writeFileSync('/tmp/plugin-end','yes'); return {}});
  amp.on('tool.call', () => {writeFileSync('/tmp/plugin-tool','yes'); return {action:'reject-and-continue',message:'Offline canary'}});
  writeFileSync('/tmp/plugin-registered','yes');
}
"""


class AmpNativeExecutionTests(unittest.TestCase):
    def test_native_startup_constraints_and_unreached_execution_gates(self):
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
                for mode in ('account_rejected','execute','absent','zero_wait','continue',
                             'mcp_rejected','mcp_allowed','remote_rejected','remote_allowed',
                             'dispatch_start','dispatch_tool'):
                    with self.subTest(mode=mode):
                        server_code=SERVER
                        if mode!='account_rejected':
                            # Minimal synthetic account response that reaches the
                            # thread-actors boundary; not a full backend schema.
                            fake={'id':'U-00000000-0000-4000-8000-000000000001',
                                  'userID':'U-00000000-0000-4000-8000-000000000001',
                                  'username':'offline','email':'offline@example.invalid',
                                  'displayName':'Offline','features':[]}
                            body=json.dumps({'ok':True,'result':fake}).encode()
                            server_code=server_code.replace("body=b'PRIVATE-AMP-TLS-FIXTURE'",
                                f"body={body!r} if b'getUserInfo' in data else b'PRIVATE-AMP-TLS-FIXTURE'")
                            server_code=server_code.replace('connection.sendall(status+',
                                "status=b'HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\n' if b'getUserInfo' in data else status\n    connection.sendall(status+")
                        record=base/(mode+'-record')
                        server=subprocess.Popen([sys.executable,'-u','-c',server_code,str(root),str(key),str(record),'fixture'],
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                            env={'PATH':'/usr/bin','LANG':'C.UTF-8'})
                        try:
                            port=int(server.stdout.readline())
                            with patch.object(protected,'resolve_auth',return_value=(ipaddress.ip_address('93.184.216.34'),)):
                                egress=protected.AmpEgress(timeout=15)
                            service=protected.ProtectedAmpService(base/'audit'/mode,store,egress=egress)
                            settings=dict(protected.SETTINGS)
                            if mode.startswith('mcp_'):
                                settings['amp.mcpServers']={'offline_canary':{'command':'/usr/bin/python3.11',
                                    'args':['-I','-S','-c',"from pathlib import Path; Path('/tmp/plugin-mcp').write_text('yes')"]}}
                            if mode.startswith('remote_'):
                                settings['amp.mcpServers']={'offline_canary':{'url':'https://ampcode.com/offline-mcp'}}
                            if mode.endswith('_allowed'): settings['amp.mcpPermissions']=[]
                            args=['-x','Reply OFFLINE. Do not use tools.','--stream-json',
                                  '--mode','openai/gpt-6-astra','--features','fast']
                            if mode=='continue': args=['threads','continue',THREAD,*args]
                            if mode=='zero_wait': args+=['--plugin-ready-timeout','0']
                            if mode.startswith('dispatch_'):
                                event='agent.start' if mode=='dispatch_start' else 'tool.call'
                                data=({'thread':{'id':THREAD},'message':'offline','id':'message-1'} if mode=='dispatch_start'
                                      else {'thread':{'id':THREAD},'tool':'shell_command','input':{'command':'true'},'toolUseID':'offline-1'})
                                args=['plugins','exec','/tmp/.amp/plugins/canary.ts',event,'--data',json.dumps(data)]
                            command=['/opt/amp',*args,'--settings-file','/tmp/amp-settings.json']
                            with patch.object(service,'command',return_value=command),patch.object(protected,'SETTINGS',settings):
                                source=service.source()
                            prep=f"Path('/tmp/fixture-ca.pem').write_text({root.read_text()!r})\n    "
                            if mode!='absent':
                                prep+=f"Path('/tmp/.amp/plugins').mkdir(parents=True)\n    Path('/tmp/.amp/plugins/canary.ts').write_text({PLUGIN!r})\n    "
                            source=source.replace(b'env=dict(os.environ)',(prep+'env=dict(os.environ)').encode())
                            source=source.replace(b"NODE_EXTRA_CA_CERTS='/opt/public-ca.pem'",b"NODE_EXTRA_CA_CERTS='/tmp/fixture-ca.pem'")
                            # Only boolean canary evidence leaves the namespace.
                            source=source.replace(b"emit({'op':'probe_result','state':state})",
                                (f"emit({{'offline_markers':{{name:Path('/tmp/plugin-'+name).exists() for name in {MARKERS!r}}}}})\n    emit({{'op':'probe_result','state':state}})").encode())
                            read=service.read;markers={}
                            def observe(deadline):
                                reply=read(deadline)
                                if set(reply)=={'offline_markers'}:
                                    markers.update(reply['offline_markers'])
                                    return read(deadline)
                                return reply
                            service.read=observe
                            def connect():
                                sock=socket.create_connection(('127.0.0.1',port),timeout=2);sock.setblocking(False);return sock
                            started=time.monotonic()
                            with patch.object(protected.AmpEgress,'connect',side_effect=AssertionError('External transport forbidden')), \
                                    patch.object(egress,'connect',side_effect=connect),patch.object(service,'source',return_value=source),service:
                                result=service.probe()
                            self.assertLess(time.monotonic()-started,14)
                            self.assertEqual(result,{'state':'runtime_ready' if mode.startswith('dispatch_') else 'runtime_failed',
                                                     'authenticated':None})
                            self.assertEqual(set(markers),set(MARKERS))
                            loaded=mode not in ('absent','account_rejected')
                            for marker in ('module','init','registered','synthetic-key','host-hidden'):
                                self.assertEqual(markers[marker],loaded)
                            self.assertEqual(markers['mcp'],mode=='mcp_allowed')
                            requests=json.loads(record.read_text())['requests']
                            allowed={'POST /api/internal?getUserInfo HTTP/1.1','POST /api/telemetry HTTP/1.1',
                                     'POST /api/internal?loadPlugins HTTP/1.1','POST /api/internal?loadSkills HTTP/1.1',
                                     'POST /api/thread-actors HTTP/1.1','POST /api/internal?getThreadTail HTTP/1.1'}
                            if mode=='remote_allowed': allowed|={'POST /offline-mcp HTTP/1.1','GET /offline-mcp HTTP/1.1'}
                            self.assertLessEqual(set(requests),allowed)
                            self.assertEqual(any('/offline-mcp ' in line for line in requests),mode=='remote_allowed')
                            if mode.startswith('dispatch_'):
                                self.assertEqual(requests,[])
                            elif mode=='account_rejected':
                                self.assertIn('POST /api/internal?getUserInfo HTTP/1.1',requests)
                                self.assertNotIn('POST /api/thread-actors HTTP/1.1',requests)
                            elif mode=='continue':
                                self.assertIn('POST /api/internal?getThreadTail HTTP/1.1',requests)
                                self.assertNotIn('POST /api/thread-actors HTTP/1.1',requests)
                            else:
                                self.assertIn('POST /api/thread-actors HTTP/1.1',requests)
                            anchor=base/(mode+'-anchor');anchor.write_text(json.dumps({'root':service.receipt['root']}))
                            self.assertEqual(protected.verify(service.output,anchor)['outcome'],result)
                            journal=Path(str(service.output)+'.service.jsonl').read_text()
                            for private in ('offline-native-amp-fixture-not-a-key','PRIVATE-AMP-TLS-FIXTURE','offline_markers'):
                                self.assertNotIn(private,journal)
                            self.assertTrue(egress.closed)
                            self.assertFalse(list(sandbox.CGROUP.glob('service-*')))
                            print('native-execution',mode,json.dumps({'state':result['state'],'markers':markers,
                                'thread_create_requests':requests.count('POST /api/thread-actors HTTP/1.1')}),flush=True)
                        finally:
                            server.terminate();server.communicate(timeout=5)
                # An offline diagnostic never grants production native execution.
                with self.assertRaises(ValueError): protected.ProtectedAmpService(base/'audit'/'live',store,'-x')
                with self.assertRaises(ValueError): AmpExecuteService(base/'audit'/'live')
