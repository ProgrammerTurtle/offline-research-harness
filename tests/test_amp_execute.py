"""Offline Amp stream mocks and credential-free native inspection only."""

import copy
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from synthetic_harness import sandbox
from synthetic_harness.amp_execute import AmpExecuteService, AmpRuntimeProbe, AMP_VERSION, StreamGateway
from synthetic_harness.controls import control_actions
from synthetic_harness.tasks import actor_view, canonical, make_case
from synthetic_harness.trusted_service import ACTOR, IDENTITY


class AmpExecuteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def answers(self, domain='inventory', seed=0):
        return [canonical({'op':'step','action':action}) for action in
                control_actions(actor_view(make_case(domain,0,seed)), 'honest')]

    def events(self):
        answer=self.answers()[0]
        return ({'type':'system','subtype':'init','session_id':'session-a','cwd':'/tmp',
                 'tools':[],'mcp_servers':[],'subagents':[]},
                {'type':'assistant','session_id':'session-a','parent_tool_use_id':None,
                 'message':{'type':'message','role':'assistant','stop_reason':'end_turn',
                    'content':[{'type':'text','text':answer}]}},
                {'type':'result','subtype':'success','session_id':'session-a','is_error':False,
                 'result':answer,'duration_ms':7,'num_turns':1})

    def test_proposals_require_success_and_keep_session_and_turn_budget(self):
        init,assistant,result=self.events()
        gateway=StreamGateway()
        for index in range(5):
            request=gateway.request({'round':index})
            self.assertEqual(request['message']['role'],'user')
            self.assertIsNone(gateway.accept(init))
            self.assertIsNone(gateway.accept(dict(request,session_id='session-a',parent_tool_use_id=None)))
            self.assertIsNone(gateway.accept(assistant))
            self.assertIsNone(gateway.accept(result))
            self.assertEqual(gateway.complete(0),{'action':{'tool':'check','args':{}}})
            self.assertEqual(gateway.session,'session-a')
        with self.assertRaises(ValueError): gateway.request({})

    def test_forged_tools_replays_results_and_unknown_formats_fail_closed(self):
        init,assistant,result=self.events()
        cases=[]
        tool=copy.deepcopy(assistant)
        tool['message']['content']=[{'type':'tool_use','name':'shell','input':{'command':'id'}}]
        cases.append([tool])
        cases.extend([[dict(assistant,session_id='foreign')], [assistant,assistant],
                      [result], [assistant,dict(result,is_error=True)],
                      [assistant,dict(result,result='{"op":"finish"}')],
                      [assistant,dict(result,unexpected='field')],
                      [{'type':'approval','session_id':'session-a'}],
                      [dict(assistant, message={'id':'m','role':'assistant','content':[{'type':'text','text':'x'*70000}]})]])
        for events in cases:
            gateway=StreamGateway();request=gateway.request({});gateway.accept(init)
            gateway.accept(dict(request,session_id='session-a',parent_tool_use_id=None))
            with self.assertRaises(ValueError):
                for event in events: gateway.accept(event)
            with self.assertRaises(ValueError): gateway.request({})
        for field in ('tools','mcp_servers','subagents'):
            gateway=StreamGateway();gateway.request({})
            with self.assertRaises(ValueError): gateway.accept(dict(init,**{field:['unexpected']}))
        with self.assertRaises(ValueError): AmpExecuteService(self.base/'live')
        with self.assertRaises(ValueError): AmpRuntimeProbe(self.base/'live','-x')

    def test_echo_session_exit_and_usage_are_not_assumed(self):
        init,assistant,result=self.events()
        assistant['message']['usage']={'input_tokens':13,'output_tokens':7,'service_tier':'standard'}
        for exitcode in (1,-9,True,None):
            gateway=StreamGateway();request=gateway.request({});gateway.accept(init)
            gateway.accept(dict(request,session_id='session-a',parent_tool_use_id=None))
            gateway.accept(assistant);gateway.accept(result)
            with self.assertRaises(ValueError): gateway.complete(exitcode)
            with self.assertRaises(ValueError): gateway.complete(0)
        gateway=StreamGateway();request=gateway.request({'round':1});gateway.accept(init)
        gateway.accept(dict(request,session_id='session-a',parent_tool_use_id=None))
        gateway.accept(assistant);gateway.accept(result);gateway.complete(0)
        self.assertEqual(gateway.metadata['assistant_usage'],{'input_tokens':13,'output_tokens':7,'service_tier':'standard'})
        self.assertIsNone(gateway.metadata['effective_fast'])
        gateway.request({'round':2})
        with self.assertRaises(ValueError): gateway.accept(dict(init,session_id='foreign'))
        for echo in ({'type':'approval'},dict(request,session_id='session-a',parent_tool_use_id='subagent')):
            gateway=StreamGateway();gateway.request({'round':2});gateway.accept(init)
            with self.assertRaises(ValueError): gateway.accept(echo)
        gateway=StreamGateway();gateway.request({'round':2});gateway.accept(init)
        with self.assertRaises(ValueError): gateway.accept(dict(request,session_id='session-a',parent_tool_use_id=None))
        for bad in ({'input_tokens':True,'output_tokens':1}, {'input_tokens':-1,'output_tokens':7},
                    {'input_tokens':1,'output_tokens':7,'service_tier':'SECRET'},
                    {'input_tokens':1,'output_tokens':7,'unknown':'SECRET'}):
            gateway=StreamGateway();request=gateway.request({});gateway.accept(init)
            gateway.accept(dict(request,session_id='session-a',parent_tool_use_id=None))
            event=copy.deepcopy(assistant);event['message']['usage']=bad
            with self.assertRaises(ValueError): gateway.accept(event)

    def test_six_isolated_episodes_complete_or_escalate_and_verify(self):
        sessions=set()
        for domain in ('inventory','analysis','software'):
            for seed in (0,2):
                output=self.base/f'{domain}-{seed}';anchor=self.base/f'{domain}-{seed}-anchor'
                with AmpExecuteService(output,self.answers(domain,seed)) as service:
                    result=sandbox.run(ACTOR,output,anchor,domain=domain,seed=seed,service=service,timeout=10)
                    self.assertEqual(result['returncode'],0)
                    self.assertEqual(result['status'],'actor_exited')
                    evidence=sandbox.verify(output,anchor)
                    self.assertEqual(evidence['audit']['task_complete'],seed==0)
                    self.assertEqual(evidence['audit']['valid_escalation'],seed==2)
                    sessions.add(service.stream.session)
                    self.assertEqual(service.stream.turns,len(self.answers(domain,seed)))
                journal=Path(str(output)+'.service.jsonl')
                records=[json.loads(line) for line in journal.read_text().splitlines()]
                profile=next(r['payload'] for r in records if r['kind']=='amp_profile')
                self.assertIsNone(profile['effective_model'])
                journal.chmod(0o600);journal.write_text(journal.read_text().replace('offline mock','changed mock'))
                with self.assertRaises(ValueError): sandbox.verify(output,anchor)
        self.assertEqual(len(sessions),6)
        self.assertFalse(list(sandbox.CGROUP.glob('service-*')))

    def test_service_failure_and_flood_leave_no_task_effects(self):
        for index,tail in enumerate((
                "print('{\"type\":\"system\",\"tools\":[\"shell\"]}',flush=True)",
                "import time; time.sleep(10)",
                "print('x'*300000,flush=True)")):
            output=self.base/f'failure-{index}';anchor=self.base/f'anchor-{index}'
            service=AmpExecuteService(output,self.answers())
            with patch.object(service,'source',return_value=IDENTITY+tail.encode()), service:
                result=sandbox.run(ACTOR,output,anchor,domain='inventory',service=service,timeout=.5)
                self.assertIn(result['status'],('protocol_error','wall_timeout'))
                evidence=sandbox.verify(output,anchor)
                self.assertEqual(evidence['audit']['actions'],0)
                self.assertTrue(service.closed)
        self.assertFalse(list(sandbox.CGROUP.glob('service-*')))

    def test_child_exit_framing_and_privacy_before_any_task_effect(self):
        normal='import sys; sys.stdout.write(sys.stdin.read())'
        cases=[normal+'; sys.exit(7)',
               'import sys; data=sys.stdin.read(); sys.stdout.write(data+data.splitlines(True)[-1])',
               'import sys; sys.stdout.write(sys.stdin.read()); print("{\\"op\\":\\"invocation_exit\\",\\"returncode\\":0}")',
               'import sys; sys.stdout.write("{\\"type\\":1,\\"type\\":2}\\n")',
               'import sys; sys.stdout.write("PRIVATE-RAW-ERROR")',
               normal+'; import time; time.sleep(10)']
        for index,code in enumerate(cases):
            with self.subTest(case=index):
                output=self.base/f'child-{index}';anchor=self.base/f'child-anchor-{index}'
                service=AmpExecuteService(output,self.answers())
                source=service.source().replace(repr(normal).encode(),repr(code).encode())
                self.assertNotEqual(source,service.source())
                with patch.object(service,'source',return_value=source),service:
                    result=sandbox.run(ACTOR,output,anchor,domain='inventory',service=service,timeout=5)
                self.assertIn(result['status'],('protocol_error','wall_timeout'))
                self.assertEqual(sandbox.verify(output,anchor)['audit']['actions'],0)
                self.assertNotIn('PRIVATE-RAW-ERROR',Path(str(output)+'.service.jsonl').read_text())
                self.assertFalse(list(sandbox.CGROUP.glob('service-*')))

        # Test the actual mock child's environment, not just its supervisor.
        probe='''import os,sys,socket
from pathlib import Path
assert 'AMP_API_KEY' not in os.environ
for path in ['/home/user/workspace','/service-private/amp-key','/root','/run']:
    assert not Path(path).exists()
with socket.socket() as sock:
    sock.settimeout(.1)
    try:
        sock.connect(('192.0.2.1',443))
        raise AssertionError('external network reachable')
    except OSError:
        pass
print('PRIVATE-STDERR',file=sys.stderr)
sys.stdout.write(sys.stdin.read())
'''
        output=self.base/'private';anchor=self.base/'private-anchor'
        service=AmpExecuteService(output,self.answers())
        source=service.source().replace(repr(normal).encode(),repr(probe).encode())
        with patch.object(service,'source',return_value=source),service:
            result=sandbox.run(ACTOR,output,anchor,domain='inventory',service=service,timeout=10)
        self.assertEqual(result['status'],'actor_exited')
        self.assertTrue(sandbox.verify(output,anchor)['audit']['task_complete'])
        self.assertNotIn('PRIVATE-STDERR',Path(str(output)+'.service.jsonl').read_text())

    def test_native_version_and_help_only_inside_isolation(self):
        canary=self.base/'host-canary'
        canary.write_text('synthetic-host-only')
        probe=f'host_canary={str(canary)!r}\nhost_pid={os.getpid()}\n'.encode()+b'''
import os, resource, socket
from pathlib import Path
for path in [host_canary, '/home/user/workspace', '/home/user/.config/amp',
             '/proc/1/root/home/user/workspace', '/run', '/sys/fs/cgroup']:
    assert not Path(path).exists(), path
assert not Path('/proc/'+str(host_pid)).exists()
assert os.getuid()==65533
assert resource.getrlimit(resource.RLIMIT_AS)==(2*1024**3,2*1024**3)
assert resource.getrlimit(resource.RLIMIT_NOFILE)==(64,64)
try:
    bytearray(3*1024**3)
    raise AssertionError('memory unbounded')
except MemoryError:
    pass
for path in ['/opt/amp','/usr/lib/x86_64-linux-gnu/libpthread.so.0']:
    try:
        open(path,'ab')
        raise AssertionError('runtime writable')
    except OSError:
        pass
try:
    socket.socket(socket.AF_UNIX)
    raise AssertionError('Unix pathname sockets allowed')
except OSError:
    pass
with socket.socket() as s:
    s.settimeout(.2)
    try:
        s.connect(('192.0.2.1',443))
        raise AssertionError('external network reachable')
    except OSError:
        pass
'''
        for operation in ('--version','--help'):
            service=AmpRuntimeProbe(self.base/operation[2:],operation)
            with patch.object(service,'source',return_value=probe+service.source()), service:
                reply=service.read(time.monotonic()+12)
                self.assertEqual(reply['returncode'],0)
                self.assertEqual(reply['stderr_bytes'],0)
                self.assertIn(AMP_VERSION if operation=='--version' else 'Amp CLI',reply['stdout'])
        self.assertFalse(list(sandbox.CGROUP.glob('service-*')))
