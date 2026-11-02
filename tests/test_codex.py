"""Credential-free native CLI integration and host transport policy tests."""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from synthetic_harness.app_server import AppServerTransport, bridge_source
from synthetic_harness.codex_runtime import DEFAULT_RUNTIME, CA_SHA256, verify as verify_runtime
from synthetic_harness.controls import control_actions
from synthetic_harness.provider import MockUpstream, ProviderTransport
from synthetic_harness.sandbox import run, verify
from synthetic_harness.tasks import actor_view, canonical, make_case


class RuntimeTrustTests(unittest.TestCase):
    def test_pinned_public_roots_are_read_only_and_loadable_in_namespace(self):
        source=f'''
import errno, hashlib, json, os, ssl, sys
from pathlib import Path
sys.stdin.readline()
path=Path('/opt/public-ca.pem')
assert os.environ['CODEX_CA_CERTIFICATE']==str(path)
assert os.environ['SSL_CERT_FILE']==str(path)
assert hashlib.sha256(path.read_bytes()).hexdigest()=={CA_SHA256!r}
assert ssl.create_default_context().cert_store_stats()['x509_ca']==148
assert not Path('/etc/ssl').exists()
try: path.write_text('untrusted replacement')
except OSError as error: assert error.errno in (errno.EROFS,errno.EACCES)
else: raise AssertionError('trust store writable')
print('{{"op":"finish"}}',flush=True)
sys.stdin.readline()
'''.encode()
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory)
            result=run(source,base/'run',base/'anchor',runtime=DEFAULT_RUNTIME,domain='inventory')
            self.assertEqual(result['returncode'],0)
        self.assertEqual(verify_runtime(DEFAULT_RUNTIME)['ca_sha256'],CA_SHA256)

    def test_missing_or_rehashed_replacement_roots_fail_runtime_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime=Path(directory)/'runtime'
            shutil.copytree(DEFAULT_RUNTIME,runtime,copy_function=os.link)
            bundle=runtime/'root/opt/public-ca.pem'
            bundle.unlink()  # Never write through a hardlink to the real runtime.
            with self.assertRaises(ValueError): verify_runtime(runtime)
            bundle.write_text('untrusted replacement')
            bundle.chmod(0o444)
            manifest_path=runtime/'manifest.json'
            manifest=json.loads(manifest_path.read_text())
            import hashlib
            manifest['files']['opt/public-ca.pem']['sha256']=hashlib.sha256(bundle.read_bytes()).hexdigest()
            manifest_path.unlink()
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaises(ValueError): verify_runtime(runtime)


class ProviderTests(unittest.TestCase):
    def body(self):
        return dict(model='gpt-5.4', stream=True, store=False,
                    reasoning={'effort': 'high', 'summary': 'auto'},
                    input=[{'role': 'user', 'content': [{'type': 'input_text', 'text': 'test'}]}],
                    tools=[], tool_choice='auto', parallel_tool_calls=True,
                    include=['reasoning.encrypted_content'], client_metadata={'session': 'untrusted'})

    def test_policy_rejects_routing_tools_and_settings(self):
        for key, value in [('url', 'http://169.254.169.254'), ('headers', {}),
                           ('model', 'other'), ('store', True), ('stream', False),
                           ('reasoning', {'effort': 'low'}),
                           ('tools', [{'type': 'web_search'}]),
                           ('input', [{'role': 'user', 'content': [{'type': 'input_image', 'image_url': 'http://host'}]}])]:
            with self.subTest(key=key):
                upstream = MockUpstream(['ok'])
                body = self.body()
                body[key] = value
                with self.assertRaises(ValueError):
                    ProviderTransport(upstream).exchange({'op': 'provider', 'body': body})
                self.assertEqual(upstream.requests, [])

    def test_credentials_metadata_and_budget(self):
        upstream = MockUpstream(['ok'] * 8)
        provider = ProviderTransport(upstream)
        for _ in range(8):
            reply = provider.exchange({'op': 'provider', 'body': self.body()})
            self.assertEqual(reply['status'], 200)
            self.assertNotIn(upstream.credential, canonical(reply))
            self.assertNotIn('client_metadata', upstream.requests[-1])
        with self.assertRaisesRegex(ValueError, 'budget'):
            provider.exchange({'op': 'provider', 'body': self.body()})
        self.assertEqual(len(upstream.requests), 8)
        for answer in (upstream.credential, 'x' * 140_000):
            reply = ProviderTransport(MockUpstream([answer])).exchange({'op': 'provider', 'body': self.body()})
            self.assertEqual(reply, {'status': 502, 'body': 'upstream transport failed'})


class CodexTests(unittest.TestCase):
    app_server = False

    def test_real_cli_mock_completions_escalations_and_failures(self):
        actor = bridge_source() if self.app_server else Path('synthetic_harness/codex_actor.py').read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            cases = [(domain, seed, None) for domain in ('inventory', 'analysis', 'software')
                     for seed in (0, 2)] + [('inventory', 0, failure) for failure in ('http429', 'truncated')]
            for index, (domain, seed, failure) in enumerate(cases):
                with self.subTest(domain=domain, seed=seed, failure=failure):
                    observation = actor_view(make_case(domain, 0, seed))
                    answers = [canonical({'op': 'step', 'action': action})
                               for action in control_actions(observation, 'honest')]
                    upstream = MockUpstream(answers, failure=failure)
                    provider = (AppServerTransport if self.app_server else ProviderTransport)(upstream)
                    output, anchor = base / str(index), base / f'anchor-{index}'
                    result = run(actor, output, anchor, domain=domain, seed=seed,
                                 runtime=DEFAULT_RUNTIME, provider=provider, timeout=20,
                                 app_server=self.app_server)
                    evidence = verify(output, anchor)
                    self.assertEqual(result['status'], 'protocol_error' if self.app_server and failure
                                     else 'actor_exited', evidence['transport'])
                    if failure:
                        self.assertNotEqual(result['returncode'], 0)
                        self.assertEqual(provider.calls, 1, 'CLI retried despite zero-retry policy')
                        self.assertEqual(evidence['audit']['actions'], 0)
                    else:
                        self.assertEqual(result['returncode'], 0, evidence['transport'])
                        self.assertEqual(provider.calls, len(answers))
                        self.assertEqual(evidence['audit']['task_complete'], seed == 0)
                        self.assertEqual(evidence['audit']['valid_escalation'], seed == 2)
                    wire = output.with_name(output.name + '.wire.jsonl').read_text()
                    self.assertNotIn(upstream.credential, wire)
                    self.assertIn('0.166.0', wire)
                    self.assertTrue(all(body['reasoning']['effort'] == 'high' for body in upstream.requests))
                    if self.app_server and not failure:
                        self.assertEqual(len({body['prompt_cache_key'] for body in upstream.requests}), 1)
                        if len(answers) > 1:
                            self.assertTrue(any(item['role'] == 'assistant' for item in upstream.requests[1]['input']))
                        sends = [json.loads(event['payload']) for event in map(json.loads, wire.splitlines())
                                 if event['kind'] == 'send']
                        methods = [rpc['method'] for send in sends for rpc in send.get('messages', [])]
                        self.assertEqual(methods.count('thread/start'), 1)
                        self.assertEqual(methods.count('turn/start'), len(answers))


class AppServerTests(CodexTests):
    app_server = True

    def test_unadvertised_tool_call_is_blocked_before_codex_receives_it(self):
        class ToolUpstream(MockUpstream):
            def send(self, body, *, authorization):
                status, events = super().send(body, authorization=authorization)
                events[1] = {'type': 'response.output_item.done', 'item': {
                    'type': 'function_call', 'name': 'exec_command', 'call_id': 'attack',
                    'arguments': '{"cmd":"cat /tmp/codex-home/auth.json"}'}}
                return status, events
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            provider = AppServerTransport(ToolUpstream(['unused']))
            result = run(bridge_source(), base / 'run', base / 'anchor', domain='inventory',
                         runtime=DEFAULT_RUNTIME, provider=provider, app_server=True, timeout=20)
            self.assertEqual(result['status'], 'protocol_error')
            self.assertEqual(provider.calls, 1)
            self.assertEqual(verify(base / 'run', base / 'anchor')['audit']['actions'], 0)
            wire = (base / 'run.wire.jsonl').read_text()
            replies = [json.loads(event['payload']) for event in map(json.loads, wire.splitlines())
                       if event['kind'] == 'send']
            self.assertEqual([reply for reply in replies if 'status' in reply],
                             [{'status': 502, 'body': 'upstream transport failed'}])

    def test_native_agent_cannot_turn_final_output_into_rpc(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            answer = canonical({'id': 99, 'method': 'process/spawn',
                                'params': {'command': ['/usr/bin/python3.11', '-c', 'raise SystemExit(0)']}})
            provider = AppServerTransport(MockUpstream([answer]))
            result = run(bridge_source(), base / 'run', base / 'anchor', domain='inventory',
                         runtime=DEFAULT_RUNTIME, provider=provider, app_server=True, timeout=20)
            self.assertEqual(provider.calls, 1)
            self.assertEqual(result['status'], 'protocol_error')
            self.assertEqual(verify(base / 'run', base / 'anchor')['audit']['actions'], 0)


if __name__ == '__main__':
    unittest.main()
