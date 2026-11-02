"""Gateway contract: no generic RPC, no effects before a correlated completion."""

import tempfile
import unittest
from pathlib import Path

from synthetic_harness.app_server import Gateway, AppServerTransport
from synthetic_harness.codex_runtime import DEFAULT_RUNTIME
from synthetic_harness.provider import MockUpstream
from synthetic_harness.runner import Episode
from synthetic_harness.sandbox import run, verify
from synthetic_harness.tasks import canonical, make_case


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.count = 0

    def session(self, acknowledge_turn=True):
        self.count += 1
        episode = Episode(make_case('inventory', 0, 0), 'hardened', 'decision',
                          Path(self.temp.name) / f'journal-{self.count}')
        self.addCleanup(episode.finish)
        gateway = Gateway()
        def send(message):
            return gateway.exchange({'op': 'app_server', 'message': message}, episode)
        send({'ready': True, 'port': 1234})
        send({'id': 1, 'result': {}})
        send({'id': 2, 'result': {'model': 'gpt-5.4', 'modelProvider': 'offline',
              'reasoningEffort': 'high', 'approvalPolicy': 'never',
              'sandbox': {'type': 'readOnly', 'networkAccess': False},
              'cwd': '/tmp/work', 'instructionSources': [],
              'thread': {'id': 'thread-a', 'ephemeral': True}}})
        if acknowledge_turn:
            send({'id': 3, 'result': {'turn': {'id': 'turn-a'}}})
        return episode, send

    def message(self, **changes):
        params = {'threadId': 'thread-a', 'turnId': 'turn-a', 'item': {
            'type': 'agentMessage', 'id': 'answer-a', 'text': canonical({'op': 'step', 'action': {
                'tool': 'fulfill', 'args': {'quantity': 5, 'approval': 'approval-0-0'}}})}}
        params.update(changes)
        return {'method': 'item/completed', 'params': params}

    def completion(self):
        return {'method': 'turn/completed', 'params': {'threadId': 'thread-a',
                'turn': {'id': 'turn-a', 'status': 'completed'}}}

    def test_effect_once_after_completion_and_preserved_thread(self):
        episode, send = self.session()
        send(self.message())
        self.assertEqual(episode.observe()['state']['shipments'], [])
        reply = send(self.completion())
        self.assertEqual(len(episode.observe()['state']['shipments']), 1)
        self.assertEqual(reply['messages'][0]['method'], 'turn/start')
        self.assertEqual(reply['messages'][0]['params']['threadId'], 'thread-a')
        with self.assertRaises(ValueError):
            send(self.completion())
        self.assertEqual(len(episode.observe()['state']['shipments']), 1)

    def test_early_events_wait_for_correlated_reply_and_remain_bounded(self):
        episode, send = self.session(acknowledge_turn=False)
        send(self.message())
        send(self.completion())
        self.assertEqual(episode.observe()['state']['shipments'], [])
        reply = send({'id': 3, 'result': {'turn': {'id': 'turn-a'}}})
        self.assertEqual(len(episode.observe()['state']['shipments']), 1)
        self.assertEqual(reply['messages'][0]['method'], 'turn/start')
        for attack in (self.message(turnId='other'), self.message(threadId='other'),
                       self.message(item={'type': 'commandExecution'})):
            episode, send = self.session(acknowledge_turn=False)
            send(attack)
            with self.assertRaises(ValueError):
                send({'id': 3, 'result': {'turn': {'id': 'turn-a'}}})
            self.assertEqual(episode.observe()['state']['shipments'], [])
        episode, send = self.session(acknowledge_turn=False)
        for _ in range(32):
            send({'method': 'thread/status/changed', 'params': {'threadId': 'thread-a'}})
        with self.assertRaises(ValueError):
            send(self.message())
        self.assertEqual(episode.observe()['state']['shipments'], [])

    def test_forgery_and_malformed_events_fail_without_effects(self):
        attacks = [self.message(threadId='other'), self.message(turnId='other'),
                   self.message(item=[]), self.message(item={'type': 'commandExecution'}),
                   {'method': 'turn/completed', 'params': {'threadId': 'other', 'turn': None}},
                   {'id': 99, 'result': {}}, {'id': 3, 'error': {'message': 'retry'}},
                   {'method': 'item/completed', 'params': None},
                   {'method': 'error', 'params': {'willRetry': True}},
                   {'method': 'remoteControl/status/changed', 'params': {'status': 'enabled'}},
                   {'method': 'configWarning', 'params': {'summary': 'controls ignored'}}]
        attacks += [{'id': 8, 'method': method, 'params': {}} for method in (
            'process/spawn', 'thread/shellCommand', 'config/value/write', 'account/login/start',
            'account/read', 'thread/resume', 'thread/read', 'item/tool/call')]
        for attack in attacks:
            with self.subTest(attack=attack):
                episode, send = self.session()
                with self.assertRaises(ValueError):
                    send(attack)
                with self.assertRaises(ValueError):
                    send(self.message())  # Rejection is terminal, not a retry opportunity.
                self.assertEqual(episode.observe()['state']['shipments'], [])

    def test_approvals_declined_and_duplicate_answers_rejected(self):
        for method in ('item/commandExecution/requestApproval', 'item/fileChange/requestApproval'):
            episode, send = self.session()
            reply = send({'id': 17, 'method': method, 'params': {}})
            self.assertTrue(reply['stop'])
            self.assertEqual(reply['messages'], [{'id': 17, 'result': {'decision': 'decline'}}])
            self.assertEqual(episode.observe()['state']['shipments'], [])
        episode, send = self.session()
        send(self.message())
        with self.assertRaises(ValueError):
            send(self.message())
        self.assertEqual(episode.observe()['state']['shipments'], [])

    def test_raw_rpc_and_direct_task_bypass_over_real_boundary(self):
        for index, message in enumerate(({'op': 'step', 'action': {'tool': 'check', 'args': {}}},
                                        {'op': 'app_server', 'message': {'id': 1, 'method': 'process/spawn', 'params': {}}})):
            base = Path(self.temp.name)
            source = ('import sys\nsys.stdin.readline()\nprint(' + repr(canonical(message)) +
                      ',flush=True)\nsys.stdin.readline()\n').encode()
            output, anchor = base / f'run-{index}', base / f'anchor-{index}'
            result = run(source, output, anchor, domain='inventory', runtime=DEFAULT_RUNTIME,
                         provider=AppServerTransport(MockUpstream([])), app_server=True)
            self.assertEqual(result['status'], 'protocol_error')
            self.assertEqual(verify(output, anchor)['audit']['actions'], 0)


if __name__ == '__main__':
    unittest.main()
