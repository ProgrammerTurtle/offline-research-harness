"""Public pool contract exercised with real offline native broker processes."""

import hashlib
import json
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from synthetic_harness import pool, sandbox


class PoolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.output, self.anchors = self.base / 'runs', self.base / 'anchors'

    def test_limits_and_disjoint_new_paths(self):
        for workers in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                pool.run(self.output, self.anchors, workers=workers)
        for episodes in (0, 2161, True):
            with self.assertRaises(ValueError):
                pool.run(self.output, self.anchors, episodes=episodes)
        with self.assertRaises(ValueError):
            pool.run(self.output, self.output / 'anchors')
        self.output.mkdir()
        with self.assertRaises(ValueError):
            pool.run(self.output, self.anchors)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_native_pool_cap_outcomes_and_independent_sessions(self):
        report = pool.run(self.output, self.anchors, workers=3, episodes=10)
        self.assertTrue(report['passed'], report)
        self.assertEqual(report['submitted'], 10)
        self.assertEqual(report['peak_brokers'], 3)
        self.assertEqual(sum(row['valid_escalation'] for row in report['results']), 3)
        self.assertEqual(sum(row['task_complete'] for row in report['results']), 7)
        sessions = set()
        for row in report['results']:
            name = row['episode']
            sandbox.verify(self.output / name, self.anchors / name)
            records = [json.loads(line) for line in
                       (self.output / (name + '.service.jsonl')).read_text().splitlines()]
            ids = {record['payload']['message']['params']['thread']['id']
                   for record in records if record['kind'] == 'receive'
                   and record['payload'].get('message', {}).get('method') == 'thread/started'}
            self.assertEqual(len(ids), 1)
            self.assertFalse(sessions & ids)
            sessions.update(ids)
        # Independent interval sweep checks the bound and that slots are reused.
        events = sorted([(row['started_seconds'], 1) for row in report['results']] +
                        [(row['finished_seconds'], -1) for row in report['results']])
        active = peak = 0
        for _, delta in events:
            active += delta
            peak = max(peak, active)
        self.assertEqual((peak, active), (3, 0))
        self.assertEqual(hashlib.sha256((self.output / 'summary.json').read_bytes()).hexdigest(),
                         (self.anchors / 'summary.sha256').read_text().strip())
        self.assertFalse(list(sandbox.CGROUP.glob('actor-*')))
        self.assertFalse(list(sandbox.CGROUP.glob('service-*')))

    def test_failure_stops_admission_without_retries(self):
        report = pool.run(self.output, self.anchors, episodes=12, workers=2,
                          runtime=self.base / 'missing-runtime')
        self.assertFalse(report['passed'])
        self.assertEqual(report['stopped'], 'episode_failed')
        self.assertEqual(report['submitted'], 2)
        self.assertEqual(len(report['results']), 2)
        self.assertTrue(all(not row['passed'] for row in report['results']))

    def test_worker_limit_is_operator_selected_not_machine_specific(self):
        report = pool.run(self.output, self.anchors, episodes=1, workers=32)
        self.assertTrue(report['passed'], report)
        self.assertEqual(report['workers'], 32)
        self.assertEqual(report['peak_brokers'], 1)

    def test_sigterm_drains_active_episodes_without_admitting_more(self):
        process = subprocess.Popen([sys.executable, '-m', 'synthetic_harness.pool',
            '--output', str(self.output), '--anchors', str(self.anchors),
            '--episodes', '30', '--workers', '2'], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 15
            while len(list(self.output.glob('*.service.jsonl'))) < 2:
                self.assertIsNone(process.poll())
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.01)
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=40)
            self.assertEqual(process.returncode, 1, stderr)
            report = json.loads((self.output / 'summary.json').read_text())
            self.assertEqual(report['stopped'], 'SIGTERM', stdout)
            self.assertEqual(report['submitted'], 2)
            self.assertTrue(all(row['passed'] for row in report['results']), report)
            self.assertFalse(list(sandbox.CGROUP.glob('actor-*')))
            self.assertFalse(list(sandbox.CGROUP.glob('service-*')))
        finally:
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=40)
