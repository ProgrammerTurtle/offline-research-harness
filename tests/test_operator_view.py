"""Only disposable synthetic PTYs are read here, never a user's terminal pane."""
import json
import os
import pty
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from synthetic_harness import amp_protected as protected, sandbox
from synthetic_harness.login import CredentialStore
from synthetic_harness.operator_view import OperatorStderrView

SECRET = b'SYNTHETIC-OPERATOR-SECRET'


class OperatorViewTests(unittest.TestCase):
    def run_terminal(self, code, *, cancel=False, auto_clear=False, decline=False):
        pid, master = pty.fork()
        if pid == 0:
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            os.execve(sys.executable, [sys.executable, '-c', code],
                      {'PATH':'/usr/bin','LANG':'C.UTF-8','TERM':'xterm-256color'})
        data = bytearray(); confirmed = displayed = False
        deadline = time.monotonic()+(75 if auto_clear else 45)
        status = None; done = 0
        try:
            while time.monotonic() < deadline:
                if select.select([master], [], [], .1)[0]:
                    try: chunk = os.read(master, 4096)
                    except OSError: break
                    if not chunk: break
                    data.extend(chunk)
                    self.assertLess(len(data), 20000, 'Synthetic terminal output exceeded bound')
                    if b'Type PRIVATE and Enter' in data and not confirmed:
                        os.write(master, b'NO\n' if decline else b'PRIVATE\n'); confirmed = True
                    if b'Press Enter to clear' in data and not displayed:
                        self.assertFalse(list(sandbox.CGROUP.glob('service-*')), 'View preceded service cleanup')
                        if not auto_clear: os.write(master, b'\x03' if cancel else b'\n')
                        displayed = True
            done, status = os.waitpid(pid, os.WNOHANG)
            if not done:
                # Short bounded wait for interpreter shutdown after PTY EOF.
                for _ in range(20):
                    time.sleep(.05); done, status = os.waitpid(pid, os.WNOHANG)
                    if done: break
            self.assertTrue(done, 'Synthetic operator process did not terminate')
            return bytes(data), status, displayed
        finally:
            if status is None or not done:
                os.kill(pid, 9); os.waitpid(pid, 0)
            os.close(master)

    def test_private_preview_controls_overflow_cleanup_and_audit(self):
        payload = SECRET+b'\x1b]52;c;evil\x07\x1b[2J\r\x08\x9b\xe2\x80\xae\\end'
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); (base/'audit').mkdir()
            for mode in ('decline', 'controls', 'overflow', 'cancel', 'auto_clear'):
                print('synthetic-operator-view', mode, flush=True)
                store = base/mode; CredentialStore.create(store)
                with CredentialStore(store) as lease: protected.provision(lease, SECRET.decode())
                output = base/'audit'/mode; anchor = base/(mode+'-root')
                body = payload if mode != 'overflow' else SECRET+b'x'*65537
                # Huge fixture bytes go in namespace tmpfs, not oversized argv.
                child = f'import sys;sys.stderr.buffer.write({body!r});sys.stderr.flush();sys.exit(1)'
                code = f'''
import ipaddress,sys,termios
from unittest.mock import patch
from synthetic_harness import amp_protected as p
original=p.ProtectedAmpService.source
def source(self):
    value=original(self)
    return value.replace(b'    env=dict(os.environ)',
        ("    Path('/tmp/child.py').write_text("+repr({child!r})+")\\n    env=dict(os.environ)").encode())
sys.argv=['operator','smoke','--enable-smoke-egress','--operator-stderr-view',
          '--store',{str(store)!r},'--output',{str(output)!r},'--anchor',{str(anchor)!r}]
with patch.object(p,'resolve_auth',return_value=(ipaddress.ip_address('93.184.216.34'),)), \\
     patch.object(p.AmpEgress,'connect',side_effect=AssertionError('External network prohibited')), \\
     patch.object(p.ProtectedAmpService,'command',return_value=['/usr/bin/python3.11','-I','-S','/tmp/child.py']), \\
     patch.object(p.ProtectedAmpService,'source',source):
    try: status=p.main()
    except KeyboardInterrupt: status=130
    except ValueError: status=2
    assert termios.tcgetattr(0)[3] & termios.ECHO
    print('TTY_RESTORED',flush=True)
    sys.exit(status)
'''
                started = time.monotonic()
                screen, status, displayed = self.run_terminal(code, cancel=mode=='cancel',
                    auto_clear=mode=='auto_clear', decline=mode=='decline')
                if mode == 'decline':
                    self.assertFalse(displayed or SECRET in screen)
                    self.assertFalse(anchor.exists() or (store/'home/smoke-used').exists())
                    continue
                self.assertTrue(displayed)
                if mode == 'auto_clear': self.assertGreaterEqual(time.monotonic()-started, 60)
                self.assertTrue(b'TTY_RESTORED' in screen, 'Terminal settings not restored')
                self.assertTrue(SECRET in screen, 'Synthetic secret missing from human-only preview')
                self.assertFalse(b'\x1b]52' in screen, 'Untrusted OSC reached terminal')
                self.assertFalse(b'\xe2\x80\xae' in screen, 'Untrusted bidi reached terminal')
                self.assertTrue(b'\x1b[2J\x1b[H\x1b[?1049l' in screen, 'Alternate screen not cleared')
                self.assertTrue(b'FIRST 2048 BYTES ONLY; TRUNCATED' in screen if mode=='overflow'
                                else b'\\x1b]52;c;evil\\x07' in screen)
                result = protected.verify(output, anchor)['outcome']
                self.assertEqual(result['state'], 'native_stderr_limit' if mode=='overflow' else 'native_failed')
                journal = Path(str(output)+'.service.jsonl').read_bytes()
                self.assertFalse(SECRET in journal or SECRET.hex().encode() in journal, 'Preview leaked into journal')
                self.assertFalse(list(sandbox.CGROUP.glob('service-*')))
                self.assertTrue((store/'home/smoke-used').exists())
                anchor.chmod(0o600); anchor.write_text(json.dumps({'root':'0'*64}))
                with self.assertRaises(ValueError): protected.verify(output, anchor)

    def test_refuse_no_tty_multiplexers_and_unconfirmed_capture(self):
        for env in ({'TERM':'xterm-256color'}, {'TERM':'xterm-256color','TMUX':'fixture'},
                    {'TERM':'screen'}, {'TERM':'dumb'}, {'TERM':'xterm','STY':'fixture'}):
            run = subprocess.run([sys.executable,'-m','synthetic_harness.amp_protected','smoke',
                                  '--enable-smoke-egress','--operator-stderr-view','--store','/nonexistent'],
                                 capture_output=True,env={'PATH':'/usr/bin','LANG':'C.UTF-8',**env})
            self.assertNotEqual(run.returncode, 0)
            self.assertNotIn(b'Traceback', run.stderr)
        view = OperatorStderrView()
        with self.assertRaises(ValueError): view.capture(SECRET.hex(),False)
        # Shape checks independent of the UI; this test never opens a real TTY.
        view.fd = 99999
        for encoded, truncated in (('a',False),('zz',False),('aa'*2049,False),('',True),(SECRET.hex(),1)):
            with self.assertRaises(ValueError): view.capture(encoded,truncated)
        view.capture(SECRET.hex(),False)
        with self.assertRaises(ValueError): view.capture(SECRET.hex(),False)
        view.fd = None
        view.__exit__()
