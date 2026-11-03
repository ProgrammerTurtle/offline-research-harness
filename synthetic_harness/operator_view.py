"""Human-only routing, not confidentiality against a privileged host observer."""
import os
import re
import select
import termios
import time


class OperatorStderrView:
    def __init__(self):
        self.fd = None
        self.preview = None
        self.truncated = False

    def __enter__(self):
        if os.environ.get('TMUX') or os.environ.get('STY') or os.environ.get('TERM', '').startswith(('screen', 'tmux')):
            raise ValueError('Private view refuses terminal multiplexers')
        if os.environ.get('TERM') not in ('xterm', 'xterm-256color'):
            raise ValueError('Private view requires an xterm-compatible alternate-screen terminal')
        if not all(os.isatty(fd) for fd in (0, 1, 2)) or len({os.fstat(fd).st_rdev for fd in (0, 1, 2)}) != 1:
            raise ValueError('Private view requires unredirected operator TTY input/output/error')
        self.fd = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        try:
            if os.tcgetpgrp(self.fd) != os.getpgrp():
                raise ValueError('Private view requires foreground operator TTY')
            self._write(b'PRIVATE STDERR VIEW: may contain credentials/account data.\r\n'
                        b'Use an unrecorded, unshared terminal. No tmux, screen, screenshots or pane capture.\r\n'
                        b'Alternate-screen clearing cannot guarantee removal from terminal/browser history,\r\n'
                        b'recordings or privileged host access. This is routing, not a secrecy boundary.\r\n'
                        b'Type PRIVATE and Enter to accept these limits (60 seconds): ')
            if self._line() != b'PRIVATE\n':
                raise ValueError('Private view not confirmed')
            return self
        except BaseException:
            self.__exit__()
            raise

    def _write(self, data):
        deadline = time.monotonic()+1
        while data:
            if time.monotonic() >= deadline or not select.select([], [self.fd], [], max(0, deadline-time.monotonic()))[1]:
                raise ValueError('Private terminal write timed out')
            data = data[os.write(self.fd, data):]

    def _line(self):
        deadline = time.monotonic()+60
        data = bytearray()
        while len(data) < 32 and time.monotonic() < deadline:
            if not select.select([self.fd], [], [], max(0, deadline-time.monotonic()))[0]:
                break
            chunk = os.read(self.fd, 32-len(data))
            if not chunk:
                break
            data.extend(chunk)
            if b'\n' in data:
                return bytes(data)
        return b''

    def capture(self, encoded, truncated):
        if self.fd is None or self.preview is not None or type(encoded) is not str \
                or len(encoded) > 4096 or re.fullmatch(r'(?:[0-9a-f]{2})*', encoded) is None \
                or type(truncated) is not bool or (truncated and len(encoded) != 4096):
            raise ValueError('Private preview rejected')
        self.preview = bytearray.fromhex(encoded)
        self.truncated = truncated

    def show(self):
        """Call only after service/egress cleanup and sealing the sanitized audit."""
        if self.preview is None:
            return
        # ASCII only: escape every control, DEL, non-ASCII and backslash. Raw
        # stderr cannot emit OSC/CSI, bidi controls, CR, bells or terminal replies.
        rendered = ''.join(chr(b) if 32 <= b <= 126 and b != 92 else f'\\x{b:02x}' for b in self.preview)
        wrapped = '\r\n'.join(rendered[i:i+76] for i in range(0, len(rendered), 76))
        saved = termios.tcgetattr(self.fd)
        quiet = list(saved); quiet[3] &= ~termios.ECHO
        try:
            termios.tcsetattr(self.fd, termios.TCSANOW, quiet)
            self._write(b'\x1b[?1049h\x1b[2J\x1b[H')
            label = b'FIRST 2048 BYTES ONLY; TRUNCATED' if self.truncated else b'BOUNDED STDERR PREVIEW'
            self._write(label+b' (untrusted text; controls escaped)\r\n'+wrapped.encode('ascii')+
                        b'\r\nPreview may be incomplete; sanitized outcome reports completeness.\r\n'
                        b'Press Enter to clear; auto-clear after 60 seconds.\r\n')
            self._line()
        finally:
            try:
                self._write(b'\x1b[2J\x1b[H\x1b[?1049l')
            finally:
                termios.tcsetattr(self.fd, termios.TCSANOW, saved)
                self.preview[:] = b'\0'*len(self.preview)
                self.preview = None

    def __exit__(self, *_):
        if self.preview is not None:
            self.preview[:] = b'\0'*len(self.preview)
            self.preview = None
        if self.fd is not None:
            os.close(self.fd); self.fd = None
