"""Destination-restricted, opaque TCP transport for Codex-managed authentication.

No HTTP bodies, TLS keys or credentials are inspected. This is a host/IP/port
policy, not a URL-path firewall. Only a trusted login service receives it.
"""

import base64
import ipaddress
import json
import select
import socket
import subprocess
import sys
import time

AUTHORITY = 'auth.openai.com:443'
CHUNK = 16384
MAX_BYTES = 16 * 1024 * 1024


def resolve_auth(host='auth.openai.com'):
    # Bound DNS independently of libc resolver timeout configuration. No host
    # credentials/environment are inherited; never resolve a supplied hostname.
    if host not in ('auth.openai.com', 'ampcode.com'):
        raise ValueError('Unsupported trusted service host')
    code = f"import json,socket; print(json.dumps(sorted({{x[4][0] for x in socket.getaddrinfo({host!r},443,type=socket.SOCK_STREAM)}})))"
    result = subprocess.run([sys.executable, '-I', '-c', code], capture_output=True,
                            timeout=5, check=True, env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
    addresses = json.loads(result.stdout)
    if not isinstance(addresses, list) or not 1 <= len(addresses) <= 32:
        raise ValueError('Authentication DNS rejected')
    checked = []
    for value in addresses:
        if not isinstance(value, str) or '%' in value:
            raise ValueError('Authentication DNS address rejected')
        address = ipaddress.ip_address(value)
        if not address.is_global or address.is_multicast or address.is_reserved \
                or (address.version == 6 and (address.ipv4_mapped or address.sixtofour or address.teredo)):
            raise ValueError('Authentication DNS must contain only public unicast addresses')
        checked.append(address)
    return tuple(sorted(checked, key=lambda address: address.version))


class AuthEgress:
    """One operator session; bounded sockets, opens, bytes, frames and lifetime."""
    authority = AUTHORITY

    def resolve(self):
        return resolve_auth()

    def __init__(self, *, timeout=900):
        if not 1 <= timeout <= 900:
            raise ValueError('Authentication lifetime must be 1..900 seconds')
        self.deadline = time.monotonic() + timeout
        self.addresses = self.resolve()
        self.sockets = {}
        self.opens = self.bytes = self.frames = 0
        self.closed = False

    def connect(self):
        # Numeric address, pinned for this session: no second DNS lookup,
        # redirects, caller-supplied ports, or inherited HTTP proxy settings.
        address = self.addresses[0]
        sock = socket.socket(socket.AF_INET if address.version == 4 else socket.AF_INET6, socket.SOCK_STREAM)
        try:
            sock.settimeout(min(3, max(.001, self.deadline - time.monotonic())))
            sock.connect((str(address), 443))
            sock.setblocking(False)
            return sock
        except BaseException:
            sock.close()
            raise

    def exchange(self, request):
        try:
            return self._exchange(request)
        except (ValueError, KeyError, TypeError, OSError):
            self.close()
            raise ValueError('Authentication egress rejected') from None

    def _exchange(self, request):
        self.frames += 1
        if self.closed or time.monotonic() >= self.deadline or self.frames > 30000 or type(request) is not dict:
            raise ValueError()
        if request.get('op') == 'open':
            if set(request) != {'op', 'authority'} or request['authority'] != self.authority \
                    or self.opens >= 16 or len(self.sockets) >= 4:
                raise ValueError()
            self.opens += 1
            self.sockets[self.opens] = self.connect()
            return {'connection': self.opens}
        if type(request.get('connection')) is not int or request['connection'] not in self.sockets:
            raise ValueError()
        sock = self.sockets[request['connection']]
        if request.get('op') == 'close' and set(request) == {'op', 'connection'}:
            sock.close()
            del self.sockets[request['connection']]
            return {'closed': True}
        if request.get('op') != 'transfer' or set(request) != {'op', 'connection', 'data'} \
                or type(request['data']) is not str or len(request['data']) > 4 * ((CHUNK + 2) // 3):
            raise ValueError()
        data = base64.b64decode(request['data'], validate=True)
        if len(data) > CHUNK or self.bytes + len(data) > MAX_BYTES:
            raise ValueError()
        readable, writable, _ = select.select([sock], [sock] if data else [], [], .05)
        sent = sock.send(data) if writable else 0
        received = sock.recv(min(CHUNK, MAX_BYTES - self.bytes - sent + 1)) if readable else b''
        eof = bool(readable) and not received
        self.bytes += sent + len(received)
        if self.bytes > MAX_BYTES:
            raise ValueError()
        return {'sent': sent, 'data': base64.b64encode(received).decode('ascii'), 'eof': eof}

    def close(self):
        self.closed = True
        for sock in self.sockets.values():
            sock.close()
        self.sockets.clear()
