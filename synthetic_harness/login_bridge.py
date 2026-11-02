"""Executed only inside the login namespace. Host independently validates egress."""

import base64
import json
import os
import queue
import select
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OUT = threading.Lock()
PENDING = {}
SEQUENCE = 0
SLOTS = threading.BoundedSemaphore(4)


def emit(message):
    with OUT:
        print(json.dumps(message, separators=(',', ':')), flush=True)


def network(request):
    global SEQUENCE
    reply = queue.Queue(maxsize=1)
    with OUT:
        SEQUENCE += 1
        ident = SEQUENCE
        PENDING[ident] = reply
        print(json.dumps({'op': 'egress', 'id': ident, 'request': request}, separators=(',', ':')), flush=True)
    try:
        return reply.get(timeout=10)
    finally:
        with OUT:
            PENDING.pop(ident, None)


class Proxy(BaseHTTPRequestHandler):
    rbufsize = 0  # Do not prefetch TLS bytes past the CONNECT headers.
    authority = 'auth.openai.com:443'

    def log_message(self, *_):
        pass

    def do_CONNECT(self):
        if self.path != self.authority or 'Content-Length' in self.headers \
                or 'Transfer-Encoding' in self.headers or not SLOTS.acquire(blocking=False):
            self.send_error(403)
            return
        ident = None
        try:
            ident = network({'op': 'open', 'authority': self.path})['connection']
            self.send_response(200, 'Connection Established')
            self.end_headers()
            self.connection.settimeout(1)
            pending = b''
            idle_wait = .01
            while True:
                # Local writes/EOF wake immediately; idle upstream polls back off
                # independently per tunnel without exempting any relay envelopes.
                if not pending and select.select([self.connection], [], [], idle_wait)[0]:
                    pending = self.connection.recv(16384)
                    if not pending:
                        return
                reply = network({'op': 'transfer', 'connection': ident,
                                 'data': base64.b64encode(pending).decode('ascii')})
                pending = pending[reply['sent']:]
                data = base64.b64decode(reply['data'], validate=True)
                if data:
                    self.connection.sendall(data)
                if reply['eof']:
                    return
                if not data and not reply['sent']:
                    if pending:
                        time.sleep(idle_wait)
                    idle_wait = min(1.0, idle_wait * 2)
                else:
                    idle_wait = .01
        except Exception:
            # Never print decrypted headers, device codes or exception payloads.
            return
        finally:
            if ident is not None:
                try:
                    network({'op': 'close', 'connection': ident})
                except Exception:
                    pass
            SLOTS.release()
            self.close_connection = True


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, *_):
        pass


def run(command):
    with Server(('127.0.0.1', 0), Proxy) as server:
        proxy = f'http://127.0.0.1:{server.server_port}'
        os.environ.update(HTTPS_PROXY=proxy, HTTP_PROXY=proxy, ALL_PROXY=proxy,
                          https_proxy=proxy, http_proxy=proxy, all_proxy=proxy,
                          NO_PROXY='', no_proxy='')
        threading.Thread(target=server.serve_forever, daemon=True).start()
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   text=True, close_fds=True)

        def receive():
            try:
                for line in sys.stdin:
                    if len(line.encode()) > 262144:
                        raise ValueError()
                    message = json.loads(line)
                    if message['op'] == 'rpc' and set(message) == {'op', 'message'}:
                        process.stdin.write(json.dumps(message['message'], separators=(',', ':')) + '\n')
                        process.stdin.flush()
                    elif message['op'] == 'egress' and set(message) == {'op', 'id', 'response'}:
                        with OUT:
                            PENDING[message['id']].put_nowait(message['response'])
                    else:
                        raise ValueError()
            except Exception:
                pass
            os._exit(70)

        threading.Thread(target=receive, daemon=True).start()
        try:
            while True:
                line = process.stdout.readline(65537)
                if not line.endswith('\n') or len(line.encode()) > 65536:
                    emit({'op': 'failure', 'category': 'transport_or_framing'})
                    break
                emit({'op': 'rpc', 'message': json.loads(line)})
        except (ValueError, UnicodeError):
            emit({'op': 'failure', 'category': 'protocol_schema'})
        finally:
            process.kill()
            process.wait(timeout=2)
            process.stdin.close()
            process.stdout.close()
