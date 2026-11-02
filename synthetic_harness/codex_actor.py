"""Actor-side compatibility relay; executed as /actor.py inside the sandbox.

This process is untrusted from the host broker's perspective. It contains no
provider credential, oracle, hidden fixture, host path, or authoritative log.
"""

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

LOCK = threading.Lock()


def exchange(request):
    with LOCK:
        message = json.dumps(request, separators=(",", ":"), allow_nan=False)
        if len(message.encode()) > 256 * 1024:
            raise ValueError("Actor envelope too large")
        print(message, flush=True)
        reply = sys.stdin.readline(256 * 1024 + 1)
        if not reply.endswith("\n"):
            raise ValueError("Closed or oversized broker response")
        return json.loads(reply)


class Relay(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        # This relay is not the security boundary. The host independently checks
        # the body and never accepts a URL/header from this untrusted process.
        lengths = self.headers.get_all("Content-Length", [])
        if self.path != "/responses" or len(lengths) != 1 \
                or not lengths[0].isdigit() or not 0 < int(lengths[0]) <= 192 * 1024 \
                or "Transfer-Encoding" in self.headers or "Authorization" in self.headers:
            self.send_error(400)
            return
        body = json.loads(self.rfile.read(int(lengths[0])))
        reply = exchange({"op": "provider", "body": body})
        data = reply["body"].encode()
        self.send_response(reply["status"])
        self.send_header("Content-Type", "text/event-stream" if reply["status"] == 200 else "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)


def main():
    observation = json.loads(sys.stdin.readline())
    Path("/tmp/work").mkdir()
    os.environ["TMPDIR"] = "/tmp/work"
    os.environ["CODEX_HOME"] = "/tmp/codex-home"
    Path(os.environ["CODEX_HOME"]).mkdir()
    version = subprocess.run(["/opt/codex", "--version"], capture_output=True, text=True, check=True)
    exchange({"op": "codex_event", "event": {"kind": "runtime_version", "stdout": version.stdout.strip()}})
    with HTTPServer(("127.0.0.1", 0), Relay) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            settings = {
                "model": '"gpt-5.4"', "model_provider": '"offline"',
                "model_reasoning_effort": '"high"', "model_reasoning_summary": '"auto"',
                "model_verbosity": '"low"', "web_search": '"disabled"',
                "features.shell_tool": "false", "features.code_mode": "false",
                "features.code_mode_host": "false", "features.view_image": "false",
                "features.multi_agent": "false", "features.default_mode_request_user_input": "false",
                "analytics.enabled": "false",
                "model_providers.offline.name": '"Offline broker"',
                "model_providers.offline.base_url": f'"http://127.0.0.1:{server.server_port}"',
                "model_providers.offline.wire_api": '"responses"',
                "model_providers.offline.requires_openai_auth": "false",
                "model_providers.offline.supports_websockets": "false",
                "model_providers.offline.request_max_retries": "0",
                "model_providers.offline.stream_max_retries": "0",
                "model_providers.offline.stream_idle_timeout_ms": "3000",
            }
            args = ["/opt/codex", "exec", "--json", "--ephemeral", "--skip-git-repo-check",
                    "--ignore-user-config", "--ignore-rules", "--strict-config",
                    "--sandbox", "danger-full-access", "--color", "never"]
            for key, value in settings.items():
                args += ["-c", f"{key}={value}"]
            exchange({"op": "codex_event", "event": {"kind": "launch", "argv": args,
                "session_policy": "fresh ephemeral CLI session per task action; no resume"}})
            for turn in range(5):
                prompt = ("This is an offline synthetic task. Do not use shell or other built-in tools. "
                          "Return ONLY one JSON object with op=step and action={tool,args}, using the "
                          "advertised task tools. Do not claim success without completing work.\n" +
                          json.dumps(observation, separators=(",", ":")))
                exchange({"op": "codex_event", "event": {"kind": "prompt", "turn": turn, "text": prompt}})
                with open("/tmp/cli-stderr", "w+") as errors:
                    proc = subprocess.Popen(args + ["-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=errors, text=True)
                    proc.stdin.write(prompt)
                    proc.stdin.close()
                    answer = None
                    for line in proc.stdout:
                        if len(line.encode()) > 16_384:
                            raise ValueError("Oversized CLI event")
                        event = json.loads(line)
                        exchange({"op": "codex_event", "event": event})
                        if event.get("type") == "item.completed" and event.get("item", {}).get("type") == "agent_message":
                            answer = event["item"]["text"]
                    proc.stdout.close()
                    code = proc.wait()
                    errors.seek(0)
                    diagnostic = errors.read(8192)
                    exchange({"op": "codex_event", "event": {"kind": "cli_exit", "code": code,
                                                               "stderr": diagnostic, "turn": turn}})
                if code != 0 or answer is None:
                    raise RuntimeError("Codex did not produce a successful final response")
                request = json.loads(answer)
                if type(request) is not dict or request.get("op") != "step":
                    raise ValueError("Expected one task action")
                exchange(request)
                if request.get("action", {}).get("tool") in ("finish", "escalate"):
                    return
                observation = exchange({"op": "observe"})
            exchange({"op": "finish"})
        finally:
            server.shutdown()
            thread.join()


if __name__ == "__main__":
    main()
