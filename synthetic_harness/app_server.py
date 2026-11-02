"""Host-owned, offline-only app-server state machine. Never a general RPC proxy."""

from pathlib import Path

from .protocol import exchange, parse_request
from .provider import MODEL, EFFORT, ProviderTransport
from .tasks import canonical


def settings(port):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid private relay port")
    values = {"model": MODEL, "model_provider": "offline",
              "model_reasoning_effort": EFFORT, "model_reasoning_summary": "auto",
              "web_search": "disabled", "analytics.enabled": False,
              "mcp_servers": {}, "model_providers.offline.name": "Offline broker",
              "model_providers.offline.base_url": f"http://127.0.0.1:{port}",
              "model_providers.offline.wire_api": "responses",
              "model_providers.offline.requires_openai_auth": False,
              "model_providers.offline.supports_websockets": False,
              "model_providers.offline.request_max_retries": 0,
              "model_providers.offline.stream_max_retries": 0,
              "model_providers.offline.stream_idle_timeout_ms": 3000}
    for feature in ("shell_tool", "code_mode", "code_mode_host", "view_image",
                    "multi_agent", "multi_agent_v2", "hooks", "plugin_hooks",
                    "plugins", "apps", "enable_mcp_apps", "shell_snapshot",
                    "default_mode_request_user_input", "in_app_browser", "goals", "remote_control"):
        values[f"features.{feature}"] = False
    return values


class Gateway:
    """Only this host constructs methods/config/IDs; service events are untrusted.

    Task effects occur once, after a matching completed turn. Unknown methods,
    mismatched IDs, tools, failed turns and unsolicited RPC requests fail closed.
    """
    def __init__(self, deferred=False):
        self.deferred = deferred
        self.phase = "ready"
        self.pending = None
        self.sequence = 0
        self.thread = self.turn = None
        self.answer = None
        self.turns = 0
        self.seen_items = set()
        self.seen_turns = set()
        self.config = None
        self.early = []

    def rpc(self, method, params):
        self.sequence += 1
        self.pending = self.sequence
        return {"id": self.sequence, "method": method, "params": params}

    def next_turn(self, episode):
        if self.turns >= 5:
            raise ValueError("Episode turn budget exhausted")
        self.turns += 1
        self.phase = "turn_reply"
        self.turn, self.answer = None, None
        self.seen_items.clear()
        prompt = ("Offline synthetic task. Return exactly one JSON object with op=step and "
                  "action={tool,args}. Use only the advertised task tools; do not use local tools.\n" +
                  canonical(episode.observe()))
        return self.rpc("turn/start", {"threadId": self.thread,
                        "input": [{"type": "text", "text": prompt}],
                        "model": MODEL, "effort": EFFORT, "summary": "auto"})

    def exchange(self, envelope, episode):
        if self.phase in ("failed", "closed"):
            raise ValueError("Gateway is closed")
        try:
            return self._exchange(envelope, episode)
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            self.phase = "failed"
            raise ValueError("App-server protocol/policy rejected") from error

    def _exchange(self, envelope, episode):
        if type(envelope) is not dict or set(envelope) != {"op", "message"} \
                or envelope["op"] != "app_server" or len(canonical(envelope).encode()) > 65536:
            raise ValueError("Invalid app-server envelope")
        message = envelope["message"]
        if type(message) is not dict:
            raise ValueError("Expected one app-server message")
        commands = []
        if self.phase == "ready":
            if set(message) != {"ready", "port"} or message["ready"] is not True:
                raise ValueError("Expected service ready")
            self.config = settings(message["port"])
            self.phase = "initialize"
            commands = [self.rpc("initialize", {"clientInfo": {
                "name": "offline_research_harness", "version": "0.1"}})]
        elif "id" in message and "method" in message:
            # Never approve model-triggered execution. Decline recognized approval
            # requests and stop; unknown server requests receive no authority.
            if message["method"] in ("item/commandExecution/requestApproval", "item/fileChange/requestApproval"):
                self.phase = "failed"
                return {"messages": [{"id": message["id"], "result": {"decision": "decline"}}],
                        "stop": True, "error": "Approval request prohibited"}
            raise ValueError("Unsolicited RPC request prohibited")
        elif "id" in message:
            if set(message) != {"id", "result"} or type(message["id"]) is not int \
                    or message["id"] != self.pending or type(message["result"]) is not dict:
                raise ValueError("Unexpected or failed RPC response")
            self.pending = None
            result = message["result"]
            if self.phase == "initialize":
                self.phase = "thread_reply"
                commands = [{"method": "initialized", "params": {}}, self.rpc("thread/start", {
                    "model": MODEL, "modelProvider": "offline", "cwd": "/tmp/work",
                    "ephemeral": True, "approvalPolicy": "never", "sandbox": "read-only",
                    "config": self.config})]
            elif self.phase == "thread_reply":
                if result.get("model") != MODEL or result.get("modelProvider") != "offline" \
                        or result.get("reasoningEffort") != EFFORT \
                        or result.get("approvalPolicy") != "never" \
                        or result.get("sandbox") != {"type": "readOnly", "networkAccess": False} \
                        or result.get("thread", {}).get("ephemeral") is not True \
                        or result.get("cwd") != "/tmp/work" \
                        or result.get("instructionSources") != []:
                    raise ValueError("Resolved thread policy mismatch")
                self.thread = result.get("thread", {}).get("id")
                if type(self.thread) is not str or not 1 <= len(self.thread) <= 128:
                    raise ValueError("Invalid thread identity")
                commands = [self.next_turn(episode)]
            elif self.phase == "turn_reply":
                self.turn = result.get("turn", {}).get("id")
                if type(self.turn) is not str or not 1 <= len(self.turn) <= 128 or self.turn in self.seen_turns:
                    raise ValueError("Invalid turn identity")
                self.seen_turns.add(self.turn)
                self.phase = "running"
                # Notifications can precede the correlated turn/start response.
                # Replay only after its identity is known, through the same checks.
                early, self.early = self.early, []
                reply = {"messages": [], "stop": False}
                for notification in early:
                    part = self.exchange(notification, episode)
                    reply["messages"].extend(part.get("messages", []))
                    reply["stop"] |= part.get("stop", False)
                    if "action" in part:
                        if "action" in reply:
                            raise ValueError("Multiple buffered proposals")
                        reply["action"] = part["action"]
                return reply
            else:
                raise ValueError("Unexpected response phase")
        else:
            if set(message) - {"method", "params", "emittedAtMs"} or type(message.get("params")) is not dict \
                    or type(message.get("method")) is not str:
                raise ValueError("Invalid notification")
            method, params = message["method"], message["params"]
            if method == "remoteControl/status/changed" and params.get("status") == "disabled":
                return {"messages": [], "stop": False}
            if method == "warning" and params.get("threadId") == self.thread and params.get("message") == (
                    f"Model metadata for `{MODEL}` not found. Defaulting to fallback metadata; "
                    "this can degrade performance and cause issues."):
                return {"messages": [], "stop": False}
            if method == "configWarning" and params.get("summary", "").startswith(
                    "Codex could not find bubblewrap on PATH."):
                # The independently enforced outer sandbox is mandatory. No
                # local execution tool is permitted by the provider policy.
                return {"messages": [], "stop": False}
            allowed = {"thread/started", "thread/status/changed", "turn/started", "turn/completed",
                       "item/started", "item/completed", "item/agentMessage/delta",
                       "item/reasoning/summaryTextDelta", "item/reasoning/summaryPartAdded",
                       "item/reasoning/textDelta", "thread/tokenUsage/updated", "account/rateLimits/updated"}
            if method not in allowed:
                raise ValueError("Unsupported notification")
            if self.phase == "turn_reply":
                early_turn = params.get("turnId") or (params.get("turn") or {}).get("id")
                if early_turn in self.seen_turns:
                    raise ValueError("Repeated prior-turn event")
                if len(self.early) >= 32 or sum(len(canonical(event).encode()) for event in self.early) \
                        + len(canonical(envelope).encode()) > 256 * 1024:
                    raise ValueError("Early notification budget exceeded")
                self.early.append(envelope)
                return {"messages": [], "stop": False}
            if method in ("item/started", "item/completed", "turn/completed") and params.get("threadId") != self.thread:
                raise ValueError("Missing thread identity")
            if method in ("item/started", "item/completed") and params.get("turnId") != self.turn:
                raise ValueError("Missing turn identity")
            if "threadId" in params and params["threadId"] != self.thread:
                raise ValueError("Cross-thread event")
            if "turnId" in params and params["turnId"] != self.turn:
                raise ValueError("Cross-turn event")
            if method in ("item/started", "item/completed"):
                item = params.get("item", {})
                if self.phase != "running" or item.get("type") not in ("userMessage", "agentMessage", "reasoning", "plan"):
                    raise ValueError("Local or unknown tool item prohibited")
                if method == "item/completed" and item.get("type") == "agentMessage":
                    if type(item.get("id")) is not str or item["id"] in self.seen_items \
                            or type(item.get("text")) is not str:
                        raise ValueError("Invalid/repeated final message")
                    self.seen_items.add(item.get("id"))
                    self.answer = item["text"]
            if method == "turn/completed":
                turn = params.get("turn", {})
                if self.phase != "running" or turn.get("id") != self.turn \
                        or turn.get("status") != "completed" or self.answer is None:
                    raise ValueError("Turn did not complete successfully")
                action = parse_request(self.answer)
                if set(action) != {"op", "action"} or action["op"] != "step":
                    raise ValueError("Expected one bounded task action")
                if self.deferred:
                    # A separate actor receives a proposal, not an authoritative
                    # task effect. Its subsequent step goes through the broker.
                    self.phase = "awaiting_observation"
                    return {"action": action["action"]}
                exchange(episode, canonical(action))
                if episode.observe()["closed"]:
                    self.phase = "closed"
                    return {"messages": [], "stop": True}
                commands = [self.next_turn(episode)]
        return {"messages": commands, "stop": False}


class AppServerTransport(ProviderTransport):
    def __init__(self, upstream):
        super().__init__(upstream)
        self.gateway = Gateway()
        self.configuration = {**self.configuration, "adapter": "app-server-offline",
                              "session": "one ephemeral thread per episode"}

    def exchange(self, request):
        reply = super().exchange(request)
        if request.get("op") != "provider" or reply.get("status") != 200:
            return reply
        # This mock dialect never delivers function/tool calls to Codex, even
        # if a malicious upstream tries an unadvertised registered tool. Do
        # not mistake rejecting later RPC notifications for prevention.
        try:
            for line in reply["body"].splitlines():
                if not line.startswith("data: "):
                    continue
                event = parse_request(line[6:], 128 * 1024)
                kind = event["type"]
                if kind == "response.output_item.done":
                    item = event["item"]
                    if set(event) != {"type", "item"} or set(item) != {"type", "role", "id", "content"} \
                            or item["type"] != "message" or item["role"] != "assistant" \
                            or type(item["content"]) is not list:
                        raise ValueError("Tool output prohibited")
                    for part in item["content"]:
                        if set(part) != {"type", "text"} or part["type"] != "output_text" \
                                or type(part["text"]) is not str:
                            raise ValueError("Only final text supported")
                elif kind in ("response.created", "response.completed"):
                    if set(event) != {"type", "response"} \
                            or set(event["response"]) - {"id", "model", "usage"}:
                        raise ValueError("Embedded output prohibited")
                else:
                    raise ValueError("Unsupported mock event")
        except (ValueError, TypeError, KeyError):
            return {"status": 502, "body": "upstream transport failed"}
        return reply


def bridge_source():
    # Reuse the existing credential-free loopback relay without running its CLI
    # entrypoint. The bridge itself has no oracle or authoritative episode state.
    relay = Path(__file__).with_name("codex_actor.py").read_text().rsplit('\nif __name__', 1)[0]
    bridge = Path(__file__).with_name("app_server_bridge.py").read_text()
    return (relay + '\nSTARTUP_CONFIG = ' + repr(settings(1)) + '\n' + bridge).encode()
