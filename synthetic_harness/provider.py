"""Host-only, bounded Responses transport with an offline mock upstream.

No URL, token, header, or arbitrary endpoint is accepted from the actor.
No real HTTP client or credential discovery exists in this stage.
"""

from .tasks import canonical

MODEL = "gpt-5.4"  # Requested identifier in mock tests; not an access claim.
EFFORT = "high"


class MockUpstream:
    def __init__(self, answers, credential="synthetic-host-only-canary", failure=None):
        self.answers = list(answers)
        self.credential = credential
        self.failure = failure
        self.requests = []

    def send(self, body, *, authorization):
        if authorization != "Bearer " + self.credential:
            raise ValueError("Mock authorization failed")
        self.requests.append(body)
        index = len(self.requests) - 1
        if self.failure == "http429":
            return 429, []
        response_id = f"mock-response-{index}"
        events = [{"type": "response.created", "response": {"id": response_id}}]
        if self.failure == "truncated":
            return 200, events
        if index >= len(self.answers):
            return 429, []
        events += [{"type": "response.output_item.done", "item": {
            "type": "message", "role": "assistant", "id": f"mock-message-{index}",
            "content": [{"type": "output_text", "text": self.answers[index]}]}},
            {"type": "response.completed", "response": {"id": response_id,
             "model": "mock-backend-not-a-model", "usage": {"input_tokens": 11,
             "output_tokens": 7, "total_tokens": 18,
             "input_tokens_details": {"cached_tokens": 0},
             "output_tokens_details": {"reasoning_tokens": 0}}}}]
        return 200, events


class ProviderTransport:
    def __init__(self, upstream, credential="synthetic-host-only-canary"):
        self._upstream, self._credential = upstream, credential
        self.calls = 0
        self.configuration = {"transport": "offline-mock-responses", "model": MODEL,
                              "effort": EFFORT, "max_calls": 8,
                              "request_retries": 0, "stream_retries": 0}

    def exchange(self, request):
        if request.get("op") == "codex_event":
            if set(request) != {"op", "event"} or len(canonical(request).encode()) > 16_384:
                raise ValueError("Invalid actor metadata envelope")
            # Retained in the host wire log as actor-reported, not authoritative.
            return {"recorded": True, "trust": "actor-reported"}
        if set(request) != {"op", "body"} or request["op"] != "provider":
            raise ValueError("Invalid provider envelope")
        body = request["body"]
        allowed = {"model", "instructions", "input", "tools", "tool_choice", "parallel_tool_calls",
                   "reasoning", "store", "stream", "include", "prompt_cache_key", "text", "client_metadata"}
        if type(body) is not dict or set(body) - allowed or len(canonical(body).encode()) > 192 * 1024:
            raise ValueError("Invalid Responses request fields/size")
        if body.get("model") != MODEL or body.get("stream") is not True or body.get("store") is not False:
            raise ValueError("Model/stream/store policy mismatch")
        if body.get("reasoning") != {"effort": EFFORT, "summary": "auto"}:
            raise ValueError("Reasoning policy mismatch")
        if ("instructions" in body and type(body["instructions"]) is not str) \
                or type(body.get("input")) is not list:
            raise ValueError("Text-only input required")
        for item in body["input"]:
            if type(item) is not dict or item.get("type", "message") != "message" \
                    or set(item) - {"type", "role", "content", "id", "status"} \
                    or item.get("role") not in ("user", "developer", "assistant", "system"):
                raise ValueError("Only text messages are supported in this compatibility stage")
            content = item.get("content")
            if type(content) is not list or any(type(part) is not dict
                    or set(part) != {"type", "text"}
                    or part["type"] not in ("input_text", "output_text")
                    or type(part["text"]) is not str for part in content):
                raise ValueError("Remote files/images/tools are not allowed")
        tools = body.get("tools")
        if type(tools) is not list or len(tools) > 1 or any(type(tool) is not dict
                or tool.get("type") != "function" or tool.get("name") != "request_user_input"
                or set(tool) - {"type", "name", "description", "strict", "parameters"} for tool in tools):
            raise ValueError("Only Codex's built-in user-input descriptor is allowed; no hosted tools")
        if body.get("tool_choice") != "auto" or body.get("parallel_tool_calls") is not True:
            raise ValueError("Tool policy mismatch")
        if body.get("include") != ["reasoning.encrypted_content"]:
            raise ValueError("Unexpected include fields")
        if "prompt_cache_key" in body and (type(body["prompt_cache_key"]) is not str
                                         or len(body["prompt_cache_key"]) > 128):
            raise ValueError("Invalid cache key")
        if "text" in body and body["text"] != {"verbosity": "low"}:
            raise ValueError("Unexpected text options")
        metadata = body.get("client_metadata", {})
        if type(metadata) is not dict or len(canonical(metadata).encode()) > 16_384 \
                or any(type(k) is not str or type(v) is not str for k, v in metadata.items()):
            raise ValueError("Invalid client metadata")
        if self.calls >= 8:
            raise ValueError("Provider request budget exhausted")
        self.calls += 1
        try:
            # Keep client-reported metadata in the wire evidence, but do not
            # forward it as routing, identity, or authentication authority.
            outbound = {k: v for k, v in body.items() if k != "client_metadata"}
            status, events = self._upstream.send(outbound, authorization="Bearer " + self._credential)
            if status not in (200, 429):
                raise ValueError("Unexpected upstream status")
            # No upstream headers, locations, or exception text cross the pipe.
            sse = "".join(f"event: {event['type']}\ndata: {canonical(event)}\n\n" for event in events)
            if len(sse.encode()) > 128 * 1024 or self._credential in sse:
                raise ValueError("Unsafe upstream response")
        except Exception:
            return {"status": 502, "body": "upstream transport failed"}
        return {"status": status, "body": sse if status == 200 else "mock rate limit"}
