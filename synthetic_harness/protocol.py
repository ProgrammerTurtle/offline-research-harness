"""Transport-independent actor JSON boundary. No model invocation belongs here.

Only the trusted host calls exchange(); a future CLI adapter forwards the
returned string, never Episode or investigator files, into its isolated actor.
"""

import json

from .tasks import canonical


def parse_request(message, limit=16_384):
    """Strict object parsing shared by task and separately bounded provider IO."""
    if type(message) is not str or len(message.encode()) > limit:
        raise ValueError("Request must be a bounded JSON string")

    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError("Duplicate JSON key")
            result[k] = v
        return result

    try:
        request = json.loads(message, object_pairs_hook=pairs)
        canonical(request)  # Reject NaN and Infinity, even in unused fields.
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError("Request must be strict JSON") from exc
    if type(request) is not dict:
        raise ValueError("Request must be an object")
    return request


def exchange(episode, message):
    """One strict JSON request -> one actor-safe JSON response.

    Malformed envelopes raise ValueError; schema-invalid *tool actions* instead
    receive a logged invalid_schema result. The transport owns framing/retries.
    """
    request = parse_request(message)
    op = request.get("op")
    if op == "observe" and set(request) == {"op"}:
        response = episode.observe()
    elif op == "step" and set(request) == {"op", "action"}:
        response = episode.step(request["action"])
    elif op == "end_round" and set(request) == {"op"}:
        response = episode.end_round()
    elif op == "finish" and set(request) == {"op"}:
        episode.finish()
        response = {"closed": True}  # Never return oracle labels or audit receipts.
    else:
        raise ValueError("Unknown operation or fields")
    return canonical(response)
