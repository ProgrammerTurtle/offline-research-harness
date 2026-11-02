"""Run the pinned Codex CLI against scripted mock Responses, never a model."""

import argparse
import json
from pathlib import Path

from .app_server import AppServerTransport, bridge_source
from .codex_runtime import DEFAULT_RUNTIME
from .controls import CONTROLS, control_actions
from .provider import MockUpstream, ProviderTransport
from .sandbox import run
from .tasks import ARMS, DOMAINS, MODES, actor_view, canonical, make_case
from .trusted_service import ACTOR, TrustedService


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", choices=DOMAINS, required=True)
    parser.add_argument("--template", type=int, default=0)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--mode", choices=MODES, default="hardened")
    parser.add_argument("--arm", choices=ARMS, default="decision")
    parser.add_argument("--control", choices=CONTROLS, default="honest")
    parser.add_argument("--failure", choices=("http429", "truncated"))
    adapter = parser.add_mutually_exclusive_group()
    adapter.add_argument("--app-server", action="store_true")
    adapter.add_argument("--trusted-service", action="store_true")
    parser.add_argument("--runtime", type=Path, default=DEFAULT_RUNTIME)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--anchor", type=Path, required=True)
    args = parser.parse_args()
    case = make_case(args.domain, args.template, args.seed)
    answers = [canonical({"op": "step", "action": action})
               for action in control_actions(actor_view(case), args.control)]
    upstream = MockUpstream(answers, failure=args.failure)
    options = dict(domain=args.domain, template=args.template, seed=args.seed,
                   mode=args.mode, arm=args.arm, timeout=20)
    if args.trusted_service:
        with TrustedService(args.output, upstream, runtime=args.runtime) as service:
            result = run(ACTOR, args.output, args.anchor, service=service, **options)
            calls = service.transport.calls
    else:
        provider = (AppServerTransport if args.app_server else ProviderTransport)(upstream)
        actor = bridge_source() if args.app_server else Path(__file__).with_name("codex_actor.py").read_bytes()
        result = run(actor, args.output, args.anchor, runtime=args.runtime, provider=provider,
                     app_server=args.app_server, **options)
        calls = provider.calls
    print(json.dumps({**result, "provider_calls": calls, "scope": "offline mock only"}, indent=2))
    return 0 if result["status"] == "actor_exited" and result["returncode"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
