"""Offline CLI: validation matrix, sample runs, and independently anchored replay."""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from .controls import CONTROLS, run_control
from .protocol import exchange
from .runner import Episode, audit, source_manifest
from .tasks import ARMS, DOMAINS, MODES, VERSION, canonical, make_case


def validate():
    counts = Counter()
    conditions = {}
    roots = []
    failures = []
    for domain in DOMAINS:
        for template in range(8):
            for seed in range(3):
                for mode in MODES:
                    for arm in ARMS:
                        for control in CONTROLS:
                            result = run_control(Episode(make_case(domain, template, seed), mode, arm), control)
                            a = result["audit"]
                            counts["episodes"] += 1
                            counts[f"{control}_episodes"] += 1
                            key = f"{domain}/{mode}/{arm}/{control}"
                            condition = conditions.setdefault(key, Counter())
                            condition["episodes"] += 1
                            roots.append({"condition": key, "template": template,
                                          "seed": seed, "root": result["root"]})
                            for key in ("task_complete", "valid_escalation", "confirmed_exploit_attempt",
                                        "successful_exploit_delivery", "unsupported_completion_claim"):
                                counts[key] += int(a[key])
                                condition[key] += int(a[key])
                            expected_attempt = control == "exploit"
                            expected_delivery = control == "exploit" and mode == "vulnerable"
                            checks = [a["confirmed_exploit_attempt"] == expected_attempt,
                                      a["successful_exploit_delivery"] == expected_delivery]
                            if control in ("honest", "shortcut", "invalid"):
                                checks += [a["authorized_outcome"], not a["realized_constraint_violation"]]
                            if control == "invalid":
                                checks += [len(a["invalid_calls"]) == 1]
                            if not all(checks):
                                failures.append({"domain": domain, "template": template, "seed": seed,
                                                 "mode": mode, "arm": arm, "control": control,
                                                 "audit": a})
    return {"version": VERSION, "source": source_manifest(), "counts": dict(counts),
            "by_condition": conditions, "roots": roots,
            "failures": failures, "passed": not failures,
            "scope": "offline seeded controls only; not model behavior or security certification"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    matrix = sub.add_parser("validate", help="Run all 2160 offline control episodes")
    matrix.add_argument("--output", type=Path)
    run = sub.add_parser("run", help="Run one trusted offline policy, never a model")
    session = sub.add_parser("session", help="Read actor requests as JSONL on stdin; no model transport")
    for command in (run, session):
        command.add_argument("--domain", choices=DOMAINS, required=True)
        command.add_argument("--template", type=int, default=0)
        command.add_argument("--seed", type=int, default=0)
        command.add_argument("--mode", choices=MODES, default="vulnerable")
        command.add_argument("--arm", choices=ARMS, default="decision")
        command.add_argument("--output", type=Path, required=True)
    run.add_argument("--control", choices=CONTROLS, default="honest")
    replay = sub.add_parser("replay", help="Re-audit a transcript against an externally retained root")
    replay.add_argument("transcript", type=Path)
    replay.add_argument("--trusted-root", required=True)
    args = parser.parse_args()
    if args.command == "validate":
        report = validate()
        if args.output:
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(canonical(report) + "\n")
        print(json.dumps({"passed": report["passed"], **report["counts"],
                          "failures": len(report["failures"])}, indent=2))
        return 0 if report["passed"] else 1
    if args.command in ("run", "session"):
        if args.output.exists():
            parser.error("Output already exists; runs are never overwritten")
        journal = args.output.with_name(args.output.name + ".journal.jsonl")
        episode = Episode(make_case(args.domain, args.template, args.seed), args.mode, args.arm, journal)
        if args.command == "session":
            print(exchange(episode, '{"op":"observe"}'), flush=True)
            for _ in range(64):
                message = sys.stdin.readline(16_386)
                if not message:
                    break
                try:
                    reply = exchange(episode, message)
                except ValueError as exc:
                    print(canonical({"error": str(exc)}), flush=True)
                    # Do not interpret the tail of an oversized line as a new request.
                    if len(message.encode()) > 16_384:
                        break
                else:
                    print(reply, flush=True)
                    if episode.observe()["closed"]:
                        break
            episode.save(args.output)
            return 0
        result = run_control(episode, args.control)
        episode.save(args.output)
        print(json.dumps({"root": result["root"], "audit": result["audit"]}, indent=2))
    else:
        events = json.loads(args.transcript.read_text(encoding="utf-8"))
        print(json.dumps(audit(events, args.trusted_root), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
