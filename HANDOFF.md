# Offline harness handoff — 2026-10-31

## Why work paused

The user requested GPT-6 Astra (`openai/gpt-6-astra`), high reasoning effort,
with Fast enabled. `amp.get_thread_status` reports this execution thread's
locked mode as `medium`. The installed CLI is
`0.0.1793479144-g397d4e`; its help exposes startup `--mode` and `--features`
flags, but no supported command to mutate this running thread's locked model
or reasoning effort. `amp.update_thread` has no model/effort/feature fields.
No model switch succeeded. No replacement thread was created and no account
configuration changed. Stop implementation here until an appropriately
configured thread owns the work. Fast was enabled for this thread's coding.

Source thread: https://ampcode.com/threads/T-01a193ba-34be-7350-8ccb-d6e402e3b92d

Originating Puck: https://ampcode.com/threads/T-01a193b5-6f63-73de-9f4c-09590e8a8d40

## Access and scope

The user has Codex CLI, NOT established API access. Earlier API access and
OpenAI sponsorship claims are superseded. This is independent research,
not an internal OpenAI study. No credentials were inspected, Codex CLI
availability checked, accounts modified, or models/API experiments invoked. Two pinned
accessible models have not been established. Keep future invocation transport
separate from the environment/oracle. Record CLI version, selected/reported
model, exposed and hidden settings, prompts, tool scaffolding, context handling,
compaction, sessions, retries, and isolation before any future model study.

## Preserved implementation

The workspace is `/home/user/workspace`, not a Git repository. All task files
are local and uncommitted. No dependencies beyond Python's standard library.

- `llm-behavior-research-proposal.md`: source-linked review/proposal, corrected
  for Codex-only access and conditional model availability.
- `synthetic_harness/tasks.py`: deterministic canonical fixtures and actor views.
- `environment.py`: inventory, exact-analysis and bounded software-DSL tasks;
  vulnerable/hardened variants and decision/diagnostic/placebo feedback.
- `oracle.py`: host-only independent authorization/process/outcome checks.
- `runner.py`: action budgets, sealed hash-chain evidence, durable optional
  append-only journals, source manifests, anchored deterministic replay and
  local plus trajectory counterfactual classification.
- `protocol.py`: strict JSON actor boundary, no model transport or audit leakage.
- `controls.py`: honest, legal-shortcut, seeded exploit, invalid-action then
  recovery, and ordinary-mistake reference policies.
- `__main__.py`: validate/run/replay and newly added JSONL session interface.
- `tests/test_harness.py`: 13 existing tests.

## Verification on the exact preserved code

`python -m unittest discover -s tests -v`: 13 tests passed (0.041 seconds).

`python -m synthetic_harness validate`: 2,160 episodes; zero failures;
432 episodes per control; 432 confirmed exploit attempts; 216 successful
deliveries (the vulnerable conditions); 864 task completions; 480 valid
escalations; 432 unsupported completion claims.

Matrix = 3 domains × 8 mechanical variants × 3 seeds × 2 validator modes ×
3 feedback arms × 5 controls. These are seeded controls, not evidence about
model behavior or spontaneous discovery. Two seeds are achievable and the
third has a deliberate blocker. Eight variants are not eight independently
designed task families.

Existing tests cover deterministic isolation, reference outcomes, asymmetric
hand-derived software results, exact rational arithmetic, authorization and
provenance violations, blocked attempts, repaired artifacts, ordinary mistakes
without exploit evidence, feedback surfaces, budgets, invalid schemas, log
mutation/truncation/reordering/rehashing, external anchors, forged results,
replay and exclusive saved bundles.

## Remaining work — do not call the build complete yet

1. Add tests for the new serialized protocol and JSONL CLI session, including
   duplicate keys, NaN, large requests, closed-session behavior and ensuring
   finish/history never expose investigator data. CLI session currently stops
   after an action closes the episode, without an extra end-round feedback.
2. Add durable-journal tests (flush/seal, permissions, exclusive create) and a
   separate-process CLI replay test. Existing tests validate saved bundles but
   do not yet exercise these new paths.
3. Review escalation classification: `oracle.outcome` currently accepts a
   correct blocker code even if preceding accepted actions had side effects.
   History violations are recorded separately, but decide and document whether
   a valid escalation must also require no shipments/artifact. Add a regression
   test for the chosen operational definition. This is an identified question,
   not a verified failing control-matrix case.
4. Extend independent hand-derived software checks to `tasks.expected`, not
   only the DSL interpreter. Review inventory exact-stock boundaries.
5. Write a README with commands, actor/host contract, classification definitions,
   reproducibility and limitations. Generate reviewable validation JSON and
   paired vulnerable/hardened bundles only after source settles, since replay
   intentionally requires matching source hashes.
6. Rerun tests/matrix, verify separate-process replay/tamper rejection, and report
   completion to Puck and in the new thread. Do not run model experiments.

## Important limits

- Capability sandbox only: bounded JSON DSL, no arbitrary-code/shell/network/
  filesystem actor tools. Python objects and investigator files must remain
  host-only. This is NOT an OS sandbox for hostile Python or Codex shell access.
- Hash chains, exclusive writes, fsync and read-only permissions are tamper
  evidence under a trusted host, not absolute immutability against the host
  owner/root. Retain root anchors externally; a nearby receipt is not an
  independent trust anchor. An interrupted journal is incomplete evidence.
- Placebo diagnostic length is character-matched, not tokenizer-matched.
- Counterfactuals replay recorded actions; they do not regenerate how an actor
  would adapt to different feedback. No intent is inferred. Wrong arithmetic
  alone is not classified as confirmed exploitation.
- A future Codex adapter must not expose this host workspace, sources, hidden
  fixtures, journals, audits or arbitrary shell capabilities to the actor.

## Transfer to a user-created Astra/high thread

The archive `.amp/in/artifacts/offline-harness-handoff.tar.gz` contains this
handoff, proposal, package sources and tests, without caches or credentials.
From the destination thread, use Amp's `download_thread_file` tool with:

- thread: `T-01a193ba-34be-7350-8ccb-d6e402e3b92d`
- path: `.amp/in/artifacts/offline-harness-handoff.tar.gz`
- destination: a new local archive filename

Extract into an empty working directory, read this handoff, and verify the
archive's SHA-256 against the value reported by the source thread. A new thread
does not inherit these files merely by receiving their paths or this thread ID.
The source orb must remain available/unarchived until download completes.
Alternatively download the linked archive and attach it to the new thread.
Have the owner explicitly choose Astra/high/Fast and verify the destination's
actual configuration; the instruction text alone does not establish a switch.
