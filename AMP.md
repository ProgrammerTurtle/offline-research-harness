# Offline Amp execute profile

The research adapter is a **mock adapter and isolated native runtime probe**, not
a live-ready research integration. A separate, explicitly gated one-shot smoke
operation is described below; its private live evidence is not published here. A separately
authorized protected read-only authentication check succeeded; this offline
adapter does not import or access that credential store. The owner explicitly
requested CLI execute mode instead of
delegating to another agent/orb. Execute mode still creates an automatically
archived CLI conversation record; it is not a threadless raw-inference API.

The [official CLI documentation](https://ampcode.com/docs/cli) and pinned local
`amp --help` identify `-x`, `--stream-json`, `--stream-json-input`,
`--settings-file`, `--no-ide`, `--mode` and `--features`. The candidate command
and requested settings live in `synthetic_harness/amp_execute.py`. The adapter
records but does not execute them; separate native startup tests use local mocks
only, as described below. The candidate settings use the documented
`amp.tools.disable: ["*"]`, reject-all permissions, no MCP servers, and both
local-command and remote-URL MCP rejection rules. These are requested
restrictions, not independently verified enforcement for authenticated execute
mode. Do not infer stream compatibility from help.

## Boundary and offline contract

`AmpExecuteService` runs a scripted stream producer in the existing separate
trusted-service namespace and cgroup. The actor can request only a decision
from the broker, which supplies the public observation. It cannot choose the
service command, model, settings, mounts, environment or observation. The host
applies task operations and retains hidden fixtures, oracles and anchored audit
files. Neither actor nor service receives those files or host credentials.

The restricted stream follows the [documented JSON schema](https://ampcode.com/docs/cli/streaming-json),
not the earlier invented message-ID protocol. Documentation shows a final
`result` for the whole invocation; multiple inputs can share one final result.
The adapter therefore models one closed-stdin subprocess per decision, up to
five decisions per episode. Each invocation must report the same session,
empty tools/MCP/subagents, `/tmp` cwd, the exact current user-message echo,
one text-only `end_turn` assistant proposal, and a matching successful result.
Only after EOF and exit zero does the host release the action. A future native
implementation must continue the explicit episode thread ID, never the latest
thread. Successful native continuation is not yet implemented or established;
the native startup tests exercise only its rejected-fetch path.

Unknown fields, tools, approvals, subagents, thinking blocks, foreign sessions,
stale echoes, duplicate/out-of-order events, partial output, malformed or duplicate-key
JSON, failed results, nonzero exits and mismatches fail closed. Missing `subagents`
also fails closed, even though older documentation examples omit it. Task-invalid
actions still go through the existing task schema checks. Assistant IDs are not
invented: identical legitimate actions across decisions are allowed. There is
no cryptographic provenance/replay guarantee for a compromised trusted service.

The mock child is a fixed Python replay process in the separate service sandbox,
not native Amp. Each invocation has a two-second deadline, a 256 KiB total stdout
read limit and 64 KiB per-event limit, plus inherited file/cgroup/episode limits.
Raw lines are wrapped as data before strict host parsing; a child cannot impersonate
the supervisor's exit envelope through stdout. Stderr is discarded. The service
journal retains only configuration, accepted proposals and allowlisted metadata,
not raw events, prompts, rejected output or stderr. Public observations and task
effects remain in the existing broker evidence; external anchors still cover both.

Optional documented token usage is bounded and type-checked. Mode, duration and
usage are labeled **reported**, not independently measured. Effective model,
effort, Fast and native retry count remain `null`. The supervisor never retries.
This subset deliberately rejects unsupported metadata/event variants rather than
silently granting capabilities. It is **not a captured authenticated execute schema**.
Actual native continuation, tool/connector/hook/subagent suppression, model transport,
provider retries and cost enforcement remain prerequisites for credential-bearing use.
No native `-x`, real key, or external endpoint is used in these adapter tests.

The first credential-free `tools list` probe timed out. Follow-up local TLS
fixtures now distinguish authentication discovery, rejected account requests,
and stalled transport; see Native tool discovery below. Native execution remains
blocked: a tool listing is not evidence of effective execution restrictions.

Validation: `python -m unittest discover -s tests -v` passed 116 tests,
including the native startup and fixed-smoke offline matrices;
`python -m synthetic_harness validate` passed 2,160 seeded controls with zero
failures. Targeted adapter tests cover six completion/escalation episodes across
the three domains, stale echoes and session changes, nonzero exits after a valid
result, duplicate/forged terminal messages, truncation, timeout, malformed JSON,
usage validation, no task effects on rejected invocations, private-path/network
denial, sanitized journals, anchor tampering and cgroup cleanup. These are finite
offline checks, not model experiments or proof against kernel/runtime escapes.

`AmpRuntimeProbe` permits only `--help` and `--version`. It runs the pinned
native binary with a private empty home and settings, no auth store, and no
host-network route. The service allows namespace-local IPv4 TCP, inherited
from the Codex profile, but no Unix pathname sockets or external networking.
It retains the original resource limits and syscall allowlist. See
[CODEX.md](CODEX.md) and [SANDBOX.md](SANDBOX.md) for the inherited threat model,
512 MiB service cgroup, 2 GiB per-process address space, 128-task budget,
3 CPU seconds per process, deadlines and whole-cgroup cleanup. The actor has
its own stricter limits. Neither profile protects against a malicious host or
kernel/runtime vulnerabilities; anchors require an independently trusted root.

## Frozen native profile

Verified native version: `0.0.1793479144-g397d4e`.
Binary SHA256: `9b8319f6aeb0b6d899880991728f36eed27b69d5e8e79cfccaa2bd963b3885cf`.
This platform-specific binary is not included in the source handoff. From an
independently obtained matching CLI executable, prepare the profile as follows
(this copies executable bytes only, never Amp's home or settings):

```sh
install -m 555 /path/to/matching/amp .runtime/amp-0.0.1793479144-g397d4e
mkdir .runtime/amp-0.0.1793479144-g397d4e-libs
install -m 444 .runtime/codex-0.166.0-ca-20250419/root/usr/lib/x86_64-linux-gnu/* \
  .runtime/amp-0.0.1793479144-g397d4e-libs/
install -m 444 /usr/lib/x86_64-linux-gnu/{libpthread.so.0,libdl.so.2,libgcc_s.so.1,librt.so.1} \
  .runtime/amp-0.0.1793479144-g397d4e-libs/
```

Prepare the base runtime using CODEX.md first. The probe verifies its manifest,
the Amp binary hash, the exact library file set, and the four extra library
hashes pinned in `AMP_LIBRARIES`. Unexpected files, changed hashes, symlinks or
writable binaries/libraries fail closed. Other desktop distributions/versions
may fail these pins; do not silently use broader host mounts. Missing pthread,
GCC support and realtime libraries were resolved with this minimal overlay,
not by weakening isolation.

After enrolling the launching shell in the delegated cgroup (SANDBOX.md):

```sh
python -m unittest discover -s tests -p test_amp_execute.py -v
python -m synthetic_harness.amp_execute --domain inventory --output /tmp/amp-mock --anchor /tmp/amp-mock-anchor
```

Use fresh output paths. Tests cover all three domains, completion/escalation,
session separation, forged/tool/replayed events, timeouts/floods, external-anchor
tampering and cleanup. Native help/version probes additionally check hidden
host paths/PIDs, read-only runtime, memory/FD limits, Unix sockets and external
network denial. These are finite adversarial checks, not proof of no escapes.

## Protected operator path (offline preparation)

`synthetic_harness.amp_protected` adds a separate, explicitly provisioned store
and operator-only service. [Amp's account documentation](https://ampcode.com/docs/cli#manage-cli-accounts)
supports `AMP_API_KEY` and says it takes precedence over saved accounts. This
is an **Amp credential, not an OpenAI API key**. No existing credentials are
discovered, copied, exported, or read from the host environment. Automated tests
use only synthetic values. Separately approved private entry and a read-only
check established authentication without enabling this model adapter.

The store uses exclusive leasing, mode-0700 directories, a create-only mode-0400
key file, and bounded printable input. Symlinks, hardlinks and incorrect file
permissions are rejected. A pinned file descriptor mounts only that one file
read-only in the service namespace, not the whole credential directory. The
native child receives it through `AMP_API_KEY`; the arbitrary actor receives
neither that environment variable nor the credential mount. Model-controlled
tools in that same native service **would** be able to access its environment
or file: verified suppression is still mandatory before enabling `-x`.
The store is permission-protected plaintext, not encrypted at rest, and the
host owner/root remain trusted. Deleting a file is not secure media erasure.

The operator interface supports `init-store`, `import-key`, `probe`, `check`, and
`verify`, with explicit paths and no defaults. `import-key` requires a private
operator terminal, uses non-echoed input, refuses piped input and getpass echo
fallback, and never accepts a key in argv. It reports only
`credential_stored_not_authenticated`. Do not put real credentials in chat,
shell commands, test fixtures, or an actor's environment. An operator can use
this sequence with new, absolute, nonoverlapping paths after an explicit
credential-provisioning decision:

```sh
python -m synthetic_harness.amp_protected init-store --store /private/new-amp-store
python -m synthetic_harness.amp_protected import-key --store /private/new-amp-store
python -m synthetic_harness.amp_protected probe --store /private/new-amp-store \
  --output /audit/new-amp-probe --anchor /anchors/new-amp-root
python -m synthetic_harness.amp_protected verify \
  --output /audit/new-amp-probe --anchor /anchors/new-amp-root
```

Parent directories must exist; enroll the launching shell as in SANDBOX.md.
**The probe cannot log in or run a model.** Only the pinned native `--version`
and `--help` operations are available. The CLI probe uses no egress at all.
`runtime_ready` means only that the runtime command exited successfully;
`authenticated` is always `null`. Other bounded outcomes are `runtime_failed`,
`timeout`, `interrupted`, and `boundary_failed`. Raw stdout/stderr are discarded;
audit events retain only allowlisted outcomes and trusted code/filter hashes.
Wire contents, exceptions, keys, URLs and account data never enter this journal.
External anchors detect tampering; the host can still forge evidence.

`AmpEgress` prepares a host-side opaque relay for exactly `ampcode.com:443`,
with public-unicast-only DNS pinned once per session, no caller-selected host,
16 opens, four simultaneous sockets, 16 MiB aggregate traffic, 30,000 frames,
and at most 900 seconds. It inherits the existing bounded CONNECT transport;
the Codex authority remains unchanged. TLS stays in the native client, so the
host relay does not inspect plaintext or log bytes. The relay restricts the
destination, **not URL paths or inference**. A shared-IP destination is not
a cryptographic hostname check; the trusted TLS client must validate hostname
and certificate. No redirects to other authorities are permitted by the proxy.
Native proxy/CA behavior is tested offline as described below. The protected
read-only list check authenticated successfully; model transport remains unverified.
Only the explicitly gated `check` operation exposes egress through the operator
CLI. It tightens these budgets to one connection and 15 seconds, as described
below. Offline tests route only to local fixtures; production has no routing override.

Offline tests use a synthetic key for native help/version, prove the child
receives the intended value while stdout/stderr cannot leak it, exercise the
namespace CONNECT relay against a socketpair, reject wrong destinations and
secret-bearing malformed results, test timeout/interruption cleanup, reject
unsafe stores and piped input, and verify actor denial and audit tampering.
Run `python -m unittest discover -s tests -p test_amp_protected.py -v` after
preparing the runtime/cgroup prerequisites.

## Native transport and TLS validation (no model execution)

The pinned binary's own `amp threads list --help` documents
`threads list --limit 1 --json` as a read-only list operation. The native TLS
test invokes that command inside the existing protected namespace, with a
synthetic key, a fresh empty home and the existing resource/syscall limits.
It never invokes `-x`, login or provider-access checks. Fixture CA and localhost
routing substitutions exist only in tests. The production `check` operation
now permits the fixed list command through a separate explicit gate.

The host TLS fixture uses ephemeral OpenSSL-generated keys/certificates and
listens only on loopback. The service retains the exact `ampcode.com:443`
authority and normal SNI/hostname validation. Tests replace the host connector
with that local fixture, mock DNS, and make any fallback connector fail.
The service has no route to the external network. No public endpoint is
contacted. Only public fixture CA bytes enter the service, never the fixture
server's private keys. No host settings or real credential are loaded.

The valid fixture observes the actual native request
`POST /api/internal?listThreads HTTP/1.1`, SNI `ampcode.com`, and the synthetic
key. This is evidence from the supported CLI command, not an independently
implemented HTTP client or a supported public API contract. Fixtures deliberately
return HTTP 404 after the TLS/request checks, so `runtime_failed` is expected;
these tests do **not** establish a successful list response or authentication.

| Native case | Verified observation |
| --- | --- |
| Valid CA and hostname | One TLS connection and one list request; fixture receives synthetic key. |
| Unknown root (unchanged public bundle) | TLS fails; no HTTP request or key reaches fixture. |
| Trusted root, wrong hostname | TLS fails before HTTP/key transmission. |
| Trusted root, expired leaf | TLS fails before HTTP/key transmission. |
| Early upstream EOF | Bounded failure; one connection, no HTTP request. |
| Stalled handshake | Eight-second child deadline produces `timeout`; whole service cgroup cleaned up. |
| HTTPS redirect to another hostname | Initial list request only; no second upstream connection. |
| HTTPS redirect to loopback IP | Initial list request only; no second upstream connection. |
| HTTP downgrade redirect | Initial list request only; no plaintext upstream connection. |
| Same-host HTTPS redirect | Two connections: list POST, then `GET /redirect`; proves redirects are not universally disabled. |
| All proxy variables removed | Zero upstream connections; no direct-network fallback. |

The CA comparison changes only the fixture trust input: native Amp honors
`NODE_EXTRA_CA_CERTS` while the inherited `SSL_CERT_FILE` still points to the
pinned public bundle. The production bundle's integrity/read-only mount remain
enforced by the existing runtime verifier. This is **not server-certificate
pinning or proof of an exclusive root set**: extra roots can augment native
built-in trust. Revocation, all TLS versions/ciphers, proxy-variable precedence,
all redirect statuses, WebSockets and the model execution transport are not
covered. Do not generalize this command's behavior to every Amp subsystem.

All eleven cases assert exact request/connection counts, completion within
14 seconds including startup/cleanup, sanitized `authenticated: null` outcomes,
external-anchor verification and absence of fixture keys/bodies from journals.
No retry was observed in these failure cases; this is not a general guarantee
about Amp's retries. The protected wrapper retains stricter aggregate framing
limits (256 frames / 2 MiB wire) in addition to the standalone egress budgets.
Run `python -m unittest discover -s tests -p test_amp_tls.py -v` with the same
frozen-runtime and cgroup prerequisites as the other native tests.

## Native tool discovery against local fixtures

`tests/test_amp_discovery.py` runs the actual pinned binary's documented
`tools list --json --mode openai/gpt-6-astra`, not a generic HTTP client or an
execute invocation. The command substitution, synthetic key, fixture CA and
loopback routing exist only in tests. The production command allowlist and
all isolation, resource and destination limits remain unchanged. No real key,
account request, model inference or external endpoint is used by these probes.

| Offline fixture/control | Native observation |
| --- | --- |
| No key supplied to child; local endpoint rejects requests | Requests `/api/auth/oauth-config`, then reaches eight-second child timeout. No successful login or tool list. |
| Synthetic key; all API requests return 404 | Exits zero and lists seven built-ins. Requests `getUserInfo` and `loadPlugins`; telemetry was also observed. |
| Same setup, HTTP 401 | Also exits zero and lists the same built-ins. **Discovery success is not authentication success.** |
| Empty disable list, `['*']`, or all seven explicit tool names | Identical tool-name sets, including `shell_command`, `apply_patch`, and `skill`. Listing does not establish execution-time filtering. |
| Local MCP canary, command-reject rule present | Process marker absent; removing only MCP rejection starts the canary and creates its marker. |
| Remote MCP canary, URL-reject rule present | No request to its fixture path; removing only MCP rejection sends POST/GET to that path. |
| Synthetic key; stalled TLS endpoint | Eight-second timeout, followed by whole-service cleanup. |

The local and remote MCP controls are positive/negative pairs: they establish
that the pinned native discovery path reads these settings and enforces the
tested MCP startup restrictions. They do **not** establish hook suppression,
server-side connector suppression, subagent restrictions, or builtin execution
permissions. In particular, `amp.tools.disable` not changing this listing does
not prove that execute mode ignores it; the listing may enumerate tools before
execution-time filtering. No builtin tool was invoked by these tests.

The no-key fixture shows an authentication-discovery path that can stall, while
responsive rejecting fixtures let the synthetic-key command complete. These
controlled observations explain why a bare offline probe is insufficient; they
do not reconstruct the exact cause of the original uninstrumented timeout.
Discovery can request plugins even with no configured MCP servers, so MCP
rejection alone is not a general extension-disabling control. Failed plugin
loads here do not establish what a successful authenticated load would do.

All ten cases verify sanitized external anchors and service cleanup. Tests
reject unexpected fixture request paths and prevent a connector fallback to a
public endpoint. Native stdout is inspected only in the synthetic test; raw
registry/error output is not added to the protected audit journal. Telemetry
ordering/count is not a protocol contract and is not used as an assertion.

## Native execution startup against local mocks

`tests/test_amp_native_execution.py` adds eleven cases using the same pinned
binary, namespace, cgroup, synthetic-only key and loopback TLS routing. Unlike
discovery tests, these invoke native `-x` startup, explicit-thread continuation
and the documented `plugins exec` operation. All real destinations are blocked.
Only the fixture's minimal `getUserInfo` response succeeds; thread creation,
thread fetch and remote plugin/skill loads return 404. This is not a complete
backend implementation or a successful agent turn. Production source and its
command allowlist are unchanged; credential-bearing execute remains disabled.

| Case | Verified observation and limit |
| --- | --- |
| Account request rejected | Execute exits before local plugin initialization. A failure this early proves nothing about tool restrictions. |
| Minimal synthetic account accepted | Execute initializes a local plugin despite wildcard tool disable and reject-all tool permissions. Removing the plugin file removes its markers. |
| Plugin ready timeout zero | Local plugin still initializes; zero is not an extension-disabling switch. |
| Synthetic service-key canary | Plugin initialization can read the known fake key mounted in its own trusted-service namespace. Host workspace path remains absent. This is a shared trust-boundary observation, not a real credential disclosure or an Amp vulnerability claim. |
| Local MCP reject/allow pair during execute startup | Command-reject rule prevents the harmless process marker; removing only MCP rejection starts it. |
| Remote MCP reject/allow pair during execute startup | URL-reject rule prevents fixture MCP requests; removing only MCP rejection produces them. |
| Explicit-thread continuation | Local plugin initializes, then thread-tail fetch is rejected. No successful session continuity established. |
| `plugins exec` for `agent.start` and `tool.call` | Module initialization and registration occur and CLI exits zero, but callback markers are absent. Hook delivery and preventive enforcement remain inconclusive. |

The fixture observed four thread-create requests in a single execute invocation,
despite zero supervisor retries. This demonstrates native startup retries, not
a fixed retry contract or measured model-provider retries. Request counts are
reported, not asserted as invariant. No builtin or subagent tool execution was
reached. Empty callback markers do not establish suppression. Remote extension
loads were rejected, so successful remote plugins, connectors and subagents
remain untested. The local plugin interface is documented in
[the plugin API](https://ampcode.com/docs/plugin-api); local extension code must
be trusted independently of model tool permissions.

Each case checks the bounded result, completion within 14 seconds, synthetic
key/body exclusion from journals, external-anchor verification, relay closure
and service-cgroup cleanup. Test-only boolean markers never enter authoritative
journals. Native stdout/stderr remain discarded. Run after preparing the pinned
runtime and enrolling the launching shell as documented in SANDBOX.md:

```sh
python -m unittest discover -s tests -p test_amp_native_execution.py -v
```

**Remaining blocker:** the local fixture does not establish a connected native
agent session, so execution-time builtin permissions, successful hook dispatch,
subagent suppression and successful continuation cannot yet be verified. Do not
treat post-output schema rejection as a preventive control for tool side effects.
Before credential-bearing execution, require a supported extension-free native
profile and connected offline test surface, or a stronger separation that keeps
native extension execution away from credentials. Do not enable live execution
merely because MCP blocking or discovery works.

## Simpler trusted decision client: supported-profile investigation

The minimal design remains Amp as a **trusted decision client**, not a task
executor: the independent host sends only a public observation and accepts one
bounded structured action proposal. The host validates the action, executes the
synthetic operation, computes hidden ground truth, and writes externally anchored
evidence. Amp gets no task filesystem, oracle, investigator artifacts, authoritative
logs or callable task-action endpoint. Never evaluate its text as shell/code.
Session continuity, output limits and fail-closed validation stay in the existing
adapter; they do not prevent side effects inside Amp before output is received.

Public documentation and the pinned native help were inspected on 2026-11-02.
No login, stored credential access, account mutation, support contact, backend
protocol reconstruction or live inference was used. Findings:

* [Settings precedence](https://ampcode.com/docs/cli/settings): `--settings-file`
  replaces the user settings location, not workspace settings. Workspace settings
  override user settings; managed workspace settings can also merge/override them.
  Empty private HOME/XDG directories and a fresh non-repository working directory
  exclude inherited local files, not account-level configuration.
* [Plugin sources](https://ampcode.com/docs/customize/plugins): project and system
  directories are local; personal and workspace plugins apply across machines.
  Plugin initialization runs code, independently of tool calls. Hooks are plugin
  behavior, not a separate isolation layer. The docs explicitly say to trust loaded
  plugins. No universal pre-initialization exclusion control was found in these
  docs, the public settings schema or the pinned CLI help. This is a bounded search
  result, not proof that no such feature exists anywhere.
* Pinned help describes `--plugin-ready-timeout 0` as disabling the readiness wait;
  the native canary tests above confirm it does not disable loading. `--mcp-config`
  merges configuration. An empty MCP object is not an all-source exclusion switch.
* [Remote MCP definitions](https://ampcode.com/docs/customize/mcp) live on Amp's
  servers and can apply without local configuration. The docs explicitly state:
  **"amp.tools.disable in local settings does not apply to remote MCP definitions."**
  Local URL/command MCP rejection has native positive/negative evidence, but that
  does not establish prevention of server-managed connectors. Restricting outbound
  connections to ampcode.com cannot restrict what Amp's server can do on behalf of
  an account. No account registry was inspected in this investigation.
* Pinned help documents `amp.tools.enable` as an allowlist and `amp.tools.disable`
  as a denylist, plus `amp.permissions`. Native `permissions test shell_command
  --context thread --json` with the existing wildcard reject rule returned
  `action: reject` and exit 2; subagent context did likewise. Changing only that
  rule to allow returned `action: allow` and exit 0. These credential-free checks
  ran inside the existing no-network runtime namespace. The command explicitly
  tests rules **without running the tool**: policy evaluation is verified,
  execution-time enforcement and disabling subagent creation are not.

Two threats must remain distinct. Malicious installed extension code is part of
the trusted client's process and can access its credentials; ordinary model tool
permissions do not sandbox that code. Model-generated task actions, by contrast,
remain untrusted data that only the host can apply. Treating Amp and every loaded
extension as trusted simplifies the architecture but changes the threat model;
it does not establish the requested extension-free startup guarantee. Unexpected
extensions, skills, connectors, subagents or inherited instructions also confound
an experiment even when they are not malicious. Results would characterize the
configured Amp agent, not raw model inference.

**Conclusion:** the host-only action design is viable as a contract, but a fully
extension-free supported native profile has not been established. Keep live
execution disabled. Do not expand the sandbox or emulate undocumented backend
protocols to paper over this gap. The smallest next approval is a read-only
inventory of personal/workspace plugins and remote-tool policies, without model
calls or setting changes. That would identify the actual trusted components and
whether a separately isolated account/workspace is needed; it would not itself
prove per-invocation exclusion or authorize configuring one. No such inventory
or account change has been performed.

## Single-use read-only authentication check

The owner approved private operator-supplied Amp key provisioning and one real
thread-list check, including its suppressed metadata access. That authorization
does not cover models, conversation creation, account changes, or retries.

`check --enable-check-egress` launches only the pinned native
`threads list --limit 1 --json` command. It requires an explicit protected store,
fresh audit output and external anchor. A durable create-only `home/check-used`
marker consumes the store's attempt before launch, including failed or interrupted
launches. Do not delete/reset this marker to retry. The supervisor launches once;
the relay denies reconnects. Opaque TLS cannot count requests reused on the same
connection, so this is not a cryptographic one-HTTP-request guarantee. The pinned
native read-only command remains trusted; the relay is not an inference firewall.

Native stderr is discarded. Stdout stays in private service tmpfs, subject to the
existing file/resource limits; the validator reads at most 65,537 bytes and rejects
outputs over 64 KiB. `authenticated: true` requires exit zero plus valid JSON
containing an empty list or one nonempty record object. Duplicate fields, nonfinite
numbers, excess records, malformed JSON and oversized output are rejected. Record
fields are owned by the native CLI, not guessed by this wrapper. No record values
are retained in the host journal or report. Outcomes are `authenticated`,
`native_failed`, `application_response_invalid`, `timeout`, `interrupted`, or
`boundary_failed`. Failures report `authenticated: null`, not a diagnosis of the
account or provider. Verify the external anchor; evidence remains host-recorded,
not independently attested by the provider.

`tests/test_amp_auth.py` exercises the pinned CLI with synthetic credentials and
local TLS: valid empty-list success, malformed server record failure, HTTP 401,
HTTP 500, and denied same-host redirect reconnection. It checks single-use stores,
sanitized anchored journals and whole-service cleanup. Separate mock-child tests
exercise successful single-record output, excess records, oversized stdout and
nonzero exit without leaking stdout/stderr. **A valid nonempty native server
response has not been reproduced offline**; incomplete server records fail in
the CLI before validation. The mock-child tests do not establish that wire schema.
No real key or live response was used for this validation.

After private import, the approved operator command is:

```sh
python -m synthetic_harness.amp_protected check --enable-check-egress \
  --store /private/new-amp-store --output /audit/new-amp-check --anchor /anchors/new-amp-check-root
```

Keep the import and check in the private terminal, never include the key in argv
or a transcript. Ctrl-C cancels the operation; do not restart it automatically.
Afterward, use `verify` with those same output/anchor paths to inspect only the
sanitized result. A missing/invalid anchor is not successful authentication.

## Remaining gate before model use

Live research construction without explicit scripted answers is disabled. No worker-pool
integration for this Amp profile or authenticated throughput claim is made.
The protected handoff, relay and native non-model TLS path are validated offline;
real account provisioning, successful authenticated responses, stream schema, actual
tool/connector/hook/subagent suppression, and metadata/session/retry behavior
remain unverified except for explicit provisioning and one successful protected
read-only authentication check (attempt 02, independently checked against its
external host anchor). Attempt 01 failed for an undetermined reason. Neither
attempt ran a model; the offline adapter never reads either credential store.
Do not infer execute compatibility from that successful list operation.
Before enabling model execution, resolve its separate gaps and authorize a
minimal live compatibility smoke test. Do not treat a functioning host Amp
installation as permission to extract its credentials or as proof that this
isolated profile can authenticate. User-provided sponsored deployment permission
is authorization context, not independently verified provider terms.

## Fixed one-shot compatibility operation

This optional operation uses a different, explicit trust assumption from the
extension-exclusion investigation above: pinned Amp and all extensions/inherited
configuration it actually loads are trusted credential-bearing infrastructure.
That is **not evidence of extension absence or tool suppression**. Model output
remains untrusted. Neither the research actor nor the task executor is invoked.
Existing offline research APIs remain mock-only.

`amp_protected smoke --enable-smoke-egress` runs one fixed command with one public
synthetic inventory observation, closed stdin, Astra and Fast requested, private
visibility, default/unverified effort, JSON streaming, and no IDE integration.
It accepts only the fixed `check` proposal with empty arguments and never applies
it. This is a transport/format compatibility canary, not a benchmark of decisions.
Callers cannot supply a prompt, command, model, destination or task action.

The operation requires an explicit operator-provisioned store and fresh output
and external-anchor paths. `home/smoke-used` is exclusively created and fsynced
before spawning the service; success, failure and interruption consume it.
Existing `check-used` authentication markers are neither reused nor reset. Each
invocation requires explicit human authorization; do not delete markers, copy
keys into new stores, or automatically retry to get another attempt.

The native child has a 30-second wall deadline and closed stdin. Stdout is read
incrementally, capped at 256 KiB total and 64 KiB per JSON event (excluding its
newline). A single five-second budget covers whole-service cgroup cleanup.
The parent has a 32-second protocol watchdog to cover service startup/reporting.
Existing namespace, syscall, CPU, memory, process, file and tmpfs limits are
unchanged. Egress remains the existing bounded ampcode.com:443-only relay,
including its socket limits and the service's 256-frame/2-MiB wire budget.
No additional destination or routing override exists in production.

The classifier requires init, exact public prompt echo, one bounded proposal,
matching successful result, EOF and native exit zero. It accepts nonempty trusted
init catalogs and records only counts, never private tool/server names. Observed
tool, approval, permission-denial or subagent activity makes the compatibility
test unsuccessful; this is observation **after possible side effects**, not a
preventive tool control. Schema drift, duplicate keys, truncation, extra events,
oversize output, native failure and timeouts fail closed. A valid proposal before
a later failure is not a successful run. Unknown fields are not guessed into a
successful schema, and private error strings are never used as diagnoses.

Only an allowlisted result leaves the namespace: state, stream stage, validated
session ID, event/catalog counts, proposal-validation boolean, requested settings,
whether reported mode matches, bounded reported usage/duration/turn count, native
exit and local elapsed/output counts. Effective model/effort/Fast and native retry
count remain null: the documented stream does not independently attest them.
Raw stream bytes are transient; stderr is discarded. Authoritative logs omit
wire payloads and raw metadata; `verify` checks the external host anchor, not
provider attestation. `egress_failed` identifies relay rejection, not an inferred
TLS/provider cause. Other failures record the last reached stream stage.
On a host-boundary failure, elapsed/output/event counters are the last received
child snapshot, not a complete wall-time or remote-activity measurement. New
outcomes additionally include host-owned `host_transport` counters: received
envelopes (including the rejected 257th), consumed stdout wire bytes, opened
tunnels, successful transfer exchanges, empty non-EOF polls, sent/received
payload bytes and host probe elapsed milliseconds (excluding cleanup).
These reveal local relay activity, not decrypted traffic or remote execution.
Old anchored outcomes without these counters remain verifiable and unchanged.

### Offline relay-budget diagnosis

`tests/test_amp_boundary.py` exercises the unchanged production proxy and relay
against a local socket pair, with synthetic credentials and external connections
forbidden. An idle CONNECT tunnel exhausts the 256-envelope budget without any
payload bytes: initial progress + tunnel open + 254 empty transfers are accepted;
the next transfer is envelope 257 and is rejected before a receive log entry.
In the targeted run this took 19.242 seconds and 20,471 stdout wire bytes, below
the 30-second native deadline and 2-MiB wire cap. A seven-byte upstream control
reached the same boundary with 253 idle polls and one substantive transfer in
19.069 seconds. Timings depend on scheduling; these are not native model tests.

The cause is unconditional empty transfer polling in `Proxy.do_CONNECT`, charged
to the same envelope counter as substantive traffic. The host upstream poll
waits up to 50 ms, and the proxy adds short waits; an idle connection therefore
spends envelopes while waiting for useful data. Multiple tunnels and actual
startup traffic can change the exhaustion time. This proves a host-side failure
mechanism, **not the precise cause of any earlier generically classified live
failure**, and does not identify a provider or TLS fault.

New allowlisted `service_*` states distinguish envelope, wire-byte, buffered-line,
outbound-message, deadline, pipe-closure, pipe-I/O, stderr-budget and envelope
schema failures. No exception text or raw pipe content is copied into results.
Fixtures test the exact 256/257 boundary, byte/buffer exhaustion, the unchanged
32-second host deadline, closed/error pipes, stderr and malformed envelopes,
secret exclusion, external-anchor verification and cgroup cleanup.

All production limits and polling behavior remain unchanged during diagnosis.
The smallest proposed correction is bounded idle-poll coalescing/backoff, tested
with all permitted tunnels and delayed data in both directions, while retaining
the envelope/byte limits, cancellation and wall deadlines. Simply exempting idle
messages from accounting would remove a resource bound. The correction requires
separate approval; another live attempt requires its own explicit authorization.

Execute mode normally creates a private automatically archived conversation and
incurs usage. One CLI invocation does not promise one provider request, one
model call, a dollar cap, or remote cancellation when the local process stops:
native retries, supporting models and trusted extensions may add work. No account
configuration is changed by this operation. A successful result would not establish
session continuation, research validity, effective tool suppression or suitability
for unattended/concurrent experiments.

Offline validation in `tests/test_amp_smoke.py` covers success with nonempty init
metadata, exact/over-limit output, secret-bearing malformed/truncated data,
tool/approval/late events, late nonzero exit, native error, forged supervisor
envelopes, interruption, the real 30-second timeout, one-shot markers, sanitized
anchors and cleanup. A pinned native CLI case uses only a rejecting local TLS
fixture and synthetic key; it establishes bounded startup failure, not successful
live model transport. Fixture command/CA/routing substitutions are test-only.

After explicit authorization, with distinct existing private parent directories:

```sh
python -m synthetic_harness.amp_protected smoke --enable-smoke-egress \
  --store /private/provisioned-store --output /audit/fresh-smoke --anchor /anchors/fresh-smoke-root
python -m synthetic_harness.amp_protected verify \
  --output /audit/fresh-smoke --anchor /anchors/fresh-smoke-root
```

Keep live results, thread IDs, account inventory and credential paths private;
never commit them with generic source/tests/docs.
