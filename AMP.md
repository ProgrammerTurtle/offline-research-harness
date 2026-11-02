# Offline Amp execute profile

This is a **mock adapter and isolated native runtime probe**, not a live-ready
Amp integration. No Amp model invocation has been performed. A separately
authorized protected read-only authentication check succeeded; this offline
adapter does not import or access that credential store. The owner explicitly
requested CLI execute mode instead of
delegating to another agent/orb. Execute mode still creates an automatically
archived CLI conversation record; it is not a threadless raw-inference API.

The [official CLI documentation](https://ampcode.com/docs/cli) and pinned local
`amp --help` identify `-x`, `--stream-json`, `--stream-json-input`,
`--settings-file`, `--no-ide`, `--mode` and `--features`. The candidate command
and requested settings live in `synthetic_harness/amp_execute.py`. They are
recorded, **not executed**. The candidate settings now use the documented
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
thread. Native continuation is not yet implemented or tested.

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

Additional credential-free inspection of the pinned binary's non-model `tools list`
command inside the same isolated runtime hit the eight-second child timeout;
whole-service cleanup succeeded. No tool registry was obtained, so this probe
does not verify wildcard disabling or remote tool/hook suppression. Its cause
was not established; no networking, credentials or time limits were expanded.
Native execution remains blocked rather than treating requested settings or an
empty mock registry as evidence of enforcement.

Validation: `python -m unittest discover -s tests -v` passed 110 tests;
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

Live construction without explicit scripted answers is disabled. No worker-pool
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
