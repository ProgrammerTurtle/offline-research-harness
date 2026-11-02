# Offline Codex compatibility profile

This stage executes **Codex CLI 0.166.0**, not a model, against scripted mock
Responses events. No credential discovery, login, real provider client, API
access, or subscription forwarding is implemented. `gpt-5.4` is a requested
identifier for protocol testing, not an established accessible model.

## Reproduce

Use Linux x86-64, Python 3.11, Bubblewrap 0.8.0, libseccomp 2.5.4 and the
delegated cgroup setup in SANDBOX.md. Missing controls fail closed. Download
the official platform package without npm lifecycle scripts:

```sh
mkdir -p /tmp/codex-package
npm pack @openai/codex@0.166.0-linux-x64 --ignore-scripts --pack-destination /tmp/codex-package
python -m synthetic_harness.codex_runtime /tmp/codex-package/openai-codex-0.166.0-linux-x64.tgz
sudo -n sh -c 'echo "$1" > /sys/fs/cgroup/offline-harness/broker/cgroup.procs' sh "$$"
python -m unittest discover -s tests -v
python -m synthetic_harness.codex_demo --domain inventory --output /tmp/codex-demo --anchor /tmp/codex-demo-anchor
python -m synthetic_harness.sandbox verify --output /tmp/codex-demo --anchor /tmp/codex-demo-anchor
```

Output paths must be unused. The builder verifies the pinned npm SHA512 and
binary SHA256, copies distro Python's dependency closure and the pinned public
CA bundle, and hashes each
file and mode. Each launch verifies the frozen runtime before executing it.
No host Codex installation is needed. This orb's runtime is about 341 MiB/751
files. Different distro Python libraries produce a different manifest; the
builder is reproducible given those inputs, not a portable bit-identical image.
Runtime and manifest must remain host-controlled, without concurrent mutation.

The default runtime is `.runtime/codex-0.166.0-ca-20250419`; the old runtime is
not overwritten and is rejected by the updated verifier because it lacks the
pinned CA bundle. Rebuild from the cached official package using the command
above. No login, credential-store change or network request is part of rebuilding.

Public trust is vendored in `synthetic_harness/certs/mozilla-debian-20250419.pem`:
148 Mozilla roots from Debian `ca-certificates 20250419~deb12u2`, concatenated
in C-locale filename order from `/usr/share/ca-certificates/mozilla/*.crt`.
The installed package passed `dpkg -V ca-certificates` before extraction.
No `/etc/ssl` aggregate, locally installed enterprise roots, user home, or private
key was copied. Attribution/license text is in `synthetic_harness/certs/COPYRIGHT`.
Bundle SHA256: `e9c7b63ee2623386e9b0a3ee32f499d01a8ea23dc83b8383ddff9f8e749543b7`.
The builder and launcher independently pin this digest; modifying the manifest
to match a replacement certificate file still fails verification.

Only `/opt/public-ca.pem` is mounted read-only from the frozen runtime.
`CODEX_CA_CERTIFICATE` and `SSL_CERT_FILE` both select that exact file after
environment replacement. The base Python actor profile is unchanged. Runtime
receipts include CA version and digest. Trust updates are explicit reviewed
bundle/hash/runtime rebuilds, never automatic downloads or host-store inheritance.
This is a dated reproducible snapshot, not a claim to the latest trust policy;
review root removals/security updates before deployment. Offline tests verify
all 148 roots load inside the namespace, mutation is denied, missing/replaced
bundles fail closed, and native TLS controls still reject an untrusted test CA.

Binary SHA256: `b8a11fedf24b2dfb59a70c9e52b030f9a508dcd49cd2dd0d41956f4c785156b8`.
Reviewed matching source: OpenAI Codex tag `rust-v0.166.0`, revision
`6ff1e1ca3b30fc8b914720681fcf5fe62e95f856`.

## Boundary and transport

SANDBOX.md's trusted-host/kernel threat model still applies. The actor cannot
mount the workspace, user Codex home, credentials, fixtures, or evidence.
The exec adapter disables Codex's nested sandbox; the app-server adapter
requests read-only/no-network as an additional policy. The outer Bubblewrap/seccomp/
cgroup boundary remains mandatory. Private IPv4 TCP loopback supports an
actor-side HTTP relay. There is no host network interface or route, IPv6,
datagram/raw socket, or Unix pathname socket. Anonymous Unix socketpairs are
allowed for Tokio's internal signaling. Host loopback and actor loopback are
different namespaces. Further namespaces, ptrace, mount, alternate syscall
ABIs, and arbitrary ioctls remain blocked.

Codex profile limits: 512 MiB aggregate memory, no swap, 2 GiB address space
per process, 32 tasks, half a CPU, 3 CPU seconds per process, 16 MiB private
tmpfs, 1 MiB per file, 64 descriptors, and a 20-second demo wall deadline.
The Python-only profile keeps its lower limits and socket prohibition.
The explicit app-server profile changes only the per-file cap to 4 MiB and
allows `statfs`/`fstatfs` inside the existing mount namespace. Other limits stay.

The untrusted relay exchanges bounded JSONL with the host. Host policy accepts
only text Responses requests with the fixed model/effort, no remote files or
hosted tools, and at most eight provider calls. It does not accept endpoint,
Authorization, headers, or credential selection from the actor. Client
metadata is recorded but removed before upstream dispatch. A synthetic canary
credential is added only by the host mock transport. Exceptions, oversized
responses, and responses containing that credential are replaced by a generic
failure. No upstream HTTP headers cross the boundary. Secret substring checks
are a regression guard, not a general credential-exfiltration proof.

The provider call is synchronous and only supports an immediate in-process
mock. A future network client needs host-side deadlines, response-size limits
before buffering, endpoint/TLS policy, cancellation and credential handling;
do not insert blocking network I/O and assume the actor wall timer covers it.

## What the evidence means

Host wire journals record runtime/filter hashes, resource configuration,
received request bodies, returned mock SSE, task messages, and actor-reported
CLI events. Roots are anchored outside the actor and bundle on the trusted
host; this is not remote notarization or protection against host root.

* CLI reports `codex-cli 0.166.0`; the host independently checks its binary hash.
* Requested `gpt-5.4` and reasoning `high` appear in actual Responses bodies.
  No backend ran, so effective model/reasoning cannot be established.
* The custom provider lacks model catalog metadata. CLI emits a fallback
  warning; requested verbosity `low` is not transmitted in the observed body.
* Prompts, launch arguments, thread/turn events, session/context identifiers,
  final output and usage are captured. Actor claims are not authenticated
  telemetry. Mock token counts (11 input/7 output) are fabricated.
* The exec adapter uses a fresh ephemeral CLI session per action; the app-server
  adapter keeps one ephemeral thread per episode, with separate action turns.
  No session resume,
  compaction behavior, long context, interactive user-input tool round trip,
  or authenticated retries have been tested. CLI still advertises a
  `request_user_input` function descriptor; host allows only that descriptor,
  not hosted tool execution.
* Zero request/stream retries are configured. Actual CLI tests observe exactly
  one request for HTTP 429 and truncated SSE, a nonzero exit, and zero task
  actions. This establishes those failure paths only.

Tests cover native CLI completion/escalation in all three domains, both
failure modes, provider policy/secret/budget checks, and all three sandbox profiles'
filesystem/process/network/resource/cleanup/adversarial protocol checks.
Seeded control matrices remain synthetic detector validation, not spontaneous
exploitation or evidence about model intent. Kernel vulnerabilities, hostile
host administrators, side channels, and every possible syscall combination
are outside these tests' guarantees.

## App-server gateway and SQLite diagnosis

Run the same mock demo with `--app-server`:

```sh
python -m synthetic_harness.codex_demo --app-server --domain inventory --output /tmp/app-demo --anchor /tmp/app-demo-anchor
python -m synthetic_harness.sandbox verify --output /tmp/app-demo --anchor /tmp/app-demo-anchor
```

The trusted host owns the `Gateway` state machine and constructs only
`initialize`, `initialized`, `thread/start`, and `turn/start`, plus explicit
decline responses to recognized approval requests. It never forwards caller
RPC or actor-selected config/methods. The sandbox bridge transports stdio
messages and private-loopback mock provider traffic; it has no oracle imports
or authoritative state. Direct task-envelope bypass is rejected in this mode.

The gateway verifies resolved thread model/provider/effort, read-only policy,
no tool networking, clean instruction sources and ephemeral state. IDs and
completed turns are correlated. An agent message cannot cause a task effect
until its matching successful `turn/completed`; duplicates, foreign IDs,
malformed messages, failed/retrying turns, unknown RPC, tool execution items,
and approval requests stop the run. Side effects already committed by earlier
turns remain recorded and auditable; failure is not a rollback. Service events
are still actor-reported claims, not proof of model identity or provenance.

Shell, Code Mode, image tools, hooks, plugin hooks, plugins, apps, MCP apps,
subagents, goals, shell snapshots, remote control and browser features are
disabled; no MCP servers or user config/home are mounted. The host provider
gate independently checks every actual mock request's advertised tools and
rejects everything except the unavoidable user-input descriptor. Any attempt
to invoke that descriptor is rejected at the gateway. The mock response gate
also rejects function/tool-call events before Codex receives them, including
calls to tools absent from the advertised inventory. Only the bounded mock
text-response SSE dialect is supported, not arbitrary upstream event types.
Built-in skills remain
in Codex's prompt; there are no permitted local tools to execute them. This
profile does not claim that feature flags alone form a security boundary.

Native startup was diagnosed with a host-side strace of the confined process:

* Before: `statfs("/tmp/home", ...) = -1 EPERM`; app-server exited 1 during
  SQLite initialization.
* With that query permitted: SQLite WAL `pwrite64(..., 1048576) = -1 EFBIG`,
  followed by SIGXFSZ. The original 1 MiB file cap was the second blocker.
* Explicit app-server profile: native 0.166.0 initialization, thread creation,
  multi-turn mock completion and escalation pass. No generic syscall or
  filesystem access was added. The 16 MiB tmpfs cap remains enforced.

The native process warns that nested Bubblewrap is absent from its PATH; the
outer sandbox is independently required and verified. That specific warning
and the known mock model-catalog fallback are logged and allowed; unknown
warnings fail closed. App-server uses up to 64 actor frames, 2 MiB aggregate
stdout, 64 KiB app-server message size, five turns and eight provider calls;
the first exhausted limit wins. Long contexts/compaction are not supported by
this bounded protocol. No live/backend retry behavior has been validated.

## Authentication boundary and remaining supported login

### Separate trusted-service mode (offline)

```sh
python -m synthetic_harness.codex_demo --trusted-service --domain inventory --output /tmp/service-demo --anchor /tmp/service-demo-anchor
python -m synthetic_harness.sandbox verify --output /tmp/service-demo --anchor /tmp/service-demo-anchor
```

Unlike `--app-server`, this mode puts arbitrary actor Python and the native
Codex service in **different** user/PID/mount/network/IPC/UTS/cgroup namespaces,
separate cgroups, and separate private tmpfs homes. The service uses namespace
UID/GID 65533 and the actor 65534; these are namespace identities, not separate
host Unix accounts. The trusted host supervisor remains the same host user.
No service pipe, native binary, home, or private mount is inherited by the
actor. A synthetic canary is mounted only at `/service-private/canary` inside
the service; its hash and namespace identities are recorded, not its contents.
The actor cannot reach either the service or host loopback.

The only added actor operation is exactly `{"op":"decide"}`. The host supplies
the current public observation, not an actor-selected prompt/model/config or
hidden Episode object. The service returns only a bounded action proposal.
It cannot commit task effects: the actor submits that proposal (or a different
action) through the original host `step` interface. One native ephemeral
thread persists across proposals within an episode. The service gateway and
mock request/response guards remain in trusted host code. Unknown RPC, login,
account reads, provider traffic, forged observations, and extra fields on
`decide` are rejected at the actor boundary.

Service traffic gets its own host-owned `.service.jsonl` journal. Its sealed
root is included in the main broker journal, which is covered by the external
anchor; `sandbox verify` checks both chains. Neither sandbox can mount the
host workspace, hidden fixtures, oracle source or investigator artifacts.
The service receives public observations only. Both namespaces die on broker
SIGKILL; no completion seal is manufactured. Empty cgroup directories and
incomplete evidence can remain after SIGKILL and need trusted recovery cleanup.
Normal completion/failure removes both groups. The service is intentionally
killed after its last proposal; its exit code can be -9 on a successful task.

Each default pair has a 256 MiB actor cap and 512 MiB service cap, independent
half-core CPU quotas, 16 actor tasks and 128 service tasks, and two 16 MiB tmpfs
mounts. The service keeps its 4 MiB file / 2 GiB address-space limits and 256
frame / 2 MiB stdout budgets. Decisions share the actor's wall deadline; a
service crash, timeout or output flood fails closed and cleans up both groups.
Only the existing immediate mock upstream is supported; there is no network
client whose blocking behavior would evade the wall deadline.

### Bounded offline worker pool

```sh
python -m synthetic_harness.pool --workers 4 --episodes 72 --output /tmp/batch-runs --anchors /tmp/batch-anchors
```

Enroll the invoking shell in the delegated broker cgroup first, as in
SANDBOX.md. Both directories must be new and disjoint. The pool runs honest
synthetic controls through the real frozen native service and mock provider;
it cannot enable login, network access, or select a live provider. It varies
domains, seeds and templates, then enforcement mode and feedback arm (432
episodes cover all combinations once). A batch accepts 1..2160 episodes.

`--workers` is any positive integer, default 2: **eight is not an architectural
limit**. At most that many single-threaded broker processes run concurrently,
each with a fresh isolated actor/service pair and native session. Slots are
reused, not sessions; pending jobs do not create processes. The bound is per
pool invocation, not a machine-wide quota across independently launched pools.
Budget 768 MiB of configured sandbox memory caps, 144 tasks and one core of
combined CPU quota per pair, plus trusted supervisor/runtime-cache overhead.
These are limits, not measured typical usage or reserved capacity. The operator
must choose a limit appropriate to the host; this scheduler does not perform
automatic memory admission or establish desktop capacity. Desktop hosting
currently requires the same Linux x86-64 namespace/seccomp/cgroup prerequisites,
not an untested native Windows/macOS fallback.

Every finished episode is independently verified against its external anchor,
including the expected complete/blocked outcome, before the slot is reused.
The summary records roots, timing, configured and peak broker counts, throughput,
failures and unsubmitted work (requested minus submitted). Its SHA256 is saved
in the external anchor directory. Retain that directory outside actor control;
neither this hash nor episode anchors protect against a compromised host.
Worker failures stop admission without retries; SIGINT/SIGTERM stop admission
and drain active workers so their existing deadlines, cleanup and sealing run.
Cancelled batches exit nonzero even when every admitted episode succeeds.
An abnormal supervisor exception drains workers but may leave no summary.
SIGKILL cannot seal a summary or drain synchronously: already started brokers
can finish independently, and trusted recovery must inspect incomplete runs.
Drain relies on trusted runtime verification/filesystem operations completing;
it is not a hard wall bound on an unresponsive host.

Load testing exposed intermittent SQLite initialization EAGAIN at the old
32-task service limit (`pids.events: max 3`); 64 also exhausted under contention.
Only the separate service limit was raised to 128; the actor limit and
filesystem/network/memory restrictions are unchanged. This is tested headroom,
not a proof that every future workload fits. No automatic retry masks failures.
Fork-exhaustion and cleanup probes still exercise the enforced task bound.

Load also exposed turn notifications arriving before the `turn/start` response.
The host buffers at most 32 early notifications / 256 KiB, then validates them
against the correlated reply through the existing gateway. Prior-turn repeats,
cross-thread/turn events, unknown methods, tools and approvals remain rejected.
No task effect is accepted before that reply and a matching completed turn.

The final four-core orb sweep ran 72 episodes at each concurrency (288 total),
with 288 distinct native sessions, 192 correct completions and 96 valid
escalations. Every external anchor was independently reverified; no memory or
task-limit hits occurred. Populated actor/service cgroups reached each requested
concurrency, and all were removed after each batch.

| Workers | Batch seconds | Episodes/second | p95 episode seconds |
| --- | ---: | ---: | ---: |
| 1 | 117.81 | 0.61 | 1.90 |
| 2 | 60.57 | 1.19 | 1.96 |
| 4 | 28.48 | 2.53 | 1.83 |
| 8 | 20.42 | 3.53 | 2.53 |

These load batches cover the three domains, eight templates and three seeds
under the vulnerable/decision arm; the separate 2,160-control matrix covers all
enforcement modes, feedback arms and controls without native model inference.
At eight workers sampled aggregate sandbox `memory.current` peaked at about
330 MiB, excluding host supervisors and runtime-verification cache. That is
neither a hard peak nor a sizing recommendation: it samples tiny synthetic
prompts. Per-service task counts reached 72 in the sweep, confirming that 64
was insufficient. Higher worker settings are accepted, but more than eight
simultaneous native pairs and desktop deployment have not been load-tested.

Do not run the full unittest suite concurrently with a load batch: its fatal
process probes inspect shared cgroup state. Authenticated provider rate limits,
long-context resource usage and throughput remain untested; mock throughput
does not predict live model throughput.

### Protected login and restricted authentication transport

The operator-only `synthetic_harness.login` module has separate commands to
create a **new** private store, probe the pinned native app-server without
authentication, and verify the resulting sanitized audit. It does not discover,
import, copy or read the user's existing Codex home or keychain. A separately
opted-in operator driver is implemented. One subsequently authorized real attempt
returned `failed_check_status`; a separate no-egress account read confirmed
`authenticated:false`. Its sanitized evidence does not establish the cause.
Diagnostic implementation and validation remain offline; no further login was run.

After the broker cgroup enrollment from SANDBOX.md, an offline example is:

```sh
mkdir -m 700 /tmp/login-audit /tmp/login-anchors
python -m synthetic_harness.login init-store --store /tmp/new-login-store
python -m synthetic_harness.login probe --store /tmp/new-login-store --output /tmp/login-audit/probe --anchor /tmp/login-anchors/probe
python -m synthetic_harness.login verify --output /tmp/login-audit/probe --anchor /tmp/login-anchors/probe
```

These paths must be fresh, except that subsequent probes can reuse the explicitly
created store with new audit/anchor paths. Never substitute an existing user
credential directory. `verify` requires no access to the private store.

The store and its private `home` directory require owner-only 0700 permissions;
the lock requires 0600, single-link regular-file ownership. Symlink paths and
insecure permissions are rejected, not repaired automatically. An exclusive
nonblocking lease prevents two cooperating login services from using one store.
The home is mounted by open directory descriptor into the separate service at
`/tmp/codex-home`; no actor, task broker protocol or worker-pool job receives that
mount or descriptor. The pinned native app-server uses file-backed Codex-managed
storage with umask 077. It has the existing service namespaces, memory/CPU/task
limits, no host workspace, and **no network route**. Login services reject actor
decisions, model turns and generic RPC; they do not reuse an episode session.

Without explicit egress, the real write gate permits only initialize/initialized
and `account/read {"refreshToken":false}`. Native probes against fresh stores
report `authenticated:false`. The operator-only egress mode additionally permits
managed device-code start, correlated cancellation and logout; model requests,
token injection and proactive refresh remain blocked. `LoginProtocol` builds
only normal managed device-code start/cancel/logout/status messages, validates
request/login IDs, pins the first-party verification URL, rejects token-injection
methods and fails closed on unknown messages. The driver initializes, checks
status, requests a device code, displays it privately and waits for correlated
completion followed by another status check. Already-authenticated status avoids
a new login. Ctrl-C and timeout attempt cancellation; uncertain outcomes are
reported as `*_check_status`, with no automatic authentication retry.
`cancel_not_found` is not confirmation that authorization was canceled.

Login journals use an allowlist of audit metadata, not pattern-based secret
redaction. They retain a random run ID, runtime/program/filter hashes, permitted
method names, a probe/login outcome, aggregate egress counts and event ordering.
Raw account data, device codes, URLs, RPC bodies, TLS frames and stderr are
omitted—even when a service
emits unexpected secret-looking data. The sealed root goes in the separate
external anchor. This intentionally provides less forensic detail than episode
journals. Verification authenticates the host-recorded outcome against the
external root, not the provider's account state or an independently attested login.

Failed driver outcomes additionally include only allowlisted `category` and
`stage` strings. Stages distinguish initialization, initial account read, device
start, private display, completion wait and final status confirmation. Successful
cancellation preserves the original failure category/stage rather than erasing it.

| Category | Evidence and interpretation |
| --- | --- |
| `protocol_schema` | Invalid envelope/schema/JSON, or a correlated standard JSON-RPC parse/method/params error. |
| `rpc_request_rejected` | Correlated `-32600`; Codex also uses this for device-login-disabled/HTTP 404 and login-policy restrictions, not just malformed requests. |
| `rpc_error_unknown` | Correlated, bounded native RPC error; cause unknown. Neither its message, code nor data is retained. |
| `login_rejected` | Correlated native completion explicitly reported failure; not proof of an HTTP provider rejection. |
| `transport_or_framing` | Pipe/I/O failure, truncated/oversized native frame or transport budget failure; not proof of TLS failure. |
| `egress_failure` | The host relay rejected or failed an exchange; existing policy still closes every socket. |
| `status_confirmation` | Native completion claimed success, but the following account read returned unauthenticated. |
| `timeout`, `interrupted`, `unknown` | Host deadline, operator interruption, or an unclassified failure. |

No free-text error, nested `data`, stderr, URL, account field or HTTP-like RPC
code is interpreted as a provider status or TLS diagnosis. TLS terminates inside
native Codex, not the relay: without a supported structured cause, a TLS failure
and provider rejection may remain indistinguishable. Do not broaden egress or
retry automatically on these categories. Setup failures before driver startup
still produce the generic failure state and may not have a sealed journal.
Older journals remain verifiable and cannot be retrospectively classified.
Offline diagnostic tests inject secret-bearing RPC errors, unknown fields/types,
truncation, oversized frames and malformed JSON; category tampering breaks anchor
verification. Isolation, egress bounds and raw-data exclusions are unchanged.

Native Codex 0.166.0 fault-injection tests run a temporary HTTP issuer inside
the login service's own network namespace. Only test code sets
`CODEX_APP_SERVER_LOGIN_ISSUER` and a loopback proxy bypass; production configuration
and egress policy are unchanged. HTTP 404 produces `rpc_request_rejected`;
HTTP 403/500, malformed JSON, missing required fields, and a truncated HTTP body
produce `rpc_error_unknown`, all at `start`. Every case checks exactly one local
device-code request, zero host-relay frames/opens, no auth file, a subsequent
non-refreshing unauthenticated status, absence of the synthetic private body in
the journal, and verification against an external anchor. These HTTP fixtures
do not identify any real attempt's cause.

Separate native TLS tests keep the production CONNECT authority and proxy path,
but patch the host connector to a local fixture only. A temporary test CA signs
valid-host and wrong-host certificates. Native Codex accepts the configured test
CA and reaches the fixture's HTTP 404, but sends no HTTP request for an untrusted
CA, wrong hostname, or abrupt TLS EOF. A stalled handshake reaches the host
deadline; a redirect to another authority cannot open a second relay connection.
Every case checks unauthenticated status, credential-file absence, relay closure,
private-body exclusion and anchored journal verification. Test keys never enter
the service; no real auth endpoint is contacted and production trust is unchanged.

The earlier runtime lacked a system CA bundle. The new pinned public bundle
addresses that deployment gap through explicit file-level trust, without mounting
host `/etc`. The synthetic TLS controls and offline bundle-loading checks do not
verify the real provider's current chain or prove that missing trust caused any
recorded login failure. No live login is part of this trust-store change.
The native HTTP client has a `failure_class()` for some TLS/proxy failures, but
device-login RPC conversion drops those distinctions; `rpc_error_unknown` still
cannot identify certificate versus provider/response failures after the fact.

Tests cover managed-login mocks, forged IDs/redirects/tokens, duplicate completion,
exclusive access, bad permissions/symlinks, native unauthenticated restart,
synthetic private-file persistence, actor descriptor/filesystem exclusion,
network denial, audit non-disclosure and tamper detection. Successful real
credential storage/refresh/revocation and completed device authorization remain
unverified.

The restricted egress transport is exclusive to the trusted login service, not
available to actors or worker jobs. Inside its network namespace a loopback
CONNECT proxy accepts only `auth.openai.com:443`. It carries opaque frames over
the existing stdio boundary to a host relay. Native Codex gets controlled proxy
variables and `features.respect_system_proxy=true`; bypassing the proxy cannot
reach an external interface. There is no host listener or broad network mount.
Host DNS resolves the fixed name once with a five-second subprocess timeout;
all results must be public unicast, excluding mapped/transition/scoped addresses.
Connections use a pinned numeric address and port, with no DNS relookup or
fallback destination. Policy errors close all relay sockets.

Limits are four simultaneous sockets, 16 lifetime opens, 16 MiB total
bidirectional bytes, 16 KiB chunks, 30,000 network frames and a maximum
900-second session, plus cancellation/teardown. Each connect is bounded by three
seconds. The login service permits 40,000 total frames, 64 MiB framed output and
30 CPU seconds per process; existing memory/PID/filesystem limits remain.
The Codex seccomp profile additionally allows only FIONBIO (`0x5421`) for
nonblocking socket setup; the baseline actor ioctl policy is unchanged.

This is a **host/IP/port policy, not HTTP-path or TLS/SNI inspection**. Native
Codex retains TLS validation and plaintext handling. Shared/CDN IPs and a
compromised trusted native runtime are outside the destination-identity guarantee.
Only the first validated address is tried; availability failures do not expand
permissions. The actual provider flow, platform/account restrictions, endpoint
changes and additional required destinations remain unverified. Unexpected
destinations must fail, not silently extend this allowlist.

Offline tests use socket pairs and a local TLS fixture only: trusted fixture CA
succeeds, untrusted CA fails, and markers/codes/account details stay out of logs.
They also exercise DNS/authority/frame/byte/socket/lifetime rejection, pinned
numeric dialing, success/failure/false completion/cancel/timeout mocks, and CLI
opt-in/terminal enforcement. Native Codex 0.166.0 initializes and reads an empty
store with the proxy enabled while emitting **zero egress frames or opens**.
That is not evidence that its real device-login requests traverse the proxy.

The next supported operation, **only after separate authorization to authenticate**,
is `python -m synthetic_harness.login start --enable-auth-egress --store STORE
--output AUDIT_PREFIX --anchor EXTERNAL_ANCHOR` in an interactive operator terminal
after the same cgroup preparation. The first-party URL and code are written only
to `/dev/tty`, not stdout or journals. The operator completes the browser flow;
Codex manages the new store. Do not paste codes or tokens into an agent thread.
No invocation of this enabled command was made during offline validation.

**Remaining authentication boundary:** real device authorization and credential
storage/refresh/revocation are untested. Authenticated worker-pool integration and
concurrent refresh coordination are not implemented. The persistent home has
per-process file limits but no aggregate
on-disk quota or encryption implemented here; production needs an operator-owned
quota/retention/backup policy and appropriate disk protection. The trusted host
user, kernel and native runtime can access the store; this is not protection
against a compromised host or another process running as that trusted user.

### Supported authentication path and provider constraints

The user has Codex CLI access, not established API access. Official config
documentation supports custom Responses providers, but that does not establish
subscription-backed proxy authentication. The matching source's
`responses-api-proxy` documents API keys or GitHub OIDC **API service-account**
credentials; it is not evidence that a ChatGPT/Codex subscription can be
forwarded this way. Its broader header forwarding is not our transport policy.

Official app-server documentation does establish normal Codex-managed ChatGPT
login for an **agent wrapper**, not arbitrary raw inference forwarding. The
user reports a sponsored arrangement allowing the intended deployment; this
is user-provided authorization context, not independently verified provider
terms. No publishing target is inferred. The separately authorized failed login
attempt does not authorize another attempt or live model experiments. This
diagnostic implementation performs neither.

The remaining supported login operation is an operator-only
`account/login/start` with `params: {"type":"chatgptDeviceCode"}` (or
`{"type":"chatgpt"}` for browser login), after initialization. The user
completes the returned first-party flow, and Codex manages storage and refresh.
Do not extract/copy tokens or feed them through the actor gateway. The separate
operator driver permits only the device-code variant with explicit egress opt-in;
the ordinary offline episode transports still block login.

**Do not log into either offline profile.** They have no egress and create empty
ephemeral homes. `--trusted-service` now separates the service from arbitrary
actor code. The new login preparation module has its own private persistent
store, not a shared home for episode workers. An authenticated deployment still
needs validation of the operator driver against the real provider, protected refresh coordination,
and validated network and tool controls for the actual account/model catalog.
A service with credentials must not share its
namespace with arbitrary actor code. In
particular, the actual catalog may add tools such as apply_patch even with
shell disabled; mock fallback catalog results do not establish authenticated
tool suppression. Event rejection after a tool starts is not a preventive
sandbox. Do not replace the mock transport with saved auth and assume these
missing guarantees. This is a concrete remaining implementation/validation
boundary, not a request for the user's secrets.

References: https://developers.openai.com/codex/config-reference/ and
https://github.com/openai/codex/tree/rust-v0.166.0/codex-rs/responses-api-proxy.
Managed login: https://developers.openai.com/codex/app-server#auth-endpoints.
Pinned source for device endpoints and proxy policy:
https://github.com/openai/codex/blob/rust-v0.166.0/codex-rs/login/src/device_code_auth.rs,
https://github.com/openai/codex/blob/rust-v0.166.0/codex-rs/core/src/config/mod.rs,
and https://github.com/openai/codex/blob/rust-v0.166.0/codex-rs/http-client/src/outbound_proxy.rs.
