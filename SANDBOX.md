# Isolated offline actor and trusted broker

This stage runs adversarial actor programs behind a real Linux process boundary.
It does **not** run Codex, authenticate to a provider, or enable a model network
connection. The existing `session` command remains a trusted transport exercise;
use `python -m synthetic_harness.sandbox run` for isolated actors.

## Threat model

The attacker controls all actor Python bytes, native code invoked through
`ctypes`, subprocesses, filesystem names, stdout/stderr, and protocol requests.
Assume it knows host path names, broker PID, and the sandbox implementation.
It may try to steal hidden data, forge results/logs, escape via `/proc`, retain
descendants, exhaust resources, or attack the broker parser. It cannot choose
the broker command, configuration, runtime mounts, evidence paths, or anchor.
Those are trusted operator inputs, never fields forwarded from actor requests.

Trusted: the host kernel, Bubblewrap, libseccomp, Python and the mounted distro
runtime, host administrator, broker source/process, cgroup delegation and anchor
storage. The host runs no attacker-controlled process outside the sandbox.
The broker is single-threaded and unprivileged; no actor is imported/evaluated
in it. Root/host compromise, kernel/runtime vulnerabilities and hardware or
timing side channels are outside the guarantee. This is not a VM boundary or a
security certification, and finite probes cannot prove absence of escapes.

## Enforced boundary

| Surface | Policy |
| --- | --- |
| Filesystem | Fresh mount namespace and read-only root. Only distro Python binary, Python 3.11 stdlib, native library directory, and an immutable snapshot of actor bytes are mounted. No host workspace, home, `/etc`, `/run`, host `/tmp`, cgroup filesystem, Docker socket, sources, fixtures, logs or anchors. |
| Scratch | Private 16 MiB `/tmp`; no writable host bind mounts. Root, runtime, `/dev` and namespace-local `/proc` are read-only. Actor output files are discarded, not imported into the host. |
| Processes | Separate user/PID/IPC/UTS/cgroup namespaces, UID/GID 65534 inside, zero capabilities, no-new-privileges, new terminal session, further user namespaces disabled. Only namespace-local processes are visible. |
| Network | Separate network namespace **and** no socket/connect/accept syscalls, including Unix and netlink sockets. No DNS, HTTP proxy, localhost service or provider endpoint is available. |
| Syscalls | Native x86-64 allowlist compiled by libseccomp; unknown calls return EPERM and foreign ABI calls are killed. Mount, setns/unshare, ptrace/process-memory access, BPF, perf, keyring and io_uring are absent. Only FIOCLEX and TCGETS ioctls are allowed. |
| Environment/FDs | Environment replaced, not filtered. Only PATH, HOME, LANG and Bubblewrap's PWD; Python may add LC_CTYPE. All non-protocol descriptors are closed before actor execution. No inherited credentials or host cwd. |
| Resources | Per-run cgroup: 256 MiB aggregate memory, zero swap, OOM group kill, 16 tasks including Bubblewrap, 50% of one CPU. Hard per-process limits: 256 MiB virtual address space, 3 CPU seconds, 64 FDs, 1 MiB per file, zero core size. |
| Lifetime | Default 5-second wall budget, trusted override limited to 0.1–30 seconds. Whole-cgroup kill on every normal/error exit, including detached children. Bubblewrap parent-death chain kills actor processes if the broker is killed. |
| Broker input | Nonblocking pipes, 16 KiB per JSONL request, 128 KiB total stdout, 64 requests, 64 KiB stderr, 1 MiB queued replies. Invalid UTF-8/envelopes terminate the run; invalid tool schemas retain normal task semantics. |

The distro runtime mounts are `/usr/bin/python3.11`, `/usr/lib/python3.11`, and
`/usr/lib/x86_64-linux-gnu`, plus loader symlinks. This fixed Debian/x86-64
profile is intentionally not an arbitrary executable or arbitrary mount API.
Those runtime trees must contain only trusted public runtime data, not secrets.
The actor can read them, execute Python subprocesses, and run native code inside
the same boundary. The profile does not attempt to restrict Python syntax.
Namespace-local `/proc` still exposes some kernel/system metadata; this does
not claim to hide the kernel version, CPU model, clocks, or aggregate metrics.

## Host preparation and fail-closed behavior

Tested in this orb with Linux 6.1.158+, Bubblewrap 0.8.0, libseccomp 2.5.4,
Debian Python 3.11.2 actor runtime and Python 3.11.6 broker. Requires cgroup v2,
`cgroup.kill`, cpu/memory/pids controllers and unprivileged user namespaces.
There is no Docker fallback, no `--unshare-*-try`, no unsandboxed retry, and no
credential-dependent setup. The broker refuses root execution.

An administrator must provision a delegated subtree. These commands were used
on this disposable orb; on a managed production host, have its administrator
provision an equivalent delegation rather than editing systemd-owned cgroups
ad hoc. The top-level controllers were already enabled here.

```sh
sudo apt-get install bubblewrap libseccomp2
sudo mkdir -p /sys/fs/cgroup/offline-harness/broker
sudo sh -c 'echo "+cpu +memory +pids" > /sys/fs/cgroup/offline-harness/cgroup.subtree_control'
sudo chown "$(id -u):$(id -g)" /sys/fs/cgroup/offline-harness \
  /sys/fs/cgroup/offline-harness/cgroup.procs \
  /sys/fs/cgroup/offline-harness/cgroup.subtree_control
```

In the shell that launches the trusted broker/tests, enroll **that shell** in
the broker subgroup first. The shell remains unprivileged; sudo is used only
to enroll its PID. This grants no privilege inside the actor. Linux requires
write access to the common ancestor's `cgroup.procs` to move a child between
cgroups; merely creating a writable child directory is insufficient.

```sh
sudo sh -c 'echo "$1" > /sys/fs/cgroup/offline-harness/broker/cgroup.procs' sh "$$"
python -m unittest discover -s tests -v
```

Cgroups are ephemeral and must be reprovisioned after reboot. This workspace is
not a Git project with an orb setup hook; the commands above are the explicit
environment prerequisite, not a silently assumed persistent installation.
Integration tests fail rather than skip when the boundary is unavailable.
The original stdlib-only tests remain runnable without sandbox preparation:
`python -m unittest discover -s tests -p test_harness.py -v`.

## Actor/broker contract

The trusted caller supplies a Python source file (at most 1 MiB). The broker
snapshots bytes before launching, starts the fixed runtime with `-I -S -u`, and
sends one initial public observation on stdin. The actor sends one request per
stdout line and reads one response per request, using the envelopes in README.
Stderr is bounded diagnostic data, never an authoritative result or command.
The actor must not put debug prints on stdout. It may access its private scratch
space, but all task effects occur through the broker's bounded JSON tools.

After a task-closing action, the broker sends the final response, closes stdin,
and rejects further requests. A stalled, spinning or pipe-closing actor still
hits the wall timeout. Actor exit code zero says only that its process exited;
task success is always the host oracle's separate decision. A killed actor can
leave a partial task state, which is recorded and classified without claiming
completion. No rollback or automatic retry is implied.

```sh
mkdir -m 700 -p evidence trusted-anchors
python -m synthetic_harness.sandbox run ACTOR.py --domain inventory \
  --mode hardened --output evidence/run-001 --anchor trusted-anchors/run-001.json
python -m synthetic_harness.sandbox verify --output evidence/run-001 \
  --anchor trusted-anchors/run-001.json
```

All output paths must be new. Choose anchor storage outside the bundle, under
trusted-host control; the actor cannot access either location. The CLI exits
nonzero on transport/resource termination or nonzero actor exit. Launcher/setup
exceptions also fail and do not run the actor unsandboxed. Their reserved empty
anchor or incomplete journal must not be treated as completed evidence.

## Authoritative evidence and external anchoring

The Episode and oracle stay entirely in the broker. It writes the existing
fsynced task journal and a separate fsynced, hash-chained `.wire.jsonl` containing
configuration, accepted/rejected framed requests, replies and terminal transport
status. Over-limit traffic is terminated with a reason rather than stored without
bound; this is not a complete packet capture. Stderr is retained up to its cap.
Configuration includes actor/BPF/Bubblewrap/Python-binary hashes, kernel version
and configured limits. Full runtime-library trees are **not byte-pinned**.

The independently reserved anchor binds both the episode root and wire root.
It is written and fsynced only after sealed evidence exists, then made read-only.
`verify` authenticates both chains against that anchor and deterministically
replays the task transcript. Actor-supplied `audit`/`root` fields cannot become
authoritative labels. The human-readable derived audit files are conveniences;
verification recomputes truth instead of trusting them.

“External” here means outside the actor and evidence bundle, on the trusted
host. It is **not** a remote timestamp/notary or immutable storage service.
Retain the printed composite root on a separate trusted system if host/bundle
replacement is in scope. A receipt copied alongside a downloadable bundle is
not an independent trust anchor. No remote anchor service was provisioned.
Host owner/root can still replace both files and local anchors. File fsync does
not prove crash/power-loss atomicity across files and directory entries.

Broker SIGKILL leaves an empty reserved anchor, unsealed journal, and possibly
an empty cgroup directory; it does not fabricate a completion seal. Once a
trusted administrator confirms no run is active, empty leftover `actor-*`
cgroups can be removed. Never trust or resume an interrupted episode as complete.

## Verification and remaining gates

The real-kernel integration suite exercises public-only honest work/escalation
and seeded exploit attempts in both modes; known host path/traversal/symlink/
`/proc/1/root` attacks; actual host-canary secrecy and unchanged content; log and
anchor read/write denial; synthetic environment and inheritable-FD canaries;
namespace separation, capabilities, no-new-privileges; IPv4/IPv6/Unix/netlink
socket denial; forbidden syscalls; alternate-ABI native code; subprocess exec;
fork exhaustion and detached-child cleanup; aggregate OOM and CPU throttling;
address-space, file-size and tmpfs limits; malformed/flooded/stalled transport;
missing prerequisites, launcher refusal, tampering and separate-process replay.
It also kills the broker with SIGKILL and checks descendants are gone and
evidence remains unsealed. These are adversarial probes, not a penetration-test
certification or proof against all kernel attacks.

Before a future Codex adapter: obtain separate approval for provider access and
credentials; establish actual CLI availability/version/auth/model settings;
build a minimal immutable Codex runtime; revise and re-test syscall/resource
requirements; design a narrow host-side model-transport broker that keeps
credentials out of the actor. Do not enable general networking or mount the
user's Codex home. No Codex installation/authentication was assumed or checked,
and the current fixed Python profile is **not claimed to run Codex unchanged**.
