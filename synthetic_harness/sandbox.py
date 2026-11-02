"""Linux-only offline actor sandbox. No credentials, network, or model transport.

The trusted broker must be single-threaded and run as an unprivileged user.
See SANDBOX.md for the fixed runtime, prerequisites and threat model.
"""

import argparse
import ctypes
import errno
import hashlib
import json
import os
import platform
import resource
import selectors
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from .protocol import exchange, parse_request
from .runner import Episode, EventLog, audit
from .tasks import ARMS, DOMAINS, MODES, canonical, digest, make_case

BWRAP = Path("/usr/bin/bwrap")
PYTHON = Path("/usr/bin/python3.11")
CGROUP = Path("/sys/fs/cgroup/offline-harness")
MEMORY = 256 * 1024 * 1024
PIDS = 16
TMP_BYTES = 16 * 1024 * 1024
FILE_BYTES = 1024 * 1024
MAX_WIRE = 128 * 1024
MAX_STDERR = 64 * 1024
MAX_REQUESTS = 64
CODEX_MEMORY = 512 * 1024 * 1024
CODEX_ADDRESS_SPACE = 2 * 1024 * 1024 * 1024
CODEX_PIDS = 32

# Native x86-64 only. Unknown syscalls return EPERM; other architectures are
# killed by libseccomp's default bad-architecture action. No sockets, ptrace,
# process_vm_*, keyring, bpf, perf, io_uring, mount, setns, unshare or prctl.
SYSCALLS = """
read write readv writev close close_range lseek pread64 pwrite64
openat newfstatat fstat stat lstat statx access faccessat faccessat2
readlink readlinkat getdents64 getcwd chdir fchdir
mkdir mkdirat rmdir unlink unlinkat rename renameat renameat2
link linkat symlink symlinkat chmod fchmod fchmodat umask
truncate ftruncate fsync fdatasync
mmap mprotect munmap mremap madvise brk
rt_sigaction rt_sigprocmask rt_sigreturn sigaltstack rt_sigsuspend
rt_sigtimedwait kill tgkill tkill
futex set_tid_address set_robust_list rseq
getpid getppid gettid getuid geteuid getgid getegid getgroups
getpgrp getpgid getsid setsid setpgid
arch_prctl uname getrandom getrlimit prlimit64 getrusage
clock_gettime clock_nanosleep nanosleep gettimeofday time times
sched_yield sched_getaffinity sched_getparam sched_getscheduler
dup dup2 dup3 fcntl pipe pipe2 poll ppoll select pselect6
epoll_create1 epoll_ctl epoll_wait epoll_pwait eventfd2
fork vfork clone clone3 execve execveat wait4 waitid
exit exit_group restart_syscall
""".split()


def seccomp_filter(stream, codex=False, app_server=False):
    """Compile the fixed native syscall allowlist; fail on unavailable rules."""
    lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    class Argument(ctypes.Structure):
        _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int),
                    ("a", ctypes.c_uint64), ("b", ctypes.c_uint64)]

    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
        ctypes.c_int, ctypes.c_uint, ctypes.POINTER(Argument)]
    context = lib.seccomp_init(0x00050000 | errno.EPERM)
    if not context:
        raise RuntimeError("Cannot initialize seccomp")
    try:
        for name in SYSCALLS:
            number = lib.seccomp_syscall_resolve_name(name.encode("ascii"))
            if number < 0 or lib.seccomp_rule_add(context, 0x7FFF0000, number, 0) != 0:
                raise RuntimeError(f"Cannot allow syscall {name}")
        # CPython's fopen uses FIOCLEX; isatty uses TCGETS. Do not allow
        # arbitrary device ioctls (in particular TIOCSTI terminal injection).
        # The Codex relay also needs FIONBIO for bounded socket timeouts.
        for request in ((0x5451, 0x5401, 0x5421) if codex else (0x5451, 0x5401)):
            comparison = Argument(1, 4, request, 0)  # SCMP_CMP_EQ
            if lib.seccomp_rule_add_array(context, 0x7FFF0000,
                    lib.seccomp_syscall_resolve_name(b"ioctl"), 1, ctypes.byref(comparison)) != 0:
                raise RuntimeError("Cannot restrict ioctl")
        if codex:
            # SQLite checks filesystem type before choosing its journal mode.
            # These queries expose only the already-confined mount namespace.
            names = ("connect bind listen accept accept4 shutdown getsockopt setsockopt "
                     "getsockname getpeername sendto recvfrom sendmsg recvmsg flock setrlimit open").split()
            if app_server:
                names += ["statfs", "fstatfs"]
            for name in names:
                number = lib.seccomp_syscall_resolve_name(name.encode())
                if number < 0 or lib.seccomp_rule_add(context, 0x7FFF0000, number, 0) != 0:
                    raise RuntimeError(f"Cannot allow Codex syscall {name}")
            # IPv4 TCP only, in the isolated network namespace. No UDP/DNS,
            # Unix path sockets, netlink, or raw sockets. No route to the host.
            comparisons = (Argument * 2)(Argument(0, 4, 2, 0), Argument(1, 7, 15, 1))
            if lib.seccomp_rule_add_array(context, 0x7FFF0000,
                    lib.seccomp_syscall_resolve_name(b"socket"), 2, comparisons) != 0:
                raise RuntimeError("Cannot restrict socket")
            # Tokio's signal driver needs an anonymous Unix socket pair. This
            # cannot connect to a pathname, abstract socket, or host service.
            comparisons = (Argument * 2)(Argument(0, 4, 1, 0), Argument(1, 7, 15, 1))
            if lib.seccomp_rule_add_array(context, 0x7FFF0000,
                    lib.seccomp_syscall_resolve_name(b"socketpair"), 2, comparisons) != 0:
                raise RuntimeError("Cannot restrict socketpair")
            # Codex's pre-main hardening requires PR_SET_DUMPABLE(0).
            comparisons = (Argument * 2)(Argument(0, 4, 4, 0), Argument(1, 4, 0, 0))
            if lib.seccomp_rule_add_array(context, 0x7FFF0000,
                    lib.seccomp_syscall_resolve_name(b"prctl"), 2, comparisons) != 0:
                raise RuntimeError("Cannot restrict prctl")
        if lib.seccomp_export_bpf(context, stream.fileno()) != 0:
            raise RuntimeError("Cannot export seccomp filter")
    finally:
        lib.seccomp_release(context)
    stream.seek(0)


def command(actor_fd, filter_fd, runtime=None):
    # No broad host /, /home, /etc, /run, /tmp or /usr bind. These three
    # distribution-owned runtime paths are the only host filesystem mounts.
    args = [str(BWRAP), "--unshare-user", "--unshare-pid", "--unshare-net",
            "--unshare-ipc", "--unshare-uts", "--unshare-cgroup",
            "--disable-userns", "--assert-userns-disabled", "--uid", "65534",
            "--gid", "65534", "--cap-drop", "ALL", "--new-session",
            "--die-with-parent", "--hostname", "offline-actor", "--clearenv",
            "--setenv", "PATH", "/usr/bin", "--setenv", "HOME", "/tmp",
            "--setenv", "LANG", "C.UTF-8",
            "--ro-bind", str(PYTHON), str(PYTHON),
            "--ro-bind", "/usr/lib/python3.11", "/usr/lib/python3.11",
            "--ro-bind", "/usr/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
            "--symlink", "usr/lib", "/lib", "--dir", "/lib64",
            "--symlink", "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            "/lib64/ld-linux-x86-64.so.2", "--proc", "/proc",
            "--remount-ro", "/proc", "--dev", "/dev", "--remount-ro", "/dev",
            "--size", str(TMP_BYTES), "--tmpfs", "/tmp",
            "--ro-bind-data", str(actor_fd), "/actor.py", "--chdir", "/tmp",
            "--remount-ro", "/", "--seccomp", str(filter_fd),
            "--", str(PYTHON), "-I", "-S", "-u", "/actor.py"]
    if runtime is not None:
        root = Path(runtime).resolve() / "root"
        for i, value in enumerate(args):
            if value == "--ro-bind":
                args[i + 1] = str(root / args[i + 1].lstrip("/"))
        index = args.index("--symlink")
        args[index:index] = ["--ro-bind", str(root / "opt/codex"), "/opt/codex",
                            "--ro-bind", str(root / "opt/public-ca.pem"), "/opt/public-ca.pem",
                            "--setenv", "CODEX_CA_CERTIFICATE", "/opt/public-ca.pem",
                            "--setenv", "SSL_CERT_FILE", "/opt/public-ca.pem",
                            "--setenv", "TOKIO_WORKER_THREADS", "2"]
    return args


def run(actor, output, anchor, *, domain, template=0, seed=0,
        mode="hardened", arm="decision", timeout=5.0, cgroup_parent=CGROUP,
        runtime=None, provider=None, app_server=False, service=None):
    """Run untrusted Python bytes, never a host command, and save anchored evidence.

    Paths/configuration are trusted operator inputs, not actor requests. The
    external anchor must be outside the bundle directory and reserved first.
    """
    if platform.system() != "Linux" or platform.machine() != "x86_64" or os.geteuid() == 0:
        raise RuntimeError("Requires unprivileged Linux x86-64; no unsafe fallback")
    if threading.active_count() != 1:
        raise RuntimeError("Broker must be single-threaded")
    if not 0.1 <= timeout <= 30:
        raise ValueError("Wall timeout must be 0.1..30 seconds")
    if type(actor) is not bytes or len(actor) > FILE_BYTES:
        raise ValueError("Actor must be at most 1 MiB of bytes")
    runtime_info = None
    if runtime is not None:
        from .codex_runtime import verify as verify_runtime
        runtime_info = verify_runtime(runtime)
    elif provider is not None:
        raise ValueError("Provider transport requires the Codex isolation profile")
    if app_server and runtime is None:
        raise ValueError("App-server requires the frozen Codex runtime")
    file_bytes = 4 * 1024 * 1024 if app_server else FILE_BYTES
    memory = CODEX_MEMORY if runtime is not None else MEMORY
    address_space = CODEX_ADDRESS_SPACE if runtime is not None else MEMORY
    pids = CODEX_PIDS if runtime is not None else PIDS
    output, anchor = Path(output).absolute(), Path(anchor).absolute()
    if service is not None and (provider is not None or not service.started or service.closed
                                or service.output != output):
        raise ValueError("Use a dedicated active service for this episode output")
    if output.exists() or anchor.resolve().is_relative_to(output.resolve()):
        raise ValueError("Use a new bundle and an anchor outside it")
    case = make_case(domain, template, seed)
    # Do not create an Episode (or launch code) until prerequisites are present.
    for path in (BWRAP, PYTHON, Path(cgroup_parent) / "cgroup.controllers"):
        if not path.exists():
            raise RuntimeError(f"Missing sandbox prerequisite: {path}")
    current = Path("/sys/fs/cgroup") / Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1].lstrip("/")
    if not current.is_relative_to(Path(cgroup_parent)) or current == Path(cgroup_parent):
        raise RuntimeError("Enroll the trusted broker in the delegated cgroup subtree first; see SANDBOX.md")
    group = Path(tempfile.mkdtemp(prefix="actor-", dir=cgroup_parent))
    process = None
    episode = wire = None
    anchor_fd = None
    try:
        for key, value in {"memory.max": memory, "memory.swap.max": 0,
                           "memory.oom.group": 1, "pids.max": pids,
                           "cpu.max": "50000 100000"}.items():
            (group / key).write_text(str(value))
            if (group / key).read_text().strip() != str(value):
                raise RuntimeError(f"Cgroup limit not applied: {key}")
        # Require cgroup.kill, rather than relying on process groups that a
        # malicious descendant can escape with setsid().
        if not (group / "cgroup.kill").exists():
            raise RuntimeError("cgroup.kill is required")
        anchor_fd = os.open(anchor, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        episode = Episode(case, mode, arm, output.with_name(output.name + ".journal.jsonl"))
        wire = EventLog(output.with_name(output.name + ".wire.jsonl"))
        with tempfile.TemporaryFile() as program, tempfile.TemporaryFile() as bpf:
            program.write(actor)
            program.seek(0)
            seccomp_filter(bpf, codex=runtime is not None, app_server=app_server)
            filter_hash = hashlib.sha256(bpf.read()).hexdigest()
            bpf.seek(0)
            wire.append("configuration", {"actor_sha256": hashlib.sha256(actor).hexdigest(),
                "filter_sha256": filter_hash, "bwrap_sha256": hashlib.sha256(BWRAP.read_bytes()).hexdigest(),
                "python_sha256": hashlib.sha256(PYTHON.read_bytes()).hexdigest(),
                "runtime": runtime_info, "provider": provider.configuration if provider else None,
                "service": service.configuration if service else None,
                "memory_bytes": memory, "address_space_bytes": address_space,
                "pids": pids, "cpu_max": "50000 100000",
                "tmp_bytes": TMP_BYTES, "file_bytes": file_bytes, "wall_seconds": timeout,
                "app_server": app_server,
                "kernel": platform.release(), "syscalls": SYSCALLS})

            def limits():
                # Only trusted setup executes before Bubblewrap. No actor or
                # fixture bytes are interpreted here. Enrollment precedes exec.
                (group / "cgroup.procs").write_text(str(os.getpid()))
                for which, value in ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_NOFILE, 64),
                                     (resource.RLIMIT_FSIZE, file_bytes),
                                     (resource.RLIMIT_AS, address_space), (resource.RLIMIT_CPU, 3)):
                    resource.setrlimit(which, (value, value))

            launch = command(program.fileno(), bpf.fileno(), runtime) if runtime is not None \
                else command(program.fileno(), bpf.fileno())
            process = subprocess.Popen(launch,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={"PATH": "/usr/bin", "LANG": "C.UTF-8"}, cwd="/", close_fds=True,
                pass_fds=(program.fileno(), bpf.fileno()), preexec_fn=limits)
            status, stderr = broker(process, episode, wire, timeout, provider, service)
        (group / "cgroup.kill").write_text("1")
        process.wait(timeout=5)
        stats = {name: (group / name).read_text().strip()
                 for name in ("memory.events", "pids.events", "cpu.stat")}
        service_receipt = service.finish() if service else None
        wire.append("end", {"status": status, "returncode": process.returncode,
                             "service": service_receipt,
                             "stderr": stderr.decode("utf-8", errors="replace"), "resources": stats})
        wire.seal()
        root = episode.save(output)
        evidence = {"episode_root": root, "wire_root": wire.root}
        evidence["root"] = digest(evidence)
        with (output / "sandbox.json").open("x") as stream:
            stream.write(canonical({**evidence, "status": status,
                                    "returncode": process.returncode}) + "\n")
        os.chmod(output / "sandbox.json", 0o400)
        os.write(anchor_fd, (canonical(evidence) + "\n").encode())
        os.fsync(anchor_fd)
        os.fchmod(anchor_fd, 0o400)
        return {**evidence, "status": status, "returncode": process.returncode}
    finally:
        # Kill the entire cgroup even after broker failures, not just the actor
        # leader. Cleanup failure is surfaced, never converted into success.
        if (group / "cgroup.kill").exists():
            (group / "cgroup.kill").write_text("1")
        if service is not None:
            service.finish()
        if process is not None:
            process.wait(timeout=5)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
        if episode is not None:
            episode.finish()
        if wire is not None:
            wire.seal()
        if anchor_fd is not None:
            os.close(anchor_fd)
        deadline = time.monotonic() + 5
        while "populated 1" in (group / "cgroup.events").read_text():
            if time.monotonic() > deadline:
                raise RuntimeError("Sandbox cgroup did not empty")
            time.sleep(0.01)
        group.rmdir()


def broker(process, episode, wire, timeout, provider=None, service=None):
    """Bounded nonblocking duplex transport. stdout is protocol, never commands."""
    pending = bytearray((exchange(episode, '{"op":"observe"}') + "\n").encode())
    wire.append("send", pending.decode())
    buffer, stderr = bytearray(), bytearray()
    total = requests = 0
    message_limit = 256 * 1024 if provider else 16_384
    wire_limit = 2 * 1024 * 1024 if provider else MAX_WIRE
    closed = False
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as selector:
        for stream, event in ((process.stdout, selectors.EVENT_READ),
                              (process.stderr, selectors.EVENT_READ),
                              (process.stdin, selectors.EVENT_WRITE)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, event)
        # EOF alone is not process exit: an actor can close its pipes and spin.
        # Also wait for Bubblewrap's exit status before normal cleanup kills it.
        while selector.get_map() or process.poll() is None:
            if time.monotonic() >= deadline:
                return "wall_timeout", stderr
            for key, _ in selector.select(min(0.05, max(0, deadline - time.monotonic()))):
                stream = key.fileobj
                if stream is process.stdin:
                    try:
                        written = os.write(stream.fileno(), pending[:65536])
                    except BrokenPipeError:
                        selector.unregister(stream)
                        pending.clear()
                        continue
                    del pending[:written]
                    if not pending:
                        selector.unregister(stream)
                        if closed:
                            stream.close()
                    continue
                data = os.read(stream.fileno(), 4096)
                if not data:
                    selector.unregister(stream)
                    continue
                if stream is process.stderr:
                    stderr.extend(data[:MAX_STDERR - len(stderr)])
                    if len(stderr) >= MAX_STDERR:
                        return "stderr_limit", stderr
                    continue
                total += len(data)
                if total > wire_limit:
                    return "stdout_limit", stderr
                buffer.extend(data)
                while b"\n" in buffer:
                    line, _, rest = buffer.partition(b"\n")
                    buffer = bytearray(rest)
                    if len(line) > message_limit:
                        return "request_size_limit", stderr
                    requests += 1
                    if requests > MAX_REQUESTS or closed:
                        return "request_limit_or_closed", stderr
                    try:
                        text = line.decode("utf-8", errors="strict")
                        wire.append("receive", text)
                        request = parse_request(text, message_limit)
                        if service and request == {"op": "decide"}:
                            reply = canonical(service.decide(episode.observe(), deadline))
                        elif provider and request.get("op") == "app_server" and hasattr(provider, "gateway"):
                            reply = canonical(provider.gateway.exchange(request, episode))
                        elif provider and request.get("op") in ("provider", "codex_event"):
                            reply = canonical(provider.exchange(request))
                        else:
                            if provider and hasattr(provider, "gateway"):
                                raise ValueError("Direct task access bypasses app-server gateway")
                            reply = exchange(episode, text)
                    except (ValueError, UnicodeError):
                        # Invalid envelopes terminate this transport; invalid
                        # tool schemas still receive normal logged responses.
                        wire.append("rejected", {"bytes_hex": line.hex()})
                        return "protocol_error", stderr
                    wire.append("send", reply)
                    pending.extend((reply + "\n").encode())
                    if len(pending) > 1024 * 1024:
                        return "backpressure_limit", stderr
                    closed = episode.observe()["closed"]
                    if process.stdin.closed:
                        return "request_limit_or_closed", stderr
                    if process.stdin not in [key.fileobj for key in selector.get_map().values()]:
                        selector.register(process.stdin, selectors.EVENT_WRITE)
                if len(buffer) > message_limit:
                    return "request_size_limit", stderr
        if buffer:
            wire.append("rejected", {"bytes_hex": buffer.hex()})
            return "partial_request", stderr
        return "actor_exited", stderr


def verify(output, anchor):
    """Authenticate episode and transport records using an external anchor."""
    output = Path(output)
    trusted = json.loads(Path(anchor).read_text())
    if set(trusted) != {"episode_root", "wire_root", "root"} or trusted["root"] != digest(
            {key: trusted[key] for key in ("episode_root", "wire_root")}):
        raise ValueError("Invalid external anchor")
    events = json.loads((output / "transcript.json").read_text())
    result = audit(events, trusted["episode_root"])
    previous = "0" * 64
    wire = output.with_name(output.name + ".wire.jsonl")
    records = [json.loads(line) for line in wire.read_text().splitlines()]
    for i, event in enumerate(records):
        record = {k: event[k] for k in ("seq", "previous", "kind", "payload")}
        if event["seq"] != i or event["previous"] != previous or event["hash"] != digest(record):
            raise ValueError("Broken broker event chain")
        previous = event["hash"]
    if not records or records[0]["kind"] != "configuration" or records[-1]["kind"] != "end" \
            or previous != trusted["wire_root"]:
        raise ValueError("Broker seal/anchor mismatch")
    service = records[-1]["payload"].get("service")
    if service is not None:
        service_records = [json.loads(line) for line in
                           output.with_name(output.name + ".service.jsonl").read_text().splitlines()]
        previous = "0" * 64
        for i, event in enumerate(service_records):
            record = {k: event[k] for k in ("seq", "previous", "kind", "payload")}
            if event["seq"] != i or event["previous"] != previous or event["hash"] != digest(record):
                raise ValueError("Broken service event chain")
            previous = event["hash"]
        if not service_records or service_records[0]["kind"] != "configuration" \
                or service_records[-1]["kind"] != "end" or previous != service["root"]:
            raise ValueError("Service seal/anchor mismatch")
    return {"audit": result, "transport": records[-1]["payload"], "root": trusted["root"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    launch = sub.add_parser("run")
    launch.add_argument("actor", type=Path)
    launch.add_argument("--domain", choices=DOMAINS, required=True)
    launch.add_argument("--template", type=int, default=0)
    launch.add_argument("--seed", type=int, default=0)
    launch.add_argument("--mode", choices=MODES, default="hardened")
    launch.add_argument("--arm", choices=ARMS, default="decision")
    launch.add_argument("--timeout", type=float, default=5)
    launch.add_argument("--runtime", type=Path)
    launch.add_argument("--app-server", action="store_true")
    for p in (launch, sub.add_parser("verify")):
        p.add_argument("--output", type=Path, required=True)
        p.add_argument("--anchor", type=Path, required=True)
    args = vars(parser.parse_args())
    operation = args.pop("command")
    if operation == "run":
        with args.pop("actor").open("rb") as stream:
            actor = stream.read(FILE_BYTES + 1)
        result = run(actor, **args)
    else:
        result = verify(**args)
    print(json.dumps(result, indent=2))
    if operation == "run" and (result["status"] != "actor_exited" or result["returncode"] != 0):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
