"""Build and verify a frozen runtime from a pinned official Codex package.

Build is a trusted host operation; it never executes downloaded Codex or reads
the user's Codex home. Runtime execution happens only inside Bubblewrap.
"""

import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

from .tasks import canonical, digest

VERSION = "0.166.0"
PACKAGE_URL = "https://registry.npmjs.org/@openai/codex/-/codex-0.166.0-linux-x64.tgz"
PACKAGE_SHA512 = "CxDm3+D1cpbGJeHrdzINoG+3wn9BVncP4qpZaaNYkxe8iPtRJOYyCJnnPoVjWRIBvI9vPKbRoifsMSA5xDaUpw=="
BINARY_SHA256 = "b8a11fedf24b2dfb59a70c9e52b030f9a508dcd49cd2dd0d41956f4c785156b8"
SOURCE_REVISION = "6ff1e1ca3b30fc8b914720681fcf5fe62e95f856"
CA_VERSION = "Debian ca-certificates 20250419~deb12u2 Mozilla roots"
CA_SHA256 = "e9c7b63ee2623386e9b0a3ee32f499d01a8ea23dc83b8383ddff9f8e749543b7"
CA_BUNDLE = Path(__file__).with_name("certs") / "mozilla-debian-20250419.pem"
DEFAULT_RUNTIME = Path(__file__).resolve().parent.parent / ".runtime" / "codex-0.166.0-ca-20250419"


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def build(package, destination):
    package, destination = Path(package), Path(destination)
    with package.open("rb") as stream:
        actual = base64.b64encode(hashlib.file_digest(stream, "sha512").digest()).decode()
    if actual != PACKAGE_SHA512:
        raise ValueError("Codex package integrity mismatch")
    if CA_BUNDLE.is_symlink() or sha256(CA_BUNDLE) != CA_SHA256:
        raise ValueError("Public CA bundle integrity mismatch")
    destination.mkdir(parents=True, exist_ok=False)
    root = destination / "root"
    (root / "opt").mkdir(parents=True)
    shutil.copyfile(CA_BUNDLE, root / "opt/public-ca.pem")
    member = "package/vendor/x86_64-unknown-linux-musl/bin/codex"
    with tarfile.open(package) as archive:
        info = archive.getmember(member)
        if not info.isfile() or info.size != 319_346_888:
            raise ValueError("Unexpected Codex binary member")
        with archive.extractfile(info) as source, (root / "opt/codex").open("xb") as target:
            shutil.copyfileobj(source, target)
    if sha256(root / "opt/codex") != BINARY_SHA256:
        raise ValueError("Codex binary digest mismatch")
    (root / "usr/bin").mkdir(parents=True)
    shutil.copyfile("/usr/bin/python3.11", root / "usr/bin/python3.11")
    shutil.copytree("/usr/lib/python3.11", root / "usr/lib/python3.11",
                    ignore=shutil.ignore_patterns("__pycache__", "sitecustomize.py"))
    # ldd is run only on the trusted distro Python runtime, never on Codex or
    # actor input. Copy the transitive ELF dependency list, not the host /usr/lib.
    binaries = [Path("/usr/bin/python3.11"), *Path("/usr/lib/python3.11/lib-dynload").glob("*.so")]
    for binary in binaries:
        deps = subprocess.run(["/usr/bin/ldd", str(binary)], capture_output=True,
                              text=True, check=True).stdout
        if "not found" in deps:
            raise RuntimeError(f"Missing distro runtime library for {binary}")
        for path in re.findall(r"(/[^\s()]+)", deps):
            source = Path(path)
            if path.startswith("/lib/"):
                relative = "usr" + path
            elif path.startswith("/lib64/"):
                relative = "/usr/lib/x86_64-linux-gnu/" + source.name
            elif path.startswith("/usr/lib/"):
                relative = path
            else:
                raise RuntimeError(f"Unexpected runtime library location: {path}")
            target = root / relative.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                shutil.copyfile(source, target)
    files = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("Runtime symlinks are not permitted")
        if path.is_file():
            with path.open("rb") as stream:
                executable = stream.read(4) == b"\x7fELF"
            path.chmod(0o555 if executable else 0o444)
            files[str(path.relative_to(root))] = {"sha256": sha256(path),
                                                  "mode": path.stat().st_mode & 0o777}
    manifest = {"codex_version": VERSION, "package_url": PACKAGE_URL,
                "package_sha512": PACKAGE_SHA512, "source_revision": SOURCE_REVISION,
                "ca_version": CA_VERSION,
                "files": files}
    (destination / "manifest.json").write_text(canonical(manifest) + "\n")
    return verify(destination)


def verify(destination):
    destination = Path(destination).resolve()
    manifest = json.loads((destination / "manifest.json").read_text())
    root = destination / "root"
    files = {str(path.relative_to(root)): {"sha256": sha256(path), "mode": path.stat().st_mode & 0o777}
             for path in root.rglob("*") if path.is_file() and not path.is_symlink()}
    if any(path.is_symlink() for path in root.rglob("*")) or files != manifest["files"] \
            or files.get("opt/codex", {}).get("sha256") != BINARY_SHA256 \
            or files.get("opt/public-ca.pem") != {"sha256": CA_SHA256, "mode": 0o444} \
            or manifest.get("ca_version") != CA_VERSION \
            or manifest["codex_version"] != VERSION:
        raise ValueError("Frozen runtime has changed; refusing to launch")
    return {"manifest_sha256": digest(manifest), "codex_version": VERSION,
            "codex_sha256": BINARY_SHA256, "files": len(files),
            "ca_version": CA_VERSION, "ca_sha256": CA_SHA256}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_RUNTIME)
    args = parser.parse_args()
    print(json.dumps(build(args.package, args.output), indent=2))


if __name__ == "__main__":
    main()
