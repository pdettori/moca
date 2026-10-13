"""sbx: a command-line client for one sandbox/v1 workspace, built on sandbox_v1_client.py.

Meant for a coding agent whose shell tool is restricted to `sbx ...`: every command runs in a fresh
microVM over the workspace, and nothing runs on the local machine. See sandbox-v1-direct-client.md.

    sbx run [COMMAND...]      run COMMAND (or, with no arguments, the script on stdin) in /workspace
    sbx put PATH              write stdin to PATH in the workspace (parent directories created)
    sbx push [DIR]            replace /workspace with DIR's git working tree; commit it as the baseline
    sbx pull                  print every change since the push as a git patch

Environment: SBX_ADDR, SBX_SANDBOX_ID, SBX_WORKSPACE_KEY, and SBX_TOKEN or SBX_TOKEN_FILE.
Optional: SBX_TIMEOUT (seconds per command, default 600), SBX_LOG (append one JSON line per call).
`sbx run` exits with the command's own exit code; 124 means it timed out, 125 that the sandbox failed.
"""

import io
import json
import os
import subprocess
import sys
import tarfile
import time

from sandbox_v1_client import Sandbox

# The sandbox image has python3 and git but not tar/gzip, so the archive is extracted with tarfile.
PUSH = (
    "cd /workspace && find . -mindepth 1 -delete && "
    "python3 -W ignore -c 'import sys,tarfile; tarfile.open(fileobj=sys.stdin.buffer, mode=\"r|gz\").extractall(\".\")' && "
    "git init -q && "
    "printf '%s\\n' __pycache__/ '*.pyc' node_modules/ .venv/ venv/ .pytest_cache/ .mypy_cache/ > .git/info/exclude && "
    "git add -A && git -c user.name=sbx -c user.email=sbx@localhost commit -q --no-verify -m sbx-baseline && "
    "git ls-files | wc -l"
)
PULL = "cd /workspace && git add -A -N . && git diff --binary HEAD"


def sandbox() -> Sandbox:
    env = os.environ
    token = env.get("SBX_TOKEN") or open(env["SBX_TOKEN_FILE"]).read().strip()
    return Sandbox(env["SBX_ADDR"], env["SBX_SANDBOX_ID"], env["SBX_WORKSPACE_KEY"], token)


def log(op: str, started: float, code: int) -> None:
    if path := os.environ.get("SBX_LOG"):
        with open(path, "a") as f:
            rec = {"t": time.time(), "op": op, "ms": round((time.time() - started) * 1000), "exit": code}
            f.write(json.dumps(rec) + "\n")


def run(command: str, stdin: bytes = b"", op: str = "run") -> int:
    started = time.time()
    try:
        r = sandbox().exec(command, stdin=stdin, timeout_s=int(os.environ.get("SBX_TIMEOUT", "600")))
    except RuntimeError as e:
        msg = str(e)
        code = 124 if "timeout:" in msg else 125
        print(f"sbx: {'command timed out' if code == 124 else msg}", file=sys.stderr)
        log(op, started, code)
        return code
    sys.stdout.buffer.write(r.stdout)
    sys.stderr.buffer.write(r.stderr)
    if r.truncated:
        print("sbx: stdout exceeded 8 MiB and was cut", file=sys.stderr)
    code = r.exit_code if r.exit_code >= 0 else 128 + 9
    log(op, started, code)
    return code


def push(directory: str) -> int:
    files = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=directory, check=True, capture_output=True,
    ).stdout.split(b"\0")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name in filter(None, files):
            path = os.path.join(directory, name.decode())
            if os.path.lexists(path):  # tracked but deleted locally: skip
                tar.add(path, arcname=name.decode(), recursive=False)
    data = buf.getvalue()
    if len(data) > 12 << 20:
        print(f"sbx: tree is {len(data) >> 20} MiB compressed; the limit is 12", file=sys.stderr)
        return 1
    return run(PUSH, stdin=data, op="push")


def main(argv: list) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 2
    cmd, args = argv[0], argv[1:]
    if cmd == "run":
        return run(" ".join(args) if args else sys.stdin.read())
    if cmd == "put" and len(args) == 1:
        q = "'" + args[0].replace("'", "'\\''") + "'"
        return run(f'mkdir -p "$(dirname -- {q})" && cat > {q}', stdin=sys.stdin.buffer.read(), op="put")
    if cmd == "push":
        return push(args[0] if args else ".")
    if cmd == "pull":
        return run(PULL, op="pull")
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
