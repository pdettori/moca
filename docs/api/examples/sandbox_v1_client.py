"""Minimal direct client for MOCA's sandbox/v1 SandboxExec API.

See docs/api/sandbox-v1-direct-client.md. Generate the stubs first, from the repo root:

    python -m grpc_tools.protoc -I proto --python_out=docs/api/examples \
        --grpc_python_out=docs/api/examples sandbox/v1/sandbox.proto

Then:

    export SBX_ADDR=localhost:9444 SBX_SANDBOX_ID=moca_microvm_0 \
           SBX_WORKSPACE_KEY=sbx-alice-demo SBX_TOKEN=<your client token>
    python docs/api/examples/sandbox_v1_client.py
"""

import os
import secrets
import sys
from dataclasses import dataclass

import grpc

from sandbox.v1 import sandbox_pb2, sandbox_pb2_grpc


@dataclass
class Result:
    stdout: bytes
    stderr: bytes
    exit_code: int  # < 0: killed by a signal (an abort, a timeout, a crash)
    truncated: bool  # stdout hit the worker's 8 MiB cap


class Sandbox:
    """One workspace on one worker. Every exec runs `bash -c` in /workspace, in a fresh VM."""

    def __init__(self, addr: str, sandbox_id: str, workspace_key: str, token: str):
        self._stub = sandbox_pb2_grpc.SandboxExecStub(
            grpc.insecure_channel(addr, options=[("grpc.max_receive_message_length", 16 << 20)])
        )
        self._sandbox_id = sandbox_id
        self._key = workspace_key
        self._md = [("authorization", f"Bearer {token}")]

    def exec(self, command: str, stdin: bytes = b"", timeout_s: int = 120) -> Result:
        # Unique per call; it is also what abort() targets. The proto says uint64, but the relay
        # decodes it as a JavaScript number, so keep it below 2**53 or the call is refused.
        req_id = secrets.randbits(53)
        events = self._stub.Exec(
            sandbox_pb2.ExecRequest(
                sandbox_id=self._sandbox_id,
                exec=sandbox_pb2.Exec(
                    req_id=req_id,
                    command=command,
                    stdin=stdin,
                    timeout_s=timeout_s,
                    streaming=True,
                    workspace_key=self._key,
                ),
            ),
            metadata=self._md,
        )
        out, err = bytearray(), bytearray()
        try:
            for ev in events:
                kind = ev.WhichOneof("event")
                if kind == "chunk":
                    (err if ev.chunk.stream == sandbox_pb2.STREAM_STDERR else out).extend(
                        ev.chunk.data
                    )
                elif kind == "end":
                    return Result(bytes(out), bytes(err), ev.end.exit_code, ev.end.truncated)
                elif kind == "error":
                    # The machinery failed (VM boot, worker gone): not the command's exit status.
                    raise RuntimeError(f"exec failed: {ev.error.message}")
        except KeyboardInterrupt:
            self.abort(req_id)
            raise
        except grpc.RpcError as e:
            # The relay ends a failed exec with a non-OK status after the error event.
            raise RuntimeError(f"exec failed: {e.code().name}: {e.details()}") from None
        raise RuntimeError("exec stream ended without an End event")

    def abort(self, req_id: int) -> None:
        self._stub.Abort(
            sandbox_pb2.AbortRequest(sandbox_id=self._sandbox_id, req_id=req_id),
            metadata=self._md,
        )

    # Files are just commands: there is no file RPC in sandbox/v1.
    def write_file(self, path: str, data: bytes) -> None:
        r = self.exec(f'mkdir -p "$(dirname -- {_q(path)})" && cat > {_q(path)}', stdin=data)
        if r.exit_code != 0:
            raise RuntimeError(f"write {path} failed: {r.stderr.decode(errors='replace')}")

    def read_file(self, path: str) -> bytes:
        r = self.exec(f"cat -- {_q(path)}")
        if r.exit_code != 0 or r.truncated:
            raise RuntimeError(f"read {path} failed: {r.stderr.decode(errors='replace')}")
        return r.stdout


def _q(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


if __name__ == "__main__":
    env = os.environ
    sbx = Sandbox(env["SBX_ADDR"], env["SBX_SANDBOX_ID"], env["SBX_WORKSPACE_KEY"], env["SBX_TOKEN"])
    sbx.write_file("hello.py", b"print('hello from the sandbox')\n")
    print(sbx.read_file("hello.py").decode(), end="")
    r = sbx.exec("python3 hello.py; ls -la; exit 3")
    print(r.stdout.decode(), end="")
    print(f"exit={r.exit_code} truncated={r.truncated}", file=sys.stderr)
