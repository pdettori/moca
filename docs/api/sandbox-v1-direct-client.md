# Coding directly against the sandbox/v1 API

How to run commands in a MOCA microVM sandbox from your own code (a script, an SDK, a local MCP
server) by calling the relay's `SandboxExec` gRPC service, with no MOCA harness in between.

> **Demo-grade.** `sandbox/v1` is MOCA's internal harness-to-relay contract, opened to a few
> trusted clients through per-client tokens. It is not the planned public API: SBX1 replaces it with
> a lifecycle API and the sandboxd data plane. Expect breaking changes.

## The contract

[`proto/sandbox/v1/sandbox.proto`](../../proto/sandbox/v1/sandbox.proto): one self-contained file
with no imports. A client uses one service:

```proto
service SandboxExec {
  rpc Exec(ExecRequest) returns (stream ExecEvent);   // run one command, stream its output
  rpc Abort(AbortRequest) returns (AbortResponse);    // cancel a running command
}
```

`SandboxWorker.Attach` in the same file is the workers' side; clients never call it.

**A call:**

```
ExecRequest { sandbox_id, exec: Exec { req_id, command, stdin, timeout_s, streaming, workspace_key } }
  -> stream ExecEvent  chunk { req_id, data, stream: STDOUT | STDERR }   zero or more
                       end   { req_id, exit_code, truncated }             then exactly one
                       error { req_id, message }                          of end / error
```

| Field           | Meaning                                                                                                                                                                |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sandbox_id`    | The **worker**, not your sandbox. The operator gives it to you, for example `moca_microvm_0`.                                                                          |
| `workspace_key` | **Your sandbox.** Any name that starts with your token's prefix, for example `sbx-alice-calc`. The first Exec creates it. Only `/workspace` persists between calls.    |
| `command`       | Run as `bash -c` with `/workspace` as the working directory, in a fresh Firecracker VM. No process, and no file outside `/workspace`, survives the call.               |
| `stdin`         | Raw bytes, sent once with the call. Use it to write files: `cat > path`.                                                                                               |
| `timeout_s`     | Kills the command when it runs out; the call ends with `error` `timeout:<s>`. 0 means the 30-minute default; the microVM tier caps it at 2 hours.                      |
| `streaming`     | `true` streams chunks as they come; `false` buffers them until the end.                                                                                                |
| `req_id`        | Unique per call, and what `Abort` targets. **Keep it below 2^53**: the proto says `uint64`, but the relay decodes it as a JavaScript number and refuses larger values. |

**Outcomes and failures differ.**

- A command that ran ends with `end`, whatever its exit code. A non-zero exit is an outcome, not
  an error.
  - `exit_code < 0`: the command was killed by a signal (your abort, an out-of-memory kill).
  - `truncated`: stdout went over the 8 MiB cap, and the rest was dropped.
- `error` means there is no exit status to report: the command timed out (`timeout:<s>`), the VM
  did not boot, or the worker went away. The stream then ends with a non-OK status (`INTERNAL`).

**gRPC status codes:**

| Code                                        | Cause                                                                                                                                                                                          |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `UNAUTHENTICATED`                           | Missing or unknown token.                                                                                                                                                                      |
| `PERMISSION_DENIED`                         | One of: the `sandbox_id` is not your token's worker; the `workspace_key` is not under your prefix or contains anything but `A-Z a-z 0-9 . _ -`; or you aborted an Exec that you did not start. |
| `UNKNOWN` with `no live worker for sandbox` | The worker is not attached.                                                                                                                                                                    |
| `INTERNAL`                                  | An `error` event, as above, including a timeout.                                                                                                                                               |

**Limits:**

- 16 MiB per message, so keep `stdin` well under that and send large trees as several calls;
- 8 MiB of stdout per call;
- **one command at a time per workspace**: concurrent calls on one key queue behind each other.

## Connecting

The relay serves `SandboxExec` on the rig's loopback, with no TLS. You reach it through an SSH
tunnel with a key that may forward that one port and nothing else:

```bash
ssh -N -L 9444:localhost:9444 sbx-client@<rig>     # leave running
```

Then:

- dial `localhost:9444`, plaintext (the tunnel is the encryption);
- send `authorization: Bearer <your client token>` as metadata on every call.

## Try it

From the repo root:

```bash
python -m venv .venv && .venv/bin/pip install grpcio grpcio-tools
.venv/bin/python -m grpc_tools.protoc -I proto --python_out=docs/api/examples \
    --grpc_python_out=docs/api/examples sandbox/v1/sandbox.proto
export SBX_ADDR=localhost:9444 SBX_SANDBOX_ID=moca_microvm_0 \
       SBX_WORKSPACE_KEY=sbx-alice-demo SBX_TOKEN=<your client token>
.venv/bin/python docs/api/examples/sandbox_v1_client.py
```

[`examples/sandbox_v1_client.py`](examples/sandbox_v1_client.py) is about 100 lines. It defines a
`Sandbox` class with `exec`, `abort`, `read_file` and `write_file`, and its `__main__` writes a file,
reads it back and runs it.

**From the shell, with `grpcurl`:**

```bash
grpcurl -plaintext -import-path proto -proto sandbox/v1/sandbox.proto \
  -H "authorization: Bearer $SBX_TOKEN" \
  -d '{"sandbox_id":"moca_microvm_0","exec":{"req_id":"42","command":"ls -la",
       "timeout_s":60,"streaming":true,"workspace_key":"sbx-alice-demo"}}' \
  localhost:9444 sandbox.v1.SandboxExec/Exec
```

Chunk `data` comes back base64-encoded in grpcurl's JSON.

**Other languages:** generate a client from the one proto file with `buf generate` or `protoc`.
MOCA's own TypeScript client is generated in `packages/k8s-sandbox/src/gen/`, and
`GrpcRelayTransport` in the same package wraps it.

## For the operator: issuing a client token

Client tokens live in the relay's environment, `/etc/serverless-harness/relay.env` on the rig:

```bash
MOCA_RELAY_CLIENT_TOKENS=moca_microvm_0:sbx-alice-:<openssl rand -hex 32>,moca_microvm_0:sbx-bob-:<...>
```

- **Each entry** binds one token to one worker and one `workspace_key` prefix.
- **Tokens** must be at least 32 characters, distinct from each other, and distinct from
  `MOCA_RELAY_EXEC_TOKEN` and every `SH_RELAY_TOKEN*`. The relay refuses to start otherwise, naming
  the entry but never the token.
- **Apply** a change by restarting `sh-relay`.
- **Name only microVM workers.** The container worker ignores `workspace_key` and shares one
  `/workspace` between every caller, so a client token on it would share files with everyone.
- **What a client token cannot do:**
  - exec on another worker;
  - exec outside its prefix;
  - abort another caller's Exec.

  The harness's `MOCA_RELAY_EXEC_TOKEN` is unchanged and unrestricted. Never hand it to a client.

- **Tunnel access:** give each client a user whose `authorized_keys` entry is
  `restrict,port-forwarding,permitopen="localhost:9444" ssh-ed25519 ...`.
