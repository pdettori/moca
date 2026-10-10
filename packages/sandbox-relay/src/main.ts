import { timingSafeEqual } from 'node:crypto';
import {
  Server,
  ServerCredentials,
  status,
  type Metadata,
  type ServerDuplexStream,
  type ServerWritableStream,
  type ServerUnaryCall,
  type sendUnaryData,
} from '@grpc/grpc-js';
import {
  SandboxWorkerService,
  SandboxExecService,
  type SandboxWorkerServer,
  type SandboxExecServer,
  type WorkerFrame,
  type ServerFrame,
  type ExecRequest,
  type ExecEvent,
  type AbortRequest,
  type AbortResponse,
  MAX_EXEC_MESSAGE_BYTES,
} from '@moca/k8s-sandbox';
import { RedisRecordStore } from '@moca/harness';
import {
  makeClientTokenAuthenticator,
  workspaceKeyAllowed,
  type ClientGrant,
} from './client-tokens.js';
import { createRelay, type RelayDeps, type AttachStream } from './relay.js';

/**
 * Ends a server-streaming exec call with a non-OK status.
 *
 * `call.destroy(err)` does NOT do that, which is the trap this helper exists to name. On
 * @grpc/grpc-js 1.14.4 a `ServerWritableStream` sends its status from `_final` (which calls
 * `call.sendStatus`), and Node's `Writable` never reaches `_final` once `destroyed` is set:
 * `end()` short-circuits with ERR_STREAM_DESTROYED. Destroying therefore sends no trailers
 * at all -- verified against a real client, which sat for 12s with no status, no `end` and
 * no `error`. A hang is strictly worse than the wrong-OK of #295, because an OK at least
 * lets the caller finish its request.
 *
 * Emitting 'error' is the supported path: grpc-js registers a listener in the stream's
 * constructor that runs the error through `serverErrorToStatus` and then ends the stream,
 * which is what actually puts a code on the wire. `serverErrorToStatus` takes a numeric
 * `code` and a string `details` when present, and otherwise reports UNKNOWN with `message`
 * as the details -- so a bare Error still terminates non-OK and still carries its reason.
 *
 * `main-exec-status.transport.test.ts` pins all of this over a real transport; a fake call
 * object cannot, because the status is produced by the transport rather than the handler.
 */
function failExecStream(call: ServerWritableStream<ExecRequest, ExecEvent>, err: Error): void {
  call.emit('error', err);
}

/**
 * A worker-reported in-stream exec failure, shaped so grpc-js terminates the stream with
 * a non-OK status instead of OK. INTERNAL (not UNKNOWN) because the failure is server-side
 * and not the caller's fault: `ExecEvent.error` means the exec machinery itself failed,
 * whereas a command that merely exited non-zero comes back as `ExecEvent.end{exitCode}`.
 * The worker's message travels as the status details so the cause is not lost.
 */
function execStreamError(message: string): Error {
  const err = new Error(message) as Error & { code: number; details: string };
  err.code = status.INTERNAL;
  err.details = message;
  return err;
}

/** Relay server dependencies: the relay's own, plus the SandboxExec caller check (MI1 §5 R5). */
export interface RelayServerDeps extends RelayDeps {
  validateExecToken: (presented: string | undefined) => boolean;
  /** Direct clients (client-tokens.ts). Omitted: only the harness's exec token is accepted. */
  authenticateClient?: (presented: string | undefined) => ClientGrant | undefined;
}

/**
 * The SandboxExec caller check. FAIL-CLOSED: with no MOCA_RELAY_EXEC_TOKEN there is no valid caller,
 * so building the validator throws and the relay does not boot. The token is the WORKERS' credential
 * and must be distinct from every sandbox's SH_RELAY_TOKEN[_<id>] (spec R5): a relay configured with
 * an exec token equal to any of them also refuses to boot, and the error names the variables, never
 * the value. Constant-time, length-checked first.
 */
export function makeExecTokenValidator(
  env: NodeJS.ProcessEnv,
): (presented: string | undefined) => boolean {
  const expected = env.MOCA_RELAY_EXEC_TOKEN;
  if (!expected) {
    throw new Error(
      'MOCA_RELAY_EXEC_TOKEN is required: the relay refuses unauthenticated SandboxExec',
    );
  }
  const clashes = Object.keys(env)
    .filter(
      (k) => (k === 'SH_RELAY_TOKEN' || k.startsWith('SH_RELAY_TOKEN_')) && env[k] === expected,
    )
    .sort();
  if (clashes.length > 0) {
    throw new Error(
      `MOCA_RELAY_EXEC_TOKEN must differ from every sandbox token, but equals ${clashes.join(', ')}`,
    );
  }
  const want = Buffer.from(expected);
  return (presented) => {
    if (!presented) return false;
    const got = Buffer.from(presented);
    return got.length === want.length && timingSafeEqual(got, want);
  };
}

function bearerOf(md: Metadata): string | undefined {
  const v = md.get('authorization')[0];
  return typeof v === 'string' && v.startsWith('Bearer ') ? v.slice('Bearer '.length) : undefined;
}

function unauthenticated(): Error & { code: number; details: string } {
  // The message never contains the presented value.
  const err = new Error('exec authentication failed') as Error & { code: number; details: string };
  err.code = status.UNAUTHENTICATED;
  err.details = err.message;
  return err;
}

function permissionDenied(message: string): Error & { code: number; details: string } {
  const err = new Error(message) as Error & { code: number; details: string };
  err.code = status.PERMISSION_DENIED;
  err.details = message;
  return err;
}

/**
 * Who is calling SandboxExec: the harness (its exec token, unrestricted, as before), a direct client
 * (a grant), or nobody.
 */
type ExecCaller = { kind: 'harness' } | { kind: 'client'; grant: ClientGrant } | undefined;

function execCaller(md: Metadata, deps: ExecAuth): ExecCaller {
  const presented = bearerOf(md);
  if (deps.validateExecToken(presented)) return { kind: 'harness' };
  const grant = deps.authenticateClient?.(presented);
  return grant ? { kind: 'client', grant } : undefined;
}

type ExecAuth = Pick<RelayServerDeps, 'validateExecToken' | 'authenticateClient'>;

function newServer(): Server {
  // Raise the ingress limit above gRPC's 4 MiB default. This is the hop that rejects an
  // oversized write today: the harness's ExecRequest carries base64 stdin at 4/3 of the
  // file, so a file the read path can return (DEFAULT_OUTPUT_CAP, 8 MiB) needs ~10.7 MiB
  // here. MAX_EXEC_MESSAGE_BYTES is shared with the Go worker's session.MaxRecvMsgBytes
  // and pinned equal to it — a relay that accepts more than the worker would forward a
  // payload the worker refuses on its Attach stream, killing every exec on it (#173 item 2).
  return new Server({ 'grpc.max_receive_message_length': MAX_EXEC_MESSAGE_BYTES });
}

function addWorkerService(server: Server, relay: ReturnType<typeof createRelay>): void {
  const workerImpl: SandboxWorkerServer = {
    // AttachStream types metadata.get() as returning string[]; grpc-js's real
    // Metadata.get() returns MetadataValue[] (string | Buffer). The relay only
    // ever reads a bearer token (always sent as a string by well-behaved
    // clients), so the cast is safe here without widening relay.ts's contract.
    attach: (call: ServerDuplexStream<WorkerFrame, ServerFrame>) =>
      relay.onAttach(call as unknown as AttachStream),
  };
  server.addService(SandboxWorkerService, workerImpl);
}

function addExecService(
  server: Server,
  relay: ReturnType<typeof createRelay>,
  auth: ExecAuth,
): void {
  // A client may abort only the Execs it started: req_ids are not secret, so without this one client
  // could kill another's command. Keyed by sandbox and req_id, held for the Exec's lifetime.
  const clientExecs = new Map<string, ClientGrant>();
  const execKey = (sandboxId: string, reqId: number) => `${sandboxId}\0${reqId}`;
  const execImpl: SandboxExecServer = {
    // Server-streaming: one ExecRequest in, a stream of ExecEvents out.
    //
    // Client cancellation (harness deadline/abort) fires the call's "cancelled"
    // event. We must NOT rely on calling .return() on the routeExec generator
    // while it idles on its internal await -- that can hang forever if the
    // worker never sends another frame. Instead, on cancellation we tell the
    // worker to abort via relay.routeAbort(); the worker then emits an
    // End/Error frame for that reqId, which drives the generator's sink so it
    // yields that event and returns normally (running its `finally`, which
    // cleans up the sink). This makes worker-disconnect (Task 6) and
    // client-cancel (this task) both terminate the generator cleanly.
    exec: async (call: ServerWritableStream<ExecRequest, ExecEvent>) => {
      const caller = execCaller(call.metadata, auth);
      if (!caller) {
        failExecStream(call, unauthenticated());
        return;
      }
      const req = call.request;
      const e = req.exec;
      if (!e) {
        const err = new Error('ExecRequest missing exec field') as Error & {
          code: number;
          details: string;
        };
        // The request itself is malformed, so this one IS the caller's fault.
        err.code = status.INVALID_ARGUMENT;
        err.details = err.message;
        failExecStream(call, err);
        return;
      }
      let owned: string | undefined;
      if (caller.kind === 'client') {
        const { grant } = caller;
        // Checked before routing, so a refused Exec never reaches a worker.
        if (req.sandboxId !== grant.sandboxId || !workspaceKeyAllowed(grant, e.workspaceKey)) {
          failExecStream(call, permissionDenied('exec not permitted for this client token'));
          return;
        }
        owned = execKey(req.sandboxId, e.reqId);
        clientExecs.set(owned, grant);
      }
      // Registered synchronously (before the loop's first await) so a
      // cancellation that races the very first event is never missed.
      // A client cancel also reaches us as an in-stream ExecEvent.error (the worker's
      // acknowledgement of our abort), but that is OUR abort completing, not a server-side
      // exec failure -- so it must not be reclassified as INTERNAL below.
      let cancelled = false;
      const onCancelled = () => {
        cancelled = true;
        relay.routeAbort(req.sandboxId, e.reqId);
      };
      call.on('cancelled', onCancelled);

      try {
        // Tracked as a flag, not by testing the message text: an ExecEvent.error with an
        // EMPTY message is still a failing Exec, and classifying on `message` alone would
        // silently re-admit it as a success (the Go exec-driver learned the same lesson --
        // see its sawErr note in cmd/exec-driver/drive.go).
        let sawExecError = false;
        let execErrorMessage = '';
        for await (const ev of relay.routeExec(req.sandboxId, e)) {
          call.write(ev);
          if (ev.error) {
            sawExecError = true;
            execErrorMessage = ev.error.message ?? '';
          }
        }
        // A failed Exec must not terminate OK (#295). routeExec returns normally after
        // yielding an error event, so ending here would report success for a command that
        // never ran: it would count toward throughput, enter p95, and never be classified
        // as an error by a client that reads only the terminal status.
        if (sawExecError && !cancelled) {
          failExecStream(call, execStreamError(execErrorMessage));
          return;
        }
        call.end();
      } catch (err) {
        // Reached by every throw out of routeExec -- including `no live worker for sandbox`
        // (an ordinary state: the worker died, or has not attached yet) and the reqId
        // in-flight collision. Codes are left to grpc-js rather than classified here: an
        // arbitrary internal throw becomes UNKNOWN with its message as the details, and a
        // thrown error that already carries a numeric `code` keeps it. Mapping these onto
        // specific codes (UNAVAILABLE for a missing worker, say) is a relay-semantics
        // decision, not part of fixing the termination primitive.
        failExecStream(call, err as Error);
      } finally {
        call.removeListener('cancelled', onCancelled);
        if (owned) clientExecs.delete(owned);
      }
    },
    abort: (
      call: ServerUnaryCall<AbortRequest, AbortResponse>,
      cb: sendUnaryData<AbortResponse>,
    ) => {
      const caller = execCaller(call.metadata, auth);
      if (!caller) {
        cb(unauthenticated(), null);
        return;
      }
      if (
        caller.kind === 'client' &&
        clientExecs.get(execKey(call.request.sandboxId, call.request.reqId)) !== caller.grant
      ) {
        cb(permissionDenied('abort not permitted: not an exec this client started'), null);
        return;
      }
      relay.routeAbort(call.request.sandboxId, call.request.reqId);
      cb(null, {});
    },
  };
  server.addService(SandboxExecService, execImpl);
}

/**
 * One listener serving both services — the Kubernetes shape, where the token is the ONLY control:
 * every sandbox can reach SandboxExec, and only a secret exec token keeps it out. With the base
 * manifest's public dev token there is no isolation between sandboxes at all.
 */
export function buildServer(deps: RelayServerDeps): { server: Server } {
  const relay = createRelay(deps);
  const server = newServer();
  addWorkerService(server, relay);
  addExecService(server, relay, deps);
  return { server };
}

/**
 * Two listeners over ONE relay (MI1 §5 R5), so the exec server can be bound where sandboxes cannot
 * reach it: loopback on deploy/vm, the brain network in compose. That reachability comes from the
 * address it is bound to, not from this function; bound on an address sandboxes can reach, the
 * exec token is again the only control. Same relay instance, so an Exec routes to a worker attached
 * on the other listener.
 */
export function buildServers(deps: RelayServerDeps): { attachServer: Server; execServer: Server } {
  const relay = createRelay(deps);
  const attachServer = newServer();
  const execServer = newServer();
  addWorkerService(attachServer, relay);
  addExecService(execServer, relay, deps);
  return { attachServer, execServer };
}

function bind(server: Server, addr: string): Promise<number> {
  return new Promise((resolve, reject) =>
    server.bindAsync(addr, ServerCredentials.createInsecure(), (err, p) =>
      err ? reject(err) : resolve(p),
    ),
  );
}

/**
 * Default token validator: fail-closed. A sandbox authenticates only against
 * an exact, non-empty match on its per-sandbox override (`SH_RELAY_TOKEN_<id>`)
 * or the global `SH_RELAY_TOKEN`. If neither env var is set for a sandbox,
 * `expected` is `undefined` and every token — including an undefined one from
 * a tokenless worker — is rejected, instead of the two `undefined`s comparing
 * equal. Constant-time, like the exec token's comparison.
 */
export function makeDefaultValidateToken(
  env: NodeJS.ProcessEnv,
): (token: string | undefined, sandboxId: string) => boolean {
  return (token, sandboxId) => {
    const expected = env[`SH_RELAY_TOKEN_${sandboxId}`] ?? env.SH_RELAY_TOKEN;
    // `!`, not `=== undefined`: an empty SH_RELAY_TOKEN= is a configuration mistake, not a token,
    // and must not admit a worker presenting an empty one.
    if (!expected || !token) return false;
    // Constant-time, length-checked first -- the same comparison as the exec token's.
    const want = Buffer.from(expected);
    const got = Buffer.from(token);
    return got.length === want.length && timingSafeEqual(got, want);
  };
}

export async function startRelay(
  opts: { port?: number; execAddr?: string; deps?: RelayServerDeps; env?: NodeJS.ProcessEnv } = {},
): Promise<{ port: number; execPort?: number; shutdown: () => Promise<void> }> {
  const env = opts.env ?? process.env;
  // The exec validator first: it throws on a missing token before anything touches Redis.
  const deps =
    opts.deps ??
    (() => {
      const validateExecToken = makeExecTokenValidator(env);
      const authenticateClient = makeClientTokenAuthenticator(env);
      return {
        records: new RedisRecordStore(),
        validateToken: makeDefaultValidateToken(env),
        validateExecToken,
        authenticateClient,
      };
    })();
  const attachAddr = `0.0.0.0:${opts.port ?? Number(env.SH_RELAY_PORT ?? 8443)}`;
  const execAddr = opts.execAddr ?? env.MOCA_RELAY_EXEC_ADDR;
  if (!execAddr) {
    const { server } = buildServer(deps);
    const port = await bind(server, attachAddr);
    return { port, shutdown: () => new Promise((r) => server.tryShutdown(() => r())) };
  }
  const { attachServer, execServer } = buildServers(deps);
  const port = await bind(attachServer, attachAddr);
  const execPort = await bind(execServer, execAddr);
  return {
    port,
    execPort,
    shutdown: async () => {
      await new Promise<void>((r) => attachServer.tryShutdown(() => r()));
      await new Promise<void>((r) => execServer.tryShutdown(() => r()));
    },
  };
}

// Bootstrap when run directly (tsx entrypoint), not when imported by tests.
if (import.meta.url === `file://${process.argv[1]}`) {
  startRelay().then(
    ({ port, execPort }) =>
      console.log(
        `sandbox-relay attach :${port}${execPort ? `, exec :${execPort}` : ' (exec on the same listener)'}`,
      ),
    // Every boot refusal (a missing or clashing exec token, an unbindable address) lands here. Left
    // unhandled it would print a raw stack; the operator needs the reason, on one line.
    (err: unknown) => {
      console.error(
        `sandbox-relay: refusing to start: ${err instanceof Error ? err.message : String(err)}`,
      );
      process.exit(1);
    },
  );
}
