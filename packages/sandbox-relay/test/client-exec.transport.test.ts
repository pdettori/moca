import {
  Metadata,
  ServerCredentials,
  credentials,
  makeGenericClientConstructor,
  status,
  type Client,
  type ClientDuplexStream,
} from '@grpc/grpc-js';
import { afterEach, describe, expect, it } from 'vitest';
import {
  SandboxExecClient,
  SandboxWorkerService,
  type ServerFrame,
  type WorkerFrame,
} from '@moca/k8s-sandbox';
import type { RecordStore } from '@moca/harness';
import { makeClientTokenAuthenticator } from '../src/client-tokens.js';
import { buildServer, makeExecTokenValidator } from '../src/main.js';

const records: RecordStore = { put: async () => {}, remove: async () => {}, list: async () => [] };
const closers: Array<() => unknown> = [];
afterEach(async () => {
  for (const c of closers.splice(0)) await c();
});

const EXEC = 'harness-exec-token-0123456789abcdef'; // notsecret
const ALICE = 'alice-client-token-0123456789abcdef'; // notsecret
const BOB = 'bob-client-token-0123456789abcdefgh'; // notsecret

const WorkerClient = makeGenericClientConstructor(SandboxWorkerService, 'SandboxWorker');

/**
 * A relay with one fake worker 'w' attached. The worker ends every Exec with exit 0, except
 * `hold`, which it never answers until aborted. `seen` records what reached it.
 */
async function relayWithWorker() {
  const { server } = buildServer({
    records,
    validateToken: () => true,
    validateExecToken: makeExecTokenValidator({ MOCA_RELAY_EXEC_TOKEN: EXEC }),
    authenticateClient: makeClientTokenAuthenticator({
      MOCA_RELAY_CLIENT_TOKENS: `w:sbx-alice-:${ALICE},w:sbx-bob-:${BOB}`,
    }),
  });
  const port = await new Promise<number>((resolve, reject) =>
    server.bindAsync('127.0.0.1:0', ServerCredentials.createInsecure(), (e, p) =>
      e ? reject(e) : resolve(p),
    ),
  );
  closers.push(() => server.forceShutdown());
  const addr = `127.0.0.1:${port}`;

  const seen: { execs: string[]; aborts: number[] } = { execs: [], aborts: [] };
  const worker = new WorkerClient(addr, credentials.createInsecure()) as unknown as Client & {
    attach: () => ClientDuplexStream<WorkerFrame, ServerFrame>;
  };
  const stream = worker.attach();
  stream.on('data', (f: ServerFrame) => {
    if (f.exec) {
      seen.execs.push(f.exec.workspaceKey);
      if (f.exec.command !== 'hold') {
        stream.write({
          end: { reqId: f.exec.reqId, exitCode: 0, truncated: false },
        } as WorkerFrame);
      }
    }
    if (f.abort) {
      seen.aborts.push(Number(f.abort.reqId));
      stream.write({
        end: { reqId: f.abort.reqId, exitCode: -9, truncated: false },
      } as WorkerFrame);
    }
  });
  stream.on('error', () => {});
  stream.write({
    hello: {
      sandboxId: 'w',
      labels: {},
      capabilities: [],
      image: '',
      arch: 'amd64',
      capacityMax: 4,
      trust: 'untrusted',
    },
  } as WorkerFrame);
  closers.push(() => {
    stream.cancel();
    worker.close();
  });
  await new Promise((r) => setTimeout(r, 150)); // let the relay park the worker
  return { addr, seen };
}

function md(token: string): Metadata {
  const m = new Metadata();
  m.set('authorization', `Bearer ${token}`);
  return m;
}

/** Starts an Exec; `done` resolves to its terminal status code. */
function startExec(
  addr: string,
  token: string,
  opts: { sandboxId?: string; key: string; reqId?: number; command?: string },
) {
  const client = new SandboxExecClient(addr, credentials.createInsecure());
  const call = client.exec(
    {
      sandboxId: opts.sandboxId ?? 'w',
      exec: {
        reqId: opts.reqId ?? 1,
        command: opts.command ?? 'true',
        stdin: new Uint8Array(),
        timeoutS: 5,
        streaming: true,
        workspaceKey: opts.key,
      },
    },
    md(token),
  );
  const done = new Promise<number>((resolve) => {
    call.on('data', () => {});
    call.on('error', (err: { code: number }) => resolve(err.code));
    call.on('end', () => resolve(status.OK));
  }).finally(() => client.close());
  return { done };
}

function abort(addr: string, token: string, reqId: number): Promise<number> {
  const client = new SandboxExecClient(addr, credentials.createInsecure());
  return new Promise<number>((resolve) =>
    client.abort({ sandboxId: 'w', reqId }, md(token), (err: { code: number } | null) =>
      resolve(err ? err.code : status.OK),
    ),
  ).finally(() => client.close());
}

describe('client tokens on SandboxExec', () => {
  it('runs a client Exec inside its prefix', async () => {
    const { addr, seen } = await relayWithWorker();
    expect(await startExec(addr, ALICE, { key: 'sbx-alice-calc' }).done).toBe(status.OK);
    expect(seen.execs).toEqual(['sbx-alice-calc']);
  });

  it.each([
    ['outside its prefix', { key: 'sbx-bob-calc' }],
    ['with an empty workspace_key', { key: '' }],
    ['with a path in the key', { key: 'sbx-alice-../sbx-bob-calc' }],
    ['on a worker its token does not name', { sandboxId: 'other', key: 'sbx-alice-calc' }],
  ])('refuses a client Exec %s, before it reaches any worker', async (_why, opts) => {
    const { addr, seen } = await relayWithWorker();
    expect(await startExec(addr, ALICE, opts).done).toBe(status.PERMISSION_DENIED);
    expect(seen.execs).toEqual([]);
  });

  it('still refuses an unknown token as UNAUTHENTICATED', async () => {
    const { addr, seen } = await relayWithWorker();
    const unknown = 'nobody-token-0123456789abcdefghijk'; // notsecret
    expect(await startExec(addr, unknown, { key: 'sbx-alice-calc' }).done).toBe(
      status.UNAUTHENTICATED,
    );
    expect(seen.execs).toEqual([]);
  });

  it('leaves the harness exec token unrestricted', async () => {
    const { addr, seen } = await relayWithWorker();
    expect(await startExec(addr, EXEC, { key: 'session-123' }).done).toBe(status.OK);
    expect(seen.execs).toEqual(['session-123']);
  });

  it('lets a client abort its own running Exec, and nobody else’s', async () => {
    const { addr, seen } = await relayWithWorker();
    const held = startExec(addr, ALICE, { key: 'sbx-alice-calc', reqId: 7, command: 'hold' });
    await new Promise((r) => setTimeout(r, 100));

    expect(await abort(addr, BOB, 7)).toBe(status.PERMISSION_DENIED);
    expect(await abort(addr, ALICE, 8)).toBe(status.PERMISSION_DENIED); // not one of hers
    expect(seen.aborts).toEqual([]);

    expect(await abort(addr, ALICE, 7)).toBe(status.OK);
    await held.done;
    expect(seen.aborts).toEqual([7]);
  });

  it('lets the harness token abort any Exec', async () => {
    const { addr, seen } = await relayWithWorker();
    const held = startExec(addr, ALICE, { key: 'sbx-alice-calc', reqId: 9, command: 'hold' });
    await new Promise((r) => setTimeout(r, 100));
    expect(await abort(addr, EXEC, 9)).toBe(status.OK);
    await held.done;
    expect(seen.aborts).toEqual([9]);
  });
});
