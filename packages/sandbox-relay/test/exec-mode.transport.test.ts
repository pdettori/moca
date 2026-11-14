import { status } from '@grpc/grpc-js';
import { afterEach, describe, expect, it } from 'vitest';
import { ExecKind, ProcessArgs, SandboxMode } from '@moca/k8s-sandbox';
import { SANDBOX_TOKEN_TYP, type SandboxTokenClaims } from '@moca/control-plane';
import { claimsToExecMode } from '../src/sandbox-caller.js';
import {
  HARNESS,
  K,
  claims,
  closeAll,
  exec,
  idsOf,
  reasons,
  relay,
  token,
  wid,
  worker,
} from './helpers/sandbox-relay.js';

// Lease-mode spec §8.2: on the sandbox-token path the relay is the only setter of an Exec's mode
// fields. Whatever a client writes into Exec.mode, mode_epoch or idle_timeout_s is overwritten
// from the verified claims, so a per-exec token can never raise its own lease mode; keepalive is
// the client's opt-in and passes through. The harness never uses leases: its Execs go out with all
// four zeroed. A worker's lease event reaches the caller on the Exec it names, under the caller's
// own req_id.

afterEach(closeAll);

/** What a client that tries to pick its own lease writes into its Exec. */
const FORGED = {
  mode: SandboxMode.SANDBOX_MODE_LEASE,
  modeEpoch: 999,
  idleTimeoutS: 5,
};
const modeOf = (e: { mode: number; modeEpoch: number; idleTimeoutS: number }) => ({
  mode: e.mode,
  modeEpoch: e.modeEpoch,
  idleTimeoutS: e.idleTimeoutS,
});

describe('claimsToExecMode', () => {
  const c = (over: Partial<SandboxTokenClaims>) =>
    ({ mode: 'per-exec', mode_epoch: 0, idle_timeout_s: 0, ...over }) as SandboxTokenClaims;
  it.each([
    ['per-exec', SandboxMode.SANDBOX_MODE_PER_EXEC],
    ['lease', SandboxMode.SANDBOX_MODE_LEASE],
    ['lease+processes', SandboxMode.SANDBOX_MODE_LEASE_PROCESSES],
  ] as const)('maps the %s claim to its proto enum', (mode, want) => {
    expect(claimsToExecMode(c({ mode, mode_epoch: 4, idle_timeout_s: 600 }))).toEqual({
      mode: want,
      modeEpoch: 4,
      idleTimeoutS: 600,
    });
  });
});

describe('the relay sets Exec mode fields from the token (lease-mode §8.2)', () => {
  it('relay overwrites client mode fields from claims', async () => {
    const r = await relay();
    const w = await worker(r.attach, 'sbx_default');
    const perExec = await exec(r.exec, { token: token(), reqId: 1, fields: FORGED }).done;
    expect(perExec.code).toBe(status.OK);
    const lease = await exec(r.exec, {
      token: token({ mode: 'lease', modeEpoch: 3, idleTimeoutS: 600 }),
      reqId: 2,
      fields: { ...FORGED, mode: SandboxMode.SANDBOX_MODE_LEASE_PROCESSES },
    }).done;
    expect(lease.code).toBe(status.OK);
    expect(w.execs.map(modeOf)).toEqual([
      { mode: SandboxMode.SANDBOX_MODE_PER_EXEC, modeEpoch: 0, idleTimeoutS: 0 },
      { mode: SandboxMode.SANDBOX_MODE_LEASE, modeEpoch: 3, idleTimeoutS: 600 },
    ]);
  });

  it('keepalive passes through', async () => {
    const r = await relay();
    const w = await worker(r.attach, 'sbx_default');
    const t = token({ mode: 'lease', modeEpoch: 1 });
    expect(
      (await exec(r.exec, { token: t, reqId: 1, fields: { keepalive: true } }).done).code,
    ).toBe(status.OK);
    expect((await exec(r.exec, { token: t, reqId: 2 }).done).code).toBe(status.OK);
    expect(w.execs.map((e) => e.keepalive)).toEqual([true, false]);
  });

  it('harness path zeroes mode fields', async () => {
    const r = await relay({ MOCA_RELAY_EXEC_TOKEN: HARNESS });
    const w = await worker(r.attach, 'sbx_default');
    const res = await exec(r.exec, {
      token: HARNESS,
      reqId: 900,
      wsk: 'run-1',
      fields: { ...FORGED, keepalive: true },
    }).done;
    expect(res.code).toBe(status.OK);
    expect(w.execs.map((e) => ({ ...modeOf(e), keepalive: e.keepalive }))).toEqual([
      {
        mode: SandboxMode.SANDBOX_MODE_UNSPECIFIED,
        modeEpoch: 0,
        idleTimeoutS: 0,
        keepalive: false,
      },
    ]);
  });

  it('an old token without mode claims routes per-exec epoch 0', async () => {
    const r = await relay();
    const w = await worker(r.attach, 'sbx_default');
    const old = claims();
    expect(old).not.toHaveProperty('mode');
    const t = K.signer.signJws(SANDBOX_TOKEN_TYP, old);
    const res = await exec(r.exec, { token: t, reqId: 1, fields: FORGED }).done;
    expect(res.code).toBe(status.OK);
    expect(w.execs.map(modeOf)).toEqual([
      { mode: SandboxMode.SANDBOX_MODE_PER_EXEC, modeEpoch: 0, idleTimeoutS: 0 },
    ]);
  });
});

describe('lease events reach the caller (lease-mode §4)', () => {
  it('lease event reaches the sandbox caller with its own req_id', async () => {
    const r = await relay();
    const w = await worker(r.attach, 'sbx_default', 'auto', 0, () => [
      {
        lease: {
          state: 'start',
          atUnixMs: 1_700_000_000_123,
          mode: SandboxMode.SANDBOX_MODE_LEASE,
          ageMs: 0,
        },
      },
      { chunk: { data: 'hi' } },
      { end: { exitCode: 0 } },
    ]);
    const res = await exec(r.exec, {
      token: token({ mode: 'lease', modeEpoch: 2 }),
      reqId: 7,
    }).done;
    expect(res.code).toBe(status.OK);
    // The worker saw the relay's id; the caller sees only its own, on every frame.
    expect(w.execs.map((e) => e.reqId)).toEqual([wid('sbx-aaaa', 7)]);
    expect(idsOf(res.events)).toEqual([7, 7, 7]);
    expect(res.events[0]!.lease).toEqual({
      reqId: 7,
      state: 'start',
      reason: '',
      atUnixMs: 1_700_000_000_123,
      mode: SandboxMode.SANDBOX_MODE_LEASE,
      ageMs: 0,
      processes: [],
      endsByUnixMs: 0,
      tracked: [],
    });
    const kinds = res.events.map((ev) => Object.entries(ev).flatMap(([k, v]) => (v ? [k] : [])));
    expect(kinds).toEqual([['lease'], ['chunk'], ['end']]);
  });
});

// Plan 5, level 2: an Exec's kind and its process arguments travel the one Exec path (spec §8.3).
// The sandbox path passes them through, but forwards a process kind only on a token whose mode
// claim is lease+processes: the relay is the first line of defence, ahead of the worker's own
// processes_not_enabled. The harness never runs processes: its Execs go out as plain commands.
describe('Exec kinds (plan 5, level 2)', () => {
  const PROCESSES = token({ mode: 'lease+processes', modeEpoch: 3 });
  const START = {
    kind: ExecKind.EXEC_KIND_PROCESS_START,
    process: ProcessArgs.fromPartial({ name: 'web', cwd: 'app' }),
  };
  const kindOf = (e: { kind: number; process: ProcessArgs | undefined }) => ({
    kind: e.kind,
    process: e.process,
  });
  type ExecLine = { audit: string; kind?: string; process?: string; cmd?: string };
  const execLines = (lines: string[]) =>
    lines.map((l) => JSON.parse(l) as ExecLine).filter((l) => l.audit === 'sandbox_exec');

  it('kind and process pass through on the sandbox path', async () => {
    const r = await relay();
    const w = await worker(r.attach, 'sbx_default');
    const started = await exec(r.exec, {
      token: PROCESSES,
      reqId: 1,
      command: 'npm run dev',
      fields: START,
    }).done;
    expect(started.code).toBe(status.OK);
    const logs = await exec(r.exec, {
      token: PROCESSES,
      reqId: 2,
      command: '',
      fields: {
        kind: ExecKind.EXEC_KIND_PROCESS_LOGS,
        process: ProcessArgs.fromPartial({ id: '3', tail: 50 }),
      },
    }).done;
    expect(logs.code).toBe(status.OK);
    expect((await exec(r.exec, { token: PROCESSES, reqId: 3 }).done).code).toBe(status.OK);
    expect(w.execs.map(kindOf)).toEqual([
      { kind: ExecKind.EXEC_KIND_PROCESS_START, process: START.process },
      {
        kind: ExecKind.EXEC_KIND_PROCESS_LOGS,
        process: ProcessArgs.fromPartial({ id: '3', tail: 50 }),
      },
      { kind: ExecKind.EXEC_KIND_COMMAND, process: undefined },
    ]);
    expect(w.execs[0]!.command).toBe('npm run dev');
  });

  it('the harness path zeroes kind and process', async () => {
    const r = await relay({ MOCA_RELAY_EXEC_TOKEN: HARNESS });
    const w = await worker(r.attach, 'sbx_default');
    const res = await exec(r.exec, { token: HARNESS, reqId: 900, wsk: 'run-1', fields: START })
      .done;
    expect(res.code).toBe(status.OK);
    expect(w.execs.map(kindOf)).toEqual([{ kind: ExecKind.EXEC_KIND_COMMAND, process: undefined }]);
  });

  it.each([
    ['lease', token({ mode: 'lease', modeEpoch: 2 }), 'lease'],
    ['per-exec', token({ mode: 'per-exec' }), 'per-exec'],
    ['absent', K.signer.signJws(SANDBOX_TOKEN_TYP, claims()), 'per-exec'],
  ])('mode claim %s: every process kind is refused before the worker', async (_, t, mode) => {
    const r = await relay();
    const w = await worker(r.attach, 'sbx_default');
    const why = `processes_not_enabled: this sandbox's mode is ${mode}`;
    for (const kind of [
      ExecKind.EXEC_KIND_PROCESS_START,
      ExecKind.EXEC_KIND_PROCESS_LIST,
      ExecKind.EXEC_KIND_PROCESS_LOGS,
      ExecKind.EXEC_KIND_PROCESS_STOP,
    ]) {
      const res = await exec(r.exec, { token: t, fields: { ...START, kind } }).done;
      expect(res.code).toBe(status.FAILED_PRECONDITION);
      expect(res.details).toBe(why);
    }
    expect(w.execs).toEqual([]);
    expect(reasons(r.lines).map((l) => [l.audit, l.outcome, l.reason])).toEqual(
      Array(4).fill(['sandbox_exec', 'refused', why]),
    );
  });

  it('lease+processes allows process_start', async () => {
    const r = await relay();
    const w = await worker(r.attach, 'sbx_default');
    const res = await exec(r.exec, { token: PROCESSES, reqId: 4, fields: START }).done;
    expect(res.code).toBe(status.OK);
    expect(w.execs).toHaveLength(1);
  });

  it.each([5, 99, -1])('an unknown kind %d is refused INVALID_ARGUMENT', async (kind) => {
    const r = await relay();
    const w = await worker(r.attach, 'sbx_default');
    const res = await exec(r.exec, { token: PROCESSES, fields: { kind } }).done;
    expect(res.code).toBe(status.INVALID_ARGUMENT);
    expect(res.details).toBe(`unknown exec kind ${kind}`);
    expect(w.execs).toEqual([]);
    expect(execLines(r.lines)).toEqual([
      expect.objectContaining({
        outcome: 'refused',
        kind: `unknown(${kind})`,
        reason: `unknown exec kind ${kind}`,
      }),
    ]);
  });

  it('the audit line has kind, and process as p<id> or the name, never its command', async () => {
    const r = await relay();
    await worker(r.attach, 'sbx_default');
    const send = (reqId: number, fields: Parameters<typeof exec>[1]['fields'], command = '') =>
      exec(r.exec, { token: PROCESSES, reqId, command, fields }).done;
    await send(1, {}, 'true');
    await send(2, START, 'npm run dev');
    await send(3, { kind: ExecKind.EXEC_KIND_PROCESS_START, process: undefined }, 'sleep 9');
    await send(4, { kind: ExecKind.EXEC_KIND_PROCESS_LIST });
    await send(5, {
      kind: ExecKind.EXEC_KIND_PROCESS_LOGS,
      process: ProcessArgs.fromPartial({ id: '3', name: 'web' }),
    });
    await send(6, {
      kind: ExecKind.EXEC_KIND_PROCESS_STOP,
      process: ProcessArgs.fromPartial({ name: 'web', signal: 'KILL' }),
    });
    const lines = execLines(r.lines);
    expect(lines.map((l) => [l.kind, l.process])).toEqual([
      ['command', undefined],
      ['process_start', 'web'],
      ['process_start', undefined],
      ['process_list', undefined],
      ['process_logs', 'p3'],
      ['process_stop', 'web'],
    ]);
    // Without SH_SANDBOX_AUDIT_COMMANDS, no command anywhere: not as cmd, not as process.
    for (const l of lines) expect(l).not.toHaveProperty('cmd');
    expect(r.lines.join('\n')).not.toContain('npm run dev');
  });

  it("cuts a caller-chosen process name to the audit line's 128 bytes", async () => {
    const r = await relay();
    await worker(r.attach, 'sbx_default');
    await exec(r.exec, {
      token: PROCESSES,
      fields: {
        kind: ExecKind.EXEC_KIND_PROCESS_STOP,
        process: ProcessArgs.fromPartial({ name: 'n'.repeat(5000) }),
      },
    }).done;
    expect(execLines(r.lines).map((l) => l.process)).toEqual(['n'.repeat(128)]);
  });

  it("logs a process_start's command only under SH_SANDBOX_AUDIT_COMMANDS", async () => {
    const r = await relay({ SH_SANDBOX_AUDIT_COMMANDS: '1' });
    await worker(r.attach, 'sbx_default');
    await exec(r.exec, { token: PROCESSES, reqId: 1, command: 'npm run dev', fields: START }).done;
    expect(execLines(r.lines)).toEqual([
      expect.objectContaining({ kind: 'process_start', process: 'web', cmd: 'npm run dev' }),
    ]);
  });

  it('a refused process kind is audited with its kind and process', async () => {
    const r = await relay();
    await worker(r.attach, 'sbx_default');
    await exec(r.exec, { token: token({ mode: 'lease' }), command: 'npm run dev', fields: START })
      .done;
    expect(execLines(r.lines)).toEqual([
      expect.objectContaining({
        outcome: 'refused',
        kind: 'process_start',
        process: 'web',
        reason: "processes_not_enabled: this sandbox's mode is lease",
      }),
    ]);
  });
});
