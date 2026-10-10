import { describe, expect, it } from 'vitest';
import { makeClientTokenAuthenticator, workspaceKeyAllowed } from '../src/client-tokens.js';

const T1 = 'a'.repeat(32); // notsecret
const T2 = 'b'.repeat(40); // notsecret

describe('makeClientTokenAuthenticator', () => {
  it('admits no client when MOCA_RELAY_CLIENT_TOKENS is unset or blank', () => {
    expect(makeClientTokenAuthenticator({})(T1)).toBeUndefined();
    expect(makeClientTokenAuthenticator({ MOCA_RELAY_CLIENT_TOKENS: ' ' })(T1)).toBeUndefined();
  });

  it('maps each token to its sandbox and workspace_key prefix', () => {
    const auth = makeClientTokenAuthenticator({
      MOCA_RELAY_CLIENT_TOKENS: `moca_microvm_0:sbx-alice-:${T1}, moca_microvm_0:sbx-bob-:${T2}`,
    });
    expect(auth(T1)).toEqual({ sandboxId: 'moca_microvm_0', prefix: 'sbx-alice-' });
    expect(auth(T2)).toEqual({ sandboxId: 'moca_microvm_0', prefix: 'sbx-bob-' });
    expect(auth(undefined)).toBeUndefined();
    expect(auth('')).toBeUndefined();
    expect(auth('a'.repeat(31))).toBeUndefined();
    expect(auth('c'.repeat(32))).toBeUndefined();
  });

  it.each([
    ['too few fields', `moca_microvm_0:${T1}`],
    ['an empty sandbox id', `:sbx-a-:${T1}`],
    ['an empty prefix', `moca_microvm_0::${T1}`],
    ['a prefix with a slash', `moca_microvm_0:sbx/a-:${T1}`],
    ['a short token', 'moca_microvm_0:sbx-a-:short'],
    ['a repeated token', `w:sbx-a-:${T1},w:sbx-b-:${T1}`],
  ])('refuses to build with %s, without echoing any token', (_why, value) => {
    let err: unknown;
    try {
      makeClientTokenAuthenticator({ MOCA_RELAY_CLIENT_TOKENS: value });
    } catch (e) {
      err = e;
    }
    expect((err as Error)?.message).toMatch(/MOCA_RELAY_CLIENT_TOKENS entry 1|entry 2/);
    expect((err as Error).message).not.toContain(T1);
    expect((err as Error).message).not.toContain('short');
  });

  it('refuses a client token equal to the exec token or a sandbox token, naming the variable', () => {
    for (const name of ['MOCA_RELAY_EXEC_TOKEN', 'SH_RELAY_TOKEN', 'SH_RELAY_TOKEN_w1']) {
      expect(() =>
        makeClientTokenAuthenticator({ MOCA_RELAY_CLIENT_TOKENS: `w:sbx-a-:${T1}`, [name]: T1 }),
      ).toThrow(new RegExp(`entry 1: token equals ${name}$`));
    }
  });
});

describe('workspaceKeyAllowed', () => {
  const grant = { sandboxId: 'w', prefix: 'sbx-alice-' };
  it.each([
    ['sbx-alice-calc', true],
    ['sbx-alice-a.b_c-1', true],
    ['sbx-alice-', false], // the bare prefix names no workspace of its own
    ['sbx-bob-calc', false],
    ['xsbx-alice-calc', false],
    ['sbx-alice-a/b', false],
    ['sbx-alice-../sbx-bob-x', false],
    ['', false],
  ])('%s -> %s', (key, ok) => {
    expect(workspaceKeyAllowed(grant, key)).toBe(ok);
  });
});
