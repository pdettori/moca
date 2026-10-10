import { timingSafeEqual } from 'node:crypto';

/**
 * What a client token admits: Execs on ONE worker, in workspaces whose key starts with a prefix.
 *
 * Client tokens let a direct `sandbox/v1` client (a developer's own code, a local MCP server) use the
 * relay without the harness's `MOCA_RELAY_EXEC_TOKEN`, which admits every workspace on every worker.
 * A demo-grade stand-in for SBX1's per-sandbox tokens (spec §6.2), not that design.
 *
 * The worker is named per token because only microvm-worker keys a workspace on `workspace_key`;
 * the container worker ignores it and shares one /workspace (sandbox.proto, Exec.workspace_key).
 * List only workers that honour the key.
 */
export interface ClientGrant {
  sandboxId: string;
  prefix: string;
}

const NAME = /^[A-Za-z0-9._-]+$/;
const MIN_TOKEN_LENGTH = 32;

/**
 * Parses `MOCA_RELAY_CLIENT_TOKENS`: comma-separated `<sandbox_id>:<workspace_key_prefix>:<token>`.
 * Unset or blank admits no client. FAIL-CLOSED on anything malformed: the relay does not boot, and
 * the error names the entry by position and the clashing variable, never a token. A client token
 * must differ from the exec token, from every sandbox token, and from every other client token.
 */
export function makeClientTokenAuthenticator(
  env: NodeJS.ProcessEnv,
): (presented: string | undefined) => ClientGrant | undefined {
  const raw = env.MOCA_RELAY_CLIENT_TOKENS?.trim();
  if (!raw) return () => undefined;

  const reserved = Object.keys(env)
    .filter(
      (k) =>
        k === 'MOCA_RELAY_EXEC_TOKEN' || k === 'SH_RELAY_TOKEN' || k.startsWith('SH_RELAY_TOKEN_'),
    )
    .sort();
  const entries: Array<{ grant: ClientGrant; token: Buffer }> = [];
  raw.split(',').forEach((part, i) => {
    const where = `MOCA_RELAY_CLIENT_TOKENS entry ${i + 1}`;
    // The token is everything after the second colon, so a token may itself contain colons.
    const [sandboxId, prefix, ...rest] = part.trim().split(':');
    const token = rest.join(':');
    if (rest.length === 0) throw new Error(`${where}: expected <sandbox_id>:<prefix>:<token>`);
    if (!NAME.test(sandboxId)) throw new Error(`${where}: invalid sandbox id`);
    if (!NAME.test(prefix)) throw new Error(`${where}: prefix must match ${NAME}`);
    if (token.length < MIN_TOKEN_LENGTH) {
      throw new Error(`${where}: token must be at least ${MIN_TOKEN_LENGTH} characters`);
    }
    const clash = reserved.find((k) => env[k] === token);
    if (clash) throw new Error(`${where}: token equals ${clash}`);
    if (entries.some((e) => e.token.equals(Buffer.from(token)))) {
      throw new Error(`${where}: token repeats an earlier entry`);
    }
    entries.push({ grant: { sandboxId, prefix }, token: Buffer.from(token) });
  });

  return (presented) => {
    if (!presented) return undefined;
    const got = Buffer.from(presented);
    // Every entry is compared, so the time taken does not say which one (if any) matched.
    let found: ClientGrant | undefined;
    for (const e of entries) {
      if (got.length === e.token.length && timingSafeEqual(got, e.token)) found = e.grant;
    }
    return found;
  };
}

/**
 * A key the grant may use: its prefix plus at least one more character, and nothing that could
 * be read as a path. vmpool refuses a key that does not resolve directly inside its root as well;
 * this keeps the decision at the relay, before anything reaches a worker.
 */
export function workspaceKeyAllowed(grant: ClientGrant, key: string): boolean {
  return key.length > grant.prefix.length && key.startsWith(grant.prefix) && NAME.test(key);
}
