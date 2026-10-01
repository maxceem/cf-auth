/**
 * OAuth connection tokens: their format, their generations, and how a
 * presented one is resolved.
 *
 * A token names the connection it belongs to, `<prefix><connectionId>.<secret>`
 * with 32 random bytes of base64url as the secret, and is resolved only
 * inside that connection: its current and previous generation are loaded and
 * the SHA-256 digest of the whole token is compared with theirs. Nothing is
 * ever looked up by digest across connections, so knowing a connection id
 * gives nothing, and only a real secret can match.
 */
import { desc, eq } from "drizzle-orm";
import type { CfAuthDatabase } from "../config.js";
import { randomToken, sha256Hex, timingSafeEqual } from "../crypto.js";
import type { CfAuthTables } from "../schema.js";

export type OAuthTokenRow = CfAuthTables["oauthToken"]["$inferSelect"];
export type OAuthTokenInsert = CfAuthTables["oauthToken"]["$inferInsert"];

/** A connection id as it may appear in a token: what `crypto.randomUUID()` and derived ids look like. */
export const connectionIdPattern = /^[A-Za-z0-9_-]{1,128}$/;
/** 32 bytes, base64url, no padding. */
const secretPattern = /^[A-Za-z0-9_-]{43}$/;

/**
 * The connection id a token names, or null when the token is not shaped
 * `<prefix><connectionId>.<secret>`; such a token is unknown.
 */
export const parseOAuthToken = (token: unknown, prefix: string): string | null => {
  if (typeof token !== "string" || !token.startsWith(prefix)) return null;
  const rest = token.slice(prefix.length);
  const dot = rest.indexOf(".");
  if (dot <= 0) return null;
  const connectionId = rest.slice(0, dot);
  const secret = rest.slice(dot + 1);
  return connectionIdPattern.test(connectionId) && secretPattern.test(secret) ? connectionId : null;
};

export interface IssuedGeneration {
  accessToken: string;
  refreshToken: string;
  /** The row to store: digests only. */
  row: OAuthTokenInsert & { id: string };
}

/** A new generation of a connection's tokens, and the row that stores their digests. */
export const issueGeneration = async (input: {
  prefix: { access: string; refresh: string };
  connectionId: string;
  generation: number;
  now: number;
  accessTokenTtlMs: number;
}): Promise<IssuedGeneration> => {
  const accessToken = `${input.prefix.access}${input.connectionId}.${randomToken(32)}`;
  const refreshToken = `${input.prefix.refresh}${input.connectionId}.${randomToken(32)}`;
  return {
    accessToken,
    refreshToken,
    row: {
      id: crypto.randomUUID(),
      apiKeyId: input.connectionId,
      generation: input.generation,
      accessTokenHash: await sha256Hex(accessToken),
      accessExpiresAt: new Date(input.now + input.accessTokenTtlMs),
      refreshTokenHash: await sha256Hex(refreshToken),
      rotatedAt: null,
      sealedResponse: null,
      createdAt: new Date(input.now),
    },
  };
};

export type ResolvedOAuthToken =
  | { kind: "unknown" }
  | {
      kind: "current" | "previous";
      connectionId: string;
      /** The generation the token matched. */
      generation: OAuthTokenRow;
      /** The connection's stored generations, newest first: at most two. */
      generations: OAuthTokenRow[];
    };

/**
 * Resolves a presented access or refresh token within the connection it
 * names: `current` when it matches the newest generation, `previous` when it
 * matches the one before, `unknown` otherwise — malformed, another prefix, no
 * such connection, or a secret that matches neither.
 */
export const resolveToken = async (
  db: CfAuthDatabase,
  tables: CfAuthTables,
  input: { token: unknown; prefix: string; type: "access" | "refresh" },
): Promise<ResolvedOAuthToken> => {
  const connectionId = parseOAuthToken(input.token, input.prefix);
  if (!connectionId) return { kind: "unknown" };
  const { oauthToken } = tables;
  const generations = await db
    .select()
    .from(oauthToken)
    .where(eq(oauthToken.apiKeyId, connectionId))
    .orderBy(desc(oauthToken.generation))
    .limit(2);
  const digest = await sha256Hex(input.token as string);
  const stored = (row: OAuthTokenRow) =>
    input.type === "access" ? row.accessTokenHash : row.refreshTokenHash;
  // Both compared whatever the first says, so the time taken says nothing.
  const matches = generations.map((row) => timingSafeEqual(digest, stored(row)));
  const index = matches.indexOf(true);
  if (index < 0) return { kind: "unknown" };
  return {
    kind: index === 0 ? "current" : "previous",
    connectionId,
    generation: generations[index]!,
    generations,
  };
};
