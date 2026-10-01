/**
 * OAuth connections: issuance, refresh with rotation and replay detection,
 * revocation, and access-token resolution.
 *
 * A connection is an `api_key` row with `source = 'oauth'`: it belongs to one
 * user in one organization, carries a grant, and ends when that row is
 * revoked or passes `expires_at` — so every rule that binds an API key binds
 * a connection too. Its tokens live in `oauth_token`, at most two generations
 * per connection. Every write here is one batch.
 *
 * The authorization request, consent and the code exchange live in
 * `./authorization.ts`; this service hands them its issuance and revocation
 * and answers them under `cfAuth.oauth`.
 *
 * Nothing here is an HTTP route: `token` and `revoke` answer the status and
 * the RFC 6749 §5.2 body for the app's own route to send.
 */
import { and, eq, isNull, lt, sql, type SQL } from "drizzle-orm";
import type { BatchItem } from "drizzle-orm/batch";
import { alias } from "drizzle-orm/sqlite-core";
import { sqliteNowMs } from "../authority.js";
import type { ResolvedCfAuthConfig, ResolvedOAuthConfig } from "../config.js";
import { createOperationsEngine, type CfAuthOperations, type OperationKind } from "../operations.js";
import { openTextForToken, randomToken, sealTextForToken, sha256Hex, timingSafeEqual } from "../crypto.js";
import { CfAuthError, validationError } from "../errors.js";
import { guardedInsert } from "../guarded-insert.js";
import type { CfAuthRepository } from "../repository.js";
import { emitCfAuthEvent, toOAuthAuthState } from "../service.js";
import {
  createEmptyAuthState,
  isCredentialGrant,
  isOrganizationExpired,
  oauthActionSources,
  type AuthState,
  type CredentialGrant,
  type OAuthActionSource,
} from "../types.js";
import {
  createOAuthAuthorization,
  createOAuthAuthorizeKind,
  type ApproveAuthorizationInput,
  type ApproveGuestAuthorizationInput,
  type AuthorizationServerMetadata,
  type OAuthAuthorizationDetails,
  type OAuthAuthorizeResult,
  type ProtectedResourceMetadata,
} from "./authorization.js";
import { oauthConnectionLiveSql, oauthMembershipLiveSql, oauthOrganizationLiveSql } from "./authority.js";
import { duplicateDescription, duplicatedParameter, formParams, type FormParams } from "./params.js";
import { connectionIdPattern, issueGeneration, parseOAuthToken, resolveToken, type IssuedGeneration, type OAuthTokenRow } from "./tokens.js";

/** How long after a rotation the previous refresh token replays its response. Fixed. */
export const oauthRefreshGraceMs = 30_000;
/** At most one rotation per this long per connection. Fixed. */
export const oauthRotationIntervalMs = 5_000;
/** How many statements {@link CfAuthOAuth.sweepStatements} returns. */
export const oauthSweepStatementCount = 1;

/** The successful token response (RFC 6749 §5.1). `scope` is always the connection's grant. */
export interface OAuthTokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: CredentialGrant;
}

export type OAuthErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "unsupported_grant_type"
  | "invalid_scope"
  | "invalid_target";

/** An RFC 6749 §5.2 error body. */
export interface OAuthErrorBody {
  error: OAuthErrorCode;
  error_description: string;
}

/** What `token` answers: 200 and the tokens, or 400 (401 for `invalid_client`) and the error. */
export type OAuthTokenResult =
  | { status: 200; body: OAuthTokenResponse }
  | { status: 400 | 401; body: OAuthErrorBody };

/** What `revoke` answers: 200 with no body (RFC 7009 §2.2), or the error. */
export type OAuthRevokeResult =
  | { status: 200; body: null }
  | { status: 400 | 401; body: OAuthErrorBody };

export interface CreateOAuthConnectionInput {
  userId: string;
  organizationId: string;
  /** The client the connection is issued to: a registered id or a CIMD URL. */
  clientId: string;
  /** The client's name, copied onto the connection's `name` and `label`. */
  clientName: string;
  /** `<issuer>` or `<issuer><resourcePath>`; stored normalised to the issuer. */
  resource: string;
  grant: CredentialGrant;
  /** Default: `Date.now()`. */
  now?: number;
  /** The connection's id. Default: a random UUID. */
  id?: string;
}

export interface OAuthConnectionStatements {
  connectionId: string;
  /**
   * Query builders for the caller's batch, in order: the guarded insert of
   * the connection row, then its first generation, which lands only if that
   * row did.
   */
  statements: BatchItem<"sqlite">[];
  /** The token response to answer once the batch has committed. */
  response: OAuthTokenResponse;
  /** Whether the connection landed. */
  landed(): Promise<boolean>;
  /** Emits `api_key.created` if it landed. Failures go to `onError`. */
  afterCommit(): Promise<void>;
}

export interface CfAuthOAuth {
  /**
   * `GET /.well-known/oauth-protected-resource<path>`: the RFC 9728 document
   * for the issuer (`""`) or one of `resourcePaths` (`"/mcp"`), whose
   * `resource` is the URL it is published for.
   */
  protectedResourceMetadata(path?: string): ProtectedResourceMetadata;
  /** `GET /.well-known/oauth-authorization-server`: the RFC 8414 document. */
  authorizationServerMetadata(): AuthorizationServerMetadata;
  /**
   * `GET /oauth/authorize`: validates the request and opens the pending
   * authorization. Answers the consent reference, an error redirect to the
   * client, or an error page when the client or its redirect URI cannot be
   * trusted. `rateLimitKey` is the browser's address, for the pending cap.
   */
  authorize(input: { query: URLSearchParams; rateLimitKey: string | null }): Promise<OAuthAuthorizeResult>;
  /** What the consent page shows, for the holder of the browser proof. */
  authorizationDetails(input: {
    id: string;
    proof: string;
    viewer: AuthState | null | undefined;
  }): Promise<OAuthAuthorizationDetails>;
  /**
   * The signed-in person allows the client into one of their accounts, with
   * the grant they chose. Idempotent: a completed authorization answers its
   * redirect again, whichever door completed it.
   */
  approveAuthorization(input: ApproveAuthorizationInput): Promise<{ redirect: string }>;
  /**
   * "Continue without an account": proof, then an already completed
   * authorization's redirect, then `admit`, then `rateLimit`, then
   * `provision` inside the batch that completes it.
   */
  approveGuestAuthorization(input: ApproveGuestAuthorizationInput): Promise<{ redirect: string; organizationId: string }>;
  /** The person declines: the `access_denied` redirect. */
  denyAuthorization(input: { id: string; proof: string }): Promise<{ redirect: string }>;
  /**
   * `POST /token`, form-encoded: `grant_type=authorization_code` exchanges a
   * code for a new connection, once; `grant_type=refresh_token` rotates.
   */
  token(input: { body: URLSearchParams }): Promise<OAuthTokenResult>;
  /** `POST /revoke` (RFC 7009): either token ends the whole connection. */
  revoke(input: { body: URLSearchParams }): Promise<OAuthRevokeResult>;
  /**
   * The {@link AuthState} an access token proves, or an empty state unless it
   * is the current generation's, unexpired, on a live connection bound to this
   * issuer, whose membership and organization are live. `source` is the
   * endpoint's, never read from the request.
   */
  resolveAccessTokenAuthState(token: string, context: { source: OAuthActionSource }): Promise<AuthState>;
  /**
   * Issues a connection and its first generation as statements for a batch of
   * the caller's own; `condition` is ANDed into the connection's guard with
   * the user's active membership and the organization's deadline. A trusted
   * boundary, like `issueServiceApiKey`: the code exchange is its caller.
   */
  connectionStatements(
    input: CreateOAuthConnectionInput & { condition?: SQL },
  ): Promise<OAuthConnectionStatements>;
  /** {@link CfAuthOAuth.connectionStatements} run in a batch of its own. Throws `409 connection_refused` if the guard refused. */
  createConnection(input: CreateOAuthConnectionInput): Promise<OAuthTokenResponse>;
  /**
   * Deletes the generations of connections that are revoked or past
   * `expires_at`, as {@link oauthSweepStatementCount} query builders.
   * Separate from the operation sweep.
   */
  sweepStatements(now?: number): BatchItem<"sqlite">[];
  /** Runs {@link CfAuthOAuth.sweepStatements} in one batch. */
  sweep(now?: number): Promise<void>;
}

const rotationSealInfo = "cf-auth:oauth-rotation-response";
const rotationSealContext = (connectionId: string, generation: number) =>
  `cf-auth:oauth-rotation:${connectionId}:${generation}`;

const fail = (error: OAuthErrorCode, description: string): { status: 400 | 401; body: OAuthErrorBody } => ({
  status: error === "invalid_client" ? 401 : 400,
  body: { error, error_description: description },
});

const maxClientIdLength = 2048;
const maxClientNameLength = 200;

/** The built-in kinds the OAuth service needs registered on the engine: none while it is off. */
export const oauthBuiltInKinds = (config: ResolvedCfAuthConfig): OperationKind[] =>
  config.oauth ? [createOAuthAuthorizeKind(config.oauth)] : [];

/**
 * The OAuth service, on an engine of its own that registers
 * `cf-auth:oauth.authorize`. `createCfAuth` builds one engine for both
 * `cfAuth.operations` and this service instead.
 */
export const createOAuthService = (
  config: ResolvedCfAuthConfig,
  repository: CfAuthRepository,
): CfAuthOAuth =>
  createOAuthServiceForEngine(
    config,
    repository,
    config.oauth
      ? createOperationsEngine(config, repository, { builtInKinds: oauthBuiltInKinds(config) }).internal
      : null,
  );

/**
 * The OAuth service on a given engine door, which must admit internal kinds
 * and have {@link oauthBuiltInKinds} registered. Not exported from the
 * package index.
 */
export const createOAuthServiceForEngine = (
  config: ResolvedCfAuthConfig,
  repository: CfAuthRepository,
  internalOperations: CfAuthOperations | null,
): CfAuthOAuth => {
  const { db, tables } = config;
  const { apiKey, oauthToken } = tables;

  const settings = (): ResolvedOAuthConfig => {
    if (!config.oauth) {
      throw validationError("OAuth is disabled; set `oauth.enabled: true` to use it");
    }
    return config.oauth;
  };

  const runBatch = async (statements: readonly unknown[]): Promise<unknown[]> =>
    (db as unknown as { batch(queries: readonly unknown[]): Promise<unknown[]> }).batch(statements);

  const emit = (event: Parameters<typeof emitCfAuthEvent>[1]) => emitCfAuthEvent(config, event);

  /** `<issuer>` or one of its resource paths, normalised to the issuer; null for anything else. */
  const normalizeResource = (oauth: ResolvedOAuthConfig, value: string): string | null =>
    oauth.resources.includes(value) ? oauth.issuer : null;

  /** The current refresh token's expiry, capped at creation + `connectionMaxAgeMs`. */
  const connectionExpiry = (oauth: ResolvedOAuthConfig, createdAt: number, now: number) =>
    Math.min(
      now + oauth.refreshTokenTtlMs,
      oauth.connectionMaxAgeMs === null ? Number.POSITIVE_INFINITY : createdAt + oauth.connectionMaxAgeMs,
    );

  const tokenResponse = (
    oauth: ResolvedOAuthConfig,
    issued: IssuedGeneration,
    grant: CredentialGrant,
  ): OAuthTokenResponse => ({
    access_token: issued.accessToken,
    token_type: "Bearer",
    expires_in: Math.floor(oauth.accessTokenTtlMs / 1000),
    refresh_token: issued.refreshToken,
    scope: grant,
  });

  const connectionColumns = {
    id: apiKey.id,
    userId: apiKey.userId,
    organizationId: apiKey.organizationId,
    name: apiKey.name,
    clientId: apiKey.clientId,
    resource: apiKey.resource,
    grant: apiKey.grant,
    enabled: apiKey.enabled,
    revokedAt: apiKey.revokedAt,
    expiresAt: apiKey.expiresAt,
    createdAt: apiKey.createdAt,
  };
  type Connection = {
    id: string;
    userId: string;
    organizationId: string;
    name: string;
    clientId: string | null;
    resource: string | null;
    grant: string;
    enabled: boolean;
    revokedAt: Date | null;
    expiresAt: Date | null;
    createdAt: Date;
  };

  const loadConnection = async (connectionId: string): Promise<Connection | null> =>
    (await db
      .select(connectionColumns)
      .from(apiKey)
      .where(and(eq(apiKey.id, connectionId), eq(apiKey.source, "oauth")))
      .get()) ?? null;

  /** An unknown stored grant fails closed, as the least one. */
  const grantOf = (connection: Connection): CredentialGrant =>
    isCredentialGrant(connection.grant) ? connection.grant : "read";

  /** The row itself: enabled, unrevoked, before `expires_at`. */
  const rowLive = (connection: Connection, now: number) =>
    Boolean(connection.enabled) &&
    connection.revokedAt === null &&
    connection.expiresAt !== null &&
    connection.expiresAt.getTime() > now;

  /** The row, the membership and the organization: everything a refresh needs live. */
  const connectionLive = async (connection: Connection, now: number) => {
    if (!rowLive(connection, now)) return false;
    const membership = await repository.findMembership(connection.userId, connection.organizationId);
    return membership !== null && !isOrganizationExpired(membership.organization, now);
  };

  const organizationLiveSql = (organizationId: string, now: number): SQL =>
    oauthOrganizationLiveSql(tables, { organizationId, nowMs: now });

  const membershipLiveSql = (userId: string, organizationId: string): SQL =>
    oauthMembershipLiveSql(tables, { userId, organizationId });

  /** The connection's whole authority: {@link oauthConnectionLiveSql} under this issuer. */
  const connectionAuthoritySql = (connection: Connection, now: number): SQL =>
    oauthConnectionLiveSql(tables, { connectionId: connection.id, issuer: settings().issuer, nowMs: now });

  /**
   * One generation and the connection's whole authority, read in a single
   * statement — the row, the membership and the organization judged by the
   * later of the caller's clock and the database's — so nothing can change
   * between the parts of the answer. Null when the connection row is gone;
   * `generation` null when the generation is.
   */
  const authoritySnapshot = async (connection: Connection, generationId: string, now: number) => {
    const row = await db
      .select({
        generationId: oauthToken.id,
        generation: oauthToken.generation,
        rotatedAt: oauthToken.rotatedAt,
        sealedResponse: oauthToken.sealedResponse,
        live: sql<number>`case when ${connectionAuthoritySql(connection, now)} then 1 else 0 end`,
        clock: sql<number>`${sqliteNowMs(now)}`,
      })
      .from(apiKey)
      .leftJoin(oauthToken, and(eq(oauthToken.id, generationId), eq(oauthToken.apiKeyId, apiKey.id)))
      .where(and(eq(apiKey.id, connection.id), eq(apiKey.source, "oauth")))
      .get();
    if (!row) return null;
    return {
      live: Number(row.live) === 1,
      clock: Number(row.clock),
      generation:
        row.generationId === null
          ? null
          : {
              generation: row.generation as number,
              rotatedAt: (row.rotatedAt ?? null) as Date | null,
              sealedResponse: (row.sealedResponse ?? null) as string | null,
            },
    };
  };

  /**
   * What a verified refresh token that is no longer the current generation
   * gets, decided from one {@link authoritySnapshot}. Ended authority wins:
   * a dead connection, membership or organization answers invalid_grant and
   * changes nothing, never a replay and never a revocation. On a live
   * connection: a generation rotated inside the grace replays its sealed
   * response; rotated outside it, or gone because later rotations moved past
   * it, is reuse.
   */
  const decideUsedToken = async (
    connection: Connection,
    generationId: string,
    presented: string,
  ): Promise<OAuthTokenResult> => {
    const snapshot = await authoritySnapshot(connection, generationId, Date.now());
    if (!snapshot?.live) return fail("invalid_grant", "The connection is no longer live");
    const generation = snapshot.generation;
    if (generation === null) return reuseDetected(connection);
    if (generation.rotatedAt === null || generation.sealedResponse === null) {
      // Unrotated, yet its rotation wrote nothing: authority flickered. Nothing changes.
      return fail("invalid_grant", "The connection is no longer live");
    }
    return snapshot.clock - generation.rotatedAt.getTime() < oauthRefreshGraceMs
      ? replay(presented, connection.id, generation)
      : reuseDetected(connection);
  };

  /**
   * Revokes the connection row and deletes every generation, in one batch.
   * With `requireAuthority`, the revocation lands only while the connection,
   * membership and organization are still live — reuse ends a live
   * connection, never re-ends a dead one. The deletion is conditioned on this
   * revocation having matched, and neither statement names a generation, so
   * a rotation racing it cannot defeat it. Answers whether it moved.
   */
  const revokeConnection = async (
    connection: Connection,
    now: number,
    options: { requireAuthority: boolean },
  ): Promise<boolean> => {
    const [revoked] = (await runBatch([
      db
        .update(apiKey)
        .set({ enabled: false, revokedAt: new Date(now) })
        .where(
          and(
            eq(apiKey.id, connection.id),
            eq(apiKey.source, "oauth"),
            // The row itself is live when the write lands, by the database's
            // clock too: an expired or revoked connection is left as it is.
            eq(apiKey.enabled, true),
            isNull(apiKey.revokedAt),
            sql`${apiKey.expiresAt} > ${sqliteNowMs(now)}`,
            ...(options.requireAuthority ? [connectionAuthoritySql(connection, now)] : []),
          ),
        )
        .returning({ id: apiKey.id }),
      // Only if the update right before it changed the row: `changes()` is
      // that statement's count, as the operation engine's guards read it.
      db.delete(oauthToken).where(and(eq(oauthToken.apiKeyId, connection.id), sql`changes() > 0`)),
    ])) as [unknown[], unknown];
    const moved = revoked.length === 1;
    if (moved) {
      await emit({
        type: "api_key.revoked",
        actorUserId: connection.userId,
        organizationId: connection.organizationId,
        apiKeyId: connection.id,
        name: connection.name,
        credentialType: "oauth",
      });
    }
    return moved;
  };

  /** Reuse of a verified token: ends the connection if, when the batch lands, it is still live. */
  const reuseDetected = async (connection: Connection): Promise<OAuthTokenResult> =>
    (await revokeConnection(connection, Date.now(), { requireAuthority: true }))
      ? fail("invalid_grant", "The refresh token was already used; the connection is revoked")
      : fail("invalid_grant", "The connection is no longer live");

  /** The response sealed on a rotated generation, opened with the token presented. */
  const replay = async (
    presented: string,
    connectionId: string,
    generation: Pick<OAuthTokenRow, "generation" | "sealedResponse">,
  ): Promise<OAuthTokenResult> => {
    try {
      const json = await openTextForToken(
        presented,
        rotationSealInfo,
        rotationSealContext(connectionId, generation.generation),
        generation.sealedResponse!,
      );
      return { status: 200, body: JSON.parse(json) as OAuthTokenResponse };
    } catch {
      return fail("invalid_grant", "The refresh token is not valid");
    }
  };


  /**
   * Rotates the current generation in one guarded batch: mark it rotated and
   * store the new response sealed under the presented refresh token; insert
   * the next generation; advance `expires_at`; delete the generation before.
   * The first write is conditional on the generation being unrotated and the
   * connection's authority live, and every later one on the one before it.
   */
  const rotate = async (
    oauth: ResolvedOAuthConfig,
    connection: Connection,
    current: OAuthTokenRow,
    presented: string,
    now: number,
  ): Promise<OAuthTokenResult> => {
    const grant = grantOf(connection);
    const next = await issueGeneration({
      prefix: oauth.tokenPrefix,
      connectionId: connection.id,
      generation: current.generation + 1,
      now,
      accessTokenTtlMs: oauth.accessTokenTtlMs,
    });
    const response = tokenResponse(oauth, next, grant);
    const sealed = await sealTextForToken(
      presented,
      rotationSealInfo,
      rotationSealContext(connection.id, current.generation),
      JSON.stringify(response),
    );
    const rotatedRow = alias(oauthToken, "cf_auth_oauth_rotated");
    const nextRow = alias(oauthToken, "cf_auth_oauth_next");
    // The sealed value is random per call, so it names this rotation exactly.
    const rotationLanded = sql`exists (select 1 from ${oauthToken} as ${sql.identifier("cf_auth_oauth_rotated")}
      where ${rotatedRow.id} = ${current.id} and ${rotatedRow.sealedResponse} = ${sealed})`;
    const nextLanded = sql`exists (select 1 from ${oauthToken} as ${sql.identifier("cf_auth_oauth_next")}
      where ${nextRow.id} = ${next.row.id})`;

    const [rotated] = (await runBatch([
      db
        .update(oauthToken)
        .set({ rotatedAt: new Date(now), sealedResponse: sealed })
        .where(
          and(
            eq(oauthToken.id, current.id),
            eq(oauthToken.apiKeyId, connection.id),
            isNull(oauthToken.rotatedAt),
            connectionAuthoritySql(connection, now),
          ),
        )
        .returning({ id: oauthToken.id }),
      guardedInsert(db, oauthToken, next.row, rotationLanded),
      db
        .update(apiKey)
        .set({ expiresAt: new Date(connectionExpiry(oauth, connection.createdAt.getTime(), now)) })
        .where(and(eq(apiKey.id, connection.id), nextLanded)),
      db
        .delete(oauthToken)
        .where(and(eq(oauthToken.apiKeyId, connection.id), lt(oauthToken.generation, current.generation), nextLanded)),
    ])) as [unknown[], ...unknown[]];
    if (rotated.length === 1) return { status: 200, body: response };

    // Nothing written, though the token was verified as current: another
    // presentation rotated it, later rotations moved past it, or the
    // authority ended. One snapshot decides.
    return decideUsedToken(connection, current.id, presented);
  };

  const refresh = async (oauth: ResolvedOAuthConfig, params: FormParams): Promise<OAuthTokenResult> => {
    for (const name of ["refresh_token", "client_id"]) {
      if (!params.get(name)) return fail("invalid_request", `${name} is required`);
    }
    const resource = params.get("resource");
    if (resource !== null && normalizeResource(oauth, resource) === null) {
      return fail("invalid_target", "resource must be the issuer or one of its resource paths");
    }
    const presented = params.get("refresh_token")!;
    const resolved = await resolveToken(db, tables, {
      token: presented,
      prefix: oauth.tokenPrefix.refresh,
      type: "refresh",
    });
    if (resolved.kind === "unknown") return fail("invalid_grant", "The refresh token is not valid");
    const connection = await loadConnection(resolved.connectionId);
    if (!connection) return fail("invalid_grant", "The refresh token is not valid");
    if (connection.clientId !== params.get("client_id")) {
      return fail("invalid_client", "client_id does not match the client the connection was issued to");
    }
    const now = Date.now();
    if (!(await connectionLive(connection, now))) {
      return fail("invalid_grant", "The connection is no longer live");
    }
    if (resource !== null && normalizeResource(oauth, resource) !== connection.resource) {
      return fail("invalid_target", "resource is not the one the connection is bound to");
    }
    // A database two deployments share must not let one rotate the other's
    // connections, as it cannot let one authenticate the other's tokens.
    if (connection.resource !== oauth.issuer) {
      return fail("invalid_grant", "The connection is bound to another issuer");
    }
    const grant = grantOf(connection);
    const scope = params.get("scope");
    if (scope !== null && scope !== grant) {
      return fail("invalid_scope", `scope must be the connection's grant, ${grant}; narrowing is not supported`);
    }

    if (resolved.kind === "previous") {
      return decideUsedToken(connection, resolved.generation.id, presented);
    }

    const lastRotation = resolved.generations[1]?.rotatedAt?.getTime();
    if (lastRotation !== undefined && now - lastRotation < oauthRotationIntervalMs) {
      return fail("invalid_grant", "slow down: refreshed too recently");
    }
    return rotate(oauth, connection, resolved.generation, presented, now);
  };

  const prepareConnection = async (
    oauth: ResolvedOAuthConfig,
    input: CreateOAuthConnectionInput & { condition?: SQL },
  ): Promise<OAuthConnectionStatements> => {
    const text = (value: unknown, label: string, max: number) => {
      const trimmed = typeof value === "string" ? value.trim() : "";
      if (!trimmed) throw validationError(`${label} is required`);
      if (trimmed.length > max) throw validationError(`${label} is too long`);
      return trimmed;
    };
    const userId = text(input.userId, "userId", 256);
    const organizationId = text(input.organizationId, "organizationId", 256);
    const clientId = text(input.clientId, "clientId", maxClientIdLength);
    const clientName = text(input.clientName, "clientName", maxClientNameLength);
    if (!isCredentialGrant(input.grant)) throw validationError('A grant must be "read" or "manage"');
    const resource = typeof input.resource === "string" ? normalizeResource(oauth, input.resource) : null;
    if (resource === null) throw validationError("resource must be the issuer or one of its resource paths");
    const now = input.now ?? Date.now();
    if (!Number.isFinite(now)) throw validationError("now must be a time in epoch milliseconds");
    const connectionId = input.id ?? crypto.randomUUID();
    if (!connectionIdPattern.test(connectionId)) {
      throw validationError("A connection id is 1 to 128 letters, digits, `_` or `-`");
    }

    // The row's own token_hash keeps the unique index honest; nothing it
    // digests is ever revealed, so no token authenticates through it.
    const hiddenTokenHash = await sha256Hex(`cf-auth:oauth-connection:${randomToken(32)}`);
    const first = await issueGeneration({
      prefix: oauth.tokenPrefix,
      connectionId,
      generation: 1,
      now,
      accessTokenTtlMs: oauth.accessTokenTtlMs,
    });
    const landedRow = alias(apiKey, "cf_auth_oauth_connection");
    const connectionLanded = sql`exists (select 1 from ${apiKey} as ${sql.identifier("cf_auth_oauth_connection")}
      where ${landedRow.id} = ${connectionId} and ${landedRow.tokenHash} = ${hiddenTokenHash})`;
    const guard = and(
      ...(input.condition ? [input.condition] : []),
      membershipLiveSql(userId, organizationId),
      organizationLiveSql(organizationId, now),
    )!;

    const statements = [
      guardedInsert(
        db,
        apiKey,
        {
          id: connectionId,
          userId,
          organizationId,
          name: clientName,
          tokenHash: hiddenTokenHash,
          tokenHint: "",
          enabled: true,
          expiresAt: new Date(connectionExpiry(oauth, now, now)),
          createdAt: new Date(now),
          revokedAt: null,
          source: "oauth",
          label: clientName,
          grant: input.grant,
          clientId,
          resource,
        },
        guard,
      ),
      guardedInsert(db, oauthToken, first.row, connectionLanded),
    ] as unknown as BatchItem<"sqlite">[];

    const landed = async () =>
      (await db
        .select({ id: apiKey.id })
        .from(apiKey)
        .where(and(eq(apiKey.id, connectionId), eq(apiKey.tokenHash, hiddenTokenHash)))
        .get()) !== undefined;

    return {
      connectionId,
      statements,
      response: tokenResponse(oauth, first, input.grant),
      landed,
      afterCommit: async () => {
        try {
          if (!(await landed())) return;
        } catch (error) {
          config.onError(error, { scope: "oauth.connection.afterCommit" });
          return;
        }
        await emit({
          type: "api_key.created",
          actorUserId: userId,
          organizationId,
          apiKeyId: connectionId,
          name: clientName,
          credentialType: "oauth",
        });
      },
    };
  };

  const sweepStatements = (now = Date.now()): BatchItem<"sqlite">[] => {
    const dead = alias(apiKey, "cf_auth_oauth_dead");
    return [
      db.delete(oauthToken).where(
        sql`exists (select 1 from ${apiKey} as ${sql.identifier("cf_auth_oauth_dead")}
          where ${dead.id} = ${oauthToken.apiKeyId}
            and (${dead.revokedAt} is not null or ${dead.expiresAt} <= ${now}))`,
      ),
    ] as unknown as BatchItem<"sqlite">[];
  };

  const authorization = createOAuthAuthorization({
    config,
    repository,
    get operations(): CfAuthOperations {
      if (!internalOperations) throw validationError("OAuth is disabled; set `oauth.enabled: true` to use it");
      return internalOperations;
    },
    settings,
    connections: {
      connectionStatements: (input) => prepareConnection(settings(), input),
      async revokeConnectionById(connectionId) {
        const connection = await loadConnection(connectionId);
        const now = Date.now();
        if (connection && rowLive(connection, now)) {
          await revokeConnection(connection, now, { requireAuthority: false });
        }
      },
    },
  });

  return {
    protectedResourceMetadata: (path) => authorization.protectedResourceMetadata(path),
    authorizationServerMetadata: () => authorization.authorizationServerMetadata(),
    authorize: (input) => authorization.authorize(input),
    authorizationDetails: (input) => authorization.authorizationDetails(input),
    approveAuthorization: (input) => authorization.approveAuthorization(input),
    approveGuestAuthorization: (input) => authorization.approveGuestAuthorization(input),
    denyAuthorization: (input) => authorization.denyAuthorization(input),

    async token({ body }) {
      const oauth = settings();
      const params = formParams(body);
      if (!params) return fail("invalid_request", "The request body must be form parameters");
      const duplicated = duplicatedParameter(params);
      if (duplicated !== null) return fail("invalid_request", duplicateDescription(duplicated));
      const grantType = params.get("grant_type");
      if (!grantType) return fail("invalid_request", "grant_type is required");
      if (grantType === "refresh_token") return refresh(oauth, params);
      if (grantType === "authorization_code") return authorization.exchangeCode(oauth, params);
      return fail("unsupported_grant_type", "grant_type must be authorization_code or refresh_token");
    },

    async revoke({ body }) {
      const oauth = settings();
      const params = formParams(body);
      if (!params) return fail("invalid_request", "The request body must be form parameters");
      const duplicated = duplicatedParameter(params);
      if (duplicated !== null) return fail("invalid_request", duplicateDescription(duplicated));
      for (const name of ["token", "client_id"]) {
        if (!params.get(name)) return fail("invalid_request", `${name} is required`);
      }
      const token = params.get("token")!;
      // `token_type_hint` is ignored: both prefixes are tried, and either
      // token ends the whole connection.
      let resolved = await resolveToken(db, tables, { token, prefix: oauth.tokenPrefix.access, type: "access" });
      if (resolved.kind === "unknown") {
        resolved = await resolveToken(db, tables, { token, prefix: oauth.tokenPrefix.refresh, type: "refresh" });
      }
      if (resolved.kind === "unknown") return { status: 200, body: null };
      const connection = await loadConnection(resolved.connectionId);
      if (!connection) return { status: 200, body: null };
      if (connection.clientId !== params.get("client_id")) {
        return fail("invalid_client", "client_id does not match the client the connection was issued to");
      }
      const now = Date.now();
      if (rowLive(connection, now)) await revokeConnection(connection, now, { requireAuthority: false });
      return { status: 200, body: null };
    },

    async resolveAccessTokenAuthState(token, context) {
      const oauth = settings();
      const source = context?.source;
      if (!(oauthActionSources as readonly unknown[]).includes(source) || typeof token !== "string") {
        return createEmptyAuthState();
      }
      const presented = token.trim();
      const connectionId = parseOAuthToken(presented, oauth.tokenPrefix.access);
      if (!connectionId) return createEmptyAuthState();
      const now = Date.now();
      // One statement: the current generation, unexpired, on a live
      // connection bound to this issuer, with its user, membership and
      // organization — nothing read apart can disagree with the rest.
      const access = await repository.findOAuthAccess({
        connectionId,
        condition: and(
          sql`${oauthToken.accessExpiresAt} > ${sqliteNowMs(now)}`,
          oauthConnectionLiveSql(tables, { connectionId, issuer: oauth.issuer, nowMs: now }),
        )!,
      });
      if (!access || !timingSafeEqual(await sha256Hex(presented), access.accessTokenHash)) {
        return createEmptyAuthState();
      }
      const grant = isCredentialGrant(access.grant) ? access.grant : "read";
      return toOAuthAuthState(access.user, access.membership, connectionId, source as OAuthActionSource, grant);
    },

    async connectionStatements(input) {
      return prepareConnection(settings(), input);
    },

    async createConnection(input) {
      const prepared = await prepareConnection(settings(), input);
      await runBatch(prepared.statements);
      if (!(await prepared.landed())) {
        throw new CfAuthError(
          "connection_refused",
          "The connection was not created: the membership or the organization is no longer live",
          409,
        );
      }
      await prepared.afterCommit();
      return prepared.response;
    },

    sweepStatements(now) {
      settings();
      return sweepStatements(now);
    },

    async sweep(now) {
      settings();
      await runBatch(sweepStatements(now));
    },
  };
};
