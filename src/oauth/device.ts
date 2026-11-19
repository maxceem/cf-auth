/**
 * The device flow (RFC 8628), for a client with no browser on its machine:
 * a command-line tool on a server, say.
 *
 * The client asks for a device code at the device authorization endpoint and
 * shows the person a link and a short user code. The person opens the link in
 * any browser, signs in, enters the code, and allows the client into one of
 * their accounts. Meanwhile the client polls the token endpoint with the
 * device code, and once the person has allowed it, receives a connection
 * exactly like the authorization-code flow's.
 *
 * A pending device authorization is an operation of the built-in internal
 * kind `cf-auth:oauth.device`. The device code is the operation's token, so
 * the database holds only its digest, and the operation's id is
 * `oauth-device-<SHA-256 of the device code, hex>`: the token endpoint finds
 * it through the primary key. The user code is the engine's: eight characters
 * derived from the device code, stored as a keyed digest for lookup plus a
 * sealed copy for display.
 *
 * Guessing limits: a user code is eight characters from a 31-letter alphabet,
 * pending for `codeTtlMs` only, unique among pending operations, and looking
 * one up needs the app's own rate limit (`lookupDevice` takes it and calls it
 * first). Approving or denying needs the operation's id as well as the code,
 * so only a lookup can be used to guess. Opening one counts toward the
 * engine's pending cap for the client's address.
 *
 * Nothing here is an HTTP route. Each function answers a plain value.
 */
import { and, eq, gt, lte, sql } from "drizzle-orm";
import { alias } from "drizzle-orm/sqlite-core";
import { sqliteNowMs } from "../authority.js";
import type { ResolvedCfAuthConfig, ResolvedOAuthConfig } from "../config.js";
import { randomToken, sha256Hex, timingSafeEqual } from "../crypto.js";
import { alreadyCompleted, CfAuthError, operationNotFound, validationError } from "../errors.js";
import type { CfAuthOperations, OperationKind } from "../operations.js";
import {
  createEmptyAuthState,
  isCredentialGrant,
  type AuthState,
  type AuthUser,
  type CredentialGrant,
  type OperationState,
  type OrganizationMembership,
} from "../types.js";
import { requireInteractiveSession } from "../service.js";
import type { OAuthAuthorizationConnections, OAuthClientIdentity, OAuthExchangeResult } from "./authorization.js";
import type { FormParams } from "./params.js";

/** The built-in internal kind a pending device authorization is an operation of. */
export const oauthDeviceKindName = "cf-auth:oauth.device";
/** How long a device authorization's record is kept, counted from opening. */
export const oauthDeviceRecordTtlMs = 24 * 60 * 60_000;
/**
 * How much earlier than `interval` a poll may come and still not be told to
 * slow down: a client that waits exactly `interval` between requests can
 * land a little early here because of network jitter. Never more than half
 * the interval, so a short interval still means something.
 */
export const oauthDevicePollToleranceMs = 1_000;

/** What a pending device authorization holds, from the request that opened it. */
export interface OAuthDevicePayload {
  client: OAuthClientIdentity;
  /** The `scope` the client asked for; `manage` when it named none. */
  requestedGrant: CredentialGrant;
  /** The `resource`, normalised to the issuer. */
  resource: string;
}

/** What a completed device authorization records, in the clear. Never the device code. */
export interface OAuthDeviceRecord {
  /** The person who allowed it: the user the connection will belong to. */
  userId: string;
  organizationId: string;
  /** The grant the person chose. */
  grant: CredentialGrant;
  requestedGrant: CredentialGrant;
  client: OAuthClientIdentity;
  resource: string;
  /**
   * The device code's deadline, epoch milliseconds: when it was issued plus
   * `codeTtlMs`. Approving does not extend it (RFC 8628 §3.2).
   */
  codeExpiresAt: number;
  /** When the device code was exchanged, epoch milliseconds; null until it is. */
  exchangedAt: number | null;
  /** The connection the exchange issued; null until it is. */
  connectionId: string | null;
}

/** The successful device authorization response (RFC 8628 §3.2). */
export interface OAuthDeviceAuthorizationResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

export type OAuthDeviceErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "unauthorized_client"
  | "invalid_scope"
  | "invalid_target"
  | "slow_down";

/**
 * What `deviceAuthorization` answers: 200 and the codes; 400 (401 for
 * `invalid_client`) and the error; or 429 `slow_down` when too many device
 * authorizations are waiting from the client's address.
 */
export type OAuthDeviceAuthorizationResult =
  | { status: 200; body: OAuthDeviceAuthorizationResponse }
  | { status: 400 | 401 | 429; body: { error: OAuthDeviceErrorCode; error_description: string } };

/** What the token endpoint answers for the device grant, as `token`'s result. */
export type OAuthDeviceExchangeResult =
  | Extract<OAuthExchangeResult, { status: 200 }>
  | {
      status: 400 | 401;
      body: {
        error:
          | "invalid_request"
          | "invalid_client"
          | "invalid_grant"
          | "invalid_target"
          | "authorization_pending"
          | "slow_down"
          | "access_denied"
          | "expired_token";
        error_description: string;
      };
    };

/** What the code-entry page shows once a code is found. */
export interface OAuthDeviceDetails {
  id: string;
  state: OperationState;
  client: OAuthClientIdentity;
  requestedGrant: CredentialGrant;
  /** The code, as the client shows it, so the page can ask the person to compare. */
  userCode: string | null;
  /** When the pending device authorization lapses. */
  expiresAt: string;
  /** The signed-in person (an interactive human session), with every membership; null otherwise. */
  viewer: { user: AuthUser; memberships: OrganizationMembership[] } | null;
}

export interface ApproveDeviceInput {
  /** From `lookupDevice`. */
  id: string;
  /** The code the person entered. */
  userCode: string;
  /** The person on the page: an interactive human session. */
  actor: AuthState | null | undefined;
  /** The account to connect: one the person is an active member of, at any role. */
  organizationId: string;
  /** The grant the person chose; any, whatever the client asked for. */
  grant: CredentialGrant;
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const parsePayload = (value: unknown): OAuthDevicePayload => {
  if (
    !isObject(value) ||
    !isObject(value.client) ||
    typeof value.client.id !== "string" ||
    typeof value.client.name !== "string" ||
    value.client.domain !== null ||
    value.client.source !== "registered" ||
    !isCredentialGrant(value.requestedGrant) ||
    typeof value.resource !== "string"
  ) {
    throw validationError("Invalid device authorization payload");
  }
  return value as unknown as OAuthDevicePayload;
};

const parseInput = (value: unknown): { grant: CredentialGrant } => {
  if (!isObject(value) || !isCredentialGrant(value.grant)) {
    throw validationError('grant must be "read" or "manage"');
  }
  return { grant: value.grant };
};

/**
 * The built-in internal kind `cf-auth:oauth.device`. Public (anyone may start
 * one; the client's address is what the pending cap counts), with a user code,
 * approved by a signed-in person who is a member, at any role, of the account
 * they pick. The engine re-reads that session and membership in the batch
 * that completes it.
 */
export const createOAuthDeviceKind = (
  oauth: ResolvedOAuthConfig & { deviceFlow: NonNullable<ResolvedOAuthConfig["deviceFlow"]> },
): OperationKind => ({
  name: oauthDeviceKindName,
  open: "public",
  browser: true,
  approver: "session",
  approverMinRole: null,
  userCode: true,
  countsTowardPending: true,
  requireClientLabel: true,
  pendingTtlMs: oauth.deviceFlow.codeTtlMs,
  recordTtlMs: Math.max(oauthDeviceRecordTtlMs, 2 * oauth.deviceFlow.codeTtlMs),
  payload: parsePayload,
  input: parseInput,
  refusal: ({ viewer }) => {
    if (!viewer?.authenticated || viewer.assurance !== "interactive" || viewer.user?.kind !== "human") {
      return "session_required";
    }
    return viewer.memberships.some((membership) => membership.status === "active")
      ? null
      : "no_eligible_organization";
  },
  approve: ({ operation, payload, input, user, organizationId }) => {
    const device = payload as OAuthDevicePayload;
    const { grant } = input as { grant: CredentialGrant };
    const record: OAuthDeviceRecord = {
      userId: user!.id,
      organizationId: organizationId!,
      grant,
      requestedGrant: device.requestedGrant,
      client: device.client,
      resource: device.resource,
      // The deadline the code was issued with: approving late does not lengthen it.
      codeExpiresAt: Date.parse(operation.expiresAt),
      exchangedAt: null,
      connectionId: null,
    };
    return { outcome: record, seal: false };
  },
});

/** 32 bytes, base64url: what `deviceAuthorization` makes. Anything else is unknown without a lookup. */
const deviceCodePattern = /^[A-Za-z0-9_-]{43}$/;
const maxClientIdLength = 2048;
/** How many device codes `deviceAuthorization` tries when a user code collides with a pending one. */
const deviceOpenAttempts = 3;

/** The operation id of the device authorization a device code belongs to: the code's digest. */
const operationIdForDeviceCode = async (deviceCode: string) => `oauth-device-${await sha256Hex(deviceCode)}`;

export const createOAuthDevice = (deps: {
  config: ResolvedCfAuthConfig;
  /** The engine's door that admits internal kinds, read on use. */
  readonly operations: CfAuthOperations;
  settings: () => ResolvedOAuthConfig;
  connections: OAuthAuthorizationConnections;
}) => {
  const { config, settings, connections } = deps;
  const engine = () => deps.operations;
  const { db, tables } = config;
  const { operation } = tables;

  /** The device flow's settings; refuses every call while it is off. */
  const deviceSettings = () => {
    const oauth = settings();
    if (!oauth.deviceFlow) {
      throw validationError("The device flow is off; set `oauth.deviceFlow` to use it");
    }
    return { oauth, device: oauth.deviceFlow };
  };

  /** The device authorization's row as stored: its effective state, payload and record. */
  const readDevice = async (id: string) => {
    const row = await db
      .select({
        kind: operation.kind,
        state: operation.state,
        expiresAt: operation.expiresAt,
        payload: operation.payload,
        outcome: operation.outcome,
      })
      .from(operation)
      .where(eq(operation.id, id))
      .get();
    if (!row || row.kind !== oauthDeviceKindName || row.payload === null) return null;
    const state: OperationState =
      row.state === "pending" && row.expiresAt.getTime() <= Date.now() ? "expired" : row.state;
    return {
      state,
      payload: parsePayload(JSON.parse(row.payload)),
      record:
        row.state === "completed" && row.outcome !== null ? (JSON.parse(row.outcome) as OAuthDeviceRecord) : null,
    };
  };

  /**
   * The device authorization a browser addresses with its id and user code.
   * One issued by another issuer sharing the database is not found here.
   */
  const loadForBrowser = async (id: string, userCode: string, viewer: AuthState | null = null) => {
    const { oauth } = deviceSettings();
    if (typeof id !== "string" || typeof userCode !== "string") throw operationNotFound();
    const device = await readDevice(id);
    if (!device || device.payload.resource !== oauth.issuer) throw operationNotFound();
    const details = await engine().details({ id, userCode, viewer });
    if (details.kind !== oauthDeviceKindName) throw operationNotFound();
    return { details, ...device };
  };

  const isCode = (error: unknown, code: string) => error instanceof CfAuthError && error.code === code;

  const deviceFail = (
    status: 400 | 401 | 429,
    error: OAuthDeviceErrorCode,
    description: string,
  ): Extract<OAuthDeviceAuthorizationResult, { status: 400 | 401 | 429 }> => ({
    status,
    body: { error, error_description: description },
  });

  const exchangeFail = (
    error: Extract<OAuthDeviceExchangeResult, { status: 400 | 401 }>["body"]["error"],
    description: string,
  ): Extract<OAuthDeviceExchangeResult, { status: 400 | 401 }> => ({
    status: error === "invalid_client" ? 401 : 400,
    body: { error, error_description: description },
  });

  /** `grant_type=urn:ietf:params:oauth:grant-type:device_code`, its parameters already free of duplicates. */
  const exchangeDeviceCode = async (
    oauth: ResolvedOAuthConfig,
    params: FormParams,
    again = false,
  ): Promise<OAuthDeviceExchangeResult> => {
    const device = oauth.deviceFlow;
    if (!device) return exchangeFail("invalid_grant", "The device flow is off");
    for (const name of ["device_code", "client_id"]) {
      if (!params.get(name)) return exchangeFail("invalid_request", `${name} is required`);
    }
    const resource = params.get("resource");
    if (resource !== null && !oauth.resources.includes(resource)) {
      return exchangeFail("invalid_target", "resource must be the issuer or one of its resource paths");
    }
    const unknown = () => exchangeFail("invalid_grant", "The device code is not valid");
    const deviceCode = params.get("device_code")!;
    if (!deviceCodePattern.test(deviceCode)) return unknown();
    const id = await operationIdForDeviceCode(deviceCode);
    const found = await readDevice(id);
    // Issued by this issuer, and to this client; anything else changes nothing.
    if (!found || found.payload.resource !== oauth.issuer) return unknown();
    if (!timingSafeEqual(params.get("client_id")!, found.payload.client.id)) return unknown();

    const now = Date.now();
    if (found.state === "pending") {
      // At most one poll per interval: the poll itself moves `updated_at`,
      // which only polls touch while the authorization is pending, so two
      // polls racing cannot both get through.
      const intervalMs = device.intervalSeconds * 1000;
      const earliest = new Date(now - (intervalMs - Math.min(oauthDevicePollToleranceMs, intervalMs / 2)));
      const polled = await db
        .update(operation)
        .set({ updatedAt: new Date(now) })
        .where(
          and(
            eq(operation.id, id),
            eq(operation.kind, oauthDeviceKindName),
            eq(operation.state, "pending"),
            gt(operation.expiresAt, new Date(now)),
            lte(operation.updatedAt, earliest),
          ),
        )
        .returning({ id: operation.id });
      if (polled.length === 1) {
        return exchangeFail("authorization_pending", "The person has not answered yet");
      }
      const current = await readDevice(id);
      if (current?.state === "pending") {
        return exchangeFail("slow_down", `Poll at most once every ${device.intervalSeconds} seconds`);
      }
      if (!current || again) return unknown();
      // It was answered meanwhile: read it again as what it is now.
      return exchangeDeviceCode(oauth, params, true);
    }
    if (found.state === "denied") return exchangeFail("access_denied", "The person denied the request");
    if (found.state === "expired" || found.state === "retired" || !found.record) {
      return exchangeFail("expired_token", "The device code has expired; start again");
    }
    const record = found.record;
    if (resource !== null && oauth.issuer !== record.resource) {
      return exchangeFail("invalid_target", "resource is not the one the device code was for");
    }

    /** A device code exchanged before: the connection it issued ends, as a replayed code's does. */
    const replayed = async (connectionId: string | null) => {
      if (connectionId) await connections.revokeConnectionById(connectionId);
      return exchangeFail("invalid_grant", "The device code was already used; the connection it issued is revoked");
    };
    if (record.exchangedAt !== null) return replayed(record.connectionId);
    if (record.codeExpiresAt <= now) return exchangeFail("expired_token", "The device code has expired; start again");

    // Completed, never exchanged, inside its validity by either clock — in
    // the batch that writes the connection, its first generation and the
    // record's `exchangedAt`.
    const device_ = alias(operation, "cf_auth_oauth_device");
    const exchangeable = sql`exists (select 1 from ${operation} as ${sql.identifier("cf_auth_oauth_device")}
      where ${device_.id} = ${id}
        and ${device_.kind} = ${oauthDeviceKindName}
        and ${device_.state} = 'completed'
        and json_extract(${device_.outcome}, '$.exchangedAt') is null
        and json_extract(${device_.outcome}, '$.codeExpiresAt') > ${sqliteNowMs(now)})`;
    const connectionId = crypto.randomUUID();
    let prepared: Awaited<ReturnType<OAuthAuthorizationConnections["connectionStatements"]>>;
    try {
      prepared = await connections.connectionStatements({
        userId: record.userId,
        organizationId: record.organizationId,
        clientId: record.client.id,
        clientName: record.client.name,
        resource: record.resource,
        grant: record.grant,
        now,
        id: connectionId,
        condition: exchangeable,
      });
    } catch (error) {
      if (error instanceof CfAuthError) return unknown();
      throw error;
    }
    let landed = false;
    try {
      landed = await engine().amend({
        id,
        record: { ...record, exchangedAt: now, connectionId } satisfies OAuthDeviceRecord,
        condition: exchangeable,
        statements: prepared.statements,
      });
    } catch (error) {
      if (!(error instanceof CfAuthError)) throw error;
    }
    if (landed) {
      await prepared.afterCommit();
      return { status: 200, body: prepared.response };
    }
    const current = await readDevice(id);
    if (current?.record && current.record.exchangedAt !== null) return replayed(current.record.connectionId);
    return exchangeFail("invalid_grant", "The device code is no longer valid");
  };

  return {
    /**
     * `POST /oauth/device_authorization`, form-encoded: `client_id`
     * required, `scope` and `resource` optional. Its parameters are already
     * free of duplicates.
     */
    async deviceAuthorization(
      params: FormParams,
      rateLimitKey: string | null,
    ): Promise<OAuthDeviceAuthorizationResult> {
      const { oauth, device } = deviceSettings();
      const value = (name: string) => {
        const found = params.get(name);
        return found === null || found === "" ? undefined : found;
      };
      const clientId = value("client_id");
      if (clientId === undefined) return deviceFail(400, "invalid_request", "client_id is required");
      if (clientId.length > maxClientIdLength) return deviceFail(400, "invalid_request", "client_id is too long");
      const registered = oauth.clients.find((client) => client.clientId === clientId);
      if (!registered) return deviceFail(401, "invalid_client", "The client is not registered with this server");
      if (!registered.deviceFlow) {
        return deviceFail(400, "unauthorized_client", "This client may not use the device flow");
      }
      const scope = value("scope") ?? "manage";
      if (!isCredentialGrant(scope)) return deviceFail(400, "invalid_scope", "scope must be read or manage");
      const resource = value("resource");
      if (resource !== undefined && !oauth.resources.includes(resource)) {
        return deviceFail(400, "invalid_target", "resource must be the issuer or one of its resource paths");
      }

      const payload: OAuthDevicePayload = {
        client: { id: registered.clientId, name: registered.name, domain: null, source: "registered" },
        requestedGrant: scope,
        resource: oauth.issuer,
      };
      // A user code is derived from the device code, and two pending ones may
      // not share it. A new device code gives a new user code, so a collision
      // is retried with a fresh one, a few times.
      let deviceCode = "";
      let userCode: string | null = null;
      for (let attempt = 1; ; attempt += 1) {
        deviceCode = randomToken(32);
        try {
          const view = await engine().open({
            kind: oauthDeviceKindName,
            token: deviceCode,
            id: await operationIdForDeviceCode(deviceCode),
            payload,
            rateLimitKey,
            client: { label: registered.name },
          });
          userCode = view.userCode;
          break;
        } catch (error) {
          if (isCode(error, "too_many_pending")) {
            return deviceFail(429, "slow_down", "Too many device authorizations are waiting from this address");
          }
          if (isCode(error, "conflict") && attempt < deviceOpenAttempts) continue;
          throw error;
        }
      }
      if (!userCode) throw new Error("cf-auth: a device authorization opened without a user code");
      const complete = new URL(device.verificationUri);
      complete.searchParams.set("user_code", userCode);
      return {
        status: 200,
        body: {
          device_code: deviceCode,
          user_code: userCode,
          verification_uri: device.verificationUri,
          verification_uri_complete: complete.toString(),
          expires_in: Math.floor(device.codeTtlMs / 1000),
          interval: device.intervalSeconds,
        },
      };
    },

    /**
     * The pending device authorization a typed user code names, for the
     * code-entry page, or null. `rateLimit` is the app's limit on guesses,
     * keyed on the browser's address or the signed-in person: it is called
     * first, and throws when exceeded. Continue with `{ id, userCode }`.
     */
    async lookupDevice(input: {
      userCode: string;
      rateLimit: () => Promise<void>;
    }): Promise<{ id: string; expiresAt: string } | null> {
      const { oauth } = deviceSettings();
      if (typeof input?.rateLimit !== "function") throw validationError("rateLimit is required");
      await input.rateLimit();
      if (typeof input.userCode !== "string") return null;
      const found = await engine().lookupByUserCode({ userCode: input.userCode });
      if (!found || found.kind !== oauthDeviceKindName) return null;
      // One another issuer sharing the database opened is not this page's.
      if ((await readDevice(found.id))?.payload.resource !== oauth.issuer) return null;
      return { id: found.id, expiresAt: found.expiresAt };
    },

    /** What the code-entry page shows, for the id and the code the person entered. */
    async deviceDetails(input: {
      id: string;
      userCode: string;
      viewer: AuthState | null | undefined;
    }): Promise<OAuthDeviceDetails> {
      const { details, state, payload } = await loadForBrowser(input.id, input.userCode, input.viewer ?? null);
      return {
        id: details.id,
        state,
        client: payload.client,
        requestedGrant: payload.requestedGrant,
        userCode: details.userCode,
        expiresAt: details.expiresAt,
        viewer: details.viewer,
      };
    },

    /**
     * The signed-in person allows the client into one of their accounts, with
     * the grant they chose. Idempotent for the same person: approving again
     * answers the same; anyone else gets `409 already_completed`.
     */
    async approveDevice(input: ApproveDeviceInput): Promise<{ state: "completed"; organizationId: string }> {
      const { state, record } = await loadForBrowser(input.id, input.userCode);
      const actor = input.actor ?? createEmptyAuthState();
      const { userId } = requireInteractiveSession(actor);
      const mine = (completed: OAuthDeviceRecord | null | undefined) => {
        if (!completed || completed.userId !== userId) {
          throw alreadyCompleted("This device authorization was already approved");
        }
        return { state: "completed" as const, organizationId: completed.organizationId };
      };
      if (state === "completed") return mine(record);
      if (!isCredentialGrant(input.grant)) throw validationError('grant must be "read" or "manage"');
      if (typeof input.organizationId !== "string" || !input.organizationId) {
        throw validationError("organizationId is required");
      }
      try {
        await engine().approve({
          id: input.id,
          userCode: input.userCode,
          actor,
          organizationId: input.organizationId,
          input: { grant: input.grant },
        });
      } catch (error) {
        if (!isCode(error, "already_completed")) throw error;
      }
      return mine((await readDevice(input.id))?.record);
    },

    /** The person declines. Nobody needs to be signed in; `actor` only records who did. */
    async denyDevice(input: {
      id: string;
      userCode: string;
      actor?: AuthState | null;
    }): Promise<{ state: "denied" }> {
      await loadForBrowser(input.id, input.userCode);
      await engine().deny({ id: input.id, userCode: input.userCode, actor: input.actor ?? null });
      return { state: "denied" };
    },

    exchangeDeviceCode,
  };
};

export type CfAuthOAuthDevice = ReturnType<typeof createOAuthDevice>;
