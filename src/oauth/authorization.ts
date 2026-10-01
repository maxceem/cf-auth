/**
 * OAuth authorization: the authorization request, the consent page's
 * decisions, the code exchange, and the discovery documents.
 *
 * A pending authorization is an operation of the built-in internal kind
 * `cf-auth:oauth.authorize`, opened by `authorize` and completed by one of
 * two doors — a signed-in person (`approveAuthorization`) or an account
 * provisioned on the spot (`approveGuestAuthorization`) — or denied. Its
 * completion record says who approved what; the code exchange turns it into
 * a connection, once.
 *
 * **The code.** 32 random bytes, base64url, made when the authorization opens.
 * The operation's id is `oauth-<SHA-256 of the code, hex>`, so the exchange
 * finds the operation by the code's digest through the primary key and never
 * stores or compares the code itself. The payload keeps the code sealed
 * (AES-256-GCM) under a key derived from the browser proof, which the
 * database holds only a digest of: whoever presents the proof again — a
 * retried approval, either door — reopens it and rebuilds the same redirect,
 * byte for byte, and nobody else can. The engine's own token for the
 * operation is a separate random value that nothing keeps, so the code does
 * not lead to the proof.
 *
 * Nothing here is an HTTP route. Each function answers a plain value: a
 * consent reference, a redirect, an error page, or a token response.
 */
import { and, eq, is, isNull, sql, SQL } from "drizzle-orm";
import { alias } from "drizzle-orm/sqlite-core";
import { credentialAuthoritySql, sqliteNowMs } from "../authority.js";
import type { CfAuthDatabase, ResolvedCfAuthConfig, ResolvedOAuthConfig } from "../config.js";
import { openTextForToken, randomToken, sealTextForToken, sha256Hex, timingSafeEqual } from "../crypto.js";
import {
  CfAuthError,
  notAMember,
  operationDenied,
  operationExpired,
  operationNotFound,
  organizationExpired,
  validationError,
} from "../errors.js";
import {
  operationBrowserProof,
  type CfAuthOperations,
  type OperationKind,
} from "../operations.js";
import type { CfAuthRepository } from "../repository.js";
import type { CfAuthTables } from "../schema.js";
import { requireInteractiveSession } from "../service.js";
import {
  createEmptyAuthState,
  isCredentialGrant,
  isOrganizationExpired,
  organizationRoles,
  type AuthState,
  type AuthUser,
  type CredentialGrant,
  type OperationState,
  type OrganizationMembership,
} from "../types.js";
import { oauthMembershipLiveSql, oauthOrganizationLiveSql } from "./authority.js";
import { ClientMetadataRefusal, fetchClientMetadataDocument } from "./cimd.js";
import { duplicateDescription, duplicatedParameter, formParams, type FormParams } from "./params.js";
import { redirectUriMatches } from "./redirect-uri.js";

// --- the kind --------------------------------------------------------------------

/** The built-in internal kind a pending authorization is an operation of. */
export const oauthAuthorizeKindName = "cf-auth:oauth.authorize";
/** How long an authorization's record is kept, counted from opening: a replayed code is recognised for this long. */
export const oauthAuthorizationRecordTtlMs = 24 * 60 * 60_000;
/** The scopes a client may ask for: the grant of the connection it wants. */
export const oauthScopes = ["read", "manage"] as const;

/** Who the client is, as the consent page shows it. */
export interface OAuthClientIdentity {
  /** The `client_id`: a registered id, or the metadata document's URL. */
  id: string;
  /** Declared by the client's domain (CIMD) or configured (registered). Display only. */
  name: string;
  /** The `client_id` URL's host for a CIMD client; null for a registered one. */
  domain: string | null;
  source: "cimd" | "registered";
}

/** What a pending authorization holds, from the request that opened it. */
export interface OAuthAuthorizationPayload {
  client: OAuthClientIdentity;
  /** The `redirect_uri` as the request presented it. */
  redirectUri: string;
  /** The S256 `code_challenge`. */
  codeChallenge: string;
  /** The `scope` the client asked for; `manage` when it named none. */
  requestedGrant: CredentialGrant;
  /** The client's `state`, echoed on every redirect; absent when it sent none. */
  state?: string;
  /** The `resource`, normalised to the issuer. */
  resource: string;
  /** The code, sealed under a key derived from the browser proof. */
  sealedCode: string;
}

/** What a completed authorization records, in the clear. Never the code. */
export interface OAuthAuthorizationRecord {
  /** Which door completed it. */
  door: "person" | "guest";
  /** The user the connection will belong to: the person, or the provisioned service user. */
  userId: string;
  organizationId: string;
  /** The grant the connection will carry. A guest connection is always `manage`. */
  grant: CredentialGrant;
  /** What the client asked for, which may differ from `grant`. */
  requestedGrant: CredentialGrant;
  client: OAuthClientIdentity;
  redirectUri: string;
  codeChallenge: string;
  resource: string;
  /** Completion + `authorizationTtlMs`, epoch milliseconds. */
  codeExpiresAt: number;
  /** When the code was exchanged, epoch milliseconds; null until it is. */
  exchangedAt: number | null;
  /** The connection the exchange issued; null until it is. */
  connectionId: string | null;
}

/** What `approveGuestAuthorization`'s `provision` is handed. */
export interface OAuthGuestProvisionContext {
  /** The authorization's operation id: derive the new ids from it, so a retry names the same rows. */
  operationId: string;
  /**
   * AND this into the WHERE of every statement: true once the batch's first
   * write has judged the engine's guard (the authorization pending and in
   * time) and the admission condition, and latched that judgement on the
   * operation row. The admission is not evaluated again, so provisioning
   * may change what it reads.
   */
  guard: SQL;
  db: CfAuthDatabase;
  tables: CfAuthTables;
  now: number;
}

/** What `provision` answers: the account it creates, and the statements that create it. */
export interface OAuthGuestProvision {
  userId: string;
  organizationId: string;
  /** drizzle query builders (`guardedInsert`, `db.update`, ...), each guarded with `guard`. */
  statements: readonly unknown[];
}

/** The approval the consent functions hand the kind. Built here, never by a page. */
type AuthorizationApproval =
  | {
      door: "person";
      userId: string;
      sessionId: string;
      organizationId: string;
      grant: CredentialGrant;
    }
  | {
      door: "guest";
      admission: SQL | null;
      provision: (
        context: OAuthGuestProvisionContext,
      ) => OAuthGuestProvision | Promise<OAuthGuestProvision>;
    };

const isObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

const parsePayload = (value: unknown): OAuthAuthorizationPayload => {
  if (!isObject(value) || !isObject(value.client)) throw validationError("Invalid authorization payload");
  const { client } = value;
  if (
    typeof client.id !== "string" ||
    typeof client.name !== "string" ||
    (client.domain !== null && typeof client.domain !== "string") ||
    (client.source !== "cimd" && client.source !== "registered") ||
    typeof value.redirectUri !== "string" ||
    typeof value.codeChallenge !== "string" ||
    !isCredentialGrant(value.requestedGrant) ||
    (value.state !== undefined && typeof value.state !== "string") ||
    typeof value.resource !== "string" ||
    typeof value.sealedCode !== "string"
  ) {
    throw validationError("Invalid authorization payload");
  }
  return value as unknown as OAuthAuthorizationPayload;
};

const parseApproval = (value: unknown): AuthorizationApproval => {
  if (isObject(value) && value.door === "person") {
    if (
      typeof value.userId === "string" &&
      typeof value.sessionId === "string" &&
      typeof value.organizationId === "string" &&
      isCredentialGrant(value.grant)
    ) {
      return value as unknown as AuthorizationApproval;
    }
  }
  if (isObject(value) && value.door === "guest") {
    if ((value.admission === null || is(value.admission, SQL)) && typeof value.provision === "function") {
      return value as unknown as AuthorizationApproval;
    }
  }
  throw validationError("Invalid authorization approval");
};

/** The provisioned ids, as `provision` must answer them. */
const parseProvision = (value: unknown): OAuthGuestProvision => {
  if (
    !isObject(value) ||
    typeof value.userId !== "string" ||
    !value.userId ||
    typeof value.organizationId !== "string" ||
    !value.organizationId ||
    !Array.isArray(value.statements)
  ) {
    throw validationError("provision must answer { userId, organizationId, statements }");
  }
  return value as unknown as OAuthGuestProvision;
};

/**
 * The built-in internal kind `cf-auth:oauth.authorize`. Public (anyone may
 * start one; the browser's address is what the pending cap counts),
 * approved by the browser proof alone, with the person's or the guest's
 * authority carried into the completing batch by the kind itself.
 */
export const createOAuthAuthorizeKind = (oauth: ResolvedOAuthConfig): OperationKind => ({
  name: oauthAuthorizeKindName,
  internal: true,
  open: "public",
  browser: true,
  approver: "proof",
  userCode: false,
  countsTowardPending: true,
  pendingTtlMs: oauth.authorizationTtlMs,
  // At least a day, and never shorter than an authorization approved at its
  // last moment plus its code's whole validity.
  recordTtlMs: Math.max(oauthAuthorizationRecordTtlMs, 2 * oauth.authorizationTtlMs),
  payload: parsePayload,
  input: parseApproval,

  approve: async ({ operation, payload, input, guard, db, tables, now }) => {
    const approval = input as AuthorizationApproval;
    const authorization = payload as OAuthAuthorizationPayload;
    const base = {
      requestedGrant: authorization.requestedGrant,
      client: authorization.client,
      redirectUri: authorization.redirectUri,
      codeChallenge: authorization.codeChallenge,
      resource: authorization.resource,
      codeExpiresAt: now + oauth.authorizationTtlMs,
      exchangedAt: null,
      connectionId: null,
    };
    /**
     * The statement the completion depends on: it changes the operation's own
     * row only while `condition` holds, and the engine completes only if the
     * statement right before the completion changed a row — so the condition
     * decides whether the whole batch lands.
     */
    const carry = (condition: SQL) =>
      db
        .update(tables.operation)
        .set({ updatedAt: new Date(now) })
        .where(and(eq(tables.operation.id, operation.id), guard, condition));

    if (approval.door === "person") {
      const { userId, sessionId, organizationId, grant } = approval;
      const record: OAuthAuthorizationRecord = { ...base, door: "person", userId, organizationId, grant };
      // The person's session, live, and their membership — any role — in an
      // organization inside its deadline, re-read when the write lands.
      const authority = and(
        credentialAuthoritySql(tables, {
          organizationId,
          userId,
          credentialId: sessionId,
          allowedRoles: organizationRoles,
          nowMs: now,
        }),
        oauthOrganizationLiveSql(tables, { organizationId, nowMs: now }),
      )!;
      return { outcome: record, seal: false, statements: [carry(authority)] };
    }

    // The admission is judged once, by the first write of the batch, before
    // anything is provisioned: a rule about the deployment's state (that it
    // is empty, say) would turn false as soon as the account's own rows land.
    // That write latches the judgement on the operation row with a claim of
    // this call's own, the `execution_claim` a reservation's execution holds
    // it by; every later statement asks for the claim, not the admission
    // again. Completing clears it, and a refused batch rolls it back.
    const claim = randomToken(32);
    const latch = db
      .update(tables.operation)
      .set({ executionClaim: claim, updatedAt: new Date(now) })
      .where(
        and(
          eq(tables.operation.id, operation.id),
          isNull(tables.operation.executionClaim),
          guard,
          ...(approval.admission ? [approval.admission] : []),
        ),
      );
    const admittedRow = alias(tables.operation, "cf_auth_oauth_admitted");
    const admitted = sql`exists (select 1 from ${tables.operation} as ${sql.identifier("cf_auth_oauth_admitted")}
      where ${admittedRow.id} = ${operation.id}
        and ${admittedRow.state} = 'pending'
        and ${admittedRow.executionClaim} = ${claim})`;
    const provided = parseProvision(
      await approval.provision({ operationId: operation.id, guard: admitted, db, tables, now }),
    );
    const record: OAuthAuthorizationRecord = {
      ...base,
      door: "guest",
      userId: provided.userId,
      organizationId: provided.organizationId,
      // A guest connection is the account's only way in, so it manages it.
      grant: "manage",
    };
    // At the end of the batch the admission is still latched and the
    // provisioned membership and organization exist and are live: otherwise
    // the completion is refused and every statement, the latch included,
    // rolls back.
    const provisioned = and(
      admitted,
      oauthMembershipLiveSql(tables, { userId: provided.userId, organizationId: provided.organizationId }),
      oauthOrganizationLiveSql(tables, { organizationId: provided.organizationId, nowMs: now }),
    )!;
    return { outcome: record, seal: false, statements: [latch, ...provided.statements, carry(provisioned)] };
  },
});

// --- service shapes ------------------------------------------------------------------

/** An error the authorization endpoint answers on a page of its own: never a redirect. */
export interface OAuthAuthorizeErrorPage {
  status: 400 | 429;
  code: "invalid_request" | "invalid_client" | "too_many_pending";
  description: string;
}

/**
 * What `authorize` answers. `consent`: send the browser to your consent page
 * with `id` in the query and `proof` in the fragment. `redirect`: send it
 * there (an error for the client). `error`: show a page — the client or its
 * redirect URI cannot be trusted, so nothing goes back to it.
 */
export type OAuthAuthorizeResult =
  | { consent: { id: string; proof: string } }
  | { redirect: string }
  | { error: OAuthAuthorizeErrorPage };

/** What the consent page shows. */
export interface OAuthAuthorizationDetails {
  id: string;
  state: OperationState;
  client: OAuthClientIdentity;
  /** Where the browser will be sent: the redirect URI's host, or its scheme for a private-use one. */
  redirectHost: string;
  requestedGrant: CredentialGrant;
  /** When the pending authorization lapses. */
  expiresAt: string;
  /** The signed-in person (an interactive human session), with every membership; null otherwise. */
  viewer: { user: AuthUser; memberships: OrganizationMembership[] } | null;
}

export interface ApproveAuthorizationInput {
  id: string;
  proof: string;
  /** The person on the consent page: an interactive human session. */
  actor: AuthState | null | undefined;
  /** The account to connect: one the person is an active member of, at any role. */
  organizationId: string;
  /** The grant the person chose; any, whatever the client asked for. */
  grant: CredentialGrant;
}

export interface ApproveGuestAuthorizationInput {
  id: string;
  proof: string;
  /**
   * The deployment's admission: throw to refuse, or answer null, or a
   * condition the completing batch must also satisfy.
   */
  admit: () => Promise<SQL | null>;
  /** The rate limit, keyed on the browser's address: throw when exceeded. */
  rateLimit: () => Promise<void>;
  /** The account to provision, as guarded statements for the completing batch. */
  provision: (context: OAuthGuestProvisionContext) => OAuthGuestProvision | Promise<OAuthGuestProvision>;
}

/** RFC 9728 protected resource metadata. */
export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
  scopes_supported: string[];
  bearer_methods_supported: string[];
}

/** RFC 8414 authorization server metadata. */
export interface AuthorizationServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  revocation_endpoint: string;
  response_types_supported: string[];
  grant_types_supported: string[];
  code_challenge_methods_supported: string[];
  token_endpoint_auth_methods_supported: string[];
  revocation_endpoint_auth_methods_supported: string[];
  scopes_supported: string[];
  authorization_response_iss_parameter_supported: boolean;
  client_id_metadata_document_supported: boolean;
}

/** Where the app mounts the endpoints the authorization server metadata names, under the issuer. */
export const oauthEndpointPaths = {
  authorize: "/oauth/authorize",
  token: "/oauth/token",
  revoke: "/oauth/revoke",
} as const;

/** What the code exchange answers, shaped as `token`'s result. */
export type OAuthExchangeResult =
  | { status: 200; body: { access_token: string; token_type: "Bearer"; expires_in: number; refresh_token: string; scope: CredentialGrant } }
  | { status: 400 | 401; body: { error: "invalid_request" | "invalid_grant" | "invalid_target"; error_description: string } };

/** The connection issuance the exchange batches, from the connection service. */
export interface OAuthAuthorizationConnections {
  connectionStatements(input: {
    userId: string;
    organizationId: string;
    clientId: string;
    clientName: string;
    resource: string;
    grant: CredentialGrant;
    now: number;
    id: string;
    condition: SQL;
  }): Promise<{
    statements: readonly unknown[];
    response: Extract<OAuthExchangeResult, { status: 200 }>["body"];
    afterCommit(): Promise<void>;
  }>;
  /** Ends a connection the way a voluntary revocation does: if its row is still live. */
  revokeConnectionById(connectionId: string): Promise<void>;
}

// --- the functions ---------------------------------------------------------------------

const codeSealInfo = "cf-auth:oauth-authorization-code";
/** 32 bytes, base64url: what `authorize` makes. Anything else is unknown without a lookup. */
const codePattern = /^[A-Za-z0-9_-]{43}$/;
/** 43 base64url characters, no padding: a SHA-256 digest. */
const challengePattern = /^[A-Za-z0-9_-]{43}$/;
/** RFC 7636 §4.1. */
const verifierPattern = /^[A-Za-z0-9._~-]{43,128}$/;
const maxClientIdLength = 2048;
const maxRedirectUriLength = 2048;
const maxStateLength = 2048;

/** The operation id of the authorization a code belongs to: the code's digest. */
const operationIdForCode = async (code: string) => `oauth-${await sha256Hex(code)}`;

/** S256 (RFC 7636 §4.2): base64url of the SHA-256 of the verifier, no padding. */
const s256 = async (verifier: string): Promise<string> => {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  let binary = "";
  for (const byte of digest) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

const errorPage = (
  code: OAuthAuthorizeErrorPage["code"],
  description: string,
  status: OAuthAuthorizeErrorPage["status"] = 400,
): { error: OAuthAuthorizeErrorPage } => ({ error: { status, code, description } });

/** `redirectUri` with `params` set on its query, in order. */
const redirectTo = (redirectUri: string, params: readonly (readonly [string, string])[]): string => {
  const url = new URL(redirectUri);
  for (const [name, value] of params) url.searchParams.set(name, value);
  return url.toString();
};

/** The host a redirect URI sends the browser to, or the scheme of a private-use one. */
const redirectHostOf = (redirectUri: string): string => {
  try {
    const url = new URL(redirectUri);
    return url.host || url.protocol.slice(0, -1);
  } catch {
    return "";
  }
};

const isCode = (error: unknown, code: string) => error instanceof CfAuthError && error.code === code;

export const createOAuthAuthorization = (deps: {
  config: ResolvedCfAuthConfig;
  repository: CfAuthRepository;
  /** The engine's door that admits internal kinds, read on use. */
  readonly operations: CfAuthOperations;
  settings: () => ResolvedOAuthConfig;
  connections: OAuthAuthorizationConnections;
}) => {
  const { config, repository, settings, connections } = deps;
  /** Read on use: the service hands a door only while OAuth is on. */
  const engine = () => deps.operations;
  const { db, tables } = config;
  const { operation } = tables;

  /** The issuer's own `iss`, `state` when one was sent, appended to every redirect. */
  const trailer = (oauth: ResolvedOAuthConfig, state: string | undefined) => [
    ...(state !== undefined ? ([["state", state]] as const) : []),
    ["iss", oauth.issuer] as const,
  ];

  /** The authorization's row as stored: its effective state, payload and record. */
  const readAuthorization = async (id: string) => {
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
    if (!row || row.kind !== oauthAuthorizeKindName || row.payload === null) return null;
    const state: OperationState =
      row.state === "pending" && row.expiresAt.getTime() <= Date.now() ? "expired" : row.state;
    return {
      state,
      payload: parsePayload(JSON.parse(row.payload)),
      record:
        row.state === "completed" && row.outcome !== null
          ? (JSON.parse(row.outcome) as OAuthAuthorizationRecord)
          : null,
    };
  };

  /**
   * The authorization a browser addresses, once its proof checks out —
   * refused exactly as the engine refuses a browser: `404
   * operation_not_found` for an unknown id or another kind, `403
   * invalid_proof` for a wrong proof.
   */
  const loadForBrowser = async (id: string, proof: string, viewer: AuthState | null = null) => {
    settings();
    const details = await engine().details({ id, proof, viewer });
    if (details.kind !== oauthAuthorizeKindName) throw operationNotFound();
    const authorization = await readAuthorization(id);
    if (!authorization) throw operationNotFound();
    return { details, ...authorization };
  };

  /** Refuses anything but a pending authorization, naming what it is instead. */
  const assertPending = (state: OperationState) => {
    if (state === "denied") throw operationDenied();
    if (state === "expired" || state === "retired") throw operationExpired();
  };

  /** The code, reopened with the proof that sealed it. */
  const openCode = async (id: string, proof: string, payload: OAuthAuthorizationPayload) => {
    try {
      return await openTextForToken(proof, codeSealInfo, id, payload.sealedCode);
    } catch {
      throw operationExpired("This authorization's code can no longer be read");
    }
  };

  /** The redirect every approval of this authorization answers: the code, `state`, `iss`. */
  const codeRedirect = async (id: string, proof: string, payload: OAuthAuthorizationPayload) =>
    redirectTo(payload.redirectUri, [
      ["code", await openCode(id, proof, payload)],
      ...trailer(settings(), payload.state),
    ]);

  /**
   * Runs the engine's approval with `approval`. One already completed — by
   * either door, before this call or racing it — is not an error here: the
   * caller answers its canonical redirect.
   */
  const approveThroughEngine = async (id: string, proof: string, approval: AuthorizationApproval) => {
    try {
      await engine().approve({ id, proof, input: approval });
    } catch (error) {
      if (!isCode(error, "already_completed")) throw error;
    }
  };

  /** The client a request names: registered, or a metadata document fetched now. */
  const resolveClient = async (
    oauth: ResolvedOAuthConfig,
    clientId: string,
  ): Promise<{ client: OAuthClientIdentity; redirectUris: readonly string[] } | { error: OAuthAuthorizeErrorPage }> => {
    const registered = oauth.clients.find((client) => client.clientId === clientId);
    if (registered) {
      return {
        client: { id: clientId, name: registered.name, domain: null, source: "registered" },
        redirectUris: registered.redirectUris,
      };
    }
    if (!/^https:\/\//i.test(clientId)) {
      return errorPage("invalid_client", "The client is not registered with this server");
    }
    if (!oauth.cimd) {
      return errorPage(
        "invalid_client",
        "This server does not accept Client ID Metadata Documents; the client must be registered",
      );
    }
    try {
      const document = await fetchClientMetadataDocument(clientId, {
        fetch: oauth.cimd.fetch ?? globalThis.fetch,
        allowUrl: oauth.cimd.allowUrl,
      });
      return {
        client: { id: clientId, name: document.name, domain: document.domain, source: "cimd" },
        redirectUris: document.redirectUris,
      };
    } catch (error) {
      if (error instanceof ClientMetadataRefusal) return errorPage("invalid_client", error.message);
      throw error;
    }
  };

  /** The value of a parameter, or undefined when it is absent or empty. */
  const value = (params: FormParams, name: string) => {
    const found = params.get(name);
    return found === null || found === "" ? undefined : found;
  };

  const exchangeFail = (
    error: "invalid_request" | "invalid_grant" | "invalid_target",
    description: string,
  ): Extract<OAuthExchangeResult, { status: 400 | 401 }> => ({
    status: 400,
    body: { error, error_description: description },
  });

  return {
    protectedResourceMetadata(path: string = ""): ProtectedResourceMetadata {
      const oauth = settings();
      if (path !== "" && !oauth.resourcePaths.includes(path)) {
        throw validationError("path must be \"\" or one of oauth.resourcePaths");
      }
      return {
        resource: `${oauth.issuer}${path}`,
        authorization_servers: [oauth.issuer],
        scopes_supported: [...oauthScopes],
        bearer_methods_supported: ["header"],
      };
    },

    authorizationServerMetadata(): AuthorizationServerMetadata {
      const oauth = settings();
      return {
        issuer: oauth.issuer,
        authorization_endpoint: `${oauth.issuer}${oauthEndpointPaths.authorize}`,
        token_endpoint: `${oauth.issuer}${oauthEndpointPaths.token}`,
        revocation_endpoint: `${oauth.issuer}${oauthEndpointPaths.revoke}`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
        revocation_endpoint_auth_methods_supported: ["none"],
        scopes_supported: [...oauthScopes],
        authorization_response_iss_parameter_supported: true,
        client_id_metadata_document_supported: oauth.cimd !== null,
      };
    },

    async authorize(input: { query: URLSearchParams; rateLimitKey: string | null }): Promise<OAuthAuthorizeResult> {
      const oauth = settings();
      const params = formParams(input?.query);
      if (!params) return errorPage("invalid_request", "The authorization request must be query parameters");

      // First, before anything is trusted: a duplicated redirect_uri or
      // client_id could not be told apart from the real one.
      const duplicated = duplicatedParameter(params);
      if (duplicated !== null) return errorPage("invalid_request", duplicateDescription(duplicated));

      const clientId = value(params, "client_id");
      if (clientId === undefined) return errorPage("invalid_request", "client_id is required");
      if (clientId.length > maxClientIdLength) return errorPage("invalid_request", "client_id is too long");
      const redirectUri = value(params, "redirect_uri");
      if (redirectUri === undefined) return errorPage("invalid_request", "redirect_uri is required");
      if (redirectUri.length > maxRedirectUriLength) return errorPage("invalid_request", "redirect_uri is too long");

      const resolved = await resolveClient(oauth, clientId);
      if ("error" in resolved) return resolved;
      if (!resolved.redirectUris.some((declared) => redirectUriMatches(declared, redirectUri))) {
        return errorPage("invalid_request", "redirect_uri is not one the client declares");
      }

      // From here on the redirect URI is the client's own, so every error goes back to it.
      const sentState = value(params, "state");
      const state = sentState !== undefined && sentState.length <= maxStateLength ? sentState : undefined;
      const fail = (error: string, description: string): { redirect: string } => ({
        redirect: redirectTo(redirectUri, [["error", error], ["error_description", description], ...trailer(oauth, state)]),
      });
      if (sentState !== undefined && state === undefined) return fail("invalid_request", "state is too long");

      const responseType = value(params, "response_type");
      if (responseType === undefined) return fail("invalid_request", "response_type is required");
      if (responseType !== "code") return fail("unsupported_response_type", "response_type must be code");

      const method = value(params, "code_challenge_method");
      if (method === undefined) return fail("invalid_request", "code_challenge_method is required");
      if (method !== "S256") return fail("invalid_request", "code_challenge_method must be S256");
      const challenge = value(params, "code_challenge");
      if (challenge === undefined) return fail("invalid_request", "code_challenge is required");
      if (!challengePattern.test(challenge)) {
        return fail("invalid_request", "code_challenge must be 43 base64url characters with no padding");
      }

      const resource = value(params, "resource");
      if (resource === undefined) return fail("invalid_request", "resource is required");
      if (!oauth.resources.includes(resource)) {
        return fail("invalid_target", "resource must be the issuer or one of its resource paths");
      }

      const scope = value(params, "scope") ?? "manage";
      if (!isCredentialGrant(scope)) return fail("invalid_scope", "scope must be read or manage");

      // The code, made now and kept sealed under the proof until an approval
      // reopens it; the operation is named by its digest.
      const code = randomToken(32);
      const id = await operationIdForCode(code);
      const token = randomToken(32);
      const proof = await operationBrowserProof(token, config.operations.realm);
      const payload: OAuthAuthorizationPayload = {
        client: resolved.client,
        redirectUri,
        codeChallenge: challenge,
        requestedGrant: scope,
        ...(state !== undefined ? { state } : {}),
        resource: oauth.issuer,
        sealedCode: await sealTextForToken(proof, codeSealInfo, id, code),
      };
      try {
        const view = await engine().open({
          kind: oauthAuthorizeKindName,
          token,
          id,
          payload,
          rateLimitKey: input.rateLimitKey ?? null,
          client: { label: resolved.client.name },
        });
        if (view.browserProof !== proof) throw new Error("cf-auth: the authorization's browser proof is not the one derived");
      } catch (error) {
        if (isCode(error, "too_many_pending")) {
          return errorPage("too_many_pending", "Too many authorizations are waiting from this address; finish or wait for one", 429);
        }
        throw error;
      }
      return { consent: { id, proof } };
    },

    async authorizationDetails(input: {
      id: string;
      proof: string;
      viewer: AuthState | null | undefined;
    }): Promise<OAuthAuthorizationDetails> {
      const { details, state, payload } = await loadForBrowser(input.id, input.proof, input.viewer ?? null);
      return {
        id: details.id,
        state,
        client: payload.client,
        redirectHost: redirectHostOf(payload.redirectUri),
        requestedGrant: payload.requestedGrant,
        expiresAt: details.expiresAt,
        viewer: details.viewer,
      };
    },

    async approveAuthorization(input: ApproveAuthorizationInput): Promise<{ redirect: string }> {
      const { state, payload } = await loadForBrowser(input.id, input.proof);
      if (state === "completed") return { redirect: await codeRedirect(input.id, input.proof, payload) };
      assertPending(state);

      const { userId, sessionId } = requireInteractiveSession(input.actor ?? createEmptyAuthState());
      if (!isCredentialGrant(input.grant)) throw validationError('grant must be "read" or "manage"');
      if (typeof input.organizationId !== "string" || !input.organizationId) {
        throw validationError("organizationId is required");
      }
      const membership = await repository.findMembership(userId, input.organizationId);
      if (!membership || membership.status !== "active") {
        throw notAMember("Approving needs a membership in this organization");
      }
      if (isOrganizationExpired(membership.organization)) throw organizationExpired();

      await approveThroughEngine(input.id, input.proof, {
        door: "person",
        userId,
        sessionId,
        organizationId: input.organizationId,
        grant: input.grant,
      });
      return { redirect: await codeRedirect(input.id, input.proof, payload) };
    },

    async approveGuestAuthorization(
      input: ApproveGuestAuthorizationInput,
    ): Promise<{ redirect: string; organizationId: string }> {
      // 1. The proof.
      const { state, payload, record } = await loadForBrowser(input.id, input.proof);
      // 2. Already completed, by either door: its redirect, never re-admitted or counted.
      if (state === "completed") {
        if (!record) throw operationExpired("This authorization's record can no longer be read");
        return { redirect: await codeRedirect(input.id, input.proof, payload), organizationId: record.organizationId };
      }
      assertPending(state);
      if (
        typeof input.admit !== "function" ||
        typeof input.rateLimit !== "function" ||
        typeof input.provision !== "function"
      ) {
        throw validationError("admit, rateLimit and provision are required");
      }
      // 3. Admission: a refusal never reaches the rate limit.
      const admission = (await input.admit()) ?? null;
      if (admission !== null && !is(admission, SQL)) {
        throw validationError("admit must answer null or an SQL condition");
      }
      // 4. The rate limit.
      await input.rateLimit();
      // 5. Provision, inside the batch that completes the authorization.
      await approveThroughEngine(input.id, input.proof, {
        door: "guest",
        admission,
        provision: input.provision,
      });
      const completed = await readAuthorization(input.id);
      if (!completed?.record) throw operationNotFound();
      return {
        redirect: await codeRedirect(input.id, input.proof, payload),
        organizationId: completed.record.organizationId,
      };
    },

    async denyAuthorization(input: { id: string; proof: string }): Promise<{ redirect: string }> {
      const { payload } = await loadForBrowser(input.id, input.proof);
      await engine().deny({ id: input.id, proof: input.proof });
      return {
        redirect: redirectTo(payload.redirectUri, [
          ["error", "access_denied"],
          ["error_description", "The authorization was denied"],
          ...trailer(settings(), payload.state),
        ]),
      };
    },

    /** `grant_type=authorization_code`, its parameters already free of duplicates. */
    async exchangeCode(oauth: ResolvedOAuthConfig, params: FormParams): Promise<OAuthExchangeResult> {
      for (const name of ["code", "redirect_uri", "client_id", "code_verifier"]) {
        if (!params.get(name)) return exchangeFail("invalid_request", `${name} is required`);
      }
      const verifier = params.get("code_verifier")!;
      if (!verifierPattern.test(verifier)) {
        return exchangeFail("invalid_request", "code_verifier must be 43 to 128 characters of A-Z, a-z, 0-9, -, ., _ or ~");
      }
      const resource = params.get("resource");
      if (resource !== null && !oauth.resources.includes(resource)) {
        return exchangeFail("invalid_target", "resource must be the issuer or one of its resource paths");
      }

      const unknown = () => exchangeFail("invalid_grant", "The authorization code is not valid");
      const code = params.get("code")!;
      if (!codePattern.test(code)) return unknown();
      const id = await operationIdForCode(code);
      const found = await readAuthorization(id);
      if (!found || found.state !== "completed" || !found.record) return unknown();
      const record = found.record;

      // The client, the redirect and the verifier must be the authorization's;
      // a mismatch is refused and changes nothing, so the code alone ends nothing.
      const matches =
        timingSafeEqual(params.get("client_id")!, record.client.id) &&
        timingSafeEqual(params.get("redirect_uri")!, record.redirectUri) &&
        timingSafeEqual(await s256(verifier), record.codeChallenge);
      if (!matches) return unknown();
      if (resource !== null && oauth.issuer !== record.resource) {
        return exchangeFail("invalid_target", "resource is not the one the authorization was for");
      }

      /** A code exchanged before: the connection it issued ends, expired or not. */
      const replayed = async (connectionId: string | null) => {
        if (connectionId) await connections.revokeConnectionById(connectionId);
        return exchangeFail("invalid_grant", "The authorization code was already used; the connection it issued is revoked");
      };
      if (record.exchangedAt !== null) return replayed(record.connectionId);
      const now = Date.now();
      if (record.codeExpiresAt <= now) return exchangeFail("invalid_grant", "The authorization code has expired");

      // Completed, never exchanged, inside its validity by either clock — in
      // the batch that writes the connection, its first generation and the
      // record's `exchangedAt`.
      const code_ = alias(operation, "cf_auth_oauth_code");
      const exchangeable = sql`exists (select 1 from ${operation} as ${sql.identifier("cf_auth_oauth_code")}
        where ${code_.id} = ${id}
          and ${code_.kind} = ${oauthAuthorizeKindName}
          and ${code_.state} = 'completed'
          and json_extract(${code_.outcome}, '$.exchangedAt') is null
          and json_extract(${code_.outcome}, '$.codeExpiresAt') > ${sqliteNowMs(now)})`;
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
          record: { ...record, exchangedAt: now, connectionId } satisfies OAuthAuthorizationRecord,
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

      // Nothing written. Exchanged meanwhile — a concurrent presentation — is
      // a replay like any other; otherwise the code expired or the account
      // ended, and nothing is revoked.
      const current = await readAuthorization(id);
      if (current?.record && current.record.exchangedAt !== null) return replayed(current.record.connectionId);
      return exchangeFail("invalid_grant", "The authorization code is no longer valid");
    },
  };
};

export type CfAuthOAuthAuthorization = ReturnType<typeof createOAuthAuthorization>;
