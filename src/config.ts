import type { D1Database } from "@cloudflare/workers-types";
import { drizzle } from "drizzle-orm/d1";
import type { BaseSQLiteDatabase } from "drizzle-orm/sqlite-core";
import type { SQL } from "drizzle-orm";
import { validationError } from "./errors.js";
import { isAcceptableRedirectUri } from "./oauth/redirect-uri.js";
import type { OperationKind } from "./operations.js";
import { cfAuthTables, type CfAuthTables } from "./schema.js";
import {
  isCredentialGrant,
  organizationRoles,
  type AuthUser,
  type CfAuthEvent,
  type OrganizationRole,
} from "./types.js";

/**
 * Any async drizzle SQLite database — `drizzle-orm/d1` in production,
 * `drizzle-orm/libsql` (or better-sqlite3) in tests.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type CfAuthDatabase = BaseSQLiteDatabase<"async", any, any>;

export interface GoogleOAuthConfig {
  clientId: string;
  clientSecret: string;
  /** Optional explicit redirect URI; better-auth derives one from `baseUrl` otherwise. */
  redirectURI?: string;
  /** Allow existing Google users to sign in but reject creation of new users. */
  disableSignUp?: boolean;
}

/**
 * Routes OAuth callbacks through one stable deployment so preview and local
 * instances do not need their dynamic callback URLs registered with providers.
 */
export interface OAuthProxyConfig {
  /** Stable deployment origin registered with the OAuth provider. */
  productionUrl: string;
  /** Dedicated encryption secret shared by the stable and preview instances. */
  secret: string;
  /** Explicit current origin when Better Auth cannot infer it from the request. */
  currentUrl?: string;
  /** Maximum accepted age of the encrypted relay payload. Default: 60 seconds. */
  maxAge?: number;
}

export interface OrganizationsConfig {
  /**
   * Auto-create a default organization (with the signing-up user as `owner`)
   * in better-auth's `user.create.after` database hook. Default: `true`.
   */
  autoProvisionDefaultOrganization?: boolean;
  /**
   * Name for the auto-provisioned organization. Either a literal string or a
   * function of the new user. Default: `"My Organization"`.
   */
  defaultOrganizationName?: string | ((user: AuthUser) => string);
}

export interface ApiKeysConfig {
  /** Enable bearer API-key authentication and the key management service. Default: `false`. */
  enabled?: boolean;
  /**
   * Prefix prepended to generated tokens, e.g. `"sk_live_"` produces
   * `sk_live_<48 chars>`. Default: `"key_"`.
   */
  tokenPrefix?: string;
  /**
   * Request header naming the client kind (`cli` / `mcp`); anything else
   * resolves to the `api` action source. Default: `"X-Client"`.
   */
  clientHeader?: string;
}

/** The built-in `login` operation: a CLI asks, a person approves, the CLI gets an API key. */
export interface LoginOperationConfig {
  /**
   * The least role the approver must hold in the organization they log the
   * CLI in to. Default: `"admin"`, matching who may create an API key in the
   * console; lower it to `"member"` to let every member log a CLI in.
   */
  minRole?: OrganizationRole;
  /** How long the person has to approve. Default: 15 minutes. */
  pendingTtlMs?: number;
  /** How long the record is kept, counted from when the CLI asked. Default: 90 days. */
  recordTtlMs?: number;
}

export interface OperationsConfig {
  /** Turn on browser-approved operations and the `operations` service. Default: `false`. */
  enabled?: boolean;
  /**
   * Mixed into every browser proof and user code, so a proof made for one
   * deployment means nothing to another that shares its database schema. Use
   * a stable public identifier of the deployment. Changing it invalidates the
   * proofs of operations still pending. Default: `appName`.
   */
  realm?: string;
  /** Your own operation kinds. Names must be unique; `login` is taken while the built-in one is on. */
  kinds?: readonly OperationKind[];
  /** The built-in `login` kind. Needs `apiKeys.enabled`. Default: on; pass `false` to leave it out. */
  login?: boolean | LoginOperationConfig;
  limits?: {
    /** Pending operations one organization may have at once. Default: `10`. */
    pendingPerOrganization?: number;
    /**
     * Pending operations one opener may have at once: the signed-in opener,
     * or, for a public kind, the client address passed as `client.meta.ip`.
     * Default: `5`.
     */
    pendingPerOpener?: number;
  };
  /** How long a sealed outcome waits to be collected. Default: 15 minutes. */
  sealTtlMs?: number;
  /** How long a reservation (`reserve`) waits to be executed. Default: 15 minutes. */
  reserveTtlMs?: number;
}

/** A pre-registered public OAuth client: the fallback where CIMD is off or refused. */
export interface OAuthClientConfig {
  clientId: string;
  /** Shown on the consent page and copied onto the connection. Trusted configuration. */
  name: string;
  /**
   * Absolute, no fragment: `https`, `http` on a loopback host (any port at
   * presentation), or a private-use scheme in reverse-DNS form.
   */
  redirectUris: string[];
}

/** Client ID Metadata Documents: a `client_id` that is an https URL names its own metadata. */
export interface OAuthCimdConfig {
  /** Default: `globalThis.fetch`. */
  fetch?: typeof fetch;
  /** Extra host policy, e.g. an allowlist, asked after the built-in refusals. */
  allowUrl?: (url: URL) => boolean | Promise<boolean>;
}

/**
 * OAuth 2.1 for public clients (MCP clients): cf-auth issues connections
 * whose tokens authenticate like API keys. cf-auth mounts no routes; the
 * service functions under `cfAuth.oauth` answer what the app's routes send.
 */
export interface OAuthConfig {
  /**
   * Needs `apiKeys.enabled`, `operations.enabled` and a database that batches
   * atomically (D1, libsql). Default: `false`.
   */
  enabled?: boolean;
  /**
   * The issuer and the single protected resource: an origin with no path and
   * no trailing slash, `https`, or `http` on a loopback host (`127.0.0.1`,
   * `[::1]`, `localhost` or a name under `.localhost`). Required when enabled.
   */
  issuer?: string;
  /** Paths under the issuer also accepted as `resource`; tokens are bound to the issuer either way. Default: `["/mcp"]`. */
  resourcePaths?: string[];
  /** Default: 10 minutes. */
  accessTokenTtlMs?: number;
  /** Default: 30 days, restarted by each rotation. */
  refreshTokenTtlMs?: number;
  /** Absolute cap from the connection's creation. Default: `null` (none: revocable, like a key). */
  connectionMaxAgeMs?: number | null;
  /** A pending authorization's life, and a code's validity from completion. Default: 10 minutes. */
  authorizationTtlMs?: number;
  /**
   * Required when enabled. Distinct from each other and from
   * `apiKeys.tokenPrefix`, and the access prefix must not be able to begin
   * an API key, since a bearer token is routed by it.
   */
  tokenPrefix?: { access: string; refresh: string };
  /** Pre-registered clients. */
  clients?: OAuthClientConfig[];
  /** Client ID Metadata Documents. On by default; `false` turns them off. */
  cimd?: false | OAuthCimdConfig;
}

export interface EmailAndPasswordConfig {
  /** Default: `true`. */
  enabled?: boolean;
  /** Default: `8`. */
  minPasswordLength?: number;
  /** Default: `128`. */
  maxPasswordLength?: number;
  /** Default: `false`. */
  requireEmailVerification?: boolean;
  /** Ignore a caller-supplied `false` and revoke every other session after a password change. Default: `false`. */
  revokeOtherSessionsOnPasswordChange?: boolean;
}

export interface AccountLinkingConfig {
  /**
   * Join a social login to an existing user who has the same email address
   * when the provider reports it verified. Default: `false`, because this
   * library does not verify email addresses itself, so whoever registered
   * the address first with a password would otherwise receive every later
   * Google sign-in for it. Explicit linking by a signed-in user is unaffected.
   */
  implicit?: boolean;
}

export interface UserHooksConfig {
  /** Runs immediately before Better Auth persists a new human identity. */
  beforeCreate?: (user: AuthUser) => void | Promise<void>;
  /**
   * Makes human creation conditional in the same SQLite statement as the insert.
   * The host owns only the admission predicate; cf-auth owns normalization and
   * persistence. This prevents concurrent creates from both passing a separate
   * preflight read.
   */
  atomicCreateGuard?: {
    condition: (tables: CfAuthTables) => SQL;
    onDenied?: () => void | Promise<void>;
  };
}

export interface CookieConfig {
  /**
   * Namespace for every cookie this package owns. better-auth cookies become
   * `<prefix>_auth.*` and the current-organization cookie becomes
   * `<prefix>_current_organization`. Defaults to a slug of `appName`.
   */
  prefix?: string;
  /** Override the current-organization cookie name outright. */
  currentOrganizationCookieName?: string;
  /** `Secure` attribute. Defaults to "true when the request URL is https". */
  secure?: boolean;
  /** Default: `"Lax"`. */
  sameSite?: "Strict" | "Lax" | "None";
  /** Current-organization cookie lifetime in seconds. Default: one year. */
  maxAge?: number;
  /** Default: `"/"`. */
  path?: string;
  /** Cookie `Domain` attribute; unset by default. */
  domain?: string;
}

export interface CfAuthConfig {
  /** Human-readable app name, surfaced by better-auth (e.g. in emails). */
  appName: string;

  /** A D1 binding. Provide this or {@link CfAuthConfig.db}, not both. */
  d1?: D1Database;
  /** A pre-built drizzle SQLite database. Provide this or {@link CfAuthConfig.d1}. */
  db?: CfAuthDatabase;

  /** Secret used by better-auth to sign sessions. */
  secret: string;
  /**
   * Explicit signing key for the current-organization cookie.
   *
   * When omitted, a domain-separated subkey is derived from {@link CfAuthConfig.secret}
   * via HKDF-SHA256 rather than reusing it directly.
   */
  cookieSecret?: string;

  /**
   * Public origin of the app, e.g. `https://app.example.com`. Required in
   * production for OAuth redirects and cookie/CSRF checks.
   */
  baseUrl?: string;
  /** Where better-auth's own routes are mounted. Default: `"/api/auth"`. */
  basePath?: string;
  /** Extra origins allowed to call the auth endpoints (dev servers, etc). */
  trustedOrigins?: string[];

  /** Reject creation of every new Better Auth user while preserving sign-in for existing users. */
  disableSignUp?: boolean;

  userHooks?: UserHooksConfig;

  emailAndPassword?: EmailAndPasswordConfig;
  google?: GoogleOAuthConfig;
  oauthProxy?: OAuthProxyConfig;
  accountLinking?: AccountLinkingConfig;

  organizations?: OrganizationsConfig;
  apiKeys?: ApiKeysConfig;
  cookies?: CookieConfig;
  operations?: OperationsConfig;
  oauth?: OAuthConfig;

  /** Tables to read/write. Defaults to {@link cfAuthTables}. */
  tables?: CfAuthTables;

  /** Mount better-auth's OpenAPI plugin at `<basePath>/reference`. Default: `false`. */
  openAPI?: boolean;

  /**
   * Called after auth lifecycle events (signup, org creation, API key
   * create/revoke) so the host app can write its own audit log. Errors thrown
   * here are swallowed and reported to {@link CfAuthConfig.onError}.
   */
  onEvent?: (event: CfAuthEvent) => void | Promise<void>;

  /** Called when a non-fatal internal error occurs (e.g. a failing `onEvent`). */
  onError?: (error: unknown, context: { scope: string }) => void;
}

const slugify = (value: string) =>
  value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "") || "app";

const trimTrailingSlash = (value: string) => value.replace(/\/+$/, "");

const normalizeBasePath = (value: string) => {
  const withLeadingSlash = value.startsWith("/") ? value : `/${value}`;
  return trimTrailingSlash(withLeadingSlash) || "/";
};

export interface ResolvedOperationsConfig {
  enabled: boolean;
  realm: string;
  /** The app's own kinds; the built-in `login` is added by the service when {@link login} is set. */
  kinds: readonly OperationKind[];
  login: Required<LoginOperationConfig> | null;
  limits: { pendingPerOrganization: number; pendingPerOpener: number };
  sealTtlMs: number;
  reserveTtlMs: number;
}

const minute = 60_000;
const day = 24 * 60 * minute;
/** Defaults a kind falls back to; see {@link OperationKind}. */
export const operationDefaults = {
  pendingTtlMs: 15 * minute,
  recordTtlMs: 90 * day,
  sealTtlMs: 15 * minute,
  reserveTtlMs: 15 * minute,
} as const;

const operationKindName = /^[a-z][a-z0-9._-]{0,63}$/;

/**
 * The namespace of cf-auth's own internal kinds. A stored operation whose kind
 * starts with it is internal whatever an engine has registered, so a row of an
 * internal kind stays out of reach of the public entry points even for an
 * engine built without that kind. An app's kind name cannot contain `:`.
 */
export const internalOperationKindPrefix = "cf-auth:";

/** Whether a kind name is in cf-auth's internal namespace. */
export const isInternalOperationKind = (name: string): boolean =>
  name.startsWith(internalOperationKindPrefix);

const positiveNumber = (value: number | undefined, fallback: number, label: string) => {
  if (value === undefined) return fallback;
  if (!Number.isFinite(value) || value <= 0) throw validationError(`\`${label}\` must be a positive number`);
  return value;
};

const positiveInteger = (value: number | undefined, fallback: number, label: string) => {
  const resolved = positiveNumber(value, fallback, label);
  if (!Number.isInteger(resolved)) throw validationError(`\`${label}\` must be a whole number`);
  return resolved;
};

/**
 * Checks one kind's own settings; exported so the built-in kinds go through the
 * same rules. A kind is internal by its name alone, `cf-auth:<name>`, and only
 * a built-in kind may take one: nothing outside cf-auth can drive an internal
 * kind, so an app declaring one would register a kind it cannot use. There is
 * no public flag for it, so nothing an app writes can mark a kind internal.
 */
export const validateOperationKind = (
  kind: OperationKind,
  label?: string,
  options: { builtIn?: boolean } = {},
): void => {
  const rawName = typeof kind.name === "string" ? kind.name : "";
  const internalName = options.builtIn === true && isInternalOperationKind(rawName);
  const baseName = internalName ? rawName.slice(internalOperationKindPrefix.length) : rawName;
  if (!operationKindName.test(baseName)) {
    throw validationError(
      `Operation kind name \`${String(kind.name)}\` must be lowercase letters, digits, \`.\`, \`_\` or \`-\``,
    );
  }
  label ??= `operations.kinds[${kind.name}]`;
  if (kind.open !== "public" && !organizationRoles.includes(kind.open?.minRole)) {
    throw validationError(`\`${label}.open\` must be "public" or { minRole }`);
  }
  if (kind.grant !== undefined) {
    if (kind.open === "public") {
      throw validationError(
        `\`${label}.grant\` applies to a kind a caller opens; a public kind binds no credential`,
      );
    }
    if (!isCredentialGrant(kind.grant)) {
      throw validationError(`\`${label}.grant\` must be "read" or "manage"`);
    }
  }
  if (
    kind.approverMinRole !== undefined &&
    kind.approverMinRole !== null &&
    !organizationRoles.includes(kind.approverMinRole)
  ) {
    throw validationError(`\`${label}.approverMinRole\` must be an organization role or null`);
  }
  if (kind.approver !== undefined && kind.approver !== "session" && kind.approver !== "proof") {
    throw validationError(`\`${label}.approver\` must be "session" or "proof"`);
  }
  if (kind.countsTowardPending !== undefined && typeof kind.countsTowardPending !== "boolean") {
    throw validationError(`\`${label}.countsTowardPending\` must be a boolean`);
  }
  if (kind.deliver !== undefined && kind.deliver !== "once" && kind.deliver !== "window" && kind.deliver !== "reveal") {
    throw validationError(`\`${label}.deliver\` must be "once", "window" or "reveal"`);
  }
  if (kind.deliver === "reveal" && kind.browser) {
    throw validationError(
      `\`${label}.deliver\`: "reveal" is for a kind without a browser step; a browser kind's client collects its outcome`,
    );
  }
  if (!kind.browser && (kind.userCode || kind.approve || kind.refusal || kind.input || kind.approver)) {
    throw validationError(
      `\`${label}\`: userCode, approver, input, approve and refusal need a browser step`,
    );
  }
  const pending = positiveNumber(kind.pendingTtlMs, operationDefaults.pendingTtlMs, `${label}.pendingTtlMs`);
  const record = positiveNumber(kind.recordTtlMs, operationDefaults.recordTtlMs, `${label}.recordTtlMs`);
  if (record < pending) {
    throw validationError(`\`${label}.recordTtlMs\` must be at least its pendingTtlMs`);
  }
};

/**
 * Refuses a database without `batch` for a feature whose writes must land
 * together or not at all: run in order instead, a write refused late would
 * leave the ones before it committed.
 */
const assertBatchingDatabase = (db: CfAuthDatabase, feature: string, why: string): void => {
  if (typeof (db as unknown as { batch?: unknown }).batch !== "function") {
    throw validationError(`\`${feature}\` needs a database that batches atomically (D1, libsql): ${why}`);
  }
};

/**
 * Operations' half of {@link assertBatchingDatabase}. Exported for the
 * engine, which may be handed a configuration that never went through
 * `resolveConfig`.
 */
export const assertOperationsDatabase = (db: CfAuthDatabase): void =>
  assertBatchingDatabase(
    db,
    "operations",
    "a completion, an execution and a sweep are each one batch, and a refused completion rolls its whole batch back",
  );

const resolveOperations = (
  config: CfAuthConfig,
  db: CfAuthDatabase,
  apiKeysEnabled: boolean,
): ResolvedOperationsConfig => {
  const input = config.operations ?? {};
  const enabled = input.enabled ?? false;
  if (enabled) assertOperationsDatabase(db);
  const loginInput = input.login ?? true;
  const login =
    enabled && loginInput !== false
      ? {
          minRole: (loginInput === true ? undefined : loginInput.minRole) ?? "admin",
          pendingTtlMs: positiveNumber(
            loginInput === true ? undefined : loginInput.pendingTtlMs,
            operationDefaults.pendingTtlMs,
            "operations.login.pendingTtlMs",
          ),
          recordTtlMs: positiveNumber(
            loginInput === true ? undefined : loginInput.recordTtlMs,
            operationDefaults.recordTtlMs,
            "operations.login.recordTtlMs",
          ),
        }
      : null;

  if (login && !organizationRoles.includes(login.minRole)) {
    throw validationError("`operations.login.minRole` must be an organization role");
  }
  if (login) {
    // The built-in kind obeys the same rules as an app's own.
    validateOperationKind({
      name: "login",
      open: "public",
      browser: true,
      userCode: true,
      requireClientLabel: true,
      approverMinRole: login.minRole,
      pendingTtlMs: login.pendingTtlMs,
      recordTtlMs: login.recordTtlMs,
    }, "operations.login");
  }
  if (login && !apiKeysEnabled) {
    throw validationError(
      "The `login` operation issues API keys; set `apiKeys.enabled: true` or `operations.login: false`",
    );
  }

  const kinds = input.kinds ?? [];
  const names = new Set<string>(login ? ["login"] : []);
  for (const kind of kinds) {
    validateOperationKind(kind);
    if (names.has(kind.name)) {
      throw validationError(`Operation kind \`${kind.name}\` is declared twice`);
    }
    names.add(kind.name);
  }

  const realm = input.realm?.trim() || config.appName.trim();

  return {
    enabled,
    realm,
    kinds,
    login,
    limits: {
      pendingPerOrganization: positiveInteger(
        input.limits?.pendingPerOrganization,
        10,
        "operations.limits.pendingPerOrganization",
      ),
      pendingPerOpener: positiveInteger(
        input.limits?.pendingPerOpener,
        5,
        "operations.limits.pendingPerOpener",
      ),
    },
    sealTtlMs: positiveNumber(input.sealTtlMs, operationDefaults.sealTtlMs, "operations.sealTtlMs"),
    reserveTtlMs: positiveNumber(
      input.reserveTtlMs,
      operationDefaults.reserveTtlMs,
      "operations.reserveTtlMs",
    ),
  };
};

export interface ResolvedOAuthConfig {
  issuer: string;
  resourcePaths: readonly string[];
  /** Every accepted spelling of `resource`: the issuer, then the issuer with each path. */
  resources: readonly string[];
  accessTokenTtlMs: number;
  refreshTokenTtlMs: number;
  connectionMaxAgeMs: number | null;
  authorizationTtlMs: number;
  tokenPrefix: { access: string; refresh: string };
  clients: readonly OAuthClientConfig[];
  /** Null when CIMD is off; `fetch` and `allowUrl` null when not configured. */
  cimd: {
    fetch: typeof fetch | null;
    allowUrl: ((url: URL) => boolean | Promise<boolean>) | null;
  } | null;
}

/** Defaults of the `oauth` block. The refresh grace and rotation limit are fixed, not configured. */
export const oauthDefaults = {
  resourcePaths: ["/mcp"],
  accessTokenTtlMs: 10 * minute,
  refreshTokenTtlMs: 30 * day,
  authorizationTtlMs: 10 * minute,
} as const;

/** Loopback for `oauth.issuer`: the loopback literals, `localhost`, or a name under `.localhost` (RFC 6761 §6.3). */
const isLoopbackIssuerHost = (hostname: string): boolean =>
  // The URL parser has already lowercased the hostname, so no case folding is needed here.
  hostname === "127.0.0.1" || hostname === "[::1]" || /^(?:localhost|(?:[^.]+\.)+localhost)$/.test(hostname);
const tokenPrefixPattern = /^[A-Za-z0-9_-]{1,32}$/;
const resourcePathPattern = /^(?:\/[A-Za-z0-9._~!$&'()*+,;=:@%-]+)+$/;
const base62Run = /^[A-Za-z0-9]*$/;

const resolveOAuth = (
  config: CfAuthConfig,
  db: CfAuthDatabase,
  apiKeys: { enabled: boolean; tokenPrefix: string },
  operationsEnabled: boolean,
): ResolvedOAuthConfig | null => {
  const input = config.oauth;
  if (!input || input.enabled !== true) {
    if (input?.enabled !== undefined && typeof input.enabled !== "boolean") {
      throw validationError("`oauth.enabled` must be a boolean");
    }
    return null;
  }
  if (!apiKeys.enabled) {
    throw validationError("`oauth` issues connections that are API-key rows; set `apiKeys.enabled: true`");
  }
  if (!operationsEnabled) {
    throw validationError("`oauth` runs its authorizations on the operation engine; set `operations.enabled: true`");
  }
  assertBatchingDatabase(db, "oauth", "its code exchange, rotation and revocation are each one batch");

  if (typeof input.issuer !== "string" || !input.issuer) {
    throw validationError("`oauth.issuer` is required");
  }
  let issuerUrl: URL;
  try {
    issuerUrl = new URL(input.issuer);
  } catch {
    throw validationError("`oauth.issuer` must be an absolute URL");
  }
  const secure =
    issuerUrl.protocol === "https:" ||
    (issuerUrl.protocol === "http:" && isLoopbackIssuerHost(issuerUrl.hostname));
  if (!secure) {
    throw validationError(
      "`oauth.issuer` must be https, or http on a loopback host (`127.0.0.1`, `[::1]`, `localhost` or a name under `.localhost`)",
    );
  }
  if (input.issuer !== issuerUrl.origin) {
    throw validationError(
      "`oauth.issuer` must be an origin: no path, no trailing slash, no query, no fragment and no credentials",
    );
  }
  const issuer = issuerUrl.origin;

  const resourcePaths = input.resourcePaths ?? [...oauthDefaults.resourcePaths];
  if (!Array.isArray(resourcePaths)) throw validationError("`oauth.resourcePaths` must be an array");
  for (const path of resourcePaths) {
    if (typeof path !== "string" || !resourcePathPattern.test(path) || path.endsWith("/")) {
      throw validationError(
        `\`oauth.resourcePaths\` entry \`${String(path)}\` must be a path such as "/mcp": a leading slash, no trailing slash, no query or fragment`,
      );
    }
  }
  if (new Set(resourcePaths).size !== resourcePaths.length) {
    throw validationError("`oauth.resourcePaths` lists a path twice");
  }

  const connectionMaxAgeMs =
    input.connectionMaxAgeMs === undefined || input.connectionMaxAgeMs === null
      ? null
      : positiveNumber(input.connectionMaxAgeMs, 0, "oauth.connectionMaxAgeMs");

  const prefix = input.tokenPrefix;
  if (!prefix || typeof prefix !== "object") {
    throw validationError("`oauth.tokenPrefix` is required: { access, refresh }");
  }
  for (const name of ["access", "refresh"] as const) {
    if (typeof prefix[name] !== "string" || !tokenPrefixPattern.test(prefix[name])) {
      throw validationError(
        `\`oauth.tokenPrefix.${name}\` must be 1 to 32 letters, digits, \`_\` or \`-\``,
      );
    }
  }
  if (prefix.access === prefix.refresh) {
    throw validationError("`oauth.tokenPrefix.access` and `.refresh` must differ");
  }
  for (const name of ["access", "refresh"] as const) {
    if (prefix[name] === apiKeys.tokenPrefix) {
      throw validationError(`\`oauth.tokenPrefix.${name}\` must differ from \`apiKeys.tokenPrefix\``);
    }
  }
  // A bearer token is routed to OAuth by the access prefix, so no API key may
  // be able to begin with it: neither may the key prefix begin with the access
  // prefix, nor may the access prefix be the key prefix plus characters a
  // key's random part can hold.
  const apiKeyPrefix = apiKeys.tokenPrefix;
  if (
    apiKeyPrefix.startsWith(prefix.access) ||
    (prefix.access.startsWith(apiKeyPrefix) && base62Run.test(prefix.access.slice(apiKeyPrefix.length)))
  ) {
    throw validationError(
      "`oauth.tokenPrefix.access` could begin an API key; choose a prefix an API key cannot start with",
    );
  }

  const clients = input.clients ?? [];
  if (!Array.isArray(clients)) throw validationError("`oauth.clients` must be an array");
  const clientIds = new Set<string>();
  const resolvedClients = clients.map((client, index): OAuthClientConfig => {
    const label = `oauth.clients[${index}]`;
    if (!client || typeof client.clientId !== "string" || !client.clientId.trim()) {
      throw validationError(`\`${label}.clientId\` is required`);
    }
    if (client.clientId !== client.clientId.trim() || client.clientId.length > 2048) {
      throw validationError(`\`${label}.clientId\` must be at most 2048 characters with no surrounding spaces`);
    }
    if (clientIds.has(client.clientId)) {
      throw validationError(`\`${label}.clientId\` \`${client.clientId}\` is declared twice`);
    }
    clientIds.add(client.clientId);
    if (typeof client.name !== "string" || !client.name.trim() || client.name.trim().length > 200) {
      throw validationError(`\`${label}.name\` is required, at most 200 characters`);
    }
    if (!Array.isArray(client.redirectUris) || client.redirectUris.length === 0) {
      throw validationError(`\`${label}.redirectUris\` must list at least one redirect URI`);
    }
    for (const uri of client.redirectUris) {
      if (!isAcceptableRedirectUri(uri)) {
        throw validationError(
          `\`${label}.redirectUris\` entry \`${String(uri)}\` must be absolute with no fragment: https, http on a loopback host, or a private-use scheme such as com.example.app:/cb`,
        );
      }
    }
    return { clientId: client.clientId, name: client.name.trim(), redirectUris: [...client.redirectUris] };
  });

  let cimd: ResolvedOAuthConfig["cimd"];
  if (input.cimd === false) {
    cimd = null;
  } else if (input.cimd === undefined) {
    cimd = { fetch: null, allowUrl: null };
  } else if (typeof input.cimd === "object" && input.cimd !== null) {
    if (input.cimd.fetch !== undefined && typeof input.cimd.fetch !== "function") {
      throw validationError("`oauth.cimd.fetch` must be a function");
    }
    if (input.cimd.allowUrl !== undefined && typeof input.cimd.allowUrl !== "function") {
      throw validationError("`oauth.cimd.allowUrl` must be a function");
    }
    cimd = { fetch: input.cimd.fetch ?? null, allowUrl: input.cimd.allowUrl ?? null };
  } else {
    throw validationError("`oauth.cimd` must be false or { fetch?, allowUrl? }");
  }

  return {
    issuer,
    resourcePaths: [...resourcePaths],
    resources: [issuer, ...resourcePaths.map((path) => `${issuer}${path}`)],
    accessTokenTtlMs: positiveNumber(input.accessTokenTtlMs, oauthDefaults.accessTokenTtlMs, "oauth.accessTokenTtlMs"),
    refreshTokenTtlMs: positiveNumber(
      input.refreshTokenTtlMs,
      oauthDefaults.refreshTokenTtlMs,
      "oauth.refreshTokenTtlMs",
    ),
    connectionMaxAgeMs,
    authorizationTtlMs: positiveNumber(
      input.authorizationTtlMs,
      oauthDefaults.authorizationTtlMs,
      "oauth.authorizationTtlMs",
    ),
    tokenPrefix: { access: prefix.access, refresh: prefix.refresh },
    clients: resolvedClients,
    cimd,
  };
};

export interface ResolvedCfAuthConfig {
  appName: string;
  db: CfAuthDatabase;
  tables: CfAuthTables;
  secret: string;
  /**
   * Explicit override only. When `undefined`, the cookie key is derived from
   * `secret` on first use — see `createCurrentOrganizationCookie`.
   */
  cookieSecret: string | undefined;
  baseUrl: string | undefined;
  basePath: string;
  trustedOrigins: string[];
  disableSignUp: boolean;
  userHooks: UserHooksConfig;
  emailAndPassword: Required<EmailAndPasswordConfig>;
  google: GoogleOAuthConfig | undefined;
  oauthProxy: OAuthProxyConfig | undefined;
  accountLinking: { implicit: boolean };
  organizations: {
    autoProvisionDefaultOrganization: boolean;
    resolveDefaultOrganizationName: (user: AuthUser) => string;
  };
  apiKeys: Required<ApiKeysConfig>;
  operations: ResolvedOperationsConfig;
  /** Null while `oauth.enabled` is off. */
  oauth: ResolvedOAuthConfig | null;
  cookies: {
    prefix: string;
    betterAuthPrefix: string;
    currentOrganizationCookieName: string;
    secure: boolean | undefined;
    sameSite: "Strict" | "Lax" | "None";
    maxAge: number;
    path: string;
    domain: string | undefined;
  };
  openAPI: boolean;
  onEvent: ((event: CfAuthEvent) => void | Promise<void>) | undefined;
  onError: (error: unknown, context: { scope: string }) => void;
}

/**
 * Normalizes user-supplied config, applying defaults and deriving every
 * app-specific name (cookie prefix, org naming) from `appName`/`cookies.prefix`
 * so nothing is hard-coded to a particular application.
 */
export const resolveConfig = (config: CfAuthConfig): ResolvedCfAuthConfig => {
  if (!config.appName?.trim()) {
    throw validationError("`appName` is required");
  }

  if (!config.secret?.trim()) {
    throw validationError("`secret` is required");
  }

  if (!config.d1 && !config.db) {
    throw validationError("Provide either `d1` (a D1 binding) or `db` (a drizzle instance)");
  }

  if (config.d1 && config.db) {
    throw validationError("Provide only one of `d1` or `db`");
  }

  const tables = config.tables ?? cfAuthTables;
  const db = config.db ?? (drizzle(config.d1!) as unknown as CfAuthDatabase);

  const cookiePrefix = config.cookies?.prefix?.trim() || slugify(config.appName);
  const defaultOrganizationName = config.organizations?.defaultOrganizationName;

  const baseUrl = config.baseUrl?.trim() ? trimTrailingSlash(config.baseUrl.trim()) : undefined;

  let oauthProxy: OAuthProxyConfig | undefined;
  if (config.oauthProxy) {
    if (!config.oauthProxy.productionUrl?.trim()) {
      throw validationError("`oauthProxy.productionUrl` is required");
    }
    if (!config.oauthProxy.secret?.trim()) {
      throw validationError("`oauthProxy.secret` is required");
    }
    if (
      config.oauthProxy.maxAge !== undefined &&
      (!Number.isFinite(config.oauthProxy.maxAge) || config.oauthProxy.maxAge <= 0)
    ) {
      throw validationError("`oauthProxy.maxAge` must be a positive number");
    }
    oauthProxy = {
      productionUrl: trimTrailingSlash(config.oauthProxy.productionUrl.trim()),
      secret: config.oauthProxy.secret,
      ...(config.oauthProxy.currentUrl?.trim()
        ? { currentUrl: trimTrailingSlash(config.oauthProxy.currentUrl.trim()) }
        : {}),
      ...(config.oauthProxy.maxAge === undefined ? {} : { maxAge: config.oauthProxy.maxAge }),
    };
  }

  const apiKeysEnabled = config.apiKeys?.enabled ?? false;
  const operations = resolveOperations(config, db, apiKeysEnabled);
  const apiKeyTokenPrefix = config.apiKeys?.tokenPrefix ?? "key_";
  const oauth = resolveOAuth(
    config,
    db,
    { enabled: apiKeysEnabled, tokenPrefix: apiKeyTokenPrefix },
    operations.enabled,
  );

  const trustedOrigins = [
    ...new Set(
      [baseUrl, ...(config.trustedOrigins ?? [])]
        .filter((origin): origin is string => Boolean(origin?.trim()))
        .map((origin) => trimTrailingSlash(origin.trim())),
    ),
  ];

  return {
    appName: config.appName.trim(),
    db,
    tables,
    secret: config.secret,
    cookieSecret: config.cookieSecret?.trim() || undefined,
    baseUrl,
    basePath: normalizeBasePath(config.basePath ?? "/api/auth"),
    trustedOrigins,
    disableSignUp: config.disableSignUp ?? false,
    userHooks: config.userHooks ?? {},
    emailAndPassword: {
      enabled: config.emailAndPassword?.enabled ?? true,
      minPasswordLength: config.emailAndPassword?.minPasswordLength ?? 8,
      maxPasswordLength: config.emailAndPassword?.maxPasswordLength ?? 128,
      requireEmailVerification: config.emailAndPassword?.requireEmailVerification ?? false,
      revokeOtherSessionsOnPasswordChange:
        config.emailAndPassword?.revokeOtherSessionsOnPasswordChange ?? false,
    },
    google: config.google,
    oauthProxy,
    accountLinking: { implicit: config.accountLinking?.implicit ?? false },
    organizations: {
      autoProvisionDefaultOrganization:
        config.organizations?.autoProvisionDefaultOrganization ?? true,
      resolveDefaultOrganizationName:
        typeof defaultOrganizationName === "function"
          ? defaultOrganizationName
          : () => defaultOrganizationName ?? "My Organization",
    },
    operations,
    oauth,
    apiKeys: {
      enabled: apiKeysEnabled,
      tokenPrefix: apiKeyTokenPrefix,
      clientHeader: config.apiKeys?.clientHeader ?? "X-Client",
    },
    cookies: {
      prefix: cookiePrefix,
      betterAuthPrefix: `${cookiePrefix}_auth`,
      currentOrganizationCookieName:
        config.cookies?.currentOrganizationCookieName?.trim() ||
        `${cookiePrefix}_current_organization`,
      secure: config.cookies?.secure,
      sameSite: config.cookies?.sameSite ?? "Lax",
      maxAge: config.cookies?.maxAge ?? 60 * 60 * 24 * 365,
      path: config.cookies?.path ?? "/",
      domain: config.cookies?.domain,
    },
    openAPI: config.openAPI ?? false,
    onEvent: config.onEvent,
    onError:
      config.onError ??
      ((error, context) => {
        console.error(`[cf-auth] ${context.scope}`, error);
      }),
  };
};
