import type { D1Database } from "@cloudflare/workers-types";
import { drizzle } from "drizzle-orm/d1";
import type { BaseSQLiteDatabase } from "drizzle-orm/sqlite-core";
import { validationError } from "./errors.js";
import { cfAuthTables, type CfAuthTables } from "./schema.js";
import type { AuthUser, CfAuthEvent } from "./types.js";

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

export interface EmailAndPasswordConfig {
  /** Default: `true`. */
  enabled?: boolean;
  /** Default: `8`. */
  minPasswordLength?: number;
  /** Default: `128`. */
  maxPasswordLength?: number;
  /** Default: `false`. */
  requireEmailVerification?: boolean;
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

  emailAndPassword?: EmailAndPasswordConfig;
  google?: GoogleOAuthConfig;
  oauthProxy?: OAuthProxyConfig;

  organizations?: OrganizationsConfig;
  apiKeys?: ApiKeysConfig;
  cookies?: CookieConfig;

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
  emailAndPassword: Required<EmailAndPasswordConfig>;
  google: GoogleOAuthConfig | undefined;
  oauthProxy: OAuthProxyConfig | undefined;
  organizations: {
    autoProvisionDefaultOrganization: boolean;
    resolveDefaultOrganizationName: (user: AuthUser) => string;
  };
  apiKeys: Required<ApiKeysConfig>;
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
      config.oauthProxy.maxAge !== undefined
      && (!Number.isFinite(config.oauthProxy.maxAge) || config.oauthProxy.maxAge <= 0)
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
    emailAndPassword: {
      enabled: config.emailAndPassword?.enabled ?? true,
      minPasswordLength: config.emailAndPassword?.minPasswordLength ?? 8,
      maxPasswordLength: config.emailAndPassword?.maxPasswordLength ?? 128,
      requireEmailVerification: config.emailAndPassword?.requireEmailVerification ?? false,
    },
    google: config.google,
    oauthProxy,
    organizations: {
      autoProvisionDefaultOrganization:
        config.organizations?.autoProvisionDefaultOrganization ?? true,
      resolveDefaultOrganizationName:
        typeof defaultOrganizationName === "function"
          ? defaultOrganizationName
          : () => defaultOrganizationName ?? "My Organization",
    },
    apiKeys: {
      enabled: config.apiKeys?.enabled ?? false,
      tokenPrefix: config.apiKeys?.tokenPrefix ?? "key_",
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
