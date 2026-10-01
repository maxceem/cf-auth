import type { Context, Env, MiddlewareHandler } from "hono";
import type { ResolvedCfAuthConfig } from "./config.js";
import type { CurrentOrganizationCookie } from "./cookies.js";
import { forbidden, grantInsufficient, sessionRequired, unauthorized, validationError } from "./errors.js";
import type { CfBetterAuth } from "./better-auth.js";
import type { CfAuthOAuth } from "./oauth/service.js";
import type { CfAuthService } from "./service.js";
import {
  canManageOrganization,
  createEmptyAuthState,
  hasGrantAtLeast,
  hasRoleAtLeast,
  type ActionSource,
  type AuthState,
  type OAuthActionSource,
  type CredentialGrant,
  type AuthUser,
  type OrganizationRole,
  type OrganizationSummary,
} from "./types.js";

const bearerPrefix = "Bearer ";

/**
 * Hono `Variables` contract. Extend your app env with this so
 * `c.get("authState")` is typed:
 *
 * ```ts
 * type AppEnv = { Bindings: Env; Variables: CfAuthVariables };
 * ```
 */
export interface CfAuthVariables {
  authState: AuthState;
}

export type CfAuthEnv = { Variables: CfAuthVariables };

export interface AuthMiddlewareOptions {
  /**
   * Resolve bearer tokens as API keys. Defaults to the package-level
   * `apiKeys.enabled` setting.
   */
  apiKeys?: boolean;
  /**
   * Resolve bearer tokens carrying `oauth.tokenPrefix.access` as OAuth
   * access tokens. Defaults to whether `oauth.enabled` is on.
   */
  oauth?: boolean;
  /**
   * Re-sync the current-organization cookie when the resolved org differs from
   * the cookie. Default: `true`.
   */
  syncCurrentOrganizationCookie?: boolean;
}

const deriveApiKeySource = (value: string | null | undefined): ActionSource => {
  const normalized = value?.trim().toLowerCase();
  return normalized === "cli" || normalized === "mcp" ? normalized : "api";
};

/** An OAuth token is presented to the MCP endpoint or the management API: `mcp`, else `api`. */
const deriveOAuthSource = (value: string | null | undefined): OAuthActionSource =>
  value?.trim().toLowerCase() === "mcp" ? "mcp" : "api";

export const createAuthMiddleware = (
  config: ResolvedCfAuthConfig,
  deps: {
    auth: CfBetterAuth;
    service: CfAuthService;
    /** Needed only when OAuth is on; `createCfAuth` passes it. */
    oauth?: CfAuthOAuth;
    currentOrganizationCookie: CurrentOrganizationCookie;
  },
) => {
  const { auth, service, oauth, currentOrganizationCookie } = deps;

  return <E extends Env = CfAuthEnv>(options: AuthMiddlewareOptions = {}): MiddlewareHandler<E> => {
    const apiKeysEnabled = options.apiKeys ?? config.apiKeys.enabled;
    const oauthAccessPrefix =
      (options.oauth ?? config.oauth !== null) && config.oauth ? config.oauth.tokenPrefix.access : null;
    if (oauthAccessPrefix !== null && !oauth) {
      throw validationError(
        "OAuth bearer routing needs `deps.oauth`; pass `createOAuthService(...)`, or `middleware({ oauth: false })`",
      );
    }
    const syncCookie = options.syncCurrentOrganizationCookie ?? true;

    return async (c, next) => {
      const setState = (state: AuthState) => {
        // Cast: the middleware is generic over the host app's Env, which we
        // only require to carry an `authState` variable.
        (c as unknown as Context<CfAuthEnv>).set("authState", state);
      };

      const authorization = c.req.header("Authorization");

      // A bearer token is routed by its prefix: the OAuth access prefix to
      // the connection's tokens, everything else to API keys.
      if (oauthAccessPrefix !== null && authorization?.startsWith(bearerPrefix)) {
        const token = authorization.slice(bearerPrefix.length).trim();
        if (token.startsWith(oauthAccessPrefix)) {
          setState(
            await oauth!.resolveAccessTokenAuthState(token, {
              source: deriveOAuthSource(c.req.header(config.apiKeys.clientHeader)),
            }),
          );
          await next();
          return;
        }
      }

      if (apiKeysEnabled && authorization?.startsWith(bearerPrefix)) {
        const token = authorization.slice(bearerPrefix.length).trim();
        const state = token
          ? await service.resolveApiKeyAuthState(
              token,
              deriveApiKeySource(c.req.header(config.apiKeys.clientHeader)),
            )
          : createEmptyAuthState();

        setState(state);
        await next();
        return;
      }

      const session = await auth.api.getSession({ headers: c.req.raw.headers });

      if (!session) {
        setState(createEmptyAuthState());
        await next();
        return;
      }

      const honoContext = c as unknown as Context<CfAuthEnv>;
      const currentOrganizationId = await currentOrganizationCookie.read(honoContext);
      const resolved = await service.getAuthState(session.session.id, currentOrganizationId);
      const state = resolved
        ? await service.ensureDefaultOrganization(resolved)
        : createEmptyAuthState();

      if (syncCookie && state.organization?.id !== currentOrganizationId) {
        if (state.organization) {
          await currentOrganizationCookie.write(honoContext, state.organization.id);
        } else if (currentOrganizationId) {
          currentOrganizationCookie.clear(honoContext);
        }
      }

      setState(state);
      await next();
    };
  };
};

// --- guards ------------------------------------------------------------------
// Plain functions rather than middleware so route handlers can narrow types at
// the point of use and apps keep control of their own error envelope.

/**
 * Requires a user session.
 *
 * Throws 401 `unauthorized` when anonymous, but 403 `session_required` when the
 * caller authenticated successfully with an API key — retrying or rotating the
 * key would not help, so a machine client should not treat it as 401.
 */
export const requireUser = (state: AuthState): AuthUser => {
  if (!state.authenticated) {
    throw unauthorized();
  }

  if (
    !state.user ||
    state.user.kind !== "human" ||
    state.assurance !== "interactive" ||
    state.credentialType !== "session"
  ) {
    throw sessionRequired();
  }

  return state.user;
};

export interface RequireOrganizationResult {
  user: AuthUser | null;
  organization: OrganizationSummary;
  role: OrganizationRole;
  state: AuthState;
}

/**
 * Throws 401 when unauthenticated and 403 when no organization is selected.
 * Accepts session and API-key callers; both resolve the owning user identity.
 */
export const requireOrganization = (
  state: AuthState,
  minimumRole?: OrganizationRole,
): RequireOrganizationResult => {
  if (!state.authenticated) {
    throw unauthorized();
  }

  if (!state.organization || !state.role) {
    throw forbidden("No organization is selected");
  }

  if (minimumRole && !hasRoleAtLeast(state.role, minimumRole)) {
    throw forbidden(`This action requires the ${minimumRole} role or higher`);
  }

  return {
    user: state.user,
    organization: state.organization,
    role: state.role,
    state,
  };
};

/**
 * Requires a credential whose grant covers `needed`, for an app gating its own
 * writes the way cf-auth gates its services: `"manage"` for anything that
 * changes state, `"read"` for anything that only reads.
 *
 * Throws 401 when unauthenticated and 403 `grant_insufficient` when the
 * credential's grant is too narrow — a `read` key asking to write. A session
 * always passes. It checks the grant only; pair it with
 * {@link requireOrganization} for the role.
 */
export const requireGrant = (state: AuthState, needed: CredentialGrant): AuthState => {
  if (!state.authenticated) {
    throw unauthorized();
  }

  if (!hasGrantAtLeast(state.grant, needed)) {
    throw grantInsufficient();
  }

  return state;
};

/** Throws 403 unless the caller is an `owner` or `admin` of the current org. */
export const requireOrganizationManager = (state: AuthState): RequireOrganizationResult => {
  const result = requireOrganization(state);

  if (!canManageOrganization(result.role)) {
    throw forbidden("Only organization owners and admins can perform this action");
  }

  return result;
};
