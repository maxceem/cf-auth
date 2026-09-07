import type { Context, Env, MiddlewareHandler } from "hono";
import type { ResolvedCfAuthConfig } from "./config.js";
import type { CurrentOrganizationCookie } from "./cookies.js";
import { forbidden, sessionRequired, unauthorized } from "./errors.js";
import type { CfBetterAuth } from "./better-auth.js";
import type { CfAuthService } from "./service.js";
import {
  canManageOrganization,
  createEmptyAuthState,
  hasRoleAtLeast,
  type ActionSource,
  type AuthState,
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
   * Re-sync the current-organization cookie when the resolved org differs from
   * the cookie. Default: `true`.
   */
  syncCurrentOrganizationCookie?: boolean;
}

const deriveApiKeySource = (value: string | null | undefined): ActionSource => {
  const normalized = value?.trim().toLowerCase();
  return normalized === "cli" || normalized === "mcp" ? normalized : "api";
};

export const createAuthMiddleware = (
  config: ResolvedCfAuthConfig,
  deps: {
    auth: CfBetterAuth;
    service: CfAuthService;
    currentOrganizationCookie: CurrentOrganizationCookie;
  },
) => {
  const { auth, service, currentOrganizationCookie } = deps;

  return <E extends Env = CfAuthEnv>(
    options: AuthMiddlewareOptions = {},
  ): MiddlewareHandler<E> => {
    const apiKeysEnabled = options.apiKeys ?? config.apiKeys.enabled;
    const syncCookie = options.syncCurrentOrganizationCookie ?? true;

    return async (c, next) => {
      const setState = (state: AuthState) => {
        // Cast: the middleware is generic over the host app's Env, which we
        // only require to carry an `authState` variable.
        (c as unknown as Context<CfAuthEnv>).set("authState", state);
      };

      const authorization = c.req.header("Authorization");

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
      const resolved = await service.getAuthState(session.user.id, currentOrganizationId);
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

  if (!state.user) {
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
 * Accepts both session and API-key callers; `user` is `null` for API keys.
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

/** Throws 403 unless the caller is an `owner` or `admin` of the current org. */
export const requireOrganizationManager = (state: AuthState): RequireOrganizationResult => {
  const result = requireOrganization(state);

  if (!canManageOrganization(result.role)) {
    throw forbidden("Only organization owners and admins can perform this action");
  }

  return result;
};
