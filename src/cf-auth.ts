import type { Env, Hono } from "hono";
import { createBetterAuthInstance, type CfBetterAuth } from "./better-auth.js";
import { resolveConfig, type CfAuthConfig, type ResolvedCfAuthConfig } from "./config.js";
import { createCurrentOrganizationCookie, type CurrentOrganizationCookie } from "./cookies.js";
import {
  createAuthMiddleware,
  type AuthMiddlewareOptions,
  type CfAuthEnv,
} from "./middleware.js";
import { createCfAuthRepository, type CfAuthRepository } from "./repository.js";
import { createAuthService, type CfAuthService } from "./service.js";
import type { MiddlewareHandler } from "hono";

export interface CfAuth {
  /** The normalized configuration, including every derived default. */
  readonly config: ResolvedCfAuthConfig;
  /** The underlying better-auth instance (`auth.api.*` for server-side calls). */
  readonly auth: CfBetterAuth;
  /** Organization / API-key operations layered on top of better-auth. */
  readonly service: CfAuthService;
  /** Low-level drizzle queries, exposed for apps that need direct access. */
  readonly repository: CfAuthRepository;
  /** Signed current-organization cookie helpers. */
  readonly currentOrganizationCookie: CurrentOrganizationCookie;
  /** Where better-auth's routes live, e.g. `"/api/auth"`. */
  readonly basePath: string;
  /** The Hono wildcard pattern that {@link CfAuth.handler} must be mounted on. */
  readonly routePattern: string;

  /** Raw fetch handler for better-auth's own endpoints. */
  handler(request: Request): Promise<Response>;
  /** Session/API-key resolution middleware. Sets `c.get("authState")`. */
  middleware<E extends Env = CfAuthEnv>(
    options?: AuthMiddlewareOptions,
  ): MiddlewareHandler<E>;
  /** Convenience: mounts {@link CfAuth.handler} at {@link CfAuth.routePattern}. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  mount(app: Hono<any, any, any>): void;
}

/**
 * Creates an auth instance for one Cloudflare Worker request scope.
 *
 * Workers get a fresh `env` per request, so call this inside your handler (or
 * memoize per-request) rather than at module scope.
 *
 * ```ts
 * const cfAuth = createCfAuth({ appName: "Gateway", d1: env.DB, secret: env.AUTH_SECRET });
 * cfAuth.mount(app);
 * app.use("/api/*", cfAuth.middleware());
 * ```
 */
export const createCfAuth = (config: CfAuthConfig): CfAuth => {
  const resolved = resolveConfig(config);
  const repository = createCfAuthRepository(resolved.db, resolved.tables, {
    onError: resolved.onError,
  });

  let service: CfAuthService | undefined;
  const getService = () => {
    if (!service) {
      throw new Error("cf-auth service accessed before initialization");
    }

    return service;
  };

  // The better-auth `user.create.after` hook needs the service, and the service
  // is independent of better-auth — so build auth with a lazy service getter.
  const auth = createBetterAuthInstance(resolved, getService);
  service = createAuthService(repository, resolved);

  const currentOrganizationCookie = createCurrentOrganizationCookie(resolved);
  const middleware = createAuthMiddleware(resolved, {
    auth,
    service,
    currentOrganizationCookie,
  });

  const routePattern = `${resolved.basePath === "/" ? "" : resolved.basePath}/*`;

  return {
    config: resolved,
    auth,
    service,
    repository,
    currentOrganizationCookie,
    basePath: resolved.basePath,
    routePattern,
    handler: (request) => auth.handler(request),
    middleware,
    mount(app) {
      app.all(routePattern, (c: { req: { raw: Request } }) => auth.handler(c.req.raw));
    },
  };
};
