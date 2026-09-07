import { drizzleAdapter } from "@better-auth/drizzle-adapter";
import { betterAuth } from "better-auth/minimal";
import { oAuthProxy, openAPI } from "better-auth/plugins";
import type { Auth, BetterAuthOptions } from "better-auth/types";
import { APIError } from "better-auth/api";
import type { ResolvedCfAuthConfig } from "./config.js";
import { toBetterAuthSchema } from "./schema.js";
import type { CfAuthService } from "./service.js";
import type { AuthUser } from "./types.js";

const toIso = (value: Date | string | number | null | undefined) => {
  if (value instanceof Date) {
    return value.toISOString();
  }

  if (typeof value === "number") {
    return new Date(value).toISOString();
  }

  return value ?? new Date().toISOString();
};

/**
 * Builds the better-auth options object from resolved cf-auth config.
 *
 * Exported so an app can take these as a starting point and layer on its own
 * plugins before calling `betterAuth()` itself.
 *
 * The return type is annotated (rather than inferred) so this package's emitted
 * `.d.ts` stays portable — better-auth's inferred option type reaches into
 * paths its `exports` map does not expose.
 */
export const createBetterAuthOptions = (
  config: ResolvedCfAuthConfig,
  getService: () => CfAuthService,
): BetterAuthOptions =>
  ({
    appName: config.appName,
    ...(config.baseUrl ? { baseURL: config.baseUrl } : {}),
    basePath: config.basePath,
    secret: config.secret,
    trustedOrigins: config.trustedOrigins,
    database: drizzleAdapter(config.db, {
      provider: "sqlite",
      schema: toBetterAuthSchema(config.tables),
    }),
    emailAndPassword: {
      enabled: config.emailAndPassword.enabled,
      disableSignUp: config.disableSignUp,
      minPasswordLength: config.emailAndPassword.minPasswordLength,
      maxPasswordLength: config.emailAndPassword.maxPasswordLength,
      requireEmailVerification: config.emailAndPassword.requireEmailVerification,
    },
    ...(config.google
      ? {
          socialProviders: {
            google: {
              clientId: config.google.clientId,
              clientSecret: config.google.clientSecret,
              ...(config.google.redirectURI ? { redirectURI: config.google.redirectURI } : {}),
              ...(config.google.disableSignUp === undefined
                ? {}
                : { disableSignUp: config.google.disableSignUp }),
            },
          },
        }
      : {}),
    databaseHooks: {
      user: {
        create: {
          ...(config.disableSignUp
            ? { before: async () => {
                throw APIError.from("FORBIDDEN", {
                  code: "REGISTRATION_DISABLED",
                  message: "signup disabled",
                });
              } }
            : {}),
          after: async (user) => {
            if (!config.organizations.autoProvisionDefaultOrganization && !config.onEvent) {
              return;
            }

            const authUser: AuthUser = {
              id: user.id,
              name: user.name ?? null,
              email: user.email,
              emailVerified: Boolean(user.emailVerified),
              image: user.image ?? null,
              createdAt: toIso(user.createdAt),
            };

            try {
              await getService().provisionNewUser(authUser);
            } catch (error) {
              // Signup has already committed the user row at this point;
              // surfacing here would leave a half-created account. The auth
              // middleware re-runs `ensureDefaultOrganization` on the next
              // request, so provisioning self-heals.
              config.onError(error, { scope: "databaseHooks.user.create.after" });
            }
          },
        },
      },
    },
    plugins: [
      ...(config.oauthProxy
        ? [oAuthProxy({
            productionURL: config.oauthProxy.productionUrl,
            secret: config.oauthProxy.secret,
            ...(config.oauthProxy.currentUrl
              ? { currentURL: config.oauthProxy.currentUrl }
              : {}),
            ...(config.oauthProxy.maxAge === undefined
              ? {}
              : { maxAge: config.oauthProxy.maxAge }),
          })]
        : []),
      ...(config.openAPI ? [openAPI()] : []),
    ],
    advanced: {
      cookiePrefix: config.cookies.betterAuthPrefix,
    },
  }) satisfies BetterAuthOptions;

/** The better-auth instance type used throughout this package. */
export type CfBetterAuth = Auth<BetterAuthOptions>;

/**
 * Constructs the better-auth instance.
 *
 * `getService` is a thunk rather than a value because the service and the
 * better-auth instance are mutually referential: the `user.create.after`
 * database hook needs the service, and the service is created alongside the
 * auth instance.
 */
export const createBetterAuthInstance = (
  config: ResolvedCfAuthConfig,
  getService: () => CfAuthService,
): CfBetterAuth => betterAuth(createBetterAuthOptions(config, getService));
