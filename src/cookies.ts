import type { Context } from "hono";
import { deleteCookie, getSignedCookie, setSignedCookie } from "hono/cookie";
import type { ResolvedCfAuthConfig } from "./config.js";
import { deriveSecret } from "./crypto.js";

/** `Secure` cookies whenever the request itself is over https. */
export const isSecureRequest = (url: string): boolean => url.startsWith("https://");

export interface CurrentOrganizationCookie {
  readonly name: string;
  /** Reads and verifies the signed cookie. Returns `null` if absent or tampered. */
  read(context: Context): Promise<string | null>;
  write(context: Context, organizationId: string): Promise<void>;
  clear(context: Context): void;
}

/**
 * Signed cookie holding the organization the user is currently acting within.
 *
 * It is signed rather than encrypted: the value is a non-secret organization id,
 * and signing is what stops a client from silently switching tenants. Every
 * read is still re-validated against actual membership by the auth middleware,
 * so a forged value cannot grant access on its own.
 */
export const createCurrentOrganizationCookie = (
  config: ResolvedCfAuthConfig,
): CurrentOrganizationCookie => {
  const name = config.cookies.currentOrganizationCookieName;

  const secure = (context: Context) => config.cookies.secure ?? isSecureRequest(context.req.url);

  // Derived once per instance, lazily: HKDF is async, but `resolveConfig` is not.
  let signingKey: Promise<string> | undefined;

  const getSigningKey = () => {
    if (config.cookieSecret) {
      return Promise.resolve(config.cookieSecret);
    }

    signingKey ??= deriveSecret(
      config.secret,
      `cf-auth:current-organization-cookie:${config.cookies.prefix}`,
    );

    return signingKey;
  };

  return {
    name,

    async read(context) {
      const value = await getSignedCookie(context, await getSigningKey(), name);
      return typeof value === "string" && value.length > 0 ? value : null;
    },

    async write(context, organizationId) {
      await setSignedCookie(context, name, organizationId, await getSigningKey(), {
        httpOnly: true,
        path: config.cookies.path,
        sameSite: config.cookies.sameSite,
        secure: secure(context),
        maxAge: config.cookies.maxAge,
        ...(config.cookies.domain ? { domain: config.cookies.domain } : {}),
      });
    },

    clear(context) {
      deleteCookie(context, name, {
        path: config.cookies.path,
        httpOnly: true,
        sameSite: config.cookies.sameSite,
        secure: secure(context),
        ...(config.cookies.domain ? { domain: config.cookies.domain } : {}),
      });
    },
  };
};
