/**
 * Test-only helpers, published behind the `@maxceem/cf-auth/testing` subpath so
 * an application's own code never reaches for them and a bundler never has to.
 *
 * They exist because signing in costs a password hash. That cost is deliberate
 * — it is what makes a stolen hash expensive to crack — but a test that only
 * needs *an authenticated caller* pays it for nothing, and better-auth falls
 * back to a pure-JS scrypt on Workers, where it costs seconds rather than
 * milliseconds. These mint the session directly instead.
 *
 * Nothing here weakens anything. Creating a session requires write access to
 * the auth database, which is exactly what the sign-up route already has; a
 * caller able to reach these could write the same rows itself. What it skips is
 * only the password check.
 */
import { makeSignature } from "better-auth/crypto";
import type { CfAuth } from "./cf-auth.js";
import type { AuthUser } from "./types.js";

/** A newly created user, their default organization, and a session for them. */
export interface TestOperator {
  userId: string;
  /** The organization auto-provisioned for the new user. */
  organizationId: string;
  /** Ready for a request's `Cookie:` header. */
  cookie: string;
  user: AuthUser;
}

export interface TestSessions {
  /**
   * A `Cookie:` header value carrying a freshly signed session for an existing
   * user. The token is random per call and signed with the instance's own
   * secret, so nothing here outlives the test that asks for it.
   */
  cookieFor(userId: string): Promise<string>;
  /**
   * A user, the organization provisioned for them, and a session — the state
   * signing up would have produced, without the password hash.
   *
   * Each call creates a distinct user, so tests that need separate tenants stay
   * independent of one another.
   */
  operator(input?: { email?: string; name?: string }): Promise<TestOperator>;
}

/**
 * better-auth's request context. Reached through a narrow structural type
 * rather than its own: `Auth<BetterAuthOptions>` resolves `$context` through
 * paths better-auth's `exports` map does not expose, which would make this
 * package's emitted `.d.ts` unportable — the same reason
 * {@link createBetterAuthOptions} annotates its return type.
 */
interface BetterAuthContext {
  internalAdapter: {
    createSession(userId: string): Promise<{ token: string }>;
    createUser(user: { email: string; name: string; emailVerified: boolean }): Promise<AuthUser>;
  };
  authCookies: { sessionToken: { name: string } };
}

let counter = 0;

export const createTestSessions = (cfAuth: CfAuth): TestSessions => {
  const context = async () =>
    (await (cfAuth.auth as unknown as { $context: Promise<unknown> }).$context) as BetterAuthContext;

  const cookieFor = async (userId: string): Promise<string> => {
    const { internalAdapter, authCookies } = await context();
    const { token } = await internalAdapter.createSession(userId);
    // better-call signs cookies as `value.signature`, URL-encoded, and
    // better-auth's `makeSignature` is the same function it signs them with.
    // `signCookieValue` itself is not on better-call's `exports` map, so this
    // one line mirrors it; the round-trip test holds it to that.
    const signed = encodeURIComponent(`${token}.${await makeSignature(token, cfAuth.config.secret)}`);
    return `${authCookies.sessionToken.name}=${signed}`;
  };

  return {
    cookieFor,
    async operator(input = {}) {
      const { internalAdapter } = await context();
      const suffix = `${Date.now().toString(36)}-${(counter += 1)}`;
      const email = input.email ?? `test-operator-${suffix}@example.test`;
      const name = input.name ?? email.split("@")[0]!;
      const user = await internalAdapter.createUser({ email, name, emailVerified: true });

      // Idempotent, and the same call better-auth's `user.create.after` hook
      // makes — so this works whether or not user creation ran the hook.
      await cfAuth.service.provisionNewUser(user);
      const [membership] = await cfAuth.service.listOrganizations(user.id);

      if (!membership) {
        throw new Error(
          "cf-auth/testing: no organization was provisioned for the new user. " +
            "`operator()` needs `organizations.autoProvisionDefaultOrganization`; " +
            "use `cookieFor()` with your own organization otherwise.",
        );
      }

      return {
        userId: user.id,
        organizationId: membership.organization.id,
        cookie: await cookieFor(user.id),
        user,
      };
    },
  };
};
