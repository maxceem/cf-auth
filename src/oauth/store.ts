import { and, eq, isNull, sql, type SQL } from "drizzle-orm";
import { alias } from "drizzle-orm/sqlite-core";
import type { CfAuthDatabase } from "../config.js";
import { authRowColumns, toAuthUser, toMembership } from "../repository.js";
import type { CfAuthTables } from "../schema.js";
import type { AuthUser, OrganizationMembership } from "../types.js";

/**
 * An OAuth connection's current generation with everything an access token's
 * state is built from — the connection's grant, its user, and the membership
 * with its organization — read in one statement, where `condition` holds, so
 * no part of the answer can disagree with the rest. The caller passes the
 * liveness rule as `condition` and then verifies the token's digest against
 * `accessTokenHash`.
 *
 * Read from the configured tables, as the OAuth service's writes are, rather
 * than through `CfAuthRepository`: the query joins `oauth_token`, which only
 * this service writes, so a repository an app wrote has nothing to add to it.
 */
export const findOAuthAccess = async (
  db: CfAuthDatabase,
  tables: CfAuthTables,
  { connectionId, condition }: { connectionId: string; condition: SQL },
): Promise<{
  accessTokenHash: string;
  grant: string;
  user: AuthUser;
  membership: OrganizationMembership;
} | null> => {
  const { user, organization, organizationUser, apiKey, oauthToken } = tables;
  const { userColumns, membershipColumns } = authRowColumns(tables);
  const newest = alias(oauthToken, "cf_auth_oauth_newest");
  const row = await db
    .select({
      accessTokenHash: oauthToken.accessTokenHash,
      grant: apiKey.grant,
      user: userColumns,
      ...membershipColumns,
    })
    .from(oauthToken)
    .innerJoin(apiKey, eq(apiKey.id, oauthToken.apiKeyId))
    .innerJoin(user, eq(user.id, apiKey.userId))
    .innerJoin(
      organizationUser,
      and(
        eq(organizationUser.userId, apiKey.userId),
        eq(organizationUser.organizationId, apiKey.organizationId),
      ),
    )
    .innerJoin(organization, eq(organization.id, apiKey.organizationId))
    .where(
      and(
        eq(oauthToken.apiKeyId, connectionId),
        isNull(oauthToken.rotatedAt),
        // The current generation is the newest one.
        sql`${oauthToken.generation} = (select max(${newest.generation}) from ${oauthToken} as ${sql.identifier("cf_auth_oauth_newest")}
          where ${newest.apiKeyId} = ${connectionId})`,
        condition,
      ),
    )
    .get();
  if (!row) return null;
  return {
    accessTokenHash: row.accessTokenHash,
    grant: row.grant,
    user: toAuthUser(row.user),
    membership: toMembership(row),
  };
};
