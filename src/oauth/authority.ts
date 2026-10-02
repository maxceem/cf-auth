import { sql, type SQL } from "drizzle-orm";
import { alias } from "drizzle-orm/sqlite-core";
import { sqliteNowMs } from "../authority.js";
import type { CfAuthTables } from "../schema.js";

/**
 * Whether an OAuth connection may act, as one SQL condition: its row is an
 * OAuth connection (`credential_type = 'oauth'`), enabled, unrevoked, bound to
 * `issuer`, with an `expires_at` strictly in the future; its user's
 * membership in its organization is active; and the organization is inside
 * its deadline. Times are judged by the later of `nowMs` and the database's
 * clock. Unlike the shared credential predicate there is no session branch
 * and no open-ended expiry: a connection always has a lifetime.
 *
 * The one rule every OAuth read that decides and every OAuth write that
 * depends on a live connection uses.
 */
export const oauthConnectionLiveSql = (
  tables: CfAuthTables,
  input: { connectionId: string; issuer: string; nowMs: number },
): SQL => {
  const key = alias(tables.apiKey, "cf_auth_oauth_live_key");
  const member = alias(tables.organizationUser, "cf_auth_oauth_live_member");
  const organization = alias(tables.organization, "cf_auth_oauth_live_organization");
  const now = sqliteNowMs(input.nowMs);
  return sql`exists (
    select 1
    from ${tables.apiKey} as ${sql.identifier("cf_auth_oauth_live_key")}
    join ${tables.organizationUser} as ${sql.identifier("cf_auth_oauth_live_member")}
      on ${member.userId} = ${key.userId}
      and ${member.organizationId} = ${key.organizationId}
      and ${member.status} = 'active'
    join ${tables.organization} as ${sql.identifier("cf_auth_oauth_live_organization")}
      on ${organization.id} = ${key.organizationId}
    where ${key.id} = ${input.connectionId}
      and ${key.credentialType} = 'oauth'
      and ${key.enabled} = 1
      and ${key.revokedAt} is null
      and ${key.resource} = ${input.issuer}
      and ${key.expiresAt} is not null
      and ${key.expiresAt} > ${now}
      and (${organization.expiresAt} is null
        or cast(unixepoch(${organization.expiresAt}, 'subsec') * 1000 as integer) > ${now})
  )`;
};

/**
 * The organization exists and is inside its deadline when the statement runs,
 * by the later of `nowMs` and the database's clock: `expires_at` is ISO text,
 * read as epoch milliseconds, as the operation engine reads it.
 */
export const oauthOrganizationLiveSql = (
  tables: CfAuthTables,
  input: { organizationId: string; nowMs: number },
): SQL => {
  const live = alias(tables.organization, "cf_auth_oauth_organization");
  return sql`exists (select 1 from ${tables.organization} as ${sql.identifier("cf_auth_oauth_organization")}
    where ${live.id} = ${input.organizationId}
      and (${live.expiresAt} is null
        or cast(unixepoch(${live.expiresAt}, 'subsec') * 1000 as integer) > ${sqliteNowMs(input.nowMs)}))`;
};

/** The user's membership in the organization is active, at any role. */
export const oauthMembershipLiveSql = (
  tables: CfAuthTables,
  input: { userId: string; organizationId: string },
): SQL => {
  const member = alias(tables.organizationUser, "cf_auth_oauth_member");
  return sql`exists (select 1 from ${tables.organizationUser} as ${sql.identifier("cf_auth_oauth_member")}
    where ${member.userId} = ${input.userId}
      and ${member.organizationId} = ${input.organizationId}
      and ${member.status} = 'active')`;
};
