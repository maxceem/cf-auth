import { alias } from "drizzle-orm/sqlite-core";
import { sql, type SQL } from "drizzle-orm";
import { SQLiteAsyncDialect } from "drizzle-orm/sqlite-core";
import type { CfAuthTables } from "./schema.js";
import type { CredentialGrant, OrganizationRole } from "./types.js";

export interface CredentialAuthorityInput {
  organizationId: string;
  userId: string;
  credentialId: string;
  /** An empty list deliberately denies authority. */
  allowedRoles: readonly OrganizationRole[];
  /**
   * The least grant the credential must carry. `"manage"` requires an API
   * key's row to say `manage`; a session always satisfies it. Default:
   * `"read"`, which every live credential satisfies.
   */
  grant?: CredentialGrant;
  /** Caller-observed time. SQLite's current clock is also enforced. */
  nowMs: number;
}

export interface CompiledSqlCondition {
  sql: string;
  params: unknown[];
}

const compileSqlite = (condition: SQL): CompiledSqlCondition => {
  const query = new SQLiteAsyncDialect().sqlToQuery(condition);
  return { sql: query.sql, params: query.params };
};

/** SQLite's current clock in epoch milliseconds, or the caller's, whichever is later. */
export const sqliteNowMs = (nowMs: number): SQL =>
  sql`max(${nowMs}, cast((julianday('now') - 2440587.5) * 86400000 as integer))`;

/**
 * The live credential and membership authority predicate as a drizzle `SQL`
 * fragment, for a write built with drizzle. See
 * {@link credentialAuthorityCondition} for the compiled form.
 */
export const credentialAuthoritySql = (
  tables: CfAuthTables,
  input: CredentialAuthorityInput,
): SQL => {
  if (input.allowedRoles.length === 0) return sql`0`;

  const membership = alias(tables.organizationUser, "cf_auth_membership");
  const user = alias(tables.user, "cf_auth_user");
  const key = alias(tables.apiKey, "cf_auth_key");
  const session = alias(tables.session, "cf_auth_session");
  const membershipAlias = sql.identifier("cf_auth_membership");
  const userAlias = sql.identifier("cf_auth_user");
  const keyAlias = sql.identifier("cf_auth_key");
  const sessionAlias = sql.identifier("cf_auth_session");
  const roles = sql.join(input.allowedRoles.map((role) => sql`${role}`), sql`, `);
  const liveAfter = sqliteNowMs(input.nowMs);

  // The key branch takes an API key or an OAuth connection, each by its exact
  // `credential_type`: a connection opens operations and claims like a key,
  // and a type cf-auth never writes is neither.
  return sql`exists (
    select 1
    from ${tables.organizationUser} as ${membershipAlias}
    join ${tables.user} as ${userAlias} on ${user.id} = ${membership.userId}
    where ${membership.organizationId} = ${input.organizationId}
      and ${membership.userId} = ${input.userId}
      and ${membership.status} = 'active'
      and ${membership.role} in (${roles})
      and (
        exists (
          select 1 from ${tables.apiKey} as ${keyAlias}
          where ${key.id} = ${input.credentialId}
            and ${key.credentialType} in ('apiKey', 'oauth')
            and ${key.userId} = ${user.id}
            and ${key.organizationId} = ${membership.organizationId}
            and ${key.enabled} = 1
            and ${key.revokedAt} is null
            and (${key.expiresAt} is null or ${key.expiresAt} > ${liveAfter})
            ${input.grant === "manage" ? sql`and ${key.grant} = 'manage'` : sql``}
        )
        or (
          ${user.kind} = 'human'
          and exists (
            select 1 from ${tables.session} as ${sessionAlias}
            where ${session.id} = ${input.credentialId}
              and ${session.userId} = ${user.id}
              and ${session.expiresAt} > ${liveAfter}
          )
        )
      )
  )`;
};

/**
 * True while `sessionId` is a live session of the human `userId`, whatever
 * organizations they belong to. For a write whose authority is the person
 * rather than a membership.
 */
export const liveHumanSessionSql = (
  tables: CfAuthTables,
  input: { userId: string; sessionId: string; nowMs: number },
): SQL => {
  const user = alias(tables.user, "cf_auth_session_user");
  const session = alias(tables.session, "cf_auth_live_session");
  return sql`exists (
    select 1
    from ${tables.session} as ${sql.identifier("cf_auth_live_session")}
    join ${tables.user} as ${sql.identifier("cf_auth_session_user")} on ${user.id} = ${session.userId}
    where ${session.id} = ${input.sessionId}
      and ${session.userId} = ${input.userId}
      and ${user.kind} = 'human'
      and ${session.expiresAt} > ${sqliteNowMs(input.nowMs)}
  )`;
};

/**
 * Compiles the live credential and membership authority predicate used inside
 * an existing SQLite mutation boundary. Table and column names come from the
 * configured cf-auth schema, including custom prefixes. This covers only a
 * live credential plus active membership, an allowed role and, when asked,
 * the credential's grant; the host must append its account, resource, and
 * deadline policy to the same mutation.
 */
export const credentialAuthorityCondition = (
  tables: CfAuthTables,
  input: CredentialAuthorityInput,
): CompiledSqlCondition => compileSqlite(credentialAuthoritySql(tables, input));
