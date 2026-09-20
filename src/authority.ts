import { alias } from "drizzle-orm/sqlite-core";
import { sql, type SQL } from "drizzle-orm";
import { SQLiteAsyncDialect } from "drizzle-orm/sqlite-core";
import type { CfAuthTables } from "./schema.js";
import type { OrganizationRole } from "./types.js";

export interface CredentialAuthorityInput {
  organizationId: string;
  userId: string;
  credentialId: string;
  /** An empty list deliberately denies authority. */
  allowedRoles: readonly OrganizationRole[];
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

/**
 * Compiles the live credential and membership authority predicate used inside
 * an existing SQLite mutation boundary. Table and column names come from the
 * configured cf-auth schema, including custom prefixes. This covers only a
 * live credential plus active membership and an allowed role; the host must
 * append its account, resource, and deadline policy to the same mutation.
 */
export const credentialAuthorityCondition = (
  tables: CfAuthTables,
  input: CredentialAuthorityInput,
): CompiledSqlCondition => {
  if (input.allowedRoles.length === 0) return { sql: "0", params: [] };

  const membership = alias(tables.organizationUser, "cf_auth_membership");
  const user = alias(tables.user, "cf_auth_user");
  const key = alias(tables.apiKey, "cf_auth_key");
  const session = alias(tables.session, "cf_auth_session");
  const membershipAlias = sql.identifier("cf_auth_membership");
  const userAlias = sql.identifier("cf_auth_user");
  const keyAlias = sql.identifier("cf_auth_key");
  const sessionAlias = sql.identifier("cf_auth_session");
  const roles = sql.join(input.allowedRoles.map((role) => sql`${role}`), sql`, `);
  const liveAfter = sql`max(
    ${input.nowMs},
    cast((julianday('now') - 2440587.5) * 86400000 as integer)
  )`;

  return compileSqlite(sql`exists (
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
            and ${key.userId} = ${user.id}
            and ${key.organizationId} = ${membership.organizationId}
            and ${key.enabled} = 1
            and ${key.revokedAt} is null
            and (${key.expiresAt} is null or ${key.expiresAt} > ${liveAfter})
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
  )`);
};
