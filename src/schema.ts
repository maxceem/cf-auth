import { sql } from "drizzle-orm";
import { check, index, integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";
import { organizationMemberStatuses, organizationRoles } from "./types.js";

export interface CfAuthTablesOptions {
  /**
   * Prefix applied to every physical table and index name, e.g. `"auth_"`
   * produces `auth_user`, `auth_user_session`, ... Defaults to `""` (unprefixed:
   * `user`, `user_session`, `user_account`, `verification`, `organization`,
   * `organization_user`, `api_key`).
   *
   * If you set this, you must regenerate the reference migration — see the
   * README "Migrations" section.
   */
  tablePrefix?: string;
}

/**
 * Builds the drizzle sqlite table definitions backing cf-auth.
 *
 * Consuming apps normally use the pre-built {@link cfAuthTables} and spread it
 * into their own drizzle schema. Use this factory only when you need a
 * non-default table prefix.
 */
export const createCfAuthTables = (options: CfAuthTablesOptions = {}) => {
  const prefix = options.tablePrefix ?? "";
  const t = (name: string) => `${prefix}${name}`;
  const ix = (name: string) => `${prefix}${name}`;

  // --- better-auth core tables -------------------------------------------------
  // Column/property names must stay aligned with better-auth's field names so
  // the drizzle adapter can map models without extra `fields` configuration.

  const user = sqliteTable(
    t("user"),
    {
      id: text("id").primaryKey(),
      name: text("name").notNull(),
      email: text("email").notNull(),
      emailVerified: integer("email_verified", { mode: "boolean" }).notNull().default(false),
      image: text("image"),
      createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
      updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
    },
    // COLLATE NOCASE: emails are case-insensitive identifiers. better-auth
    // lowercases on write, but a binary-collated index would still let a direct
    // insert (a seed script, an admin tool) create `A@x.com` alongside
    // `a@x.com` and silently split one person into two accounts.
    (table) => [uniqueIndex(ix("idx_user_email")).on(sql`${table.email} COLLATE NOCASE`)],
  );

  const session = sqliteTable(
    t("user_session"),
    {
      id: text("id").primaryKey(),
      expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
      token: text("token").notNull(),
      createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
      updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
      ipAddress: text("ip_address"),
      userAgent: text("user_agent"),
      userId: text("user_id")
        .notNull()
        .references(() => user.id, { onDelete: "cascade" }),
    },
    (table) => [
      uniqueIndex(ix("idx_session_token")).on(table.token),
      index(ix("idx_session_user_id")).on(table.userId),
    ],
  );

  const account = sqliteTable(
    t("user_account"),
    {
      id: text("id").primaryKey(),
      accountId: text("account_id").notNull(),
      providerId: text("provider_id").notNull(),
      userId: text("user_id")
        .notNull()
        .references(() => user.id, { onDelete: "cascade" }),
      accessToken: text("access_token"),
      refreshToken: text("refresh_token"),
      idToken: text("id_token"),
      accessTokenExpiresAt: integer("access_token_expires_at", { mode: "timestamp_ms" }),
      refreshTokenExpiresAt: integer("refresh_token_expires_at", { mode: "timestamp_ms" }),
      scope: text("scope"),
      password: text("password"),
      createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
      updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
    },
    (table) => [
      index(ix("idx_account_user_id")).on(table.userId),
      uniqueIndex(ix("idx_account_provider_account")).on(table.providerId, table.accountId),
    ],
  );

  const verification = sqliteTable(
    t("verification"),
    {
      id: text("id").primaryKey(),
      identifier: text("identifier").notNull(),
      value: text("value").notNull(),
      expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
      createdAt: integer("created_at", { mode: "timestamp_ms" }),
      updatedAt: integer("updated_at", { mode: "timestamp_ms" }),
    },
    (table) => [index(ix("idx_verification_identifier")).on(table.identifier)],
  );

  // --- organization / tenancy tables -------------------------------------------
  // These use ISO-8601 text timestamps: organization ids double as tenant ids
  // handed to external services, so their timestamps are read far more often
  // than they are compared.

  const organization = sqliteTable(t("organization"), {
    id: text("id").primaryKey(),
    name: text("name").notNull(),
    createdByUserId: text("created_by_user_id")
      .notNull()
      .references(() => user.id),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
  });

  const organizationUser = sqliteTable(
    t("organization_user"),
    {
      id: text("id").primaryKey(),
      organizationId: text("organization_id")
        .notNull()
        .references(() => organization.id, { onDelete: "cascade" }),
      userId: text("user_id")
        .notNull()
        .references(() => user.id, { onDelete: "cascade" }),
      role: text("role", { enum: organizationRoles }).notNull(),
      status: text("status", { enum: organizationMemberStatuses }).notNull(),
      joinedAt: text("joined_at").notNull(),
    },
    (table) => [
      uniqueIndex(ix("organization_user_organization_id_user_id_unique")).on(
        table.organizationId,
        table.userId,
      ),
      index(ix("idx_organization_user_user_id")).on(table.userId),
      index(ix("idx_organization_user_organization_id")).on(table.organizationId),
      check(
        `${prefix}organization_user_role_check`,
        sql`${table.role} in ('owner', 'admin', 'member')`,
      ),
      check(`${prefix}organization_user_status_check`, sql`${table.status} in ('active')`),
    ],
  );

  const apiKey = sqliteTable(
    t("api_key"),
    {
      id: text("id").primaryKey(),
      organizationId: text("organization_id")
        .notNull()
        .references(() => organization.id, { onDelete: "cascade" }),
      name: text("name").notNull(),
      tokenHash: text("token_hash").notNull(),
      // Nullable: keys minted before hints existed have no recoverable tail.
      tokenHint: text("token_hint"),
      createdAt: text("created_at").notNull(),
      revokedAt: text("revoked_at"),
    },
    (table) => [
      uniqueIndex(ix("api_key_token_hash_unique")).on(table.tokenHash),
      index(ix("idx_api_key_organization_id")).on(table.organizationId),
    ],
  );

  return { user, session, account, verification, organization, organizationUser, apiKey };
};

/**
 * The default (unprefixed) cf-auth drizzle tables.
 *
 * Spread these into your app's drizzle schema:
 *
 * ```ts
 * import { cfAuthTables } from "@maxceem/cf-auth/schema";
 * export const { user, session, account, verification, organization, organizationUser, apiKey } =
 *   cfAuthTables;
 * export const myAppTable = sqliteTable("my_app", { ... });
 * ```
 */
export const cfAuthTables = createCfAuthTables();

export type CfAuthTables = ReturnType<typeof createCfAuthTables>;

/**
 * The subset better-auth's drizzle adapter needs, keyed by better-auth model
 * name. Built automatically by `createCfAuth`; exported for advanced setups
 * that construct the better-auth instance themselves.
 */
export const toBetterAuthSchema = (tables: CfAuthTables) => ({
  user: tables.user,
  session: tables.session,
  account: tables.account,
  verification: tables.verification,
});

export const {
  user: userTable,
  session: sessionTable,
  account: accountTable,
  verification: verificationTable,
  organization: organizationTable,
  organizationUser: organizationUserTable,
  apiKey: apiKeyTable,
} = cfAuthTables;
