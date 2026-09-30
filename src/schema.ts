import { sql } from "drizzle-orm";
import { check, index, integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";
import { operationStates, organizationMemberStatuses, organizationRoles } from "./types.js";

export interface CfAuthTablesOptions {
  /**
   * Prefix applied to every physical table and index name, e.g. `"auth_"`
   * produces `auth_user`, `auth_user_session`, ... Defaults to `""` (unprefixed:
   * `user`, `user_session`, `user_account`, `verification`, `organization`,
   * `organization_user`, `api_key`, `operation`).
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
      email: text("email"),
      kind: text("kind", { enum: ["human", "service"] })
        .notNull()
        .default("human"),
      emailVerified: integer("email_verified", { mode: "boolean" }).notNull().default(false),
      image: text("image"),
      createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
      updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
    },
    // COLLATE NOCASE: emails are case-insensitive identifiers. better-auth
    // lowercases on write, but a binary-collated index would still let a direct
    // insert (a seed script, an admin tool) create `A@x.com` alongside
    // `a@x.com` and silently split one person into two accounts.
    (table) => [
      uniqueIndex(ix("idx_user_email")).on(sql`${table.email} COLLATE NOCASE`),
      check(
        ix("user_kind_email_check"),
        sql`(${table.kind} = 'human' and ${table.email} is not null) or (${table.kind} = 'service' and ${table.email} is null)`,
      ),
    ],
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
      accessTokenExpiresAt: integer("access_token_expires_at", {
        mode: "timestamp_ms",
      }),
      refreshTokenExpiresAt: integer("refresh_token_expires_at", {
        mode: "timestamp_ms",
      }),
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
    expiresAt: text("expires_at"),
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
      userId: text("user_id")
        .notNull()
        .references(() => user.id, { onDelete: "cascade" }),
      organizationId: text("organization_id")
        .notNull()
        .references(() => organization.id, { onDelete: "cascade" }),
      name: text("name").notNull(),
      tokenHash: text("token_hash").notNull(),
      tokenHint: text("token_hint").notNull(),
      enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
      expiresAt: integer("expires_at", { mode: "timestamp_ms" }),
      createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
      revokedAt: integer("revoked_at", { mode: "timestamp_ms" }),
      /** Where the key was issued from, e.g. `console`, `cli` or `bootstrap`. Display only. */
      source: text("source").notNull().default("console"),
      /** A human-readable note about the holder, e.g. `CLI on mac-studio`. Display only. */
      label: text("label"),
    },
    (table) => [
      uniqueIndex(ix("api_key_token_hash_unique")).on(table.tokenHash),
      index(ix("idx_api_key_user_id")).on(table.userId),
      index(ix("idx_api_key_organization_id")).on(table.organizationId),
    ],
  );

  // --- browser-approved operations ---------------------------------------------
  // One row per operation a client opened: what it asked for, who may approve
  // it, and what it achieved. Secrets are never stored in the clear: the
  // client's token, the browser proof and the redeem code are SHA-256
  // digests; the user code is a digest for lookup plus a sealed (AES-GCM) copy
  // for display; and an outcome carrying a secret is sealed until it is
  // collected or its window passes. Timestamps are epoch milliseconds so the
  // guards inside a write can compare them with SQLite's own clock.

  const operation = sqliteTable(
    t("operation"),
    {
      id: text("id").primaryKey(),
      kind: text("kind").notNull(),
      state: text("state", { enum: operationStates }).notNull(),
      /** Null for a kind anyone may open. */
      openerUserId: text("opener_user_id").references(() => user.id, { onDelete: "cascade" }),
      /** The session or API key the opener held; rechecked when the operation is approved. */
      openerCredentialId: text("opener_credential_id"),
      /** The opener's organization, or, for a public kind, the one its approver chose. */
      organizationId: text("organization_id").references(() => organization.id, {
        onDelete: "cascade",
      }),
      /** What the pending-per-opener cap counts: the opener's user id, or the client's address. */
      openerKey: text("opener_key"),
      /** Digest of the request a retry with the same token must repeat. */
      requestHash: text("request_hash").notNull(),
      pollTokenHash: text("poll_token_hash").notNull(),
      browserProofHash: text("browser_proof_hash"),
      userCodeHash: text("user_code_hash"),
      /** The user code itself, sealed, so the approval page can show what the terminal shows. */
      userCodeSealed: text("user_code_sealed"),
      clientLabel: text("client_label"),
      clientMeta: text("client_meta"),
      loopbackRedirect: text("loopback_redirect"),
      redeemCodeHash: text("redeem_code_hash"),
      /** What the operation achieved, kept in the clear; never a secret. */
      outcome: text("outcome"),
      sealedOutcome: text("sealed_outcome"),
      sealedUntil: integer("sealed_until", { mode: "timestamp_ms" }),
      decidedByUserId: text("decided_by_user_id").references(() => user.id, {
        onDelete: "set null",
      }),
      payload: text("payload"),
      createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
      updatedAt: integer("updated_at", { mode: "timestamp_ms" }).notNull(),
      /** While pending, the deadline for approval or completion. */
      expiresAt: integer("expires_at", { mode: "timestamp_ms" }).notNull(),
      /** When the sweep may delete the record, whatever its state. */
      retainUntil: integer("retain_until", { mode: "timestamp_ms" }).notNull(),
    },
    (table) => [
      uniqueIndex(ix("operation_poll_token_hash_unique")).on(table.pollTokenHash),
      uniqueIndex(ix("operation_user_code_pending_unique"))
        .on(table.userCodeHash)
        .where(sql`${table.state} = 'pending'`),
      index(ix("idx_operation_organization")).on(
        table.organizationId,
        table.state,
        table.expiresAt,
      ),
      index(ix("idx_operation_opener")).on(table.openerKey, table.state, table.expiresAt),
      index(ix("idx_operation_state_expires")).on(table.state, table.expiresAt),
      index(ix("idx_operation_sealed_until")).on(table.sealedUntil),
      index(ix("idx_operation_retain_until")).on(table.retainUntil),
      check(
        `${prefix}operation_state_check`,
        sql`${table.state} in ('pending', 'completed', 'denied', 'expired', 'retired')`,
      ),
    ],
  );

  return {
    user,
    session,
    account,
    verification,
    organization,
    organizationUser,
    apiKey,
    operation,
  };
};

/**
 * The default (unprefixed) cf-auth drizzle tables.
 *
 * Spread these into your app's drizzle schema:
 *
 * ```ts
 * import { cfAuthTables } from "@maxceem/cf-auth/schema";
 * export const { user, session, account, verification, organization, organizationUser, apiKey, operation } =
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
  operation: operationTable,
} = cfAuthTables;
