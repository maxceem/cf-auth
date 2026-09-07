import { and, asc, count, eq, ne, or, sql } from "drizzle-orm";
import { alias } from "drizzle-orm/sqlite-core";
import type { CfAuthDatabase } from "./config.js";
import { deterministicUuid } from "./crypto.js";
import { CfAuthError, conflict } from "./errors.js";
import type { CfAuthTables } from "./schema.js";
import type {
  ApiKeySummary,
  AuthUser,
  OrganizationMember,
  OrganizationMembership,
  OrganizationRole,
} from "./types.js";

const toIso = (value: Date | string | number) =>
  value instanceof Date
    ? value.toISOString()
    : typeof value === "number"
      ? new Date(value).toISOString()
      : value;

/**
 * Flattens an error and its `cause` chain into one string.
 *
 * drizzle wraps driver errors as `DrizzleQueryError` ("Failed query: ..."), so
 * the actual SQLite constraint message is only reachable through `cause`.
 */
const errorText = (error: unknown) => {
  const parts: string[] = [];
  let current: unknown = error;

  // Bounded in case a driver ever produces a cyclic cause chain.
  for (let depth = 0; depth < 10 && current !== undefined && current !== null; depth += 1) {
    if (current instanceof Error) {
      parts.push(current.message);
      current = (current as { cause?: unknown }).cause;
      continue;
    }

    parts.push(String(current));
    break;
  }

  return parts.join("\n");
};

/** SQLite's wording, surfaced identically by D1 and libsql. */
const isUniqueConstraintError = (error: unknown) =>
  /unique constraint failed/i.test(errorText(error));

const isForeignKeyConstraintError = (error: unknown) =>
  /foreign key constraint failed/i.test(errorText(error));

/** How many deterministic default-organization slots to try before giving up. */
const maxDefaultOrganizationGenerations = 64;

export type MembershipMutationResult =
  | { ok: true; membership: OrganizationMembership }
  | { ok: false; reason: "not_a_member" | "last_owner" };

export interface CfAuthRepositoryOptions {
  /** Reports non-fatal internal failures (e.g. a compensating delete that fails). */
  onError?: (error: unknown, context: { scope: string }) => void;
}

type BatchCapableDatabase = {
  batch?: (queries: readonly unknown[]) => Promise<unknown>;
};

/**
 * Runs dependent writes atomically.
 *
 * D1 has no interactive transactions, so `db.batch()` (a single implicit
 * transaction) is the only way to make multi-statement writes all-or-nothing.
 * Both the D1 and libsql drizzle drivers provide it; if a driver does not, fall
 * back to sequential writes plus a compensating cleanup so a partial failure
 * cannot leave an orphaned row behind.
 */
const runAtomically = async (
  db: CfAuthDatabase,
  queries: readonly unknown[],
  compensate: () => Promise<unknown>,
  onError: (error: unknown, context: { scope: string }) => void,
) => {
  const batch = (db as unknown as BatchCapableDatabase).batch;

  if (typeof batch === "function") {
    await batch.call(db, queries);
    return;
  }

  try {
    for (const query of queries) {
      await (query as Promise<unknown>);
    }
  } catch (error) {
    try {
      await compensate();
    } catch (compensationError) {
      // The original error is the one worth propagating, but a failed cleanup
      // means a row really is orphaned — surface it rather than swallowing it.
      onError(compensationError, { scope: "runAtomically.compensate" });
    }

    throw error;
  }
};

export interface ApiKeyAuthRecord extends ApiKeySummary {
  organization: { id: string; name: string; createdAt: string };
}

export interface EnsureDefaultOrganizationResult {
  membership: OrganizationMembership;
  created: boolean;
}

/**
 * All database access used by cf-auth, expressed as plain drizzle queries over
 * the configured tables. Kept deliberately small so a host app could swap in
 * its own implementation if it already owns these tables.
 */
export interface CfAuthRepository {
  findUserById(userId: string): Promise<AuthUser | null>;
  findUserByEmail(email: string): Promise<AuthUser | null>;

  listOrganizationsForUser(userId: string): Promise<OrganizationMembership[]>;
  findMembership(userId: string, organizationId: string): Promise<OrganizationMembership | null>;
  listMembers(organizationId: string): Promise<OrganizationMember[]>;
  /**
   * How many `owner`-role members the organization currently has.
   *
   * Informational only — for display or reporting. Do NOT gate a demote/remove
   * on this: the count and the write would be separate statements, letting two
   * owners concurrently pass the check and leave the org with none. Pass
   * `requireAnotherOwner` to the mutating methods instead, which folds the
   * check into the write itself.
   */
  countOrganizationOwners(organizationId: string): Promise<number>;

  createOrganizationWithOwner(input: {
    userId: string;
    name: string;
  }): Promise<OrganizationMembership>;
  ensureDefaultOrganizationWithOwner(input: {
    userId: string;
    name: string;
  }): Promise<EnsureDefaultOrganizationResult>;
  addOrganizationUser(input: {
    organizationId: string;
    userId: string;
    role: OrganizationRole;
  }): Promise<OrganizationMembership>;
  /**
   * `requireAnotherOwner` folds the last-owner check into the UPDATE's own
   * WHERE clause, so the check and the write are one atomic statement.
   */
  updateOrganizationUserRole(input: {
    organizationId: string;
    userId: string;
    role: OrganizationRole;
    requireAnotherOwner?: boolean;
  }): Promise<MembershipMutationResult>;
  /** See {@link CfAuthRepository.updateOrganizationUserRole} for `requireAnotherOwner`. */
  removeOrganizationUser(input: {
    organizationId: string;
    userId: string;
    requireAnotherOwner?: boolean;
  }): Promise<MembershipMutationResult>;

  createApiKey(input: {
    organizationId: string;
    name: string;
    tokenHash: string;
    tokenHint: string;
  }): Promise<ApiKeySummary>;
  listApiKeys(organizationId: string): Promise<ApiKeySummary[]>;
  revokeApiKey(apiKeyId: string, organizationId: string): Promise<ApiKeySummary | null>;
  findApiKeyById(apiKeyId: string, organizationId: string): Promise<ApiKeySummary | null>;
  findActiveApiKeyByHash(tokenHash: string): Promise<ApiKeyAuthRecord | null>;
}

export const createCfAuthRepository = (
  db: CfAuthDatabase,
  tables: CfAuthTables,
  options: CfAuthRepositoryOptions = {},
): CfAuthRepository => {
  const { user, organization, organizationUser, apiKey } = tables;

  const onError =
    options.onError ??
    ((error, context) => {
      console.error(`[cf-auth] ${context.scope}`, error);
    });

  // Aliased so the guard subquery is unambiguous against the row being written.
  const ownerGuard = alias(organizationUser, "cf_auth_owner_guard");

  /**
   * True when this organization would still have an owner after the target row
   * is demoted or deleted — either because the target is not an owner, or
   * because at least one other owner exists.
   *
   * Evaluated inside the mutating statement's WHERE clause, which SQLite (and
   * therefore D1) executes atomically. Counting in a separate SELECT first
   * would let two owners concurrently remove each other and leave zero.
   */
  const wouldLeaveAnOwner = (organizationId: string) => {
    // Built through the query builder (not a hand-written FROM) so the aliased
    // table renders with its real, possibly prefixed, name.
    const otherOwners = db
      .select({ value: count() })
      .from(ownerGuard)
      .where(and(eq(ownerGuard.organizationId, organizationId), eq(ownerGuard.role, "owner")));

    return or(ne(organizationUser.role, "owner"), sql`(${otherOwners}) > 1`);
  };

  const userColumns = {
    id: user.id,
    name: user.name,
    email: user.email,
    emailVerified: user.emailVerified,
    image: user.image,
    createdAt: user.createdAt,
  };

  const toAuthUser = (row: {
    id: string;
    name: string | null;
    email: string;
    emailVerified: boolean;
    image: string | null;
    createdAt: Date | string | number;
  }): AuthUser => ({
    id: row.id,
    name: row.name,
    email: row.email,
    emailVerified: Boolean(row.emailVerified),
    image: row.image,
    createdAt: toIso(row.createdAt),
  });

  const membershipColumns = {
    role: organizationUser.role,
    status: organizationUser.status,
    joinedAt: organizationUser.joinedAt,
    organizationId: organization.id,
    organizationName: organization.name,
    organizationCreatedAt: organization.createdAt,
  };

  const toMembership = (row: {
    role: OrganizationRole;
    status: "active";
    joinedAt: string;
    organizationId: string;
    organizationName: string;
    organizationCreatedAt: string;
  }): OrganizationMembership => ({
    role: row.role,
    status: row.status,
    joinedAt: row.joinedAt,
    organization: {
      id: row.organizationId,
      name: row.organizationName,
      createdAt: row.organizationCreatedAt,
    },
  });

  const apiKeyColumns = {
    id: apiKey.id,
    organizationId: apiKey.organizationId,
    name: apiKey.name,
    tokenHint: apiKey.tokenHint,
    createdAt: apiKey.createdAt,
    revokedAt: apiKey.revokedAt,
  };

  const findMembership = async (userId: string, organizationId: string) => {
    const row = await db
      .select(membershipColumns)
      .from(organizationUser)
      .innerJoin(organization, eq(organization.id, organizationUser.organizationId))
      .where(
        and(
          eq(organizationUser.userId, userId),
          eq(organizationUser.organizationId, organizationId),
        ),
      )
      .get();

    return row ? toMembership(row) : null;
  };

  /**
   * A guarded write that affected no rows means either the last-owner guard
   * blocked it, or the row vanished concurrently. Re-read to tell them apart.
   */
  const describeGuardFailure = async (input: { organizationId: string; userId: string }) =>
    (await findMembership(input.userId, input.organizationId))
      ? ("last_owner" as const)
      : ("not_a_member" as const);

  const createOrganizationWithOwner = async (input: {
    userId: string;
    name: string;
  }): Promise<OrganizationMembership> => {
    const now = new Date().toISOString();
    const organizationId = crypto.randomUUID();

    // Both rows or neither: an organization with no owner is unreachable.
    await runAtomically(
      db,
      [
        db.insert(organization).values({
          id: organizationId,
          name: input.name,
          createdByUserId: input.userId,
          createdAt: now,
          updatedAt: now,
        }),
        db.insert(organizationUser).values({
          id: crypto.randomUUID(),
          organizationId,
          userId: input.userId,
          role: "owner",
          status: "active",
          joinedAt: now,
        }),
      ],
      () => db.delete(organization).where(eq(organization.id, organizationId)),
      onError,
    );

    return {
      role: "owner",
      status: "active",
      joinedAt: now,
      organization: { id: organizationId, name: input.name, createdAt: now },
    };
  };

  return {
    async findUserById(userId) {
      const row = await db.select(userColumns).from(user).where(eq(user.id, userId)).get();
      return row ? toAuthUser(row) : null;
    },

    async findUserByEmail(email) {
      const row = await db
        .select(userColumns)
        .from(user)
        .where(eq(user.email, email.trim().toLowerCase()))
        .get();
      return row ? toAuthUser(row) : null;
    },

    async listOrganizationsForUser(userId) {
      const rows = await db
        .select(membershipColumns)
        .from(organizationUser)
        .innerJoin(organization, eq(organization.id, organizationUser.organizationId))
        .where(eq(organizationUser.userId, userId))
        .orderBy(asc(organization.createdAt), asc(organization.id));

      return rows.map(toMembership);
    },

    findMembership,

    async listMembers(organizationId) {
      const rows = await db
        .select({
          ...userColumns,
          role: organizationUser.role,
          status: organizationUser.status,
          joinedAt: organizationUser.joinedAt,
        })
        .from(organizationUser)
        .innerJoin(user, eq(user.id, organizationUser.userId))
        .where(eq(organizationUser.organizationId, organizationId))
        .orderBy(asc(organizationUser.joinedAt), asc(user.id));

      return rows.map((row) => ({
        ...toAuthUser(row),
        role: row.role,
        status: row.status,
        joinedAt: row.joinedAt,
      }));
    },

    async countOrganizationOwners(organizationId) {
      const rows = await db
        .select({ userId: organizationUser.userId })
        .from(organizationUser)
        .where(
          and(
            eq(organizationUser.organizationId, organizationId),
            eq(organizationUser.role, "owner"),
          ),
        );

      return rows.length;
    },

    createOrganizationWithOwner,

    async ensureDefaultOrganizationWithOwner(input) {
      const now = new Date().toISOString();

      // Walk deterministic "generation" slots rather than minting a random id.
      // Generation 0 is the user's original default org; each time they leave
      // one, the next slot becomes their default. Because every slot id is a
      // pure function of the user id, two concurrent re-provisions target the
      // same row and `on conflict do nothing` settles it — a random id would
      // let them mint two organizations.
      for (
        let generation = 0;
        generation < maxDefaultOrganizationGenerations;
        generation += 1
      ) {
        const suffix = generation === 0 ? "" : `:${generation}`;
        const organizationId = await deterministicUuid(
          `default-organization:${input.userId}${suffix}`,
        );
        const membershipId = await deterministicUuid(
          `default-organization-owner:${input.userId}${suffix}`,
        );

        const existingOrganization = await db
          .select({ id: organization.id })
          .from(organization)
          .where(eq(organization.id, organizationId))
          .get();

        if (existingOrganization) {
          const membership = await findMembership(input.userId, organizationId);

          if (membership) {
            return { membership, created: false };
          }

          // This slot's organization exists but the user is no longer in it —
          // they were explicitly removed. It may now have other members and
          // live API keys, so re-adding them would make "leave organization"
          // unenforceable. Move on to the next slot.
          continue;
        }

        await db
          .insert(organization)
          .values({
            id: organizationId,
            name: input.name,
            createdByUserId: input.userId,
            createdAt: now,
            updatedAt: now,
          })
          .onConflictDoNothing({ target: organization.id });

        const inserted = await db
          .insert(organizationUser)
          .values({
            id: membershipId,
            organizationId,
            userId: input.userId,
            role: "owner",
            status: "active",
            joinedAt: now,
          })
          .onConflictDoNothing({
            target: [organizationUser.organizationId, organizationUser.userId],
          })
          .returning({ joinedAt: organizationUser.joinedAt });

        if (inserted.length > 0) {
          return {
            created: true,
            membership: {
              role: "owner",
              status: "active",
              joinedAt: inserted[0]?.joinedAt ?? now,
              organization: { id: organizationId, name: input.name, createdAt: now },
            },
          };
        }

        // Lost the race — read back the winning row so the caller sees the
        // persisted name/timestamps rather than ours.
        const existing = await findMembership(input.userId, organizationId);

        if (existing) {
          return { created: false, membership: existing };
        }
      }

      // Every slot is taken by an organization the user has left. Vanishingly
      // unlikely, but fall back to a unique organization rather than looping.
      return { membership: await createOrganizationWithOwner(input), created: true };
    },

    async addOrganizationUser(input) {
      const now = new Date().toISOString();

      if (await findMembership(input.userId, input.organizationId)) {
        throw conflict("That user is already a member of this organization", "already_a_member");
      }

      try {
        await db.insert(organizationUser).values({
          id: crypto.randomUUID(),
          organizationId: input.organizationId,
          userId: input.userId,
          role: input.role,
          status: "active",
          joinedAt: now,
        });
      } catch (error) {
        // Backstop for the race between the check above and this insert: the
        // unique index is the real guarantee, so translate it rather than
        // letting a raw SQLite error surface as a 500.
        if (isUniqueConstraintError(error)) {
          throw conflict("That user is already a member of this organization", "already_a_member");
        }

        // An invite flow can hand us an id for a user (or org) that no longer
        // exists; that is a caller mistake, not an internal fault.
        if (isForeignKeyConstraintError(error)) {
          throw new CfAuthError(
            "user_not_found",
            "That user or organization no longer exists",
            404,
          );
        }

        throw error;
      }

      const membership = await findMembership(input.userId, input.organizationId);

      if (!membership) {
        throw new Error("Organization membership was not created");
      }

      return membership;
    },

    async updateOrganizationUserRole(input) {
      const updated = await db
        .update(organizationUser)
        .set({ role: input.role })
        .where(
          and(
            eq(organizationUser.organizationId, input.organizationId),
            eq(organizationUser.userId, input.userId),
            ...(input.requireAnotherOwner ? [wouldLeaveAnOwner(input.organizationId)] : []),
          ),
        )
        .returning({ id: organizationUser.id });

      if (updated.length === 0) {
        return { ok: false, reason: await describeGuardFailure(input) };
      }

      const membership = await findMembership(input.userId, input.organizationId);

      return membership
        ? { ok: true, membership }
        : { ok: false, reason: "not_a_member" as const };
    },

    async removeOrganizationUser(input) {
      // Read first so the caller can be told what was removed; the delete's own
      // WHERE clause — not this read — is what enforces the last-owner rule.
      const existing = await findMembership(input.userId, input.organizationId);

      if (!existing) {
        return { ok: false, reason: "not_a_member" };
      }

      const deleted = await db
        .delete(organizationUser)
        .where(
          and(
            eq(organizationUser.organizationId, input.organizationId),
            eq(organizationUser.userId, input.userId),
            ...(input.requireAnotherOwner ? [wouldLeaveAnOwner(input.organizationId)] : []),
          ),
        )
        .returning({ id: organizationUser.id });

      if (deleted.length === 0) {
        return { ok: false, reason: await describeGuardFailure(input) };
      }

      return { ok: true, membership: existing };
    },

    async createApiKey(input) {
      const now = new Date().toISOString();
      const id = crypto.randomUUID();

      await db.insert(apiKey).values({
        id,
        organizationId: input.organizationId,
        name: input.name,
        tokenHash: input.tokenHash,
        tokenHint: input.tokenHint,
        createdAt: now,
        revokedAt: null,
      });

      return {
        id,
        organizationId: input.organizationId,
        name: input.name,
        tokenHint: input.tokenHint,
        createdAt: now,
        revokedAt: null,
      };
    },

    async listApiKeys(organizationId) {
      return db
        .select(apiKeyColumns)
        .from(apiKey)
        .where(eq(apiKey.organizationId, organizationId))
        .orderBy(asc(apiKey.createdAt), asc(apiKey.id));
    },

    async findApiKeyById(apiKeyId, organizationId) {
      const row = await db
        .select(apiKeyColumns)
        .from(apiKey)
        .where(and(eq(apiKey.id, apiKeyId), eq(apiKey.organizationId, organizationId)))
        .get();

      return row ?? null;
    },

    async revokeApiKey(apiKeyId, organizationId) {
      const existing = await db
        .select(apiKeyColumns)
        .from(apiKey)
        .where(and(eq(apiKey.id, apiKeyId), eq(apiKey.organizationId, organizationId)))
        .get();

      if (!existing || existing.revokedAt) {
        return existing ?? null;
      }

      await db
        .update(apiKey)
        .set({ revokedAt: new Date().toISOString() })
        .where(
          and(
            eq(apiKey.id, apiKeyId),
            eq(apiKey.organizationId, organizationId),
            sql`${apiKey.revokedAt} is null`,
          ),
        );

      const row = await db
        .select(apiKeyColumns)
        .from(apiKey)
        .where(and(eq(apiKey.id, apiKeyId), eq(apiKey.organizationId, organizationId)))
        .get();

      return row ?? null;
    },

    async findActiveApiKeyByHash(tokenHash) {
      const row = await db
        .select({
          ...apiKeyColumns,
          organizationName: organization.name,
          organizationCreatedAt: organization.createdAt,
        })
        .from(apiKey)
        .innerJoin(organization, eq(organization.id, apiKey.organizationId))
        .where(and(eq(apiKey.tokenHash, tokenHash), sql`${apiKey.revokedAt} is null`))
        .get();

      if (!row) {
        return null;
      }

      return {
        id: row.id,
        organizationId: row.organizationId,
        name: row.name,
        tokenHint: row.tokenHint,
        createdAt: row.createdAt,
        revokedAt: row.revokedAt,
        organization: {
          id: row.organizationId,
          name: row.organizationName,
          createdAt: row.organizationCreatedAt,
        },
      };
    },
  };
};
