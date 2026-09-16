import { and, asc, count, eq, gt, isNull, ne, or, sql, type SQL } from "drizzle-orm";
import { alias } from "drizzle-orm/sqlite-core";
import type { CfAuthDatabase } from "./config.js";
import { deterministicUuid } from "./crypto.js";
import { CfAuthError, conflict } from "./errors.js";
import type { CfAuthTables } from "./schema.js";
import type {
  ApiKeySummary,
  AuthSession,
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

export interface EnsureDefaultOrganizationResult {
  membership: OrganizationMembership;
  created: boolean;
}

/**
 * The write behind {@link CfAuthRepository.claimOrganization}.
 *
 * `provisioning` describes the machine identity that created the organization:
 * the claim only counts while that credential is still live, and `revokeAccess`
 * decides whether it keeps its membership afterwards.
 */
export interface ClaimOrganizationWrite {
  organizationId: string;
  userId: string;
  sessionId: string;
  provisioning?: {
    userId: string;
    credentialId: string;
    revokeAccess: boolean;
  };
}

export type ApiKeyAuthRecord = ApiKeySummary;

/**
 * All database access used by cf-auth, expressed as plain drizzle queries over
 * the configured tables. Kept deliberately small so a host app could swap in
 * its own implementation if it already owns these tables.
 */
export interface CfAuthRepository {
  findUserById(userId: string): Promise<AuthUser | null>;
  findUserByEmail(email: string): Promise<AuthUser | null>;
  /**
   * The session row behind a cookie, or null when it is unknown or expired.
   *
   * This is the evidence an interactive {@link AuthState} is built on: without
   * it, a user id alone would be enough to mint one.
   */
  findActiveSession(sessionId: string, now: Date): Promise<AuthSession | null>;

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
  /**
   * Hands an organization that no person owns yet to one, clearing the
   * provisional deadline in the same transaction.
   *
   * Idempotent: every statement carries its own guard, so a repeated call
   * settles on the same state and answers with the same membership. Returns
   * null when the claim did not happen — the organization is already someone
   * else's, its deadline has passed, the session is not live, or the
   * provisioning credential is not.
   */
  claimOrganization(input: ClaimOrganizationWrite): Promise<OrganizationMembership | null>;
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
    userId: string;
    organizationId: string;
    name: string;
    tokenHash: string;
    tokenHint: string;
    enabled: boolean;
    expiresAt: Date | null;
  }): Promise<ApiKeySummary>;
  listApiKeys(organizationId: string): Promise<ApiKeySummary[]>;
  /**
   * Activates a key issued with `enabled: false`, and answers with the key as
   * it stands afterwards — so a caller reads `enabled` rather than assuming.
   *
   * Refuses a key that has been revoked or has expired, and one whose
   * organization is past its deadline, matching what
   * {@link CfAuthRepository.findActiveApiKeyByHash} would accept. Null means no
   * such key in this organization.
   */
  enableApiKey(apiKeyId: string, organizationId: string, now: Date): Promise<ApiKeySummary | null>;
  revokeApiKey(apiKeyId: string, organizationId: string): Promise<ApiKeySummary | null>;
  findApiKeyById(apiKeyId: string, organizationId: string): Promise<ApiKeySummary | null>;
  findActiveApiKeyByHash(tokenHash: string, now: Date): Promise<ApiKeyAuthRecord | null>;
}

export const createCfAuthRepository = (
  db: CfAuthDatabase,
  tables: CfAuthTables,
  options: CfAuthRepositoryOptions = {},
): CfAuthRepository => {
  const { user, session, organization, organizationUser, apiKey } = tables;

  const onError =
    options.onError ??
    ((error, context) => {
      console.error(`[cf-auth] ${context.scope}`, error);
    });

  // Aliased so the guard subquery is unambiguous against the row being written.
  const ownerGuard = alias(organizationUser, "cf_auth_owner_guard");
  const organizationGuard = alias(organization, "cf_auth_organization_guard");
  const credentialGuard = alias(apiKey, "cf_auth_credential_guard");

  /** Renders a guard subquery as `(select count(*) ...) = n`, ready to AND into a WHERE. */
  const countIs = (query: { getSQL(): SQL }, expected: number) =>
    sql`(${query}) = ${expected}`;

  /**
   * True while the organization is inside its provisional deadline.
   *
   * `expiresAt` is stored as an ISO-8601 instant, which sorts as text, so the
   * comparison is the same one a timestamp column would make.
   */
  const organizationUsable = (organizationId: string, now: Date) =>
    countIs(
      db
        .select({ value: count() })
        .from(organizationGuard)
        .where(
          and(
            eq(organizationGuard.id, organizationId),
            or(isNull(organizationGuard.expiresAt), gt(organizationGuard.expiresAt, now.toISOString())),
          ),
        ),
      1,
    );

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

    const humanOwners = db
      .select({ value: count() })
      .from(ownerGuard)
      .innerJoin(user, eq(user.id, ownerGuard.userId))
      .where(
        and(
          eq(ownerGuard.organizationId, organizationId),
          eq(ownerGuard.role, "owner"),
          eq(user.kind, "human"),
        ),
      );
    const targetKind = db
      .select({ kind: user.kind })
      .from(user)
      .where(eq(user.id, organizationUser.userId));
    return or(
      ne(organizationUser.role, "owner"),
      sql`CASE WHEN (${targetKind}) = 'human'
      THEN (${humanOwners}) > 1
      ELSE (${otherOwners}) > 1 END`,
    );
  };

  const userColumns = {
    id: user.id,
    kind: user.kind,
    name: user.name,
    email: user.email,
    emailVerified: user.emailVerified,
    image: user.image,
    createdAt: user.createdAt,
  };

  const toAuthUser = (row: {
    id: string;
    name: string | null;
    email: string | null;
    kind: "human" | "service";
    emailVerified: boolean;
    image: string | null;
    createdAt: Date | string | number;
  }): AuthUser => ({
    id: row.id,
    kind: row.kind,
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
    claimed: sql<boolean>`EXISTS (
      SELECT 1 FROM ${organizationUser} claimed_membership
      JOIN ${user} claimed_user ON claimed_user.id = claimed_membership.user_id
      WHERE claimed_membership.organization_id = ${organization.id}
        AND claimed_membership.role = 'owner'
        AND claimed_user.kind = 'human'
    )`,
    expiresAt: organization.expiresAt,
  };

  const toMembership = (row: {
    role: OrganizationRole;
    status: "active";
    joinedAt: string;
    organizationId: string;
    organizationName: string;
    organizationCreatedAt: string;
    claimed: boolean | number;
    expiresAt: string | null;
  }): OrganizationMembership => ({
    role: row.role,
    status: row.status,
    joinedAt: row.joinedAt,
    organization: {
      claimed: Boolean(row.claimed),
      expiresAt: row.expiresAt,
      id: row.organizationId,
      name: row.organizationName,
      createdAt: row.organizationCreatedAt,
    },
  });

  const apiKeyColumns = {
    id: apiKey.id,
    organizationId: apiKey.organizationId,
    userId: apiKey.userId,
    name: apiKey.name,
    tokenHint: apiKey.tokenHint,
    enabled: apiKey.enabled,
    createdAt: apiKey.createdAt,
    revokedAt: apiKey.revokedAt,
    expiresAt: apiKey.expiresAt,
  };
  const toApiKeySummary = (row: {
    id: string;
    organizationId: string;
    userId: string;
    name: string;
    tokenHint: string;
    enabled: boolean | number;
    createdAt: Date;
    revokedAt: Date | null;
    expiresAt: Date | null;
  }): ApiKeySummary => {
    return {
      id: row.id,
      organizationId: row.organizationId,
      userId: row.userId,
      name: row.name,
      tokenHint: row.tokenHint,
      enabled: Boolean(row.enabled),
      createdAt: toIso(row.createdAt),
      expiresAt: row.expiresAt ? toIso(row.expiresAt) : null,
      revokedAt: row.revokedAt ? toIso(row.revokedAt) : null,
    };
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
      organization: {
        id: organizationId,
        name: input.name,
        createdAt: now,
        claimed:
          (await db.select({ kind: user.kind }).from(user).where(eq(user.id, input.userId)).get())
            ?.kind === "human",
        expiresAt: null,
      },
    };
  };

  return {
    async findUserById(userId) {
      const row = await db.select(userColumns).from(user).where(eq(user.id, userId)).get();
      return row ? toAuthUser(row) : null;
    },

    async findActiveSession(sessionId, now) {
      const row = await db
        .select({ id: session.id, userId: session.userId, expiresAt: session.expiresAt })
        .from(session)
        .where(and(eq(session.id, sessionId), gt(session.expiresAt, now)))
        .get();
      return row ? { id: row.id, userId: row.userId, expiresAt: toIso(row.expiresAt) } : null;
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

    async claimOrganization(input) {
      const now = new Date();
      const nowIso = now.toISOString();

      // What lets a person take the organization over. Every part is checked
      // inside the statements themselves rather than by a preceding read, so
      // two people racing to claim the same organization cannot both pass.
      const entry = and(
        organizationUsable(input.organizationId, now),
        // Nobody else has claimed it. Phrased as "no *other* human owner" so a
        // repeat of a claim that already succeeded is a no-op, not a refusal.
        countIs(
          db
            .select({ value: count() })
            .from(ownerGuard)
            .innerJoin(user, eq(user.id, ownerGuard.userId))
            .where(
              and(
                eq(ownerGuard.organizationId, input.organizationId),
                eq(ownerGuard.role, "owner"),
                eq(user.kind, "human"),
                ne(ownerGuard.userId, input.userId),
              ),
            ),
          0,
        ),
        // The claimer's own session, re-read here rather than trusted from the
        // caller: this is the one write that hands an organization to a person.
        countIs(
          db
            .select({ value: count() })
            .from(session)
            .innerJoin(user, eq(user.id, session.userId))
            .where(
              and(
                eq(session.id, input.sessionId),
                eq(session.userId, input.userId),
                gt(session.expiresAt, now),
                eq(user.kind, "human"),
              ),
            ),
          1,
        ),
        ...(input.provisioning
          ? [
              countIs(
                db
                  .select({ value: count() })
                  .from(credentialGuard)
                  .where(
                    and(
                      eq(credentialGuard.id, input.provisioning.credentialId),
                      eq(credentialGuard.userId, input.provisioning.userId),
                      eq(credentialGuard.organizationId, input.organizationId),
                      eq(credentialGuard.enabled, true),
                      isNull(credentialGuard.revokedAt),
                      or(isNull(credentialGuard.expiresAt), gt(credentialGuard.expiresAt, now)),
                    ),
                  ),
                1,
              ),
            ]
          : []),
      )!;

      // Everything after the promotion keys off the promotion itself, not off
      // `entry` again: the earlier statements deliberately change what `entry`
      // sees, and a repeated call must still finish the parts it did not reach.
      const claimed = countIs(
        db
          .select({ value: count() })
          .from(ownerGuard)
          .where(
            and(
              eq(ownerGuard.organizationId, input.organizationId),
              eq(ownerGuard.userId, input.userId),
              eq(ownerGuard.role, "owner"),
            ),
          ),
        1,
      );

      const statements: unknown[] = [
        // `insert ... select ... where` rather than `values`: a WHERE clause is
        // the only way to make the grant itself carry the guard.
        db
          .insert(organizationUser)
          .select(
            sql`select ${crypto.randomUUID()}, ${input.organizationId}, ${input.userId}, 'owner', 'active', ${nowIso} where ${entry}`,
          )
          .onConflictDoNothing({
            target: [organizationUser.organizationId, organizationUser.userId],
          }),
        db
          .update(organizationUser)
          .set({ role: "owner", status: "active" })
          .where(
            and(
              eq(organizationUser.organizationId, input.organizationId),
              eq(organizationUser.userId, input.userId),
              entry,
            ),
          ),
        db
          .update(organization)
          .set({ expiresAt: null, updatedAt: nowIso })
          .where(and(eq(organization.id, input.organizationId), claimed)),
      ];

      if (input.provisioning?.revokeAccess) {
        const { userId: provisioningUserId } = input.provisioning;
        // Only ever the machine identity that provisioned the organization; a
        // person's membership is never collateral of someone else's claim.
        const isService = countIs(
          db
            .select({ value: count() })
            .from(user)
            .where(and(eq(user.id, provisioningUserId), eq(user.kind, "service"))),
          1,
        );

        statements.push(
          db
            .update(apiKey)
            .set({ enabled: false, revokedAt: now })
            .where(
              and(
                eq(apiKey.organizationId, input.organizationId),
                eq(apiKey.userId, provisioningUserId),
                isNull(apiKey.revokedAt),
                claimed,
                isService,
              ),
            ),
          db
            .delete(organizationUser)
            .where(
              and(
                eq(organizationUser.organizationId, input.organizationId),
                eq(organizationUser.userId, provisioningUserId),
                claimed,
                isService,
              ),
            ),
        );
      }

      // No compensation to hand `runAtomically`: every statement carries its own
      // guard and is a no-op once it has run, so a driver without `batch` that
      // fails halfway leaves a state the next call simply finishes.
      await runAtomically(db, statements, async () => {}, onError);

      // The outcome is read from the rows, not from how many changed: a repeat
      // of a claim that already landed changes nothing and is still a success.
      const membership = await findMembership(input.userId, input.organizationId);
      return membership?.role === "owner" && membership.organization.expiresAt === null
        ? membership
        : null;
    },

    async ensureDefaultOrganizationWithOwner(input) {
      const now = new Date().toISOString();

      // Walk deterministic "generation" slots rather than minting a random id.
      // Generation 0 is the user's original default org; each time they leave
      // one, the next slot becomes their default. Because every slot id is a
      // pure function of the user id, two concurrent re-provisions target the
      // same row and `on conflict do nothing` settles it — a random id would
      // let them mint two organizations.
      for (let generation = 0; generation < maxDefaultOrganizationGenerations; generation += 1) {
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
              organization: {
                id: organizationId,
                name: input.name,
                createdAt: now,
                claimed:
                  (await db.select({ kind: user.kind }).from(user).where(eq(user.id, input.userId)).get())
                    ?.kind === "human",
                expiresAt: null,
              },
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
      return {
        membership: await createOrganizationWithOwner(input),
        created: true,
      };
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

      return membership ? { ok: true, membership } : { ok: false, reason: "not_a_member" as const };
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
      const id = crypto.randomUUID();
      const createdAt = new Date();
      await db.insert(apiKey).values({ id, ...input, createdAt, revokedAt: null });
      return {
        id,
        userId: input.userId,
        organizationId: input.organizationId,
        name: input.name,
        tokenHint: input.tokenHint,
        enabled: input.enabled,
        expiresAt: input.expiresAt?.toISOString() ?? null,
        createdAt: createdAt.toISOString(),
        revokedAt: null,
      };
    },

    async listApiKeys(organizationId) {
      const rows = await db
        .select(apiKeyColumns)
        .from(apiKey)
        .where(eq(apiKey.organizationId, organizationId))
        .orderBy(asc(apiKey.createdAt), asc(apiKey.id));
      return rows.map(toApiKeySummary);
    },
    async findApiKeyById(apiKeyId, organizationId) {
      const row = await db
        .select(apiKeyColumns)
        .from(apiKey)
        .where(and(eq(apiKey.id, apiKeyId), eq(apiKey.organizationId, organizationId)))
        .get();
      return row ? toApiKeySummary(row) : null;
    },
    async enableApiKey(apiKeyId, organizationId, now) {
      await db
        .update(apiKey)
        .set({ enabled: true })
        .where(
          and(
            eq(apiKey.id, apiKeyId),
            eq(apiKey.organizationId, organizationId),
            isNull(apiKey.revokedAt),
            or(isNull(apiKey.expiresAt), gt(apiKey.expiresAt, now)),
            organizationUsable(organizationId, now),
          ),
        );
      const row = await db
        .select(apiKeyColumns)
        .from(apiKey)
        .where(and(eq(apiKey.id, apiKeyId), eq(apiKey.organizationId, organizationId)))
        .get();
      return row ? toApiKeySummary(row) : null;
    },

    async revokeApiKey(apiKeyId, organizationId) {
      await db
        .update(apiKey)
        .set({
          enabled: false,
          revokedAt: new Date(),
        })
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
      return row ? toApiKeySummary(row) : null;
    },

    async findActiveApiKeyByHash(tokenHash, now) {
      const row = await db
        .select(apiKeyColumns)
        .from(apiKey)
        .where(
          and(
            eq(apiKey.tokenHash, tokenHash),
            eq(apiKey.enabled, true),
            isNull(apiKey.revokedAt),
            or(isNull(apiKey.expiresAt), gt(apiKey.expiresAt, now)),
          ),
        )
        .get();
      return row ? toApiKeySummary(row) : null;
    },
  };
};
