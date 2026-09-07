import { describe, expect, it } from "vitest";
import type { CfAuthDatabase } from "../src/config.js";
import { createCfAuthRepository } from "../src/repository.js";
import { cfAuthTables } from "../src/schema.js";
import { createTestAuth, type TestAuth } from "./helpers.js";

/** drizzle wraps driver errors, so the trigger's message sits in `.cause`. */
const errorChain = (error: unknown): string => {
  const parts: string[] = [];
  let current: unknown = error;

  while (current instanceof Error) {
    parts.push(current.message);
    current = (current as { cause?: unknown }).cause;
  }

  return parts.join("\n");
};

const captureRejection = async (run: () => Promise<unknown>) => {
  try {
    await run();
  } catch (error) {
    return errorChain(error);
  }

  throw new Error("Expected the operation to reject, but it resolved");
};

/** A view of the database with `db.batch` hidden, forcing the fallback path. */
const withoutBatch = (db: CfAuthDatabase): CfAuthDatabase =>
  new Proxy(db, {
    get(target, property, receiver) {
      if (property === "batch") {
        return undefined;
      }

      const value = Reflect.get(target, property, receiver);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });

const insertUser = (harness: TestAuth, email: string) =>
  harness.client.execute({
    sql: "INSERT INTO user (id, name, email, email_verified, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?)",
    args: [crypto.randomUUID(), "Direct", email, Date.now(), Date.now()],
  });

describe("user email uniqueness", () => {
  it("is case-insensitive", async () => {
    const harness = await createTestAuth();

    await insertUser(harness, "casing@example.com");

    // Without COLLATE NOCASE this would happily create a second account for
    // what is, for every practical purpose, the same person.
    await expect(insertUser(harness, "Casing@Example.com")).rejects.toThrow(
      /unique constraint failed/i,
    );
  });

  it("still rejects an exact duplicate", async () => {
    const harness = await createTestAuth();

    await insertUser(harness, "exact@example.com");
    await expect(insertUser(harness, "exact@example.com")).rejects.toThrow(
      /unique constraint failed/i,
    );
  });

  it("blocks signup for an address differing only in case", async () => {
    const harness = await createTestAuth();

    await harness.signUp({ email: "mixed@example.com", password: "correct-horse-battery" });
    harness.jar.clear();

    const response = await harness.request(`${harness.cfAuth.basePath}/sign-up/email`, {
      json: { email: "MIXED@example.com", password: "correct-horse-battery", name: "Dup" },
    });

    expect(response.ok).toBe(false);
  });
});

describe("organization creation is atomic", () => {
  it("never leaves an organization without an owner", async () => {
    const harness = await createTestAuth();
    await harness.signUp({ email: "atomic@example.com", password: "correct-horse-battery" });
    const user = await harness.cfAuth.repository.findUserByEmail("atomic@example.com");

    await harness.cfAuth.service.createOrganization(user!.id, "Second");
    await harness.cfAuth.service.createOrganization(user!.id, "Third");

    const orphans = await harness.client.execute(
      `SELECT o.id FROM organization o
       LEFT JOIN organization_user ou
         ON ou.organization_id = o.id AND ou.role = 'owner'
       WHERE ou.id IS NULL`,
    );

    expect(orphans.rows).toEqual([]);
  });

  /**
   * Makes the SECOND statement fail while the first succeeds.
   *
   * Using a bogus user id would trip the FK on the *first* statement, which
   * proves nothing about rollback — the organization row would never exist.
   */
  const installFailingMembershipTrigger = async (harness: TestAuth) => {
    await harness.client.execute(`
      CREATE TRIGGER cf_auth_test_reject_membership
      BEFORE INSERT ON organization_user
      WHEN (SELECT name FROM organization WHERE id = NEW.organization_id) LIKE 'TRIGGER-FAIL%'
      BEGIN SELECT RAISE(ABORT, 'membership insert rejected by test trigger'); END;
    `);
    await harness.client.execute(`
      CREATE TRIGGER cf_auth_test_reject_cleanup
      BEFORE DELETE ON organization
      WHEN OLD.name = 'TRIGGER-FAIL-CLEANUP'
      BEGIN SELECT RAISE(ABORT, 'cleanup delete rejected by test trigger'); END;
    `);
  };

  const countOrganizations = async (harness: TestAuth, name: string) => {
    const result = await harness.client.execute({
      sql: "SELECT COUNT(*) AS count FROM organization WHERE name = ?",
      args: [name],
    });

    return Number(result.rows[0]?.count ?? 0);
  };

  const signUpOwner = async (harness: TestAuth, email: string) => {
    await harness.signUp({ email, password: "correct-horse-battery" });
    const user = await harness.cfAuth.repository.findUserByEmail(email);
    return user!;
  };

  it("rolls back the organization row mid-batch when the membership insert fails", async () => {
    const harness = await createTestAuth();
    const user = await signUpOwner(harness, "batch@example.com");
    await installFailingMembershipTrigger(harness);

    // Guard the premise: this driver really does take the db.batch() path.
    expect(typeof (harness.db as unknown as { batch?: unknown }).batch).toBe("function");

    await expect(
      harness.cfAuth.repository.createOrganizationWithOwner({
        userId: user.id,
        name: "TRIGGER-FAIL",
      }),
    ).rejects.toThrow(/rejected by test trigger/);

    expect(await countOrganizations(harness, "TRIGGER-FAIL")).toBe(0);
  });

  it("compensates on drivers without db.batch", async () => {
    const harness = await createTestAuth();
    const user = await signUpOwner(harness, "nobatch@example.com");
    await installFailingMembershipTrigger(harness);

    const errors: { error: unknown; scope: string }[] = [];
    const repository = createCfAuthRepository(withoutBatch(harness.db), cfAuthTables, {
      onError: (error, context) => errors.push({ error, scope: context.scope }),
    });

    const message = await captureRejection(() =>
      repository.createOrganizationWithOwner({ userId: user.id, name: "TRIGGER-FAIL" }),
    );
    expect(message).toMatch(/rejected by test trigger/);

    // The sequential path left an orphan behind; the compensating delete cleared it.
    expect(await countOrganizations(harness, "TRIGGER-FAIL")).toBe(0);
    expect(errors).toEqual([]);
  });

  it("reports a compensating delete that itself fails", async () => {
    const harness = await createTestAuth();
    const user = await signUpOwner(harness, "nocleanup@example.com");
    await installFailingMembershipTrigger(harness);

    const errors: { error: unknown; scope: string }[] = [];
    const repository = createCfAuthRepository(withoutBatch(harness.db), cfAuthTables, {
      onError: (error, context) => errors.push({ error, scope: context.scope }),
    });

    const message = await captureRejection(() =>
      repository.createOrganizationWithOwner({ userId: user.id, name: "TRIGGER-FAIL-CLEANUP" }),
    );
    // The original failure is what propagates, not the cleanup failure.
    expect(message).toMatch(/membership insert rejected/);

    // A row really is orphaned here — the point is that it is not silent.
    expect(await countOrganizations(harness, "TRIGGER-FAIL-CLEANUP")).toBe(1);
    expect(errors).toHaveLength(1);
    expect(errors[0]?.scope).toBe("runAtomically.compensate");
    expect(errorChain(errors[0]?.error)).toMatch(/cleanup delete rejected/);
  });
});
