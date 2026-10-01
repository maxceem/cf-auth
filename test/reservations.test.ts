/**
 * The engine's reservation, status and reveal entry points, and the internal
 * kinds every public entry point refuses. On libsql; `operations-d1.test.ts`
 * runs the batching paths on a real D1.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { and, eq, sql } from "drizzle-orm";
import { sqliteTable, text } from "drizzle-orm/sqlite-core";
import { validateOperationKind } from "../src/config.js";
import { createOperationToken } from "../src/crypto.js";
import { guardedInsert } from "../src/guarded-insert.js";
import {
  createOperationsEngine,
  defineOperationKind,
  type ExecuteOperationFunction,
  type OperationKind,
} from "../src/operations.js";
import { createEmptyAuthState, type AuthState } from "../src/types.js";
import { createTestAuth, holdReveal, type TestAuth, type TestOverrides } from "./helpers.js";

const expectCode = async (promise: Promise<unknown>, code: string) => {
  await expect(promise).rejects.toMatchObject({ code });
};

/** A write a caller reserves and executes later; the default grant, `manage`. */
const createApp = defineOperationKind({
  name: "app.create",
  open: { minRole: "member" },
  browser: false,
  payload: (value: unknown) => {
    const name = (value as { name?: unknown } | null)?.name;
    if (typeof name !== "string" || !name) throw new Error("name is required");
    return { name: name.trim() };
  },
});
/** A read a caller may reserve with a read key. */
const report = defineOperationKind({ name: "report", open: { minRole: "member" }, browser: false, grant: "read" });
/** Anybody opens it: not reservable. */
const bootstrap = defineOperationKind({ name: "bootstrap", open: "public", browser: false });
/** A key only a person may see (`deliver: "reveal"`), and only while it is not revoked. */
const keyIssue = defineOperationKind({
  name: "key.issue",
  open: { minRole: "member" },
  browser: false,
  deliver: "reveal",
  // Revoked by a `revoked:<keyId>` marker row; the key is the record's, or the operation's id.
  deliverable: ({ operation, record }) =>
    sql`not exists (select 1 from side_effect where id = ${`revoked:${(record as { keyId?: string } | null)?.keyId ?? operation.id}`})`,
});
/** Kept for a second, as briefly as a kind may be. */
const brief = defineOperationKind({
  name: "brief",
  open: { minRole: "member" },
  browser: false,
  pendingTtlMs: 1_000,
  recordTtlMs: 1_000,
});
/** Approved in a browser: not reservable. */
const change = defineOperationKind({
  name: "change",
  open: { minRole: "member" },
  browser: true,
  approve: () => ({ outcome: { changed: true }, seal: true }),
});
/** Approved in a browser, writing whatever statements the test hands it. */
let approveStatements: (guard: ReturnType<typeof sql>) => unknown[] = () => [];
const approveWrites = defineOperationKind({
  name: "approve.writes",
  open: { minRole: "member" },
  browser: true,
  approverMinRole: null,
  approve: ({ guard }) => ({ outcome: { ok: true }, statements: approveStatements(guard) }),
});
const kinds: OperationKind[] = [createApp, report, bootstrap, change, keyIssue, brief, approveWrites];

/** Built-in kinds only cf-auth's own flows drive. */
const internalTask = defineOperationKind({
  name: "cf-auth:internal.task",
  open: { minRole: "member" },
  browser: false,
  internal: true,
});
const internalPage = defineOperationKind({
  name: "cf-auth:internal.page",
  open: "public",
  browser: true,
  approver: "proof",
  userCode: true,
  internal: true,
  approve: () => ({ outcome: { approved: true } }),
});

const sideEffect = sqliteTable("side_effect", { id: text("id").primaryKey() });

const setup = async (operations: NonNullable<TestOverrides["operations"]> = {}) => {
  const harness = await createTestAuth({
    operations: { enabled: true, realm: "test-deployment", kinds, ...operations },
  });
  await harness.client.execute("CREATE TABLE side_effect (id TEXT PRIMARY KEY)");
  const engine = createOperationsEngine(harness.cfAuth.config, harness.cfAuth.repository, {
    builtInKinds: [internalTask, internalPage],
  });
  const owner = await harness.sessions.human();
  const ownerActor = await harness.actorFor(owner.userId);
  return { harness, operations: engine.operations, internal: engine.internal, owner, ownerActor };
};

const keyFor = async (
  harness: TestAuth,
  organizationId: string,
  actor: Awaited<ReturnType<TestAuth["actorFor"]>>,
  grant: "read" | "manage" = "manage",
) => {
  const key = await harness.cfAuth.service.createApiKey({ organizationId, actor, name: `${grant} key`, grant, source: "mcp" });
  return { key, state: await harness.cfAuth.service.resolveApiKeyAuthState(key.plaintext, "mcp") };
};

/** An execute function that records its calls and writes one guarded side effect. */
const recorder = (harness: TestAuth, id = "app_1") => {
  const calls: unknown[] = [];
  const fn: ExecuteOperationFunction<unknown, { appId: string; key: string }> = ({ input, guard, db }) => {
    calls.push(input);
    return {
      outcome: { appId: id, key: `secret-for-${id}` },
      record: { appId: id },
      statements: [guardedInsert(db, sideEffect, { id }, guard)],
    };
  };
  const sideEffects = async () =>
    (await harness.client.execute("SELECT id FROM side_effect ORDER BY id")).rows.map((row) => row.id);
  return { calls, fn, sideEffects };
};

/** A promise the test resolves when it chooses, to hold an execution inside its function. */
const barrier = () => {
  let open!: () => void;
  const opened = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { open, opened };
};

/**
 * Two guarded inserts where the first invalidates the second's guard, so the
 * last statement changes nothing and the completion must be refused — taking
 * the first insert with it.
 */
const selfDefeating = (db: TestAuth["cfAuth"]["config"]["db"], id: string, guard: ReturnType<typeof sql>) => [
  guardedInsert(db, sideEffect, { id: `${id}:first` }, guard),
  guardedInsert(
    db,
    sideEffect,
    { id: `${id}:second` },
    sql`${guard} and not exists (select 1 from side_effect where id = ${`${id}:first`})`,
  ),
];

afterEach(() => {
  vi.restoreAllMocks();
  approveStatements = () => [];
});

const row = async (harness: TestAuth, id: string) =>
  (await harness.client.execute({ sql: "SELECT * FROM operation WHERE id = ?", args: [id] })).rows[0]!;

describe("status", () => {
  it("shows an operation to its organization only, and never the sealed outcome", async () => {
    const { harness, operations, owner, ownerActor } = await setup();
    const { state: reader } = await keyFor(harness, owner.organizationId, ownerActor, "read");
    const reserved = await operations.reserve({ kind: "app.create", opener: ownerActor, input: { name: "A" } });

    expect(await operations.status({ id: reserved.id, opener: ownerActor })).toEqual({
      id: reserved.id,
      kind: "app.create",
      state: "pending",
      createdAt: expect.any(String),
      expiresAt: reserved.expiresAt,
      organizationId: owner.organizationId,
      record: null,
    });

    const { fn } = recorder(harness);
    await operations.execute({ handle: reserved.handle, kind: "app.create", opener: ownerActor }, fn);
    for (const opener of [ownerActor, reader]) {
      const status = await operations.status({ id: reserved.id, opener });
      expect(status).toMatchObject({ state: "completed", record: { appId: "app_1" } });
      expect(status).not.toHaveProperty("outcome");
      expect(JSON.stringify(status)).not.toContain("secret-for");
    }

    const stranger = await harness.sessions.human();
    for (const opener of [await harness.actorFor(stranger.userId), createEmptyAuthState(), null]) {
      await expectCode(operations.status({ id: reserved.id, opener }), "operation_not_found");
    }
    await expectCode(operations.status({ id: "no-such-id", opener: ownerActor }), "operation_not_found");

    // One with no organization is never shown here.
    const loose = await operations.open({ kind: "bootstrap", token: createOperationToken() });
    await expectCode(operations.status({ id: loose.id, opener: ownerActor }), "operation_not_found");
  });

  it("does not consume a sealed outcome delivered once", async () => {
    const { harness, operations, owner, ownerActor } = await setup();
    const { state: opener } = await keyFor(harness, owner.organizationId, ownerActor);
    const token = createOperationToken();
    const opened = await operations.open({ kind: "app.create", token, opener, payload: { name: "B" } });
    await operations.complete({ id: opened.id, outcome: { key: "k" }, record: { appId: "b" }, seal: true });

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const status = await operations.status({ id: opened.id, opener });
      expect(status).toMatchObject({ state: "completed", record: { appId: "b" } });
      expect(status).not.toHaveProperty("outcome");
    }
    expect((await operations.poll({ id: opened.id, token })).outcome).toEqual({ key: "k" });
  });
});

describe("reserve", () => {
  it("refuses what cannot be reserved, and who may not reserve it", async () => {
    const { harness, operations, owner, ownerActor } = await setup();
    const { state: reader } = await keyFor(harness, owner.organizationId, ownerActor, "read");

    await expectCode(operations.reserve({ kind: "bootstrap", opener: ownerActor }), "validation_error");
    await expectCode(operations.reserve({ kind: "change", opener: ownerActor }), "validation_error");
    await expectCode(operations.reserve({ kind: "cf-auth:internal.task", opener: ownerActor }), "validation_error");
    await expectCode(operations.reserve({ kind: "nope", opener: ownerActor }), "validation_error");
    await expectCode(
      operations.reserve({ kind: "app.create", opener: reader, input: { name: "A" } }),
      "grant_insufficient",
    );
    await expectCode(operations.reserve({ kind: "app.create", opener: null, input: { name: "A" } }), "unauthorized");
    await expectCode(operations.reserve({ kind: "app.create", opener: ownerActor, input: {} }), "validation_error");
    await expectCode(operations.reserve({ kind: "report", opener: ownerActor, input: { x: 1 } }), "validation_error");
    expect(await harness.client.execute("SELECT id FROM operation")).toMatchObject({ rows: [] });
  });

  it("answers a server-made handle, pending for 15 minutes, with the payload read by the kind", async () => {
    const { harness, operations, owner, ownerActor } = await setup();
    const { state: reader } = await keyFor(harness, owner.organizationId, ownerActor, "read");
    const before = Date.now();
    const reserved = await operations.reserve({ kind: "app.create", opener: ownerActor, input: { name: "  Spaced " } });
    expect(reserved.handle).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const lapses = Date.parse(reserved.expiresAt) - before;
    expect(lapses).toBeGreaterThanOrEqual(15 * 60_000);
    expect(lapses).toBeLessThan(15 * 60_000 + 5_000);

    const stored = await row(harness, reserved.id);
    expect(stored).toMatchObject({
      kind: "app.create",
      state: "pending",
      payload: JSON.stringify({ name: "Spaced" }),
      organization_id: owner.organizationId,
      opener_user_id: owner.userId,
      opener_credential_id: ownerActor.actor!.credentialId,
      browser_proof_hash: null,
      user_code_hash: null,
    });
    expect(JSON.stringify(stored)).not.toContain(reserved.handle);
    // The handle is the operation's token.
    expect((await operations.findByToken({ token: reserved.handle }))?.id).toBe(reserved.id);

    // A read kind takes a read key; the lifetime is configurable.
    expect(await operations.reserve({ kind: "report", opener: reader })).toMatchObject({ handle: expect.any(String) });
    const short = await setup({ reserveTtlMs: 60_000 });
    const quick = await short.operations.reserve({ kind: "report", opener: short.ownerActor });
    expect(Date.parse(quick.expiresAt) - Date.now()).toBeLessThanOrEqual(60_000);
  });
  it("refuses a reservation lifetime that is not positive", async () => {
    await expect(
      createTestAuth({ operations: { enabled: true, reserveTtlMs: 0 } }),
    ).rejects.toMatchObject({ code: "validation_error" });
  });
});

describe("execute", () => {
  it("runs the function once in the completion batch, then replays only its record", async () => {
    const { harness, operations, ownerActor } = await setup();
    const reserved = await operations.reserve({ kind: "app.create", opener: ownerActor, input: { name: "A" } });
    const { calls, fn, sideEffects } = recorder(harness);
    const input = { handle: reserved.handle, kind: "app.create", opener: ownerActor };

    const first = await operations.execute(input, fn);
    expect(first).toEqual({
      id: reserved.id,
      state: "completed",
      record: { appId: "app_1" },
      outcome: { appId: "app_1", key: "secret-for-app_1" },
      replayed: false,
    });
    expect(calls).toEqual([{ name: "A" }]);
    expect(await sideEffects()).toEqual(["app_1"]);

    const stored = await row(harness, reserved.id);
    expect(stored.sealed_outcome).not.toBeNull();
    expect(stored.outcome).toBe(JSON.stringify({ appId: "app_1" }));
    expect(stored.decided_by_user_id).toBe(ownerActor.user!.id);
    expect(stored.execution_claim).toBeNull();
    expect(JSON.stringify(stored)).not.toContain("secret-for");

    // A repeat answers the record, never the outcome again.
    const again = await operations.execute(input, fn);
    expect(again).toEqual({ id: reserved.id, state: "completed", record: { appId: "app_1" }, replayed: true });
    expect(again).not.toHaveProperty("outcome");
    expect(calls).toHaveLength(1);
    expect(await sideEffects()).toEqual(["app_1"]);

    // After the seal window the repeat is refused, still without running it.
    await harness.client.execute({ sql: "UPDATE operation SET sealed_until = 1 WHERE id = ?", args: [reserved.id] });
    await expectCode(operations.execute(input, fn), "already_completed");
    expect(calls).toHaveLength(1);
  });

  it("guards the write with the reserving credential's authority", async () => {
    const { harness, operations, owner, ownerActor } = await setup();
    const { key, state: opener } = await keyFor(harness, owner.organizationId, ownerActor);
    const reserved = await operations.reserve({ kind: "app.create", opener, input: { name: "A" } });
    const { calls, fn, sideEffects } = recorder(harness);
    const input = { handle: reserved.handle, kind: "app.create", opener };

    // The key loses `manage` after the caller's state was read: the check
    // before the function passes, and the guard in the batch refuses.
    await harness.client.execute({ sql: `UPDATE api_key SET "grant" = 'read' WHERE id = ?`, args: [key.id] });
    await expectCode(operations.execute(input, fn), "conflict");
    expect(calls).toHaveLength(1);
    expect(await sideEffects()).toEqual([]);
    expect((await operations.status({ id: reserved.id, opener })).state).toBe("pending");

    // Read afresh, the downgraded key is refused before anything runs.
    const downgraded = await harness.cfAuth.service.resolveApiKeyAuthState(key.plaintext, "mcp");
    await expectCode(operations.execute({ ...input, opener: downgraded }, fn), "grant_insufficient");
    expect(calls).toHaveLength(1);

    // The refused attempt released its claim: with `manage` back, it runs.
    await harness.client.execute({ sql: `UPDATE api_key SET "grant" = 'manage' WHERE id = ?`, args: [key.id] });
    expect(await operations.execute(input, fn)).toMatchObject({ replayed: false });
    expect(calls).toHaveLength(2);
    expect(await sideEffects()).toEqual(["app_1"]);
  });

  it("gives the handle back when the function throws", async () => {
    const { harness, operations, ownerActor } = await setup();
    const reserved = await operations.reserve({ kind: "app.create", opener: ownerActor, input: { name: "A" } });
    const input = { handle: reserved.handle, kind: "app.create", opener: ownerActor };
    await expect(
      operations.execute(input, () => {
        throw new Error("app name taken");
      }),
    ).rejects.toThrow("app name taken");
    expect((await row(harness, reserved.id)).execution_claim).toBeNull();
    const { calls, fn } = recorder(harness);
    expect(await operations.execute(input, fn)).toMatchObject({ replayed: false });
    expect(calls).toHaveLength(1);
  });

  it("refuses an unknown, mismatched or expired handle, in that order", async () => {
    const { harness, operations, owner, ownerActor } = await setup();
    const reserved = await operations.reserve({ kind: "app.create", opener: ownerActor, input: { name: "A" } });
    const { calls, fn } = recorder(harness);
    const stranger = await harness.sessions.human();
    const strangerActor = await harness.actorFor(stranger.userId);

    for (const handle of [createOperationToken(), "short", ""]) {
      await expectCode(operations.execute({ handle, kind: "report", opener: ownerActor }, fn), "operation_not_found");
    }
    await expectCode(operations.execute({ handle: reserved.handle, kind: "app.create", opener: null }, fn), "unauthorized");
    await expectCode(
      operations.execute({ handle: reserved.handle, kind: "report", opener: ownerActor }, fn),
      "operation_mismatch",
    );
    await expectCode(
      operations.execute({ handle: reserved.handle, kind: "app.create", opener: strangerActor }, fn),
      "operation_mismatch",
    );

    await harness.client.execute({ sql: "UPDATE operation SET expires_at = 1 WHERE id = ?", args: [reserved.id] });
    // Mismatch is judged before expiry.
    await expectCode(
      operations.execute({ handle: reserved.handle, kind: "app.create", opener: strangerActor }, fn),
      "operation_mismatch",
    );
    await expectCode(
      operations.execute({ handle: reserved.handle, kind: "app.create", opener: ownerActor }, fn),
      "operation_expired",
    );
    expect(calls).toEqual([]);
    expect(owner.organizationId).not.toBe(stranger.organizationId);
  });

  it("never runs the function twice for a call arriving while one runs, nor for one already completed", async () => {
    const { harness, operations, ownerActor } = await setup();
    const reserved = await operations.reserve({ kind: "app.create", opener: ownerActor, input: { name: "A" } });
    const { calls, fn, sideEffects } = recorder(harness);
    const input = { handle: reserved.handle, kind: "app.create", opener: ownerActor };

    // The first call pauses inside its function while the second arrives.
    const gate = barrier();
    let entered!: () => void;
    const inside = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const first = operations.execute(input, async (context) => {
      entered();
      await gate.opened;
      return fn(context);
    });
    await inside;
    await expectCode(operations.execute(input, fn), "conflict");
    expect(calls).toHaveLength(0);
    gate.open();
    expect(await first).toMatchObject({ replayed: false, outcome: { key: "secret-for-app_1" } });
    expect(calls).toHaveLength(1);
    expect(await sideEffects()).toEqual(["app_1"]);
    expect(await operations.execute(input, fn)).toEqual({
      id: reserved.id,
      state: "completed",
      record: { appId: "app_1" },
      replayed: true,
    });
    expect(calls).toHaveLength(1);

    // Completed some other way first: replayed, never run.
    const other = await operations.reserve({ kind: "app.create", opener: ownerActor, input: { name: "B" } });
    await operations.complete({ id: other.id, outcome: { key: "b" }, record: { appId: "b" }, seal: true });
    expect(await operations.execute({ ...input, handle: other.handle }, fn)).toEqual({
      id: other.id,
      state: "completed",
      record: { appId: "b" },
      replayed: true,
    });
    expect(calls).toHaveLength(1);
  });

  it("keeps the claim when the user executing is deleted mid-execution", async () => {
    const { harness, operations, owner, ownerActor } = await setup();
    const executor = await harness.sessions.human();
    await harness.cfAuth.service.addOrganizationMember({
      actor: ownerActor,
      organizationId: owner.organizationId,
      userId: executor.userId,
      role: "admin",
    });
    const executorActor = await harness.actorFor(executor.userId, owner.organizationId);
    const reserved = await operations.reserve({ kind: "app.create", opener: ownerActor, input: { name: "A" } });
    const { calls, fn, sideEffects } = recorder(harness);

    const gate = barrier();
    let entered!: () => void;
    const inside = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const first = operations.execute({ handle: reserved.handle, kind: "app.create", opener: executorActor }, async (context) => {
      entered();
      await gate.opened;
      return fn(context);
    });
    await inside;
    // Their own organization first: it names them as its creator.
    await harness.client.execute({ sql: "DELETE FROM organization WHERE id = ?", args: [executor.organizationId] });
    await harness.client.execute({ sql: "DELETE FROM user WHERE id = ?", args: [executor.userId] });
    expect((await row(harness, reserved.id)).execution_claim).not.toBeNull();
    await expectCode(
      operations.execute({ handle: reserved.handle, kind: "app.create", opener: ownerActor }, fn),
      "conflict",
    );
    gate.open();
    // The reserving credential is the owner's, still live: the write lands,
    // attributed to nobody, since its executor is gone.
    expect(await first).toMatchObject({ replayed: false });
    expect(calls).toHaveLength(1);
    expect(await sideEffects()).toEqual(["app_1"]);
    expect((await row(harness, reserved.id)).decided_by_user_id).toBeNull();
  });

  it("rolls the whole batch back when the completion is refused", async () => {
    const { harness, operations, owner, ownerActor } = await setup();
    const db = harness.cfAuth.config.db;
    const sideEffects = async () =>
      (await harness.client.execute("SELECT id FROM side_effect ORDER BY id")).rows.map((value) => value.id);

    // execute: the first insert invalidates the second's guard.
    const reserved = await operations.reserve({ kind: "app.create", opener: ownerActor, input: { name: "A" } });
    const input = { handle: reserved.handle, kind: "app.create", opener: ownerActor };
    let target = "";
    await expectCode(
      operations.execute(input, ({ operation, guard }) => {
        target = operation.id;
        return { outcome: { key: "k" }, statements: selfDefeating(db, operation.id, guard) };
      }),
      "conflict",
    );
    expect(target).toBe(reserved.id);
    expect(await sideEffects()).toEqual([]);
    expect(await row(harness, reserved.id)).toMatchObject({ state: "pending", execution_claim: null, sealed_outcome: null });
    // The handle is still good.
    expect(await operations.execute(input, recorder(harness).fn)).toMatchObject({ replayed: false });

    // complete
    const opened = await operations.open({ kind: "report", token: createOperationToken(), opener: ownerActor });
    const guard = await operations.guard({ id: opened.id });
    await expectCode(
      operations.complete({ id: opened.id, outcome: {}, statements: selfDefeating(db, opened.id, guard) }),
      "conflict",
    );
    expect((await row(harness, opened.id)).state).toBe("pending");

    // approve
    approveStatements = (approveGuard) => selfDefeating(db, "approved", approveGuard);
    const page = await operations.open({ kind: "approve.writes", token: createOperationToken(), opener: ownerActor });
    await expectCode(operations.approve({ id: page.id, proof: page.browserProof!, actor: ownerActor }), "conflict");
    expect((await row(harness, page.id)).state).toBe("pending");

    // amend
    await operations.complete({ id: opened.id, outcome: { rows: 1 } });
    const completedGuard = await operations.guard({ id: opened.id, state: "completed" });
    expect(
      await operations.amend({
        id: opened.id,
        outcome: { key: "renewed" },
        seal: true,
        statements: selfDefeating(db, `${opened.id}:amend`, completedGuard),
      }),
    ).toBe(false);
    expect((await row(harness, opened.id)).sealed_outcome).toBeNull();

    expect(await sideEffects()).toEqual(["app_1"]);
    expect(owner.organizationId).toBeTruthy();
    expect(harness.errors).toEqual([]);
  });

  it("keeps the record through its replay window, whatever its retention, until retired", async () => {
    const { harness, operations, ownerActor } = await setup({ reserveTtlMs: 1_000 });
    const reserved = await operations.reserve({ kind: "brief", opener: ownerActor });
    const input = { handle: reserved.handle, kind: "brief", opener: ownerActor };
    const executed = await operations.execute(input, () => ({ outcome: { key: "k" }, record: { done: true } }));
    expect(executed.replayed).toBe(false);
    const stored = await row(harness, reserved.id);
    expect(Number(stored.retain_until)).toBeGreaterThanOrEqual(Number(stored.sealed_until));

    // Past its own retention, inside the seal window: the sweep keeps it.
    await operations.sweep(Date.now() + 5 * 60_000);
    expect(await operations.execute(input, () => ({ outcome: null }))).toMatchObject({ replayed: true, record: { done: true } });

    // Retired: the replay ends.
    expect(await operations.retire({ id: reserved.id })).toBe(true);
    await expectCode(operations.execute(input, () => ({ outcome: null })), "operation_expired");

    // Past the seal window the sweep deletes it.
    await operations.sweep(Date.now() + 16 * 60_000);
    await expectCode(operations.execute(input, () => ({ outcome: null })), "operation_not_found");

    // amend sealing afresh extends the retention too.
    const opened = await operations.open({ kind: "brief", token: createOperationToken(), opener: ownerActor });
    await operations.complete({ id: opened.id, outcome: { n: 1 } });
    await harness.client.execute({ sql: "UPDATE operation SET retain_until = ? WHERE id = ?", args: [Date.now() + 1_000, opened.id] });
    expect(await operations.amend({ id: opened.id, outcome: { key: "k" }, seal: true })).toBe(true);
    await operations.sweep(Date.now() + 5 * 60_000);
    expect(await row(harness, opened.id)).toBeDefined();
  });
});

describe("reveal", () => {
  const executed = async (kind = "app.create") => {
    const context = await setup();
    const { harness, operations, owner, ownerActor } = context;
    const { key, state: opener } = await keyFor(harness, owner.organizationId, ownerActor);
    const reserved = await operations.reserve({ kind, opener, input: kind === "app.create" ? { name: "A" } : undefined });
    const { fn } = recorder(harness);
    const input = { handle: reserved.handle, kind, opener };
    await operations.execute(input, fn);
    return { ...context, key, opener, reserved, input, fn };
  };

  it("releases the sealed outcome once, to an admin session in its organization, without ending the replay", async () => {
    const { harness, operations, owner, ownerActor, reserved, input, fn } = await executed();
    const admin = await harness.sessions.human();
    await harness.cfAuth.service.addOrganizationMember({
      actor: ownerActor,
      organizationId: owner.organizationId,
      userId: admin.userId,
      role: "admin",
    });

    const revealed = await operations.reveal({ id: reserved.id, actor: await harness.actorFor(admin.userId) });
    expect(revealed).toEqual({
      id: reserved.id,
      kind: "app.create",
      organizationId: owner.organizationId,
      outcome: { appId: "app_1", key: "secret-for-app_1" },
    });
    await expectCode(operations.reveal({ id: reserved.id, actor: ownerActor }), "already_revealed");
    expect((await row(harness, reserved.id)).sealed_outcome).toBeNull();
    // Revealing spends the secret, not the replay: the record is still answered.
    expect(await operations.execute(input, fn)).toEqual({
      id: reserved.id,
      state: "completed",
      record: { appId: "app_1" },
      replayed: true,
    });
    expect((await operations.status({ id: reserved.id, opener: ownerActor })).record).toEqual({ appId: "app_1" });

    // Once the window passes, the sweep clears the marker and it is simply gone.
    await operations.sweep(Date.now() + 16 * 60_000);
    await expectCode(operations.reveal({ id: reserved.id, actor: ownerActor }), "operation_expired");
    await expectCode(operations.execute(input, fn), "already_completed");
  });

  it("refuses a member, a key, another organization and nobody", async () => {
    const { harness, operations, owner, ownerActor, opener, reserved } = await executed();
    const member = await harness.sessions.human();
    await harness.cfAuth.service.addOrganizationMember({
      actor: ownerActor,
      organizationId: owner.organizationId,
      userId: member.userId,
      role: "member",
    });
    const stranger = await harness.sessions.human();

    await expectCode(
      operations.reveal({ id: reserved.id, actor: await harness.actorFor(member.userId) }),
      "forbidden",
    );
    await expectCode(operations.reveal({ id: reserved.id, actor: opener }), "session_required");
    await expectCode(operations.reveal({ id: reserved.id, actor: null }), "session_required");
    await expectCode(
      operations.reveal({ id: reserved.id, actor: await harness.actorFor(stranger.userId) }),
      "operation_not_found",
    );
    await expectCode(operations.reveal({ id: "no-such-id", actor: ownerActor }), "operation_not_found");
    // Nothing was spent by the refusals.
    expect(await operations.reveal({ id: reserved.id, actor: ownerActor })).toMatchObject({
      outcome: { key: "secret-for-app_1" },
    });
  });

  it("refuses once the seal window passed, while pending, or with nothing sealed", async () => {
    const { harness, operations, ownerActor, reserved } = await executed();
    await harness.client.execute({ sql: "UPDATE operation SET sealed_until = 1 WHERE id = ?", args: [reserved.id] });
    await expectCode(operations.reveal({ id: reserved.id, actor: ownerActor }), "operation_expired");

    const pending = await operations.reserve({ kind: "app.create", opener: ownerActor, input: { name: "P" } });
    await expectCode(operations.reveal({ id: pending.id, actor: ownerActor }), "operation_pending");

    // Never sealed: nothing to reveal.
    const plain = await operations.open({ kind: "report", token: createOperationToken(), opener: ownerActor });
    await operations.complete({ id: plain.id, outcome: { rows: 1 } });
    await expectCode(operations.reveal({ id: plain.id, actor: ownerActor }), "operation_expired");
  });

  it("is the person's authority, whatever became of the credential that opened it", async () => {
    const { harness, operations, owner, ownerActor, key, reserved } = await executed();
    // Downgraded to read: still revealed.
    await harness.client.execute({ sql: `UPDATE api_key SET "grant" = 'read' WHERE id = ?`, args: [key.id] });
    expect(await operations.reveal({ id: reserved.id, actor: ownerActor })).toMatchObject({
      outcome: { key: "secret-for-app_1" },
    });

    // Revoked: still revealed.
    const { state: opener } = await keyFor(harness, owner.organizationId, ownerActor);
    const second = await operations.reserve({ kind: "app.create", opener, input: { name: "S" } });
    await operations.execute({ handle: second.handle, kind: "app.create", opener }, recorder(harness, "app_2").fn);
    await harness.cfAuth.service.revokeApiKey({
      organizationId: owner.organizationId,
      actor: ownerActor,
      apiKeyId: opener.actor!.credentialId!,
    });
    expect(await operations.reveal({ id: second.id, actor: ownerActor })).toMatchObject({
      outcome: { key: "secret-for-app_2" },
    });
  });

  it("judges the person and the deadline in the write that takes the outcome", async () => {
    const { harness, operations, owner, ownerActor, reserved } = await executed("key.issue");
    const admin = await harness.sessions.human();
    await harness.cfAuth.service.addOrganizationMember({
      actor: ownerActor,
      organizationId: owner.organizationId,
      userId: admin.userId,
      role: "admin",
    });
    const adminActor = await harness.actorFor(admin.userId);

    // The admin's session ends after their state was read: the membership
    // read before the write still passes, and the write refuses.
    await harness.client.execute({
      sql: "DELETE FROM user_session WHERE id = ?",
      args: [adminActor.actor!.credentialId!],
    });
    await expectCode(operations.reveal({ id: reserved.id, actor: adminActor }), "conflict");
    expect((await row(harness, reserved.id)).sealed_outcome).not.toBeNull();

    // The seal's deadline by the database's clock, though this process's
    // clock still says it is open.
    const realNow = Date.now();
    await harness.client.execute({
      sql: "UPDATE operation SET sealed_until = ? WHERE id = ?",
      args: [realNow - 1_000, reserved.id],
    });
    vi.spyOn(Date, "now").mockReturnValue(realNow - 60_000);
    await expectCode(operations.reveal({ id: reserved.id, actor: ownerActor }), "operation_expired");
    vi.restoreAllMocks();
    expect((await row(harness, reserved.id)).sealed_outcome).not.toBeNull();
  });

  describe("with something changing between reading the outcome and taking it", () => {
    const raced = async (
      at: "decrypt" | "update",
      change: (context: Awaited<ReturnType<typeof executed>> & { adminActor: AuthState }) => Promise<void>,
    ) => {
      const context = await executed("key.issue");
      const { harness, operations, owner, ownerActor, reserved } = context;
      const admin = await harness.sessions.human();
      await harness.cfAuth.service.addOrganizationMember({
        actor: ownerActor,
        organizationId: owner.organizationId,
        userId: admin.userId,
        role: "admin",
      });
      const adminActor = await harness.actorFor(admin.userId);
      const sealedUntil = (await row(harness, reserved.id)).sealed_until;
      const hold = holdReveal(harness.cfAuth.config.db, at);
      const revealing = operations.reveal({ id: reserved.id, actor: adminActor });
      await hold.entered;
      await change({ ...context, adminActor });
      hold.open();
      return { ...context, adminActor, revealing, sealedUntil };
    };

    for (const at of ["decrypt", "update"] as const) {
      describe(`paused before the ${at}`, () => {
      it("refuses an outcome that stopped being deliverable, dropping it but not the replay", async () => {
        const { harness, operations, ownerActor, reserved, input, fn, revealing, sealedUntil } = await raced(at,
          async ({ harness, reserved }) => {
            await harness.client.execute({ sql: "INSERT INTO side_effect (id) VALUES (?)", args: [`revoked:${reserved.id}`] });
          },
        );
        await expectCode(revealing, "operation_expired");
        const stored = await row(harness, reserved.id);
        expect(stored.sealed_outcome).toBeNull();
        expect(stored.sealed_until).toBe(sealedUntil);
        await expectCode(operations.reveal({ id: reserved.id, actor: ownerActor }), "already_revealed");
        expect(await operations.execute(input, fn)).toMatchObject({ replayed: true, record: { appId: "app_1" } });
      });

      it("refuses an admin demoted meanwhile", async () => {
        const { harness, operations, owner, ownerActor, reserved, revealing } = await raced(at, async ({ harness, owner, adminActor }) => {
          await harness.client.execute({
            sql: "UPDATE organization_user SET role = 'member' WHERE user_id = ? AND organization_id = ?",
            args: [adminActor.user!.id, owner.organizationId],
          });
        });
        await expectCode(revealing, "conflict");
        expect((await row(harness, reserved.id)).sealed_outcome).not.toBeNull();
        expect(owner.organizationId).toBeTruthy();
        expect(await operations.reveal({ id: reserved.id, actor: ownerActor })).toMatchObject({ outcome: { key: "secret-for-app_1" } });
      });

      it("refuses once the organization's deadline passed meanwhile", async () => {
        const { harness, reserved, revealing } = await raced(at, async ({ harness, owner }) => {
          await harness.client.execute({
            sql: "UPDATE organization SET expires_at = ? WHERE id = ?",
            args: [new Date(Date.now() - 1_000).toISOString(), owner.organizationId],
          });
        });
        await expectCode(revealing, "organization_expired");
        expect((await row(harness, reserved.id)).sealed_outcome).not.toBeNull();
      });

      it("leaves alone an outcome amend sealed meanwhile", async () => {
        const { harness, operations, ownerActor, reserved, revealing } = await raced(at, async ({ operations, reserved }) => {
          expect(await operations.amend({ id: reserved.id, outcome: { key: "renewed" }, seal: true })).toBe(true);
        });
        await expectCode(revealing, "conflict");
        expect((await row(harness, reserved.id)).sealed_outcome).not.toBeNull();
        expect(await operations.reveal({ id: reserved.id, actor: ownerActor })).toMatchObject({ outcome: { key: "renewed" } });
      });
      });
    }
  });

  it("never drops a newer outcome when cleaning up an undeliverable one", async () => {
    const { harness, operations, ownerActor, reserved } = await executed("key.issue");
    const db = harness.cfAuth.config.db;
    await harness.client.execute({ sql: "INSERT INTO side_effect (id) VALUES (?)", args: [`revoked:${reserved.id}`] });
    // `amend` seals a new, deliverable outcome right after the refused
    // reveal found the old one undeliverable, before its cleanup runs.
    const all = db.all.bind(db);
    let amended = false;
    vi.spyOn(db, "all").mockImplementation((async (query: Parameters<typeof db.all>[0]) => {
      const rows = (await all(query)) as unknown[];
      if (!amended && rows.length === 0) {
        amended = true;
        await operations.amend({ id: reserved.id, outcome: { key: "renewed" }, record: { keyId: "k2" }, seal: true });
      }
      return rows;
    }) as typeof db.all);
    await expectCode(operations.reveal({ id: reserved.id, actor: ownerActor }), "operation_expired");
    expect(amended).toBe(true);
    vi.restoreAllMocks();
    expect((await row(harness, reserved.id)).sealed_outcome).not.toBeNull();
    expect(await operations.reveal({ id: reserved.id, actor: ownerActor })).toMatchObject({ outcome: { key: "renewed" } });
  });

  it("refuses a kind with a browser step, whose outcome has its own delivery", async () => {
    const { harness, operations, owner, ownerActor } = await setup();
    const token = createOperationToken();
    const login = await operations.open({ kind: "login", token, client: { label: "CLI" } });
    await operations.approve({
      id: login.id,
      proof: login.browserProof!,
      actor: ownerActor,
      organizationId: owner.organizationId,
    });
    await expectCode(operations.reveal({ id: login.id, actor: ownerActor }), "validation_error");
    // The CLI still collects it.
    expect((await operations.poll({ id: login.id, token })).outcome).toMatchObject({ credential: expect.any(Object) });
    expect(harness.errors).toEqual([]);
  });
});

describe("delivery", () => {
  it("keeps a `reveal` kind's outcome from every collection route but reveal", async () => {
    const { harness, operations, ownerActor } = await setup();
    const reserved = await operations.reserve({ kind: "key.issue", opener: ownerActor });
    const input = { handle: reserved.handle, kind: "key.issue", opener: ownerActor };
    expect(await operations.execute(input, recorder(harness).fn)).toMatchObject({ replayed: false });

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const polled = await operations.poll({ id: reserved.id, token: reserved.handle });
      expect(polled).toMatchObject({ state: "completed", record: { appId: "app_1" }, collect: null });
      expect(polled).not.toHaveProperty("outcome");
      const found = await operations.findByToken({ token: reserved.handle });
      expect(found).toMatchObject({ collect: null });
      expect(found).not.toHaveProperty("outcome");
    }
    await expectCode(
      operations.redeem({ id: reserved.id, token: reserved.handle, redeemCode: createOperationToken() }),
      "already_completed",
    );
    expect((await row(harness, reserved.id)).sealed_outcome).not.toBeNull();
    expect(await operations.reveal({ id: reserved.id, actor: ownerActor })).toMatchObject({
      outcome: { key: "secret-for-app_1" },
    });

    // Completed rather than executed, the same.
    const opened = await operations.open({ kind: "key.issue", token: createOperationToken(), opener: ownerActor });
    const completed = await operations.complete({ id: opened.id, outcome: { key: "k" }, seal: true });
    expect(completed.collect).toBeNull();
  });

  it("is refused for a kind with a browser step", async () => {
    await expect(
      createTestAuth({
        operations: { enabled: true, kinds: [{ ...change, name: "change.reveal", deliver: "reveal" }] },
      }),
    ).rejects.toMatchObject({ code: "validation_error" });
  });

  it("collecting a `once` outcome by poll spends the outcome, not the replay", async () => {
    const { harness, operations, ownerActor } = await setup();
    const reserved = await operations.reserve({ kind: "app.create", opener: ownerActor, input: { name: "A" } });
    const { fn } = recorder(harness);
    const input = { handle: reserved.handle, kind: "app.create", opener: ownerActor };
    await operations.execute(input, fn);
    const sealedUntil = (await row(harness, reserved.id)).sealed_until;

    expect((await operations.poll({ id: reserved.id, token: reserved.handle })).outcome).toEqual({
      appId: "app_1",
      key: "secret-for-app_1",
    });
    const stored = await row(harness, reserved.id);
    expect(stored.sealed_outcome).toBeNull();
    expect(stored.sealed_until).toBe(sealedUntil);
    expect(await operations.execute(input, fn)).toMatchObject({ replayed: true, record: { appId: "app_1" } });
    await expectCode(operations.reveal({ id: reserved.id, actor: ownerActor }), "already_revealed");
  });
});

describe("a refused completion whose statements deleted the operation", () => {
  /** A guarded side effect, then a guarded delete of the operation — directly, or through its organization. */
  const deleting = (
    harness: TestAuth,
    id: string,
    organizationId: string,
    guard: ReturnType<typeof sql>,
    how: "directly" | "cascade",
  ) => {
    const db = harness.cfAuth.config.db;
    const { operation, organization } = harness.cfAuth.config.tables;
    return [
      guardedInsert(db, sideEffect, { id: `${id}:${how}` }, guard),
      how === "directly"
        ? db.delete(operation).where(and(eq(operation.id, id), guard))
        : db.delete(organization).where(and(eq(organization.id, organizationId), guard)),
    ];
  };

  for (const how of ["directly", "cascade"] as const) {
    it(`commits nothing when it deleted it ${how === "directly" ? "directly" : "through its organization"}`, async () => {
      const { harness, operations, owner, ownerActor } = await setup();
      const orgId = owner.organizationId;
      const sideEffects = async () =>
        (await harness.client.execute("SELECT id FROM side_effect")).rows.map((value) => value.id);
      const organizationLeft = async () =>
        (await harness.client.execute({ sql: "SELECT id FROM organization WHERE id = ?", args: [orgId] })).rows.length;

      const reserved = await operations.reserve({ kind: "app.create", opener: ownerActor, input: { name: "A" } });
      await expect(
        operations.execute({ handle: reserved.handle, kind: "app.create", opener: ownerActor }, ({ operation, guard }) => ({
          outcome: null,
          statements: deleting(harness, operation.id, orgId, guard, how),
        })),
      ).rejects.toMatchObject({ code: expect.stringMatching(/^(conflict|operation_not_found)$/) });
      expect(await row(harness, reserved.id)).toMatchObject({ state: "pending", execution_claim: null });

      const opened = await operations.open({ kind: "report", token: createOperationToken(), opener: ownerActor });
      await expect(
        operations.complete({
          id: opened.id,
          outcome: {},
          statements: deleting(harness, opened.id, orgId, await operations.guard({ id: opened.id }), how),
        }),
      ).rejects.toBeInstanceOf(Error);
      expect((await row(harness, opened.id)).state).toBe("pending");

      const page = await operations.open({ kind: "approve.writes", token: createOperationToken(), opener: ownerActor });
      approveStatements = (guard) => deleting(harness, page.id, orgId, guard, how);
      await expect(operations.approve({ id: page.id, proof: page.browserProof!, actor: ownerActor })).rejects.toBeInstanceOf(
        Error,
      );
      expect((await row(harness, page.id)).state).toBe("pending");

      await operations.complete({ id: opened.id, outcome: { n: 1 } });
      expect(
        await operations.amend({
          id: opened.id,
          record: { n: 2 },
          statements: deleting(harness, opened.id, orgId, await operations.guard({ id: opened.id, state: "completed" }), how),
        }),
      ).toBe(false);
      expect((await row(harness, opened.id)).outcome).toBe(JSON.stringify({ n: 1 }));

      expect(await sideEffects()).toEqual([]);
      expect(await organizationLeft()).toBe(1);
    });
  }
});

describe("internal kinds", () => {
  it("are refused by every public entry point and driven only through the internal door", async () => {
    const { harness, operations, internal, owner, ownerActor } = await setup();
    const { fn } = recorder(harness, "internal_1");

    // Reserved, executed and sealed through the internal door.
    const reserved = await internal.reserve({ kind: "cf-auth:internal.task", opener: ownerActor });
    expect(await internal.execute({ handle: reserved.handle, kind: "cf-auth:internal.task", opener: ownerActor }, fn)).toMatchObject({
      replayed: false,
    });
    expect(await internal.status({ id: reserved.id, opener: ownerActor })).toMatchObject({ state: "completed" });

    // A browser kind, opened through the internal door.
    const pageToken = createOperationToken();
    const page = await internal.open({ kind: "cf-auth:internal.page", token: pageToken });
    expect(page.userCode).toEqual(expect.any(String));

    expect([...operations.kinds.keys()].sort()).toEqual([
      "app.create",
      "approve.writes",
      "bootstrap",
      "brief",
      "change",
      "key.issue",
      "login",
      "report",
    ]);
    expect(internal.kinds.has("cf-auth:internal.task")).toBe(true);

    await expectCode(operations.open({ kind: "cf-auth:internal.page", token: createOperationToken() }), "validation_error");
    await expectCode(operations.reserve({ kind: "cf-auth:internal.task", opener: ownerActor }), "validation_error");
    await expectCode(operations.poll({ id: page.id, token: pageToken }), "operation_not_found");
    await expectCode(operations.poll({ id: reserved.id, token: reserved.handle }), "operation_not_found");
    expect(await operations.findByToken({ token: pageToken })).toBeNull();
    expect(await operations.findByToken({ token: reserved.handle })).toBeNull();
    expect(await operations.lookupByUserCode({ userCode: page.userCode! })).toBeNull();
    await expectCode(operations.details({ id: page.id, proof: page.browserProof! }), "operation_not_found");
    await expectCode(operations.details({ id: page.id, userCode: page.userCode! }), "operation_not_found");
    await expectCode(operations.approve({ id: page.id, proof: page.browserProof! }), "operation_not_found");
    await expectCode(operations.deny({ id: page.id, proof: page.browserProof! }), "operation_not_found");
    await expectCode(
      operations.redeem({ id: page.id, token: pageToken, redeemCode: createOperationToken() }),
      "operation_not_found",
    );
    await expectCode(operations.complete({ id: reserved.id, outcome: {} }), "operation_not_found");
    await expectCode(operations.amend({ id: reserved.id, record: {} }), "operation_not_found");
    await expectCode(operations.guard({ id: reserved.id }), "operation_not_found");
    expect(await operations.retire({ id: page.id })).toBe(false);
    await expectCode(operations.status({ id: reserved.id, opener: ownerActor }), "operation_not_found");
    await expectCode(
      operations.execute({ handle: reserved.handle, kind: "cf-auth:internal.task", opener: ownerActor }, fn),
      "operation_not_found",
    );
    await expectCode(operations.reveal({ id: reserved.id, actor: ownerActor }), "operation_not_found");

    // The internal door still does everything.
    expect(await internal.lookupByUserCode({ userCode: page.userCode! })).toMatchObject({ id: page.id });
    await internal.approve({ id: page.id, proof: page.browserProof! });
    expect((await internal.poll({ id: page.id, token: pageToken })).record).toEqual({ approved: true });
    expect(await internal.reveal({ id: reserved.id, actor: ownerActor })).toMatchObject({
      organizationId: owner.organizationId,
      outcome: { appId: "internal_1" },
    });
    const opened = await internal.open({ kind: "cf-auth:internal.task", token: createOperationToken(), opener: ownerActor });
    expect(await internal.complete({ id: opened.id, outcome: { done: true } })).toMatchObject({ state: "completed" });

    // The sweep covers them like any other.
    const stale = await internal.reserve({ kind: "cf-auth:internal.task", opener: ownerActor });
    await operations.sweep(Date.now() + 16 * 60_000);
    expect((await row(harness, stale.id)).state).toBe("expired");
    expect(await internal.retire({ id: page.id })).toBe(true);
  });

  it("stay hidden from an engine that does not register them", async () => {
    const { harness, internal, ownerActor } = await setup();
    const reserved = await internal.reserve({ kind: "cf-auth:internal.task", opener: ownerActor });
    await internal.execute(
      { handle: reserved.handle, kind: "cf-auth:internal.task", opener: ownerActor },
      recorder(harness, "internal_2").fn,
    );
    const pageToken = createOperationToken();
    const page = await internal.open({ kind: "cf-auth:internal.page", token: pageToken });

    // `cfAuth.operations` was built without either kind: the namespace alone hides them.
    const plain = harness.cfAuth.operations;
    expect(plain.kinds.has("cf-auth:internal.task")).toBe(false);
    await expectCode(plain.status({ id: reserved.id, opener: ownerActor }), "operation_not_found");
    await expectCode(plain.poll({ id: reserved.id, token: reserved.handle }), "operation_not_found");
    await expectCode(plain.poll({ id: page.id, token: pageToken }), "operation_not_found");
    expect(await plain.findByToken({ token: reserved.handle })).toBeNull();
    expect(await plain.findByToken({ token: pageToken })).toBeNull();
    expect(await plain.lookupByUserCode({ userCode: page.userCode! })).toBeNull();
    await expectCode(plain.reveal({ id: reserved.id, actor: ownerActor }), "operation_not_found");
    await expectCode(plain.open({ kind: "cf-auth:internal.task", token: createOperationToken(), opener: ownerActor }), "validation_error");
    expect(await plain.retire({ id: reserved.id })).toBe(false);
    expect((await row(harness, reserved.id)).sealed_outcome).not.toBeNull();
  });

  it("are named in cf-auth's namespace, and only they are", () => {
    const named = (name: string, internalFlag?: true) =>
      ({ name, open: { minRole: "member" }, browser: false, ...(internalFlag ? { internal: internalFlag } : {}) }) as OperationKind;
    expect(() => validateOperationKind(named("cf-auth:x.y", true), "k", { builtIn: true })).not.toThrow();
    expect(() => validateOperationKind(named("x.y", true), "k", { builtIn: true })).toThrow(/cf-auth:/);
    expect(() => validateOperationKind(named("cf-auth:x.y"), "k", { builtIn: true })).toThrow(/cf-auth:/);
    expect(() => validateOperationKind(named("cf-auth:x.y"), "k")).toThrow(/lowercase/);
    expect(() => validateOperationKind(named("cf-auth:"), "k", { builtIn: true })).toThrow(/lowercase/);
  });

  it("may not be declared by an app", async () => {
    await expect(
      createTestAuth({
        operations: { enabled: true, kinds: [{ ...createApp, internal: true }] },
      }),
    ).rejects.toMatchObject({ code: "validation_error" });
    await expect(
      createTestAuth({
        operations: { enabled: true, kinds: [{ ...createApp, internal: false as unknown as true }] },
      }),
    ).rejects.toMatchObject({ code: "validation_error" });
    await expect(
      createTestAuth({
        operations: { enabled: true, kinds: [{ ...createApp, name: "cf-auth:app.create" }] },
      }),
    ).rejects.toMatchObject({ code: "validation_error" });
  });
});
