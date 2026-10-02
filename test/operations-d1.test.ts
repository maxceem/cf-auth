/**
 * The operations engine on a real D1 database (Miniflare, on workerd).
 *
 * Everything else in this suite runs on libsql, whose batch accepts anything
 * drizzle can execute. D1's batch binds parameters through each item's
 * prepared statement, so an item without one — `db.run(sql)` with parameters —
 * works on libsql and crashes on D1. These tests take the paths that batch.
 */
import { and, eq, sql } from "drizzle-orm";
import { sqliteTable, text } from "drizzle-orm/sqlite-core";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { createOperationToken } from "../src/crypto.js";
import { guardedInsert } from "../src/guarded-insert.js";
import { defineOperationKind, type ExecuteOperationFunction } from "../src/operations.js";
import { createD1TestAuth, holdReveal, type D1TestAuth } from "./helpers.js";

const bootstrap = defineOperationKind({
  name: "bootstrap",
  open: "public",
  browser: false,
  deliver: "window",
});

const grant = defineOperationKind({
  name: "grant",
  open: { minRole: "member" },
  browser: true,
  approverMinRole: "admin",
  payload: (value: unknown) => ({ note: String((value as { note?: unknown }).note ?? "") }),
  approve: ({ payload }) => ({ outcome: { granted: payload.note } }),
});

const secretEntry = defineOperationKind({
  name: "secret.enter",
  open: { minRole: "member" },
  browser: true,
  approver: "proof",
  input: (value: unknown) => ({ secret: String((value as { secret?: unknown }).secret) }),
  approve: ({ input }) => ({ outcome: { length: input!.secret.length } }),
});

const windowedGrant = defineOperationKind({
  name: "grant.window",
  open: { minRole: "member" },
  browser: true,
  approverMinRole: "admin",
  deliver: "window",
  approve: () => ({ outcome: { secret: "s" }, seal: true }),
});

const claim = defineOperationKind({
  name: "claim",
  open: { minRole: "owner" },
  browser: true,
  approverMinRole: null,
  approve: ({ actor, organizationId, operation, guard }) => ({
    outcome: { claimed: organizationId },
    ...harness.cfAuth.service.claimOrganizationStatements({
      actor: actor!,
      organizationId: organizationId!,
      provisioning: {
        userId: operation.openerUserId!,
        credentialId: operation.openerCredentialId!,
        revokeAccess: false,
      },
      condition: guard,
    }),
  }),
});

const reservedWrite = defineOperationKind({
  name: "app.create",
  open: { minRole: "member" },
  browser: false,
  payload: (value: unknown) => ({ name: String((value as { name?: unknown }).name) }),
});

/** Revealed only, and deliverable while no `revoked:<keyId>` marker row exists for it. */
const keyIssue = defineOperationKind({
  name: "key.issue",
  open: { minRole: "member" },
  browser: false,
  deliver: "reveal",
  deliverable: ({ operation, record }) =>
    sql`not exists (select 1 from side_effect where id = ${`revoked:${(record as { keyId?: string } | null)?.keyId ?? operation.id}`})`,
});

const sideEffect = sqliteTable("side_effect", { id: text("id").primaryKey() });

/** Approved in a browser, writing whatever statements the test hands it. */
let approveStatements: (guard: ReturnType<typeof sql>) => unknown[] = () => [];
const approveWrites = defineOperationKind({
  name: "approve.writes",
  open: { minRole: "member" },
  browser: true,
  approverMinRole: null,
  approve: ({ guard }) => ({ outcome: { ok: true }, statements: approveStatements(guard) }),
});

/** A promise the test opens when it chooses, and one that says the function was entered. */
const barrier = () => {
  let open!: () => void;
  let enter!: () => void;
  const opened = new Promise<void>((resolve) => {
    open = resolve;
  });
  const entered = new Promise<void>((resolve) => {
    enter = resolve;
  });
  return { open, opened, enter, entered };
};

afterEach(() => {
  vi.restoreAllMocks();
  approveStatements = () => [];
});

let harness: D1TestAuth;

beforeAll(async () => {
  harness = await createD1TestAuth({
    operations: { enabled: true, realm: "d1-test", kinds: [bootstrap, grant, secretEntry, windowedGrant, claim, reservedWrite, keyIssue, approveWrites] },
  });
  await harness.execute("CREATE TABLE side_effect (id TEXT PRIMARY KEY)");
}, 60_000);

afterAll(async () => {
  await harness?.dispose();
});

describe("operations on D1", () => {
  it("approves a login, writing its key in the completion batch, and redeems it", async () => {
    const { operations, service } = harness.cfAuth;
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);
    const token = createOperationToken();
    const view = await operations.open({
      kind: "login",
      token,
      client: { label: "CLI on d1", loopbackRedirect: "http://127.0.0.1:40123/callback" },
    });

    const details = await operations.details({ id: view.id, proof: view.browserProof!, viewer: actor });
    expect(details.userCode).toBe(view.userCode);

    const approval = await operations.approve({
      id: view.id,
      proof: view.browserProof!,
      actor,
      organizationId: human.organizationId,
    });
    expect(await operations.poll({ id: view.id, token })).toMatchObject({ state: "completed", collect: "redeem" });

    const { outcome } = await operations.redeem({ id: view.id, token, redeemCode: approval.redeemCode! });
    const key = (outcome as { credential: { token: string } }).credential.token;
    const state = await service.resolveApiKeyAuthState(key, "cli");
    expect(state).toMatchObject({ authenticated: true, source: "cli" });
    expect(state.organization?.id).toBe(human.organizationId);
    await expect(
      operations.redeem({ id: view.id, token, redeemCode: approval.redeemCode! }),
    ).rejects.toMatchObject({ code: "already_completed" });
  });

  it("shows the organization an operation acts in, and approves it with an admin session", async () => {
    const { operations } = harness.cfAuth;
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);
    const token = createOperationToken();
    const opened = await operations.open({ kind: "grant", token, payload: { note: "n" }, opener: actor });

    const details = await operations.details({ id: opened.id, proof: opened.browserProof! });
    expect(details.organization).toMatchObject({ id: human.organizationId, claimed: true });

    await operations.approve({ id: opened.id, proof: opened.browserProof!, actor });
    expect((await operations.poll({ id: opened.id, token })).record).toEqual({ granted: "n" });
  });

  it("approves a proof kind with page input", async () => {
    const { operations } = harness.cfAuth;
    const human = await harness.sessions.human();
    const opener = await harness.actorFor(human.userId);
    const token = createOperationToken();
    const opened = await operations.open({ kind: "secret.enter", token, opener });
    await operations.approve({ id: opened.id, proof: opened.browserProof!, input: { secret: "abc" } });
    expect((await operations.poll({ id: opened.id, token })).record).toEqual({ length: 3 });
  });

  it("completes with guarded statements, amends, retires and sweeps", async () => {
    const { operations } = harness.cfAuth;
    const db = harness.cfAuth.config.db;
    const token = createOperationToken();
    const opened = await operations.open({ kind: "bootstrap", token });

    await operations.complete({
      id: opened.id,
      outcome: { key: "k1" },
      seal: true,
      statements: [guardedInsert(db, sideEffect, { id: opened.id }, await operations.guard({ id: opened.id }))],
    });
    expect(await harness.execute("SELECT id FROM side_effect WHERE id = ?", opened.id)).toHaveLength(1);
    expect((await operations.poll({ id: opened.id, token })).outcome).toEqual({ key: "k1" });

    const renewed = await operations.amend({
      id: opened.id,
      outcome: { key: "k2" },
      seal: true,
      statements: [
        guardedInsert(
          db,
          sideEffect,
          { id: `${opened.id}:2` },
          await operations.guard({ id: opened.id, state: "completed" }),
        ),
      ],
    });
    expect(renewed).toBe(true);
    expect((await operations.poll({ id: opened.id, token })).outcome).toEqual({ key: "k2" });

    expect(await operations.retire({ id: opened.id })).toBe(true);
    await harness.execute("UPDATE operation SET retain_until = 0 WHERE id = ?", opened.id);
    await operations.sweep();
    expect(await harness.execute("SELECT id FROM operation WHERE id = ?", opened.id)).toEqual([]);
  });

  it("withholds a windowed outcome once its opener's key is revoked", async () => {
    const { operations, service } = harness.cfAuth;
    const owner = await harness.sessions.human();
    const ownerActor = await harness.actorFor(owner.userId);
    const key = await service.createApiKey({ organizationId: owner.organizationId, actor: ownerActor, name: "CLI" });
    const opener = await service.resolveApiKeyAuthState(key.plaintext, "cli");
    const token = createOperationToken();
    const opened = await operations.open({ kind: "grant.window", token, opener });
    await operations.approve({ id: opened.id, proof: opened.browserProof!, actor: ownerActor });
    expect((await operations.poll({ id: opened.id, token })).outcome).toEqual({ secret: "s" });

    await service.revokeApiKey({ organizationId: owner.organizationId, actor: ownerActor, apiKeyId: key.id });
    const polled = await operations.poll({ id: opened.id, token });
    expect(polled).toMatchObject({ state: "completed", collect: null });
    expect(polled).not.toHaveProperty("outcome");
  });

  it("withdraws a login key revoked before it was collected", async () => {
    const { operations, service } = harness.cfAuth;
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);

    for (const loopbackRedirect of [undefined, "http://127.0.0.1:40124/callback"]) {
      const token = createOperationToken();
      const view = await operations.open({
        kind: "login",
        token,
        client: { label: "CLI on d1", ...(loopbackRedirect ? { loopbackRedirect } : {}) },
      });
      const approval = await operations.approve({
        id: view.id,
        proof: view.browserProof!,
        actor,
        organizationId: human.organizationId,
      });
      const { apiKeyId } = (await operations.findByToken({ token }))!.record as { apiKeyId: string };
      await service.revokeApiKey({ organizationId: human.organizationId, actor, apiKeyId });
      const collecting = loopbackRedirect
        ? operations.redeem({ id: view.id, token, redeemCode: approval.redeemCode! })
        : operations.poll({ id: view.id, token });
      await expect(collecting).rejects.toMatchObject({ code: "operation_expired" });
    }
  });

  it("claims an organization in the batch that completes the operation", async () => {
    const { operations, service } = harness.cfAuth;
    const identity = await service.createServiceIdentity({ name: "CLI service" });
    const { organization } = await service.createOrganization(identity.id, "Unclaimed");
    await harness.execute(
      "UPDATE organization SET expires_at = ? WHERE id = ?",
      new Date(Date.now() + 86_400_000).toISOString(),
      organization.id,
    );
    const key = await service.issueServiceApiKey({ userId: identity.id, organizationId: organization.id, name: "b" });
    const opener = await service.resolveApiKeyAuthState(key.plaintext, "cli");
    const token = createOperationToken();
    const opened = await operations.open({ kind: "claim", token, opener });
    const claimer = await harness.sessions.human();

    await operations.approve({ id: opened.id, proof: opened.browserProof!, actor: await harness.actorFor(claimer.userId) });
    expect((await service.getIdentity(claimer.userId))?.kind).toBe("human");
    expect((await harness.cfAuth.repository.findMembership(claimer.userId, organization.id))?.role).toBe("owner");
    expect((await harness.cfAuth.repository.findOrganization(organization.id))?.expiresAt).toBeNull();
  });

  it("reserves, executes once in a guarded batch, replays, reveals once and shows its status", async () => {
    const { operations, service } = harness.cfAuth;
    const db = harness.cfAuth.config.db;
    const owner = await harness.sessions.human();
    const ownerActor = await harness.actorFor(owner.userId);
    const key = await service.createApiKey({ organizationId: owner.organizationId, actor: ownerActor, name: "MCP" });
    const opener = await service.resolveApiKeyAuthState(key.plaintext, "mcp");

    const reserved = await operations.reserve({ kind: "app.create", opener, input: { name: "d1" } });
    const targets: string[] = [];
    const input = { handle: reserved.handle, kind: "app.create", opener };
    const fn: ExecuteOperationFunction = ({ operation, input: payload, guard }) => {
      const id = `${operation.id}:${(payload as { name: string }).name}`;
      targets.push(id);
      return {
        outcome: { appId: id, key: "d1-secret" },
        record: { appId: id },
        statements: [guardedInsert(db, sideEffect, { id }, guard)],
      };
    };

    // The first call holds inside its function while the second arrives.
    const gate = barrier();
    const first = operations.execute(input, async (context) => {
      gate.enter();
      await gate.opened;
      return fn(context);
    });
    await gate.entered;
    await expect(operations.execute(input, fn)).rejects.toMatchObject({ code: "conflict" });
    expect(targets).toEqual([]);
    gate.open();
    expect(await first).toMatchObject({ replayed: false, outcome: { key: "d1-secret" } });
    expect(targets).toEqual([`${reserved.id}:d1`]);
    expect(await harness.execute("SELECT id FROM side_effect WHERE id = ?", targets[0])).toHaveLength(1);

    const replay = await operations.execute(input, fn);
    expect(replay).toEqual({ id: reserved.id, state: "completed", record: { appId: `${reserved.id}:d1` }, replayed: true });
    expect(targets).toHaveLength(1);
    const status = await operations.status({ id: reserved.id, opener: ownerActor });
    expect(status).toMatchObject({ state: "completed", record: { appId: `${reserved.id}:d1` } });
    expect(status).not.toHaveProperty("outcome");

    expect(await operations.reveal({ id: reserved.id, actor: ownerActor })).toMatchObject({
      outcome: { key: "d1-secret" },
    });
    await expect(operations.reveal({ id: reserved.id, actor: ownerActor })).rejects.toMatchObject({
      code: "already_revealed",
    });
    // The reveal did not end the replay.
    expect(await operations.execute(input, fn)).toMatchObject({ replayed: true });

    // A downgraded key's reservation writes nothing, at the target the function chose.
    const second = await operations.reserve({ kind: "app.create", opener, input: { name: "late" } });
    await harness.execute(`UPDATE api_key SET "grant" = 'read' WHERE id = ?`, key.id);
    await expect(
      operations.execute({ handle: second.handle, kind: "app.create", opener }, fn),
    ).rejects.toMatchObject({ code: "conflict" });
    expect(targets.at(-1)).toBe(`${second.id}:late`);
    expect(await harness.execute("SELECT id FROM side_effect WHERE id = ?", `${second.id}:late`)).toEqual([]);
  });

  it("rolls a refused completion's whole batch back", async () => {
    const { operations } = harness.cfAuth;
    const db = harness.cfAuth.config.db;
    const owner = await harness.sessions.human();
    const actor = await harness.actorFor(owner.userId);
    // The first insert invalidates the second's guard, so the last statement
    // changes nothing and the completion is refused.
    const selfDefeating = (id: string, guard: ReturnType<typeof sql>) => [
      guardedInsert(db, sideEffect, { id: `${id}:first` }, guard),
      guardedInsert(
        db,
        sideEffect,
        { id: `${id}:second` },
        sql`${guard} and not exists (select 1 from side_effect where id = ${`${id}:first`})`,
      ),
    ];

    const reserved = await operations.reserve({ kind: "app.create", opener: actor, input: { name: "r" } });
    let target = "";
    await expect(
      operations.execute({ handle: reserved.handle, kind: "app.create", opener: actor }, ({ operation, guard }) => {
        target = operation.id;
        return { outcome: { key: "k" }, statements: selfDefeating(operation.id, guard) };
      }),
    ).rejects.toMatchObject({ code: "conflict" });
    expect(target).toBe(reserved.id);
    expect(await harness.execute("SELECT id FROM side_effect WHERE id LIKE ?", `${reserved.id}:%`)).toEqual([]);
    expect(await harness.execute("SELECT state, execution_claim FROM operation WHERE id = ?", reserved.id)).toEqual([
      { state: "pending", execution_claim: null },
    ]);

    const opened = await operations.open({ kind: "bootstrap", token: createOperationToken() });
    await expect(
      operations.complete({
        id: opened.id,
        outcome: {},
        statements: selfDefeating(opened.id, await operations.guard({ id: opened.id })),
      }),
    ).rejects.toMatchObject({ code: "conflict" });
    expect(await harness.execute("SELECT id FROM side_effect WHERE id LIKE ?", `${opened.id}:%`)).toEqual([]);

    await operations.complete({ id: opened.id, outcome: { n: 1 } });
    expect(
      await operations.amend({
        id: opened.id,
        record: { n: 2 },
        statements: selfDefeating(`${opened.id}:amend`, await operations.guard({ id: opened.id, state: "completed" })),
      }),
    ).toBe(false);
    expect(await harness.execute("SELECT id FROM side_effect WHERE id LIKE ?", `${opened.id}:%`)).toEqual([]);
    expect(await harness.execute("SELECT outcome FROM operation WHERE id = ?", opened.id)).toEqual([
      { outcome: JSON.stringify({ n: 1 }) },
    ]);
  });

  it("keeps a record through its replay window past its retention, until retired or swept after it", async () => {
    const { operations } = harness.cfAuth;
    const owner = await harness.sessions.human();
    const actor = await harness.actorFor(owner.userId);
    const reserved = await operations.reserve({ kind: "app.create", opener: actor, input: { name: "brief" } });
    // As short a retention as a kind may have.
    await harness.execute("UPDATE operation SET retain_until = ? WHERE id = ?", Date.now() + 1_000, reserved.id);
    const input = { handle: reserved.handle, kind: "app.create", opener: actor };
    await operations.execute(input, () => ({ outcome: { key: "k" }, record: { brief: true } }));

    await operations.sweep(Date.now() + 5 * 60_000);
    expect(await operations.execute(input, () => ({ outcome: null }))).toMatchObject({
      replayed: true,
      record: { brief: true },
    });

    expect(await operations.retire({ id: reserved.id })).toBe(true);
    await expect(operations.execute(input, () => ({ outcome: null }))).rejects.toMatchObject({
      code: "operation_expired",
    });
    await operations.sweep(Date.now() + 16 * 60_000);
    expect(await harness.execute("SELECT id FROM operation WHERE id = ?", reserved.id)).toEqual([]);
  });

  it("keeps an execution's claim when the user executing it is deleted", async () => {
    const { operations, service } = harness.cfAuth;
    const db = harness.cfAuth.config.db;
    const owner = await harness.sessions.human();
    const ownerActor = await harness.actorFor(owner.userId);
    const executor = await harness.sessions.human();
    await service.addOrganizationMember({
      actor: ownerActor,
      organizationId: owner.organizationId,
      userId: executor.userId,
      role: "admin",
    });
    const executorActor = await harness.actorFor(executor.userId, owner.organizationId);
    const reserved = await operations.reserve({ kind: "app.create", opener: ownerActor, input: { name: "c" } });
    let runs = 0;
    const fn: ExecuteOperationFunction = ({ operation, guard }) => {
      runs += 1;
      return { outcome: null, statements: [guardedInsert(db, sideEffect, { id: `${operation.id}:claimed` }, guard)] };
    };

    const gate = barrier();
    const first = operations.execute(
      { handle: reserved.handle, kind: "app.create", opener: executorActor },
      async (context) => {
        gate.enter();
        await gate.opened;
        return fn(context);
      },
    );
    await gate.entered;
    await harness.execute("DELETE FROM organization WHERE id = ?", executor.organizationId);
    await harness.execute("DELETE FROM user WHERE id = ?", executor.userId);
    await expect(
      operations.execute({ handle: reserved.handle, kind: "app.create", opener: ownerActor }, fn),
    ).rejects.toMatchObject({ code: "conflict" });
    expect(runs).toBe(0);
    gate.open();
    expect(await first).toMatchObject({ replayed: false });
    expect(runs).toBe(1);
    expect(await harness.execute("SELECT id FROM side_effect WHERE id = ?", `${reserved.id}:claimed`)).toHaveLength(1);
    expect(await harness.execute("SELECT decided_by_user_id FROM operation WHERE id = ?", reserved.id)).toEqual([
      { decided_by_user_id: null },
    ]);
  });

  it("reveals on the person's authority, judged with deliverability and the deadline in the consuming write", async () => {
    const { operations, service } = harness.cfAuth;
    const owner = await harness.sessions.human();
    const ownerActor = await harness.actorFor(owner.userId);
    const key = await service.createApiKey({ organizationId: owner.organizationId, actor: ownerActor, name: "MCP" });
    const opener = await service.resolveApiKeyAuthState(key.plaintext, "mcp");
    const executed = async () => {
      const reserved = await operations.reserve({ kind: "key.issue", opener });
      await operations.execute({ handle: reserved.handle, kind: "key.issue", opener }, () => ({
        outcome: { key: "shown-once" },
        record: { keyId: reserved.id },
      }));
      return reserved.id;
    };
    const sealedOutcome = async (id: string) =>
      (await harness.execute("SELECT sealed_outcome FROM operation WHERE id = ?", id))[0]!.sealed_outcome;

    // The credential that opened it is revoked: the person still reveals.
    const kept = await executed();
    const deadline = await executed();
    const undeliverable = await executed();
    await service.revokeApiKey({ organizationId: owner.organizationId, actor: ownerActor, apiKeyId: key.id });
    expect(await operations.reveal({ id: kept, actor: ownerActor })).toMatchObject({ outcome: { key: "shown-once" } });

    // The person's session ends after their state was read.
    const admin = await harness.sessions.human();
    await service.addOrganizationMember({
      actor: ownerActor,
      organizationId: owner.organizationId,
      userId: admin.userId,
      role: "admin",
    });
    const adminActor = await harness.actorFor(admin.userId);
    await harness.execute("DELETE FROM user_session WHERE id = ?", adminActor.actor!.credentialId);
    await expect(operations.reveal({ id: deadline, actor: adminActor })).rejects.toMatchObject({ code: "conflict" });
    expect(await sealedOutcome(deadline)).not.toBeNull();

    // The seal's deadline by the database's clock, while this process's clock says open.
    const realNow = Date.now();
    await harness.execute("UPDATE operation SET sealed_until = ? WHERE id = ?", realNow - 1_000, deadline);
    vi.spyOn(Date, "now").mockReturnValue(realNow - 60_000);
    await expect(operations.reveal({ id: deadline, actor: ownerActor })).rejects.toMatchObject({
      code: "operation_expired",
    });
    vi.restoreAllMocks();
    expect(await sealedOutcome(deadline)).not.toBeNull();

    // No longer deliverable: refused, and dropped.
    await harness.execute("INSERT INTO side_effect (id) VALUES (?)", `revoked:${undeliverable}`);
    await expect(operations.reveal({ id: undeliverable, actor: ownerActor })).rejects.toMatchObject({
      code: "operation_expired",
    });
    expect(await sealedOutcome(undeliverable)).toBeNull();
  });
  it("commits nothing when a refused completion's statements deleted the operation", async () => {
    const { operations } = harness.cfAuth;
    const db = harness.cfAuth.config.db;
    const { operation, organization } = harness.cfAuth.config.tables;
    for (const how of ["directly", "cascade"] as const) {
      const owner = await harness.sessions.human();
      const actor = await harness.actorFor(owner.userId);
      const deleting = (id: string, guard: ReturnType<typeof sql>) => [
        guardedInsert(db, sideEffect, { id: `${id}:${how}` }, guard),
        how === "directly"
          ? db.delete(operation).where(and(eq(operation.id, id), guard))
          : db.delete(organization).where(and(eq(organization.id, owner.organizationId), guard)),
      ];

      const reserved = await operations.reserve({ kind: "app.create", opener: actor, input: { name: how } });
      await expect(
        operations.execute({ handle: reserved.handle, kind: "app.create", opener: actor }, ({ operation: record, guard }) => ({
          outcome: null,
          statements: deleting(record.id, guard),
        })),
      ).rejects.toBeInstanceOf(Error);
      expect(await harness.execute("SELECT state FROM operation WHERE id = ?", reserved.id)).toEqual([{ state: "pending" }]);
      expect(await harness.execute("SELECT id FROM side_effect WHERE id = ?", `${reserved.id}:${how}`)).toEqual([]);

      const completable = await operations.open({
        kind: "app.create",
        token: createOperationToken(),
        payload: { name: how },
        opener: actor,
      });
      await expect(
        operations.complete({
          id: completable.id,
          outcome: {},
          statements: deleting(completable.id, await operations.guard({ id: completable.id })),
        }),
      ).rejects.toBeInstanceOf(Error);
      expect(await harness.execute("SELECT state FROM operation WHERE id = ?", completable.id)).toEqual([{ state: "pending" }]);
      expect(await harness.execute("SELECT id FROM side_effect WHERE id = ?", `${completable.id}:${how}`)).toEqual([]);

      const page = await operations.open({ kind: "approve.writes", token: createOperationToken(), opener: actor });
      approveStatements = (guard) => deleting(page.id, guard);
      await expect(operations.approve({ id: page.id, proof: page.browserProof!, actor })).rejects.toBeInstanceOf(Error);
      expect(await harness.execute("SELECT state FROM operation WHERE id = ?", page.id)).toEqual([{ state: "pending" }]);
      expect(await harness.execute("SELECT id FROM side_effect WHERE id = ?", `${page.id}:${how}`)).toEqual([]);

      await operations.complete({ id: completable.id, outcome: { n: 1 } });
      expect(
        await operations.amend({
          id: completable.id,
          record: { n: 2 },
          statements: deleting(completable.id, await operations.guard({ id: completable.id, state: "completed" })),
        }),
      ).toBe(false);
      expect(await harness.execute("SELECT state, outcome FROM operation WHERE id = ?", completable.id)).toEqual([
        { state: "completed", outcome: JSON.stringify({ n: 1 }) },
      ]);
      expect(await harness.execute("SELECT id FROM side_effect WHERE id = ?", `${completable.id}:${how}`)).toEqual([]);
      expect(await harness.execute("SELECT id FROM organization WHERE id = ?", owner.organizationId)).toHaveLength(1);
    }
  });

  it("keeps a `reveal` outcome from poll, and a `once` poll spends the outcome, not the replay", async () => {
    const { operations } = harness.cfAuth;
    const owner = await harness.sessions.human();
    const actor = await harness.actorFor(owner.userId);

    const secret = await operations.reserve({ kind: "key.issue", opener: actor });
    await operations.execute({ handle: secret.handle, kind: "key.issue", opener: actor }, () => ({
      outcome: { key: "only-on-a-page" },
      record: { keyId: secret.id },
    }));
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const polled = await operations.poll({ id: secret.id, token: secret.handle });
      expect(polled).toMatchObject({ state: "completed", collect: null });
      expect(polled).not.toHaveProperty("outcome");
    }
    expect(await operations.reveal({ id: secret.id, actor })).toMatchObject({ outcome: { key: "only-on-a-page" } });

    const plain = await operations.reserve({ kind: "app.create", opener: actor, input: { name: "once" } });
    const input = { handle: plain.handle, kind: "app.create", opener: actor };
    await operations.execute(input, () => ({ outcome: { key: "polled" }, record: { done: true } }));
    const [{ sealed_until: sealedUntil }] = (await harness.execute(
      "SELECT sealed_until FROM operation WHERE id = ?",
      plain.id,
    )) as [{ sealed_until: number }];
    expect((await operations.poll({ id: plain.id, token: plain.handle })).outcome).toEqual({ key: "polled" });
    expect(await harness.execute("SELECT sealed_outcome, sealed_until FROM operation WHERE id = ?", plain.id)).toEqual([
      { sealed_outcome: null, sealed_until: sealedUntil },
    ]);
    expect(await operations.execute(input, () => ({ outcome: null }))).toMatchObject({ replayed: true });
    await expect(operations.reveal({ id: plain.id, actor })).rejects.toMatchObject({ code: "already_revealed" });
  });

  it("reveals in an organization whose deadline, ISO text with fractional seconds, is still ahead", async () => {
    const { operations } = harness.cfAuth;
    const owner = await harness.sessions.human();
    const actor = await harness.actorFor(owner.userId);
    const reserved = await operations.reserve({ kind: "key.issue", opener: actor });
    await operations.execute({ handle: reserved.handle, kind: "key.issue", opener: actor }, () => ({
      outcome: { key: "before-the-deadline" },
      record: { keyId: reserved.id },
    }));
    const deadline = new Date(Math.floor(Date.now() / 1_000) * 1_000 + 120_456);
    const iso = deadline.toISOString();
    expect(iso).toMatch(/\.456Z$/);
    await harness.execute("UPDATE organization SET expires_at = ? WHERE id = ?", iso, owner.organizationId);
    expect(
      await harness.execute(
        "SELECT cast(unixepoch(expires_at, 'subsec') * 1000 as integer) AS ms FROM organization WHERE id = ?",
        owner.organizationId,
      ),
    ).toEqual([{ ms: deadline.getTime() }]);
    expect(await operations.reveal({ id: reserved.id, actor })).toMatchObject({
      outcome: { key: "before-the-deadline" },
    });
  });

  describe("reveal with something changing between reading the outcome and taking it", () => {
    const raced = async (
      at: "decrypt" | "update",
      change: (context: { id: string; organizationId: string; adminUserId: string }) => Promise<void>,
    ) => {
      const { operations, service } = harness.cfAuth;
      const owner = await harness.sessions.human();
      const ownerActor = await harness.actorFor(owner.userId);
      const reserved = await operations.reserve({ kind: "key.issue", opener: ownerActor });
      await operations.execute({ handle: reserved.handle, kind: "key.issue", opener: ownerActor }, () => ({
        outcome: { key: "first" },
        record: { keyId: reserved.id },
      }));
      const admin = await harness.sessions.human();
      await service.addOrganizationMember({
        actor: ownerActor,
        organizationId: owner.organizationId,
        userId: admin.userId,
        role: "admin",
      });
      const adminActor = await harness.actorFor(admin.userId);
      const [{ sealed_until: sealedUntil }] = (await harness.execute(
        "SELECT sealed_until FROM operation WHERE id = ?",
        reserved.id,
      )) as [{ sealed_until: number }];

      const hold = holdReveal(harness.cfAuth.config.db, at);
      const revealing = operations.reveal({ id: reserved.id, actor: adminActor });
      await hold.entered;
      await change({ id: reserved.id, organizationId: owner.organizationId, adminUserId: admin.userId });
      hold.open();
      const stored = async () =>
        (await harness.execute("SELECT sealed_outcome, sealed_until FROM operation WHERE id = ?", reserved.id))[0]!;
      return { revealing, stored, sealedUntil, id: reserved.id, ownerActor };
    };

    for (const at of ["decrypt", "update"] as const) {
      describe(`paused before the ${at}`, () => {
      it("refuses an outcome no longer deliverable, dropping the outcome but not the replay window", async () => {
        const { revealing, stored, sealedUntil, id, ownerActor } = await raced(at, async ({ id }) => {
          await harness.execute("INSERT INTO side_effect (id) VALUES (?)", `revoked:${id}`);
        });
        await expect(revealing).rejects.toMatchObject({ code: "operation_expired" });
        expect(await stored()).toEqual({ sealed_outcome: null, sealed_until: sealedUntil });
        await expect(harness.cfAuth.operations.reveal({ id, actor: ownerActor })).rejects.toMatchObject({
          code: "already_revealed",
        });
      });

      it("refuses an admin demoted meanwhile", async () => {
        const { revealing, stored } = await raced(at, async ({ organizationId, adminUserId }) => {
          await harness.execute(
            "UPDATE organization_user SET role = 'member' WHERE user_id = ? AND organization_id = ?",
            adminUserId,
            organizationId,
          );
        });
        await expect(revealing).rejects.toMatchObject({ code: "conflict" });
        expect((await stored()).sealed_outcome).not.toBeNull();
      });

      it("refuses once the organization's deadline passed meanwhile", async () => {
        const { revealing, stored } = await raced(at, async ({ organizationId }) => {
          await harness.execute(
            "UPDATE organization SET expires_at = ? WHERE id = ?",
            new Date(Date.now() - 1_000).toISOString(),
            organizationId,
          );
        });
        await expect(revealing).rejects.toMatchObject({ code: "organization_expired" });
        expect((await stored()).sealed_outcome).not.toBeNull();
      });

      it("leaves alone an outcome amend sealed meanwhile", async () => {
        const { revealing, stored, id, ownerActor } = await raced(at, async ({ id }) => {
          expect(await harness.cfAuth.operations.amend({ id, outcome: { key: "renewed" }, seal: true })).toBe(true);
        });
        await expect(revealing).rejects.toMatchObject({ code: "conflict" });
        expect((await stored()).sealed_outcome).not.toBeNull();
        expect(await harness.cfAuth.operations.reveal({ id, actor: ownerActor })).toMatchObject({
          outcome: { key: "renewed" },
        });
      });
      });
    }
  });

  it("never drops a newer outcome when cleaning up an undeliverable one", async () => {
    const { operations } = harness.cfAuth;
    const db = harness.cfAuth.config.db;
    const owner = await harness.sessions.human();
    const actor = await harness.actorFor(owner.userId);
    const reserved = await operations.reserve({ kind: "key.issue", opener: actor });
    await operations.execute({ handle: reserved.handle, kind: "key.issue", opener: actor }, () => ({
      outcome: { key: "old" },
      record: { keyId: reserved.id },
    }));
    await harness.execute("INSERT INTO side_effect (id) VALUES (?)", `revoked:${reserved.id}`);
    const all = db.all.bind(db);
    let amended = false;
    vi.spyOn(db, "all").mockImplementation((async (query: Parameters<typeof db.all>[0]) => {
      const rows = (await all(query)) as unknown[];
      if (!amended && rows.length === 0) {
        amended = true;
        await operations.amend({ id: reserved.id, outcome: { key: "renewed" }, record: { keyId: "fresh" }, seal: true });
      }
      return rows;
    }) as typeof db.all);
    await expect(operations.reveal({ id: reserved.id, actor })).rejects.toMatchObject({ code: "operation_expired" });
    expect(amended).toBe(true);
    vi.restoreAllMocks();
    expect(await operations.reveal({ id: reserved.id, actor })).toMatchObject({ outcome: { key: "renewed" } });
  });
});
