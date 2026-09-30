/**
 * The operations engine on a real D1 database (Miniflare, on workerd).
 *
 * Everything else in this suite runs on libsql, whose batch accepts anything
 * drizzle can execute. D1's batch binds parameters through each item's
 * prepared statement, so an item without one — `db.run(sql)` with parameters —
 * works on libsql and crashes on D1. These tests take the paths that batch.
 */
import { sqliteTable, text } from "drizzle-orm/sqlite-core";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createOperationToken } from "../src/crypto.js";
import { guardedInsert } from "../src/guarded-insert.js";
import { defineOperationKind } from "../src/operations.js";
import { createD1TestAuth, type D1TestAuth } from "./helpers.js";

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

const sideEffect = sqliteTable("side_effect", { id: text("id").primaryKey() });

let harness: D1TestAuth;

beforeAll(async () => {
  harness = await createD1TestAuth({
    operations: { enabled: true, realm: "d1-test", kinds: [bootstrap, grant, secretEntry, windowedGrant, claim] },
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
});
