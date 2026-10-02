import { describe, expect, it } from "vitest";
import { sql } from "drizzle-orm";
import { sqliteTable, text } from "drizzle-orm/sqlite-core";
import { createCfAuth } from "../src/cf-auth.js";
import { createOperationToken, deriveSecret, hmacHex, sha256Hex } from "../src/crypto.js";
import { guardedInsert } from "../src/guarded-insert.js";
import {
  defineOperationKind,
  operationSweepStatementCount,
  type OperationKind,
} from "../src/operations.js";
import { createTestAuth, testSecret, type TestAuth, type TestOverrides } from "./helpers.js";

const enabled = (overrides: TestOverrides["operations"] = {}): TestOverrides => ({
  operations: { enabled: true, realm: "test-deployment", ...overrides },
});

const expectCode = async (promise: Promise<unknown>, code: string) => {
  await expect(promise).rejects.toMatchObject({ code });
};

/** Opens a `login` the way a CLI would, and returns what the CLI would hold. */
const openLogin = async (
  harness: TestAuth,
  client: { loopbackRedirect?: string; ip?: string; rateLimitKey?: string } = {},
) => {
  const token = createOperationToken();
  const view = await harness.cfAuth.operations.open({
    kind: "login",
    token,
    ...(client.rateLimitKey ? { rateLimitKey: client.rateLimitKey } : {}),
    client: {
      label: "CLI on mac-studio",
      meta: { os: "darwin", ...(client.ip ? { ip: client.ip } : {}), userAgent: "agw/1.0" },
      ...(client.loopbackRedirect ? { loopbackRedirect: client.loopbackRedirect } : {}),
    },
  });
  return { token, view };
};

describe("login operation", () => {
  it("opens, is approved in a browser, and hands the key to the CLI exactly once", async () => {
    const harness = await createTestAuth(enabled());
    const { operations } = harness.cfAuth;
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);

    const { token, view } = await openLogin(harness);
    expect(view).toMatchObject({ kind: "login", state: "pending", organizationId: null, collect: null });
    expect(view.browserProof).toMatch(/^[a-f0-9]{64}$/);
    expect(view.userCode).toMatch(/^[A-HJKMNP-Z2-9]{4}-[A-HJKMNP-Z2-9]{4}$/);

    // Polling while pending repeats the same proof and code: both come from the token.
    const pending = await operations.poll({ id: view.id, token });
    expect(pending).toMatchObject({
      state: "pending",
      browserProof: view.browserProof,
      userCode: view.userCode,
    });

    const details = await operations.details({ id: view.id, proof: view.browserProof!, viewer: actor });
    expect(details).toMatchObject({
      kind: "login",
      state: "pending",
      // No grant asked for is the default one, spelled out for the page.
      payload: { grant: "manage" },
      client: { label: "CLI on mac-studio", meta: { os: "darwin", userAgent: "agw/1.0" } },
      organization: null,
      hasLoopbackRedirect: false,
      blockedBy: null,
    });
    expect(details.viewer?.user.id).toBe(human.userId);
    expect(details.viewer?.memberships.map((m) => m.organization.id)).toEqual([human.organizationId]);

    const anonymous = await operations.details({ id: view.id, proof: view.browserProof! });
    expect(anonymous.viewer).toBeNull();
    expect(anonymous.blockedBy).toBe("session_required");

    const approval = await operations.approve({
      id: view.id,
      proof: view.browserProof!,
      actor,
      organizationId: human.organizationId,
    });
    expect(approval).toEqual({
      id: view.id,
      kind: "login",
      state: "completed",
      organizationId: human.organizationId,
      redeemCode: null,
      redirectUrl: null,
    });

    const completed = await operations.poll({ id: view.id, token });
    expect(completed.state).toBe("completed");
    expect(completed.browserProof).toBeNull();
    expect(completed.userCode).toBeNull();
    const outcome = completed.outcome as {
      credential: { token: string };
      organizationId: string;
      apiKeyId: string;
    };
    expect(outcome.organizationId).toBe(human.organizationId);
    expect(outcome.credential.token).toMatch(/^key_/);
    expect(completed.record).toEqual({
      organizationId: human.organizationId,
      apiKeyId: outcome.apiKeyId,
      grant: "manage",
    });

    // The key works, belongs to the approver, and says where it came from.
    const state = await harness.me({
      useJar: false,
      headers: { Authorization: `Bearer ${outcome.credential.token}`, "X-Client": "cli" },
    });
    expect(state).toMatchObject({ credentialType: "apiKey", source: "cli", grant: "manage" });
    expect(state.user?.id).toBe(human.userId);
    expect(state.organization?.id).toBe(human.organizationId);
    const keys = await harness.cfAuth.service.listApiKeys({
      organizationId: human.organizationId,
      actor,
    });
    expect(keys).toEqual([
      expect.objectContaining({
        id: outcome.apiKeyId,
        userId: human.userId,
        name: "CLI on mac-studio",
        source: "cli",
        label: "CLI on mac-studio",
        grant: "manage",
        enabled: true,
      }),
    ]);
    expect(harness.events).toContainEqual({
      type: "api_key.created",
      actorUserId: human.userId,
      organizationId: human.organizationId,
      apiKeyId: outcome.apiKeyId,
      name: "CLI on mac-studio",
    });

    // Handed over once: the next poll reports completion and the record only.
    const again = await operations.poll({ id: view.id, token });
    expect(again).toMatchObject({ state: "completed", collect: null });
    expect(again).not.toHaveProperty("outcome");

    // Nothing secret is stored in the clear.
    const row = (await harness.client.execute({ sql: "SELECT * FROM operation WHERE id = ?", args: [view.id] }))
      .rows[0]!;
    expect(row.sealed_outcome).toBeNull();
    expect(JSON.stringify(row)).not.toContain(outcome.credential.token);
    expect(JSON.stringify(row)).not.toContain(token);
  });

  it("with a loopback redirect, releases the key only to redeem", async () => {
    const harness = await createTestAuth(enabled());
    const { operations } = harness.cfAuth;
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);

    const { token, view } = await openLogin(harness, {
      loopbackRedirect: "http://127.0.0.1:53682/callback",
    });
    const details = await operations.details({ id: view.id, proof: view.browserProof!, viewer: actor });
    expect(details.hasLoopbackRedirect).toBe(true);

    const approval = await operations.approve({
      id: view.id,
      proof: view.browserProof!,
      actor,
      organizationId: human.organizationId,
    });
    expect(approval.redeemCode).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const redirect = new URL(approval.redirectUrl!);
    expect(`${redirect.origin}${redirect.pathname}`).toBe("http://127.0.0.1:53682/callback");
    expect(redirect.searchParams.get("code")).toBe(approval.redeemCode);

    // Polling reports completion but never hands over the key.
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const polled = await operations.poll({ id: view.id, token });
      expect(polled).toMatchObject({ state: "completed", collect: "redeem" });
      expect(polled).not.toHaveProperty("outcome");
    }

    await expectCode(
      operations.redeem({ id: view.id, token, redeemCode: createOperationToken() }),
      "invalid_proof",
    );
    // The redeem code alone is not enough: the token must match too.
    await expectCode(
      operations.redeem({ id: view.id, token: createOperationToken(), redeemCode: approval.redeemCode! }),
      "operation_not_found",
    );

    const redeemed = await operations.redeem({ id: view.id, token, redeemCode: approval.redeemCode! });
    expect(redeemed).toMatchObject({ id: view.id, kind: "login", organizationId: human.organizationId });
    expect((redeemed.outcome as { credential: { token: string } }).credential.token).toMatch(/^key_/);

    await expectCode(
      operations.redeem({ id: view.id, token, redeemCode: approval.redeemCode! }),
      "already_completed",
    );
    expect(await operations.poll({ id: view.id, token })).toMatchObject({ collect: null });
  });

  it("refuses to redeem before approval", async () => {
    const harness = await createTestAuth(enabled());
    const { token, view } = await openLogin(harness, {
      loopbackRedirect: "http://[::1]:4000/cb",
    });
    await expectCode(
      harness.cfAuth.operations.redeem({ id: view.id, token, redeemCode: createOperationToken() }),
      "operation_pending",
    );
  });

  it("accepts only a loopback IP literal with a port as the redirect", async () => {
    const harness = await createTestAuth(enabled());
    for (const loopbackRedirect of [
      "http://localhost:5000/callback",
      "https://127.0.0.1:5000/callback",
      "http://127.0.0.1/callback",
      "http://example.com:5000/callback",
      "http://127.0.0.1:5000/callback?next=/evil",
    ]) {
      await expectCode(openLogin(harness, { loopbackRedirect }), "validation_error");
    }
  });

  it("requires a client label", async () => {
    const harness = await createTestAuth(enabled());
    await expectCode(
      harness.cfAuth.operations.open({ kind: "login", token: createOperationToken() }),
      "validation_error",
    );
  });

  it("can be denied, after which it cannot be approved or redeemed", async () => {
    const harness = await createTestAuth(enabled());
    const { operations } = harness.cfAuth;
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);
    const { token, view } = await openLogin(harness);

    expect(await operations.deny({ id: view.id, proof: view.browserProof!, actor })).toEqual({
      id: view.id,
      kind: "login",
      state: "denied",
    });
    // Idempotent.
    expect((await operations.deny({ id: view.id, userCode: view.userCode! })).state).toBe("denied");

    expect(await operations.poll({ id: view.id, token })).toMatchObject({
      state: "denied",
      browserProof: null,
      userCode: null,
    });
    await expectCode(
      operations.approve({ id: view.id, proof: view.browserProof!, actor, organizationId: human.organizationId }),
      "operation_denied",
    );
    await expectCode(
      operations.redeem({ id: view.id, token, redeemCode: createOperationToken() }),
      "operation_denied",
    );
    const row = (
      await harness.client.execute({ sql: "SELECT decided_by_user_id FROM operation WHERE id = ?", args: [view.id] })
    ).rows[0]!;
    expect(row.decided_by_user_id).toBe(human.userId);
  });

  it("expires when nobody approves in time, and the sweep records it", async () => {
    const harness = await createTestAuth(enabled());
    const { operations } = harness.cfAuth;
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);
    const { token, view } = await openLogin(harness);

    await harness.client.execute({
      sql: "UPDATE operation SET expires_at = ? WHERE id = ?",
      args: [Date.now() - 1, view.id],
    });

    expect(await operations.poll({ id: view.id, token })).toMatchObject({
      state: "expired",
      browserProof: null,
      userCode: null,
    });
    expect(await operations.lookupByUserCode({ userCode: view.userCode! })).toBeNull();
    await expectCode(
      operations.approve({ id: view.id, proof: view.browserProof!, actor, organizationId: human.organizationId }),
      "operation_expired",
    );
    await expectCode(operations.deny({ id: view.id, proof: view.browserProof! }), "operation_expired");

    await operations.sweep();
    const state = async () =>
      (await harness.client.execute({ sql: "SELECT state FROM operation WHERE id = ?", args: [view.id] }))
        .rows[0]?.state;
    expect(await state()).toBe("expired");

    // Retention ends the record entirely.
    await harness.client.execute({
      sql: "UPDATE operation SET retain_until = ? WHERE id = ?",
      args: [Date.now() - 1, view.id],
    });
    await operations.sweep();
    expect(await state()).toBeUndefined();
  });

  it("drops a sealed outcome nobody collected once its window passes", async () => {
    const harness = await createTestAuth(enabled());
    const { operations } = harness.cfAuth;
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);
    const { token, view } = await openLogin(harness);
    await operations.approve({
      id: view.id,
      proof: view.browserProof!,
      actor,
      organizationId: human.organizationId,
    });

    await harness.client.execute({
      sql: "UPDATE operation SET sealed_until = ? WHERE id = ?",
      args: [Date.now() - 1, view.id],
    });
    const polled = await operations.poll({ id: view.id, token });
    expect(polled).toMatchObject({ state: "completed", collect: null });
    expect(polled).not.toHaveProperty("outcome");

    await operations.sweep();
    const row = (
      await harness.client.execute({ sql: "SELECT sealed_outcome, state FROM operation WHERE id = ?", args: [view.id] })
    ).rows[0]!;
    expect(row).toMatchObject({ sealed_outcome: null, state: "completed" });
  });

  it("refuses a wrong browser proof or user code", async () => {
    const harness = await createTestAuth(enabled());
    const { operations } = harness.cfAuth;
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);
    const { view } = await openLogin(harness);
    const other = await openLogin(harness);

    const wrongProof = "0".repeat(64);
    await expectCode(operations.details({ id: view.id, proof: wrongProof }), "invalid_proof");
    await expectCode(operations.details({ id: view.id, proof: "not-a-proof" }), "invalid_proof");
    // A real proof, but for another operation.
    await expectCode(operations.details({ id: view.id, proof: other.view.browserProof! }), "invalid_proof");
    await expectCode(operations.details({ id: view.id, userCode: other.view.userCode! }), "invalid_proof");
    await expectCode(
      operations.approve({ id: view.id, proof: wrongProof, actor, organizationId: human.organizationId }),
      "invalid_proof",
    );
    await expectCode(operations.deny({ id: view.id, userCode: "ABCD-EFGH" }), "invalid_proof");
    await expectCode(
      operations.details({ id: crypto.randomUUID(), proof: view.browserProof! }),
      "operation_not_found",
    );
  });

  it("refuses a wrong token the same way as an unknown operation", async () => {
    const harness = await createTestAuth(enabled());
    const { operations } = harness.cfAuth;
    const { view } = await openLogin(harness);

    await expectCode(operations.poll({ id: view.id, token: createOperationToken() }), "operation_not_found");
    await expectCode(operations.poll({ id: view.id, token: "short" }), "operation_not_found");
    await expectCode(
      operations.poll({ id: crypto.randomUUID(), token: createOperationToken() }),
      "operation_not_found",
    );
  });

  it("finds a pending operation by its user code, however it is typed", async () => {
    const harness = await createTestAuth(enabled());
    const { operations } = harness.cfAuth;
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);
    const { token, view } = await openLogin(harness);
    const code = view.userCode!;

    for (const typed of [code, code.toLowerCase(), code.replace("-", ""), ` ${code.slice(0, 4)} ${code.slice(5)} `]) {
      expect(await operations.lookupByUserCode({ userCode: typed })).toEqual({
        id: view.id,
        kind: "login",
        expiresAt: view.expiresAt,
      });
    }
    expect(await operations.lookupByUserCode({ userCode: "AAAA-AAAA" })).toBeNull();
    expect(await operations.lookupByUserCode({ userCode: "I0O1-L000" })).toBeNull();
    expect(await operations.lookupByUserCode({ userCode: "" })).toBeNull();

    // The code-entry page carries on with the code in place of the proof.
    const details = await operations.details({ id: view.id, userCode: code.toLowerCase(), viewer: actor });
    expect(details.blockedBy).toBeNull();
    await operations.approve({ id: view.id, userCode: code, actor, organizationId: human.organizationId });
    expect(await operations.poll({ id: view.id, token })).toMatchObject({ state: "completed" });
    expect(await operations.lookupByUserCode({ userCode: code })).toBeNull();
  });

  it("caps pending logins per rate-limit key, never per what the client claims", async () => {
    const harness = await createTestAuth(enabled({ limits: { pendingPerOpener: 2 } }));
    await openLogin(harness, { rateLimitKey: "203.0.113.7" });
    await openLogin(harness, { rateLimitKey: "203.0.113.7" });
    await expectCode(openLogin(harness, { rateLimitKey: "203.0.113.7" }), "too_many_pending");

    // Another key is unaffected, and so is one whose earlier logins expired.
    await openLogin(harness, { rateLimitKey: "203.0.113.8" });
    await harness.client.execute({
      sql: "UPDATE operation SET expires_at = ? WHERE opener_key = ?",
      args: [Date.now() - 1, "key:203.0.113.7"],
    });
    await openLogin(harness, { rateLimitKey: "203.0.113.7" });

    // The client's own claimed address counts for nothing.
    for (let attempt = 0; attempt < 3; attempt += 1) await openLogin(harness, { ip: "198.51.100.1" });
    await expectCode(
      harness.cfAuth.operations.open({
        kind: "login",
        token: createOperationToken(),
        client: { label: "x" },
        rateLimitKey: "k".repeat(257),
      }),
      "validation_error",
    );
  });

  it("is idempotent for a retry with the same token", async () => {
    const harness = await createTestAuth(enabled());
    const { operations } = harness.cfAuth;
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);
    const { token, view } = await openLogin(harness);

    const retry = await operations.open({ kind: "login", token, client: { label: "CLI on mac-studio" } });
    expect(retry.id).toBe(view.id);
    expect(retry.browserProof).toBe(view.browserProof);
    expect(Number((await harness.client.execute("SELECT count(*) AS n FROM operation")).rows[0]!.n)).toBe(1);

    await operations.approve({ id: view.id, proof: view.browserProof!, actor, organizationId: human.organizationId });

    // A retry after completion is answered as a poll: the key, once.
    const recovered = await operations.open({ kind: "login", token, client: { label: "CLI on mac-studio" } });
    expect(recovered).toMatchObject({ id: view.id, state: "completed" });
    expect((recovered.outcome as { credential: { token: string } }).credential.token).toMatch(/^key_/);
    const repeated = await operations.open({ kind: "login", token, client: { label: "CLI on mac-studio" } });
    expect(repeated).toMatchObject({ id: view.id, state: "completed", collect: null });
    expect(repeated).not.toHaveProperty("outcome");
  });

  it("shows the terminal's user code on the approval page, stored only sealed", async () => {
    const harness = await createTestAuth(enabled());
    const { view } = await openLogin(harness);

    const details = await harness.cfAuth.operations.details({ id: view.id, proof: view.browserProof! });
    expect(details.userCode).toBe(view.userCode);
    expect(details).toMatchObject({ approver: "session", takesInput: false });
    // When it was asked for, without arithmetic on the deadline.
    expect(details.createdAt).toBe(view.createdAt);
    expect(Date.parse(view.expiresAt) - Date.parse(view.createdAt)).toBe(15 * 60_000);

    const row = (
      await harness.client.execute({
        sql: "SELECT user_code_sealed, user_code_hash FROM operation WHERE id = ?",
        args: [view.id],
      })
    ).rows[0]!;
    expect(row.user_code_sealed).not.toContain(view.userCode!.replace("-", ""));
    // Keyed by a subkey of the secret, so the table alone cannot test codes offline.
    const normalized = view.userCode!.replace("-", "");
    expect(row.user_code_hash).not.toBe(await sha256Hex(normalized));
    expect(row.user_code_hash).toBe(
      await hmacHex(await deriveSecret(testSecret, "cf-auth:operation-user-code"), normalized),
    );
  });

  it("keeps the session through ensureDefaultOrganization, so that state can approve", async () => {
    const harness = await createTestAuth(enabled());
    const human = await harness.sessions.human();
    // Left their only organization: the next request provisions a new one.
    await harness.client.execute({ sql: "DELETE FROM organization_user WHERE user_id = ?", args: [human.userId] });
    const bare = await harness.actorFor(human.userId);
    expect(bare.memberships).toEqual([]);

    const ensured = await harness.cfAuth.service.ensureDefaultOrganization(bare);
    expect(ensured.actor?.credentialId).toBe(bare.actor?.credentialId);
    expect(ensured.organization).not.toBeNull();

    const { token, view } = await openLogin(harness);
    await harness.cfAuth.operations.approve({
      id: view.id,
      proof: view.browserProof!,
      actor: ensured,
      organizationId: ensured.organization!.id,
    });
    expect((await harness.cfAuth.operations.poll({ id: view.id, token })).state).toBe("completed");
  });

  it("refuses an approver who is not a member of the chosen organization", async () => {
    const harness = await createTestAuth(enabled());
    const { operations } = harness.cfAuth;
    const owner = await harness.sessions.human();
    const stranger = await harness.sessions.human();
    const strangerActor = await harness.actorFor(stranger.userId);
    const { token, view } = await openLogin(harness);

    await expectCode(
      operations.approve({
        id: view.id,
        proof: view.browserProof!,
        actor: strangerActor,
        organizationId: owner.organizationId,
      }),
      "not_a_member",
    );
    await expectCode(
      operations.approve({ id: view.id, proof: view.browserProof!, actor: strangerActor }),
      "validation_error",
    );
    expect((await operations.poll({ id: view.id, token })).state).toBe("pending");
    expect(await harness.cfAuth.repository.listApiKeys(owner.organizationId)).toEqual([]);
  });

  it("needs an admin to approve a login unless configured down to member", async () => {
    for (const [overrides, allowed] of [
      [enabled(), false],
      [enabled({ login: { minRole: "member" } }), true],
    ] as const) {
      const harness = await createTestAuth(overrides);
      const { operations } = harness.cfAuth;
      const owner = await harness.sessions.human();
      const member = await harness.sessions.human();
      await harness.cfAuth.service.addOrganizationMember({
        actor: await harness.actorFor(owner.userId),
        organizationId: owner.organizationId,
        userId: member.userId,
        role: "member",
      });
      const memberActor = await harness.actorFor(member.userId, owner.organizationId);
      const { token, view } = await openLogin(harness);
      const approving = operations.approve({
        id: view.id,
        proof: view.browserProof!,
        actor: memberActor,
        organizationId: owner.organizationId,
      });
      if (allowed) {
        await approving;
        expect((await operations.poll({ id: view.id, token })).state).toBe("completed");
      } else {
        await expectCode(approving, "not_a_member");
      }
    }
  });

  it("holds the built-in login to the same kind rules", async () => {
    await expect(
      createTestAuth(enabled({ login: { pendingTtlMs: 2 * 86_400_000, recordTtlMs: 86_400_000 } })),
    ).rejects.toMatchObject({ code: "validation_error" });
  });

  it("switches a loopback operation to polling when its sealed outcome is amended", async () => {
    const harness = await createTestAuth(enabled());
    const { operations } = harness.cfAuth;
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);
    const { token, view } = await openLogin(harness, { loopbackRedirect: "http://127.0.0.1:5000/cb" });
    const approval = await operations.approve({
      id: view.id,
      proof: view.browserProof!,
      actor,
      organizationId: human.organizationId,
    });
    await operations.redeem({ id: view.id, token, redeemCode: approval.redeemCode! });

    expect(await operations.amend({ id: view.id, outcome: { renewed: true }, seal: true })).toBe(true);
    const polled = await operations.poll({ id: view.id, token });
    expect(polled.outcome).toEqual({ renewed: true });
    await expectCode(
      operations.redeem({ id: view.id, token, redeemCode: approval.redeemCode! }),
      "already_completed",
    );
  });

  it("withdraws a login key revoked before it was collected", async () => {
    const harness = await createTestAuth(enabled());
    const { operations, service } = harness.cfAuth;
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);
    const revokeAll = async () => {
      for (const key of await service.listApiKeys({ organizationId: human.organizationId, actor })) {
        if (!key.revokedAt) {
          await service.revokeApiKey({ organizationId: human.organizationId, actor, apiKeyId: key.id });
        }
      }
    };

    const polled = await openLogin(harness);
    await operations.approve({
      id: polled.view.id,
      proof: polled.view.browserProof!,
      actor,
      organizationId: human.organizationId,
    });
    await revokeAll();
    await expectCode(operations.poll({ id: polled.view.id, token: polled.token }), "operation_expired");
    // Withdrawn for good, not just this once.
    expect(await operations.poll({ id: polled.view.id, token: polled.token })).toMatchObject({ collect: null });

    const redeemed = await openLogin(harness, { loopbackRedirect: "http://127.0.0.1:5000/cb" });
    const approval = await operations.approve({
      id: redeemed.view.id,
      proof: redeemed.view.browserProof!,
      actor,
      organizationId: human.organizationId,
    });
    await revokeAll();
    await expectCode(
      operations.redeem({ id: redeemed.view.id, token: redeemed.token, redeemCode: approval.redeemCode! }),
      "operation_expired",
    );
  });

  it("reports an unreadable sealed outcome as expired without erasing it", async () => {
    const harness = await createTestAuth(enabled());
    const rotated = createCfAuth({
      appName: "Test App",
      secret: "a-rotated-secret-not-a-real-credential-9876",
      db: harness.db,
      apiKeys: { enabled: true },
      operations: { enabled: true, realm: "test-deployment" },
      onError: () => {},
    });
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);

    const polling = await openLogin(harness);
    const looping = await openLogin(harness, { loopbackRedirect: "http://127.0.0.1:5000/cb" });
    // The page still loads after a rotation; it just cannot echo the code.
    const details = await rotated.operations.details({ id: polling.view.id, proof: polling.view.browserProof! });
    expect(details.userCode).toBeNull();

    await harness.cfAuth.operations.approve({
      id: polling.view.id,
      proof: polling.view.browserProof!,
      actor,
      organizationId: human.organizationId,
    });
    const approval = await harness.cfAuth.operations.approve({
      id: looping.view.id,
      proof: looping.view.browserProof!,
      actor,
      organizationId: human.organizationId,
    });

    await expectCode(
      rotated.operations.poll({ id: polling.view.id, token: polling.token }),
      "operation_expired",
    );
    await expectCode(
      rotated.operations.redeem({ id: looping.view.id, token: looping.token, redeemCode: approval.redeemCode! }),
      "operation_expired",
    );
    // Nothing was spent: the original secret still collects both.
    expect((await harness.cfAuth.operations.poll({ id: polling.view.id, token: polling.token })).outcome).toBeTruthy();
    expect(
      (await harness.cfAuth.operations.redeem({
        id: looping.view.id,
        token: looping.token,
        redeemCode: approval.redeemCode!,
      })).outcome,
    ).toBeTruthy();
  });

  it("refuses an API key or an anonymous state as the approver", async () => {
    const harness = await createTestAuth(enabled());
    const { operations } = harness.cfAuth;
    const human = await harness.sessions.human();
    const key = await harness.cfAuth.service.createApiKey({
      organizationId: human.organizationId,
      actor: await harness.actorFor(human.userId),
      name: "CI",
    });
    const keyState = await harness.cfAuth.service.resolveApiKeyAuthState(key.plaintext, "cli");
    const { view } = await openLogin(harness);

    await expectCode(
      operations.approve({ id: view.id, proof: view.browserProof!, actor: keyState, organizationId: human.organizationId }),
      "session_required",
    );
  });

  it("re-reads the approver's session at write time", async () => {
    const harness = await createTestAuth(enabled());
    const { operations } = harness.cfAuth;
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);
    const { token, view } = await openLogin(harness);

    // The state was resolved while the session was live; it has since ended.
    await harness.client.execute({
      sql: "DELETE FROM user_session WHERE id = ?",
      args: [actor.actor!.credentialId!],
    });

    await expectCode(
      operations.approve({ id: view.id, proof: view.browserProof!, actor, organizationId: human.organizationId }),
      "conflict",
    );
    expect((await operations.poll({ id: view.id, token })).state).toBe("pending");
    expect(await harness.cfAuth.repository.listApiKeys(human.organizationId)).toEqual([]);
  });

  it("needs apiKeys, and can be turned off", async () => {
    await expect(
      createTestAuth({ apiKeys: { enabled: false }, operations: { enabled: true } }),
    ).rejects.toMatchObject({ code: "validation_error" });

    const harness = await createTestAuth({
      apiKeys: { enabled: false },
      operations: { enabled: true, login: false },
    });
    expect([...harness.cfAuth.operations.kinds.keys()]).toEqual([]);
    await expectCode(
      harness.cfAuth.operations.open({ kind: "login", token: createOperationToken() }),
      "validation_error",
    );
  });

  it("refuses every call while operations are disabled", async () => {
    const harness = await createTestAuth();
    await expectCode(openLogin(harness), "validation_error");
  });
});

describe("app-defined operation kinds", () => {
  /** A bootstrap: public, no browser, completed by the app with a secret. */
  const bootstrap = defineOperationKind({
    name: "bootstrap",
    open: "public",
    browser: false,
    payload: (value: unknown) => {
      const input = value as { name?: unknown } | undefined;
      if (typeof input?.name !== "string" || !input.name) throw new Error("name is required");
      return { name: input.name };
    },
  });

  /** A resource write a member opens and an admin approves in a browser. */
  const grant = defineOperationKind({
    name: "grant",
    open: { minRole: "member" },
    browser: true,
    approverMinRole: "admin",
    payload: { parse: (value: unknown) => ({ note: String((value as { note?: unknown }).note ?? "") }) },
    approve: ({ payload, organizationId }) => ({ outcome: { granted: payload.note, organizationId } }),
  });

  const kinds: OperationKind[] = [bootstrap, grant];

  it("completes a kind with no browser step and returns its sealed outcome once", async () => {
    const harness = await createTestAuth(enabled({ kinds }));
    const { operations } = harness.cfAuth;
    const token = createOperationToken();

    const opened = await operations.open({ kind: "bootstrap", token, payload: { name: "first" } });
    expect(opened).toMatchObject({ state: "pending", browserProof: null, userCode: null });

    await expectCode(
      operations.open({ kind: "bootstrap", token: createOperationToken(), payload: {} }),
      "validation_error",
    );
    await expectCode(
      operations.open({ kind: "bootstrap", token, payload: { name: "second" } }),
      "conflict",
    );

    const completed = await operations.complete({
      id: opened.id,
      outcome: { credential: { token: "service-secret" } },
      record: { account: "acct_1" },
      seal: true,
    });
    expect(completed).toMatchObject({ state: "completed", collect: "poll", record: { account: "acct_1" } });
    expect(completed).not.toHaveProperty("outcome");
    await expectCode(operations.complete({ id: opened.id, outcome: {} }), "already_completed");

    const first = await operations.poll({ id: opened.id, token });
    expect(first.outcome).toEqual({ credential: { token: "service-secret" } });
    const second = await operations.poll({ id: opened.id, token });
    expect(second).not.toHaveProperty("outcome");
    expect(second).toMatchObject({ state: "completed", collect: null, record: { account: "acct_1" } });

    expect(await operations.retire({ id: opened.id })).toBe(true);
    expect((await operations.poll({ id: opened.id, token })).state).toBe("retired");
    expect(await operations.retire({ id: opened.id })).toBe(false);
  });

  it("runs the app's statements in the completion batch, under its guard", async () => {
    const harness = await createTestAuth(enabled({ kinds }));
    const { operations } = harness.cfAuth;
    await harness.client.execute("CREATE TABLE side_effect (id TEXT PRIMARY KEY)");
    const sideEffect = sqliteTable("side_effect", { id: text("id").primaryKey() });
    const opened = await operations.open({
      kind: "bootstrap",
      token: createOperationToken(),
      payload: { name: "x" },
    });

    const guard = await operations.guard({ id: opened.id });
    await operations.complete({
      id: opened.id,
      outcome: { ok: true },
      statements: [guardedInsert(harness.db, sideEffect, { id: "first" }, guard)],
    });
    expect((await harness.client.execute("SELECT id FROM side_effect")).rows.map((r) => r.id)).toEqual(["first"]);

    // Once completed the guard is false, so a write under it does not land.
    await guardedInsert(harness.db, sideEffect, { id: "late" }, guard);
    expect((await harness.client.execute("SELECT count(*) AS n FROM side_effect")).rows[0]!.n).toBe(1);
  });

  it("refuses a raw statement with parameters, which D1 could not batch", async () => {
    const harness = await createTestAuth(enabled({ kinds }));
    const { operations } = harness.cfAuth;
    await harness.client.execute("CREATE TABLE side_effect (id TEXT PRIMARY KEY)");
    const opened = await operations.open({
      kind: "bootstrap",
      token: createOperationToken(),
      payload: { name: "x" },
    });
    const guard = await operations.guard({ id: opened.id });
    await expectCode(
      operations.complete({
        id: opened.id,
        outcome: {},
        statements: [harness.db.run(sql`insert into side_effect (id) select ${"raw"} where ${guard}`)],
      }),
      "validation_error",
    );
    expect((await harness.client.execute("SELECT count(*) AS n FROM side_effect")).rows[0]!.n).toBe(0);
  });

  it("shows the organization an operation acts in", async () => {
    const harness = await createTestAuth(enabled({ kinds }));
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);
    const opened = await harness.cfAuth.operations.open({
      kind: "grant",
      token: createOperationToken(),
      payload: { note: "x" },
      opener: actor,
    });
    const details = await harness.cfAuth.operations.details({
      id: opened.id,
      proof: opened.browserProof!,
      viewer: actor,
    });
    expect(details.organization).toMatchObject({ id: human.organizationId, claimed: true, expiresAt: null });
    expect(details.userCode).toBeNull();
  });

  it("accepts an app-chosen id and finds an operation by its token", async () => {
    const harness = await createTestAuth(enabled({ kinds }));
    const { operations } = harness.cfAuth;
    const token = createOperationToken();
    const id = `op:${await sha256Hex(token)}`;

    const opened = await operations.open({ kind: "bootstrap", token, id, payload: { name: "x" } });
    expect(opened.id).toBe(id);
    expect(await operations.findByToken({ token })).toMatchObject({ id, state: "pending" });
    expect(await operations.findByToken({ token: createOperationToken() })).toBeNull();
    expect(await operations.findByToken({ token: "short" })).toBeNull();

    // The same token with another id, or another token with this id, is a different request.
    await expectCode(
      operations.open({ kind: "bootstrap", token, id: "op:other", payload: { name: "x" } }),
      "conflict",
    );
    await expectCode(
      operations.open({ kind: "bootstrap", token: createOperationToken(), id, payload: { name: "x" } }),
      "conflict",
    );
    await expectCode(
      operations.open({ kind: "bootstrap", token: createOperationToken(), id: "x".repeat(129), payload: { name: "x" } }),
      "validation_error",
    );

    // findByToken reports without handing anything over.
    await operations.complete({ id, outcome: { secret: 1 }, seal: true });
    expect(await operations.findByToken({ token })).toMatchObject({ state: "completed", collect: "poll" });
    expect((await operations.poll({ id, token })).outcome).toEqual({ secret: 1 });
  });

  it("approves a proof kind with page input and no person", async () => {
    const secretEntry = defineOperationKind({
      name: "secret.enter",
      open: { minRole: "member" },
      browser: true,
      userCode: true,
      approver: "proof",
      payload: (value: unknown) => ({ providerId: String((value as { providerId?: unknown }).providerId) }),
      input: (value: unknown) => {
        const secret = (value as { secret?: unknown } | undefined)?.secret;
        if (typeof secret !== "string" || !secret.trim()) throw new Error("secret is required");
        return { secret };
      },
      approve: ({ payload, input, actor, user, organizationId }) => ({
        outcome: { providerId: payload.providerId, length: input!.secret.length, actor, user, organizationId },
      }),
    });
    const harness = await createTestAuth(enabled({ kinds: [secretEntry, grant] }));
    const { operations } = harness.cfAuth;
    const human = await harness.sessions.human();
    const opener = await harness.actorFor(human.userId);
    const token = createOperationToken();
    const opened = await operations.open({ kind: "secret.enter", token, payload: { providerId: "p1" }, opener });

    const details = await operations.details({ id: opened.id, proof: opened.browserProof! });
    expect(details).toMatchObject({ approver: "proof", takesInput: true, viewer: null });

    await expectCode(
      operations.approve({ id: opened.id, userCode: opened.userCode!, input: { secret: "s3cret" } }),
      "invalid_proof",
    );
    await expectCode(operations.approve({ id: opened.id, proof: opened.browserProof! }), "validation_error");

    const approval = await operations.approve({
      id: opened.id,
      proof: opened.browserProof!,
      input: { secret: "s3cret" },
    });
    expect(approval.organizationId).toBe(human.organizationId);
    expect((await operations.poll({ id: opened.id, token })).record).toEqual({
      providerId: "p1",
      length: 6,
      actor: null,
      user: null,
      organizationId: human.organizationId,
    });
    const row = (
      await harness.client.execute({ sql: "SELECT * FROM operation WHERE id = ?", args: [opened.id] })
    ).rows[0]!;
    expect(JSON.stringify(row)).not.toContain("s3cret");
    expect(row.decided_by_user_id).toBeNull();

    // A kind without an input schema refuses input.
    const grantToken = createOperationToken();
    const granted = await operations.open({ kind: "grant", token: grantToken, payload: { note: "n" }, opener });
    await expectCode(
      operations.approve({ id: granted.id, proof: granted.browserProof!, actor: opener, input: { x: 1 } }),
      "validation_error",
    );
  });

  it("delivers a windowed outcome on every poll until its seal expires", async () => {
    const windowed = defineOperationKind({ ...bootstrap, name: "bootstrap.window", deliver: "window" });
    const harness = await createTestAuth(enabled({ kinds: [windowed] }));
    const { operations } = harness.cfAuth;
    const token = createOperationToken();
    const opened = await operations.open({ kind: "bootstrap.window", token, payload: { name: "x" } });
    await operations.complete({ id: opened.id, outcome: { key: "k1" }, seal: true, record: { n: 1 } });

    for (let attempt = 0; attempt < 3; attempt += 1) {
      const polled = await operations.poll({ id: opened.id, token });
      expect(polled).toMatchObject({ outcome: { key: "k1" }, collect: "poll", record: { n: 1 } });
    }
    // A retried open recovers it the same way.
    expect((await operations.open({ kind: "bootstrap.window", token, payload: { name: "x" } })).outcome).toEqual({
      key: "k1",
    });

    await harness.client.execute({
      sql: "UPDATE operation SET sealed_until = ? WHERE id = ?",
      args: [Date.now() - 1, opened.id],
    });
    const lapsed = await operations.poll({ id: opened.id, token });
    expect(lapsed).not.toHaveProperty("outcome");
    await operations.sweep();
    const row = (
      await harness.client.execute({ sql: "SELECT sealed_outcome FROM operation WHERE id = ?", args: [opened.id] })
    ).rows[0]!;
    expect(row.sealed_outcome).toBeNull();
  });

  it("amends a completed record under a guard", async () => {
    const harness = await createTestAuth(enabled({ kinds }));
    const { operations } = harness.cfAuth;
    const token = createOperationToken();
    const opened = await operations.open({ kind: "bootstrap", token, payload: { name: "x" } });
    await expectCode(operations.amend({ id: opened.id, record: {} }), "operation_pending");
    await operations.complete({ id: opened.id, outcome: { key: "k1" }, seal: true, record: { keyId: "1" } });
    expect((await operations.poll({ id: opened.id, token })).outcome).toEqual({ key: "k1" });

    // Renew the key only while nothing is sealed: a false condition changes nothing.
    const { operation } = harness.cfAuth.config.tables;
    expect(
      await operations.amend({
        id: opened.id,
        outcome: { key: "never" },
        seal: true,
        condition: sql`${operation.sealedOutcome} is not null`,
      }),
    ).toBe(false);
    const guard = await operations.guard({ id: opened.id, state: "completed" });
    expect(
      await operations.amend({
        id: opened.id,
        outcome: { key: "k2" },
        seal: true,
        record: { keyId: "2" },
        condition: sql`${guard} and ${operation.sealedOutcome} is null`,
      }),
    ).toBe(true);
    const renewed = await operations.poll({ id: opened.id, token });
    expect(renewed).toMatchObject({ outcome: { key: "k2" }, record: { keyId: "2" } });

    await expectCode(
      operations.amend({ id: opened.id, outcome: { a: 1 }, record: { b: 2 } }),
      "validation_error",
    );
  });

  it("retires an operation in any state", async () => {
    const harness = await createTestAuth(enabled());
    const { operations } = harness.cfAuth;
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);
    const { token, view } = await openLogin(harness);

    expect(await operations.retire({ id: view.id })).toBe(true);
    expect((await operations.poll({ id: view.id, token })).state).toBe("retired");
    await expectCode(
      operations.approve({ id: view.id, proof: view.browserProof!, actor, organizationId: human.organizationId }),
      "operation_expired",
    );
    expect(await operations.retire({ id: view.id })).toBe(false);
  });

  it("returns batchable sweep statements, one per step", async () => {
    const harness = await createTestAuth(enabled());
    const statements = harness.cfAuth.operations.sweepStatements();
    expect(operationSweepStatementCount).toBe(3);
    expect(statements).toHaveLength(operationSweepStatementCount);
    await (harness.db as unknown as { batch(items: unknown[]): Promise<unknown> }).batch(statements);
  });

  it("binds an authenticated kind to its opener and rechecks the opener at approval", async () => {
    const harness = await createTestAuth(enabled({ kinds, limits: { pendingPerOrganization: 1 } }));
    const { operations } = harness.cfAuth;
    const owner = await harness.sessions.human();
    const ownerActor = await harness.actorFor(owner.userId);
    const key = await harness.cfAuth.service.createApiKey({
      organizationId: owner.organizationId,
      actor: ownerActor,
      name: "CLI",
    });
    const opener = await harness.cfAuth.service.resolveApiKeyAuthState(key.plaintext, "cli");

    await expectCode(
      operations.open({ kind: "grant", token: createOperationToken(), payload: { note: "x" } }),
      "unauthorized",
    );

    const token = createOperationToken();
    const opened = await operations.open({ kind: "grant", token, payload: { note: "hello" }, opener });
    expect(opened).toMatchObject({ organizationId: owner.organizationId, userCode: null });
    await expectCode(
      operations.open({ kind: "grant", token: createOperationToken(), payload: { note: "y" }, opener }),
      "too_many_pending",
    );

    // The approval is pinned to the opener's organization.
    const other = await harness.sessions.human();
    await expectCode(
      operations.approve({
        id: opened.id,
        proof: opened.browserProof!,
        actor: await harness.actorFor(other.userId),
        organizationId: other.organizationId,
      }),
      "forbidden",
    );

    // Revoking the key that opened it withdraws the request.
    await harness.cfAuth.service.revokeApiKey({
      organizationId: owner.organizationId,
      actor: ownerActor,
      apiKeyId: key.id,
    });
    await expectCode(
      operations.approve({ id: opened.id, proof: opened.browserProof!, actor: ownerActor }),
      "conflict",
    );

    // A fresh request from a live key goes through, unsealed.
    await harness.client.execute("DELETE FROM operation");
    const live = await harness.cfAuth.service.createApiKey({
      organizationId: owner.organizationId,
      actor: ownerActor,
      name: "CLI 2",
    });
    const liveOpener = await harness.cfAuth.service.resolveApiKeyAuthState(live.plaintext, "cli");
    const token2 = createOperationToken();
    const second = await operations.open({ kind: "grant", token: token2, payload: { note: "hi" }, opener: liveOpener });
    await operations.approve({ id: second.id, proof: second.browserProof!, actor: ownerActor });
    const polled = await operations.poll({ id: second.id, token: token2 });
    expect(polled).toMatchObject({
      state: "completed",
      collect: null,
      record: { granted: "hi", organizationId: owner.organizationId },
    });
  });

  it("lets an approver with no role requirement attach only an organization they belong to", async () => {
    const adopt = defineOperationKind({
      name: "adopt",
      open: "public",
      browser: true,
      approverMinRole: null,
      approve: ({ organizationId }) => ({ outcome: { organizationId } }),
    });
    const pinned = defineOperationKind({ ...adopt, name: "adopt.pinned", open: { minRole: "member" } });
    const byProof = defineOperationKind({ ...adopt, name: "adopt.proof", approver: "proof" });
    const harness = await createTestAuth(enabled({ kinds: [adopt, pinned, byProof] }));
    const { operations } = harness.cfAuth;
    const owner = await harness.sessions.human();
    const stranger = await harness.sessions.human();
    const strangerActor = await harness.actorFor(stranger.userId);

    const token = createOperationToken();
    const opened = await operations.open({ kind: "adopt", token });
    for (const organizationId of [owner.organizationId, "no-such-organization"]) {
      await expectCode(
        operations.approve({ id: opened.id, proof: opened.browserProof!, actor: strangerActor, organizationId }),
        "not_a_member",
      );
    }
    await operations.approve({
      id: opened.id,
      proof: opened.browserProof!,
      actor: strangerActor,
      organizationId: stranger.organizationId,
    });
    expect((await operations.poll({ id: opened.id, token })).organizationId).toBe(stranger.organizationId);

    // Without a requested organization, a live session is enough.
    const bare = await operations.open({ kind: "adopt", token: createOperationToken() });
    await operations.approve({ id: bare.id, proof: bare.browserProof!, actor: strangerActor });

    // An organization fixed by the opener cannot be swapped for another.
    const pinnedOpened = await operations.open({
      kind: "adopt.pinned",
      token: createOperationToken(),
      opener: await harness.actorFor(owner.userId),
    });
    await expectCode(
      operations.approve({
        id: pinnedOpened.id,
        proof: pinnedOpened.browserProof!,
        actor: strangerActor,
        organizationId: stranger.organizationId,
      }),
      "forbidden",
    );

    // A proof-approved kind has nobody to vouch for a membership.
    const proofOpened = await operations.open({ kind: "adopt.proof", token: createOperationToken() });
    await expectCode(
      operations.approve({ id: proofOpened.id, proof: proofOpened.browserProof!, organizationId: owner.organizationId }),
      "validation_error",
    );
  });

  it("withholds a sealed outcome once the credential that opened it is revoked", async () => {
    const sealedGrant = defineOperationKind({
      name: "grant.sealed",
      open: { minRole: "member" },
      browser: true,
      approverMinRole: "admin",
      approve: () => ({ outcome: { secret: "s" }, seal: true }),
    });
    const windowed = defineOperationKind({ ...sealedGrant, name: "grant.window", deliver: "window" });
    const harness = await createTestAuth(enabled({ kinds: [sealedGrant, windowed] }));
    const { operations, service } = harness.cfAuth;
    const owner = await harness.sessions.human();
    const ownerActor = await harness.actorFor(owner.userId);
    const key = await service.createApiKey({ organizationId: owner.organizationId, actor: ownerActor, name: "CLI" });
    const opener = await service.resolveApiKeyAuthState(key.plaintext, "cli");

    const openApproved = async (kind: string, loopbackRedirect?: string) => {
      const token = createOperationToken();
      const opened = await operations.open({
        kind,
        token,
        opener,
        ...(loopbackRedirect ? { client: { loopbackRedirect } } : {}),
      });
      const approval = await operations.approve({ id: opened.id, proof: opened.browserProof!, actor: ownerActor });
      return { token, id: opened.id, redeemCode: approval.redeemCode };
    };
    const once = await openApproved("grant.sealed");
    const window = await openApproved("grant.window");
    const loop = await openApproved("grant.sealed", "http://127.0.0.1:5000/cb");

    await service.revokeApiKey({ organizationId: owner.organizationId, actor: ownerActor, apiKeyId: key.id });

    for (const operation of [once, window]) {
      const polled = await operations.poll({ id: operation.id, token: operation.token });
      expect(polled).toMatchObject({ state: "completed", collect: null });
      expect(polled).not.toHaveProperty("outcome");
    }
    await expectCode(
      operations.redeem({ id: loop.id, token: loop.token, redeemCode: loop.redeemCode! }),
      "operation_expired",
    );
  });

  it("answers a proof kind only with its proof, and judges the viewer alike in details and approve", async () => {
    const signedIn = defineOperationKind({
      name: "needs.person",
      open: "public",
      browser: true,
      userCode: true,
      approver: "proof",
      refusal: ({ viewer }) => (viewer ? null : "sign_in_first"),
    });
    const harness = await createTestAuth(enabled({ kinds: [signedIn] }));
    const { operations, service } = harness.cfAuth;
    const human = await harness.sessions.human();
    const key = await service.createApiKey({
      organizationId: human.organizationId,
      actor: await harness.actorFor(human.userId),
      name: "CI",
    });
    const keyState = await service.resolveApiKeyAuthState(key.plaintext, "cli");
    const opened = await operations.open({ kind: "needs.person", token: createOperationToken() });

    await expectCode(operations.deny({ id: opened.id, userCode: opened.userCode! }), "invalid_proof");

    // An API key is not a viewer, on the page or at approval.
    const details = await operations.details({ id: opened.id, proof: opened.browserProof!, viewer: keyState });
    expect(details).toMatchObject({ viewer: null, blockedBy: "sign_in_first" });
    await expectCode(
      operations.approve({ id: opened.id, proof: opened.browserProof!, actor: keyState }),
      "sign_in_first",
    );

    // A person may approve, and anyone holding the proof may decline.
    expect((await operations.deny({ id: opened.id, proof: opened.browserProof! })).state).toBe("denied");
  });

  it("counts only browser kinds toward the pending caps unless a kind says otherwise", async () => {
    const write = defineOperationKind({ name: "write", open: { minRole: "member" }, browser: false });
    const counted = defineOperationKind({ ...write, name: "write.counted", countsTowardPending: true });
    const harness = await createTestAuth(enabled({ kinds: [write, counted, grant, bootstrap] }));
    const { operations } = harness.cfAuth;
    const human = await harness.sessions.human();
    const opener = await harness.actorFor(human.userId);

    // Eleven refused writes left pending trip neither the organization cap
    // (10) nor the opener cap (5), and neither do public ones sharing a key.
    for (let attempt = 0; attempt < 11; attempt += 1) {
      await operations.open({ kind: "write", token: createOperationToken(), opener });
      await operations.open({
        kind: "bootstrap",
        token: createOperationToken(),
        payload: { name: "x" },
        rateLimitKey: "203.0.113.9",
      });
    }

    // A browser kind still counts, and is still capped per opener.
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await operations.open({ kind: "grant", token: createOperationToken(), payload: { note: "n" }, opener });
    }
    await expectCode(
      operations.open({ kind: "grant", token: createOperationToken(), payload: { note: "n" }, opener }),
      "too_many_pending",
    );
    // So does a kind without one that opts in; the uncounted kind still opens.
    await expectCode(
      operations.open({ kind: "write.counted", token: createOperationToken(), opener }),
      "too_many_pending",
    );
    await operations.open({ kind: "write", token: createOperationToken(), opener });
  });

  it("lets only one of a racing claim approval and denial land", async () => {
    let cfAuth!: TestAuth["cfAuth"];
    let beforeBatch: (() => Promise<void>) | undefined;
    const claim = defineOperationKind({
      name: "claim",
      open: { minRole: "owner" },
      browser: true,
      approverMinRole: null,
      approve: async ({ actor, organizationId, operation, guard }) => {
        await beforeBatch?.();
        return {
          outcome: { claimed: organizationId },
          ...cfAuth.service.claimOrganizationStatements({
            actor: actor!,
            organizationId: organizationId!,
            provisioning: {
              userId: operation.openerUserId!,
              credentialId: operation.openerCredentialId!,
              revokeAccess: false,
            },
            condition: guard,
          }),
        };
      },
    });
    const harness = await createTestAuth(enabled({ kinds: [claim] }));
    cfAuth = harness.cfAuth;
    const { operations, service } = cfAuth;

    const unclaimed = async () => {
      const identity = await service.createServiceIdentity({ name: "CLI service" });
      const { organization } = await service.createOrganization(identity.id, "Unclaimed");
      await harness.client.execute({
        sql: "UPDATE organization SET expires_at = ? WHERE id = ?",
        args: [new Date(Date.now() + 86_400_000).toISOString(), organization.id],
      });
      const key = await service.issueServiceApiKey({ userId: identity.id, organizationId: organization.id, name: "boot" });
      const opener = await service.resolveApiKeyAuthState(key.plaintext, "cli");
      const opened = await operations.open({ kind: "claim", token: createOperationToken(), opener });
      return { organizationId: organization.id, opened };
    };
    const owners = async (organizationId: string) =>
      (
        await harness.client.execute({
          sql: `SELECT ou.user_id, u.kind FROM organization_user ou JOIN user u ON u.id = ou.user_id
                WHERE ou.organization_id = ? AND ou.role = 'owner'`,
          args: [organizationId],
        })
      ).rows.map((row) => row.kind);
    const claimer = await harness.sessions.human();
    const actor = await harness.actorFor(claimer.userId);

    // The denial commits after approval's pending check but before its batch.
    const first = await unclaimed();
    beforeBatch = async () => {
      await operations.deny({ id: first.opened.id, proof: first.opened.browserProof! });
    };
    await expectCode(
      operations.approve({ id: first.opened.id, proof: first.opened.browserProof!, actor }),
      "operation_denied",
    );
    expect(await owners(first.organizationId)).toEqual(["service"]);
    expect((await cfAuth.repository.findOrganization(first.organizationId))?.expiresAt).not.toBeNull();

    // The approval commits first: the claim lands, and the denial changes nothing.
    beforeBatch = undefined;
    const second = await unclaimed();
    await operations.approve({ id: second.opened.id, proof: second.opened.browserProof!, actor });
    await expectCode(
      operations.deny({ id: second.opened.id, proof: second.opened.browserProof! }),
      "already_completed",
    );
    expect((await owners(second.organizationId)).sort()).toEqual(["human", "service"]);
    expect((await cfAuth.repository.findOrganization(second.organizationId))?.expiresAt).toBeNull();
    expect(harness.events).toContainEqual({
      type: "organization.claimed",
      userId: claimer.userId,
      organizationId: second.organizationId,
    });
  });

  it("rejects conflicting or malformed kind declarations", async () => {
    await expect(createTestAuth(enabled({ kinds: [{ ...bootstrap, name: "login" }] }))).rejects.toMatchObject({
      code: "validation_error",
    });
    await expect(createTestAuth(enabled({ kinds: [bootstrap, bootstrap] }))).rejects.toMatchObject({
      code: "validation_error",
    });
    await expect(
      createTestAuth(enabled({ kinds: [{ ...bootstrap, name: "Bad Name" }] })),
    ).rejects.toMatchObject({ code: "validation_error" });
    await expect(
      createTestAuth(enabled({ kinds: [{ ...bootstrap, userCode: true }] })),
    ).rejects.toMatchObject({ code: "validation_error" });
  });
});

describe("api key provenance", () => {
  it("records source and label, defaulting to the console", async () => {
    const harness = await createTestAuth();
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);
    const plain = await harness.cfAuth.service.createApiKey({
      organizationId: human.organizationId,
      actor,
      name: "Plain",
    });
    const labelled = await harness.cfAuth.service.createApiKey({
      organizationId: human.organizationId,
      actor,
      name: "Deploy",
      source: "cli",
      label: "  CI on runner-4  ",
    });
    expect(plain).toMatchObject({ source: "console", label: null });
    expect(labelled).toMatchObject({ source: "cli", label: "CI on runner-4" });

    const listed = await harness.cfAuth.service.listApiKeys({ organizationId: human.organizationId, actor });
    expect(listed.map(({ source, label }) => ({ source, label }))).toEqual([
      { source: "console", label: null },
      { source: "cli", label: "CI on runner-4" },
    ]);

    await expectCode(
      harness.cfAuth.service.createApiKey({
        organizationId: human.organizationId,
        actor,
        name: "Bad",
        source: "Not A Source",
      }),
      "validation_error",
    );
  });

  it("lets a key holder revoke exactly its own key", async () => {
    const harness = await createTestAuth();
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);
    const mine = await harness.cfAuth.service.createApiKey({
      organizationId: human.organizationId,
      actor,
      name: "Mine",
    });
    const other = await harness.cfAuth.service.createApiKey({
      organizationId: human.organizationId,
      actor,
      name: "Other",
    });
    const keyState = await harness.cfAuth.service.resolveApiKeyAuthState(mine.plaintext, "cli");

    const revoked = await harness.cfAuth.service.revokeOwnApiKey({ actor: keyState });
    expect(revoked).toMatchObject({ id: mine.id, enabled: false });
    expect(revoked.revokedAt).not.toBeNull();

    expect((await harness.cfAuth.service.resolveApiKeyAuthState(mine.plaintext)).authenticated).toBe(false);
    expect((await harness.cfAuth.service.resolveApiKeyAuthState(other.plaintext)).authenticated).toBe(true);
    expect(harness.events).toContainEqual(
      expect.objectContaining({ type: "api_key.revoked", apiKeyId: mine.id }),
    );

    await expectCode(harness.cfAuth.service.revokeOwnApiKey({ actor }), "api_key_required");
    await expectCode(
      harness.cfAuth.service.revokeOwnApiKey({ actor: await harness.cfAuth.service.resolveApiKeyAuthState("nope") }),
      "unauthorized",
    );
  });
});

describe("operation grants", () => {
  /** A write a caller opens and an admin approves; the default grant, `manage`. */
  const change = defineOperationKind({
    name: "change",
    open: { minRole: "member" },
    browser: true,
    approve: () => ({ outcome: { changed: true }, seal: true }),
  });
  /** A read a caller opens and the app completes; declares `read`. */
  const report = defineOperationKind({
    name: "report",
    open: { minRole: "member" },
    browser: false,
    grant: "read",
  });
  /** A write the app completes itself; the default grant. */
  const apply = defineOperationKind({
    name: "apply",
    open: { minRole: "member" },
    browser: false,
  });
  const kinds: OperationKind[] = [change, report, apply];

  const keyState = async (harness: TestAuth, grant: "read" | "manage") => {
    const owner = await harness.sessions.human();
    const actor = await harness.actorFor(owner.userId);
    const key = await harness.cfAuth.service.createApiKey({
      organizationId: owner.organizationId,
      actor,
      name: `${grant} key`,
      grant,
    });
    return {
      owner,
      actor,
      key,
      opener: await harness.cfAuth.service.resolveApiKeyAuthState(key.plaintext, "cli"),
    };
  };

  it("issues the grant a login asks for, and keeps it in the record", async () => {
    const harness = await createTestAuth(enabled());
    const { operations } = harness.cfAuth;
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);
    const token = createOperationToken();

    const view = await operations.open({
      kind: "login",
      token,
      payload: { grant: "read" },
      client: { label: "Read-only agent" },
    });
    const details = await operations.details({ id: view.id, proof: view.browserProof!, viewer: actor });
    expect(details.payload).toEqual({ grant: "read" });

    await operations.approve({
      id: view.id,
      proof: view.browserProof!,
      actor,
      organizationId: human.organizationId,
    });
    const completed = await operations.poll({ id: view.id, token });
    const outcome = completed.outcome as { credential: { token: string }; apiKeyId: string };
    expect(completed.record).toEqual({
      organizationId: human.organizationId,
      apiKeyId: outcome.apiKeyId,
      grant: "read",
    });
    const state = await harness.cfAuth.service.resolveApiKeyAuthState(outcome.credential.token, "cli");
    expect(state).toMatchObject({ authenticated: true, grant: "read" });

    // An explicit grant is its own request: a resend may not change it, nor
    // drop it for the legacy spelling.
    const explicit = createOperationToken();
    const first = await operations.open({
      kind: "login",
      token: explicit,
      payload: { grant: "manage" },
      client: { label: "Agent" },
    });
    expect(
      (await operations.open({ kind: "login", token: explicit, payload: { grant: "manage" }, client: { label: "Agent" } })).id,
    ).toBe(first.id);
    await expectCode(
      operations.open({ kind: "login", token: explicit, payload: { grant: "read" }, client: { label: "Agent" } }),
      "conflict",
    );
    await expectCode(
      operations.open({ kind: "login", token: explicit, client: { label: "Agent" } }),
      "conflict",
    );
  });

  it("keeps a login opened without a payload as it was stored before grants, meaning manage", async () => {
    const harness = await createTestAuth(enabled());
    const { operations } = harness.cfAuth;
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);
    const token = createOperationToken();

    const first = await operations.open({ kind: "login", token, client: { label: "Old CLI" } });
    // Stored and hashed exactly as before grants existed: no payload.
    const row = (
      await harness.client.execute({
        sql: "SELECT payload, request_hash FROM operation WHERE id = ?",
        args: [first.id],
      })
    ).rows[0]!;
    expect(row.payload).toBeNull();
    expect(row.request_hash).toBe(await sha256Hex(JSON.stringify(["login", null, null, null])));

    // The CLI repeating the identical open is answered, not refused.
    const repeated = await operations.open({ kind: "login", token, client: { label: "Old CLI" } });
    expect(repeated.id).toBe(first.id);
    const withNull = await operations.open({ kind: "login", token, payload: null, client: { label: "Old CLI" } });
    expect(withNull.id).toBe(first.id);

    // Everywhere it is read, no payload means manage.
    const details = await operations.details({ id: first.id, proof: first.browserProof!, viewer: actor });
    expect(details.payload).toEqual({ grant: "manage" });
    await operations.approve({
      id: first.id,
      proof: first.browserProof!,
      actor,
      organizationId: human.organizationId,
    });
    const completed = await operations.poll({ id: first.id, token });
    expect(completed.record).toMatchObject({ grant: "manage" });
    const outcome = completed.outcome as { credential: { token: string } };
    expect((await harness.cfAuth.service.resolveApiKeyAuthState(outcome.credential.token)).grant).toBe("manage");
  });

  it("refuses a login payload that is not a grant", async () => {
    const harness = await createTestAuth(enabled());
    const { operations } = harness.cfAuth;
    for (const payload of [{ grant: "admin" }, { grant: "read", scope: "all" }, "read", ["read"]]) {
      await expectCode(
        operations.open({
          kind: "login",
          token: createOperationToken(),
          payload,
          client: { label: "Agent" },
        }),
        "validation_error",
      );
    }
  });

  it("refuses to open a kind from a key whose grant is below the kind's", async () => {
    const harness = await createTestAuth(enabled({ kinds }));
    const { operations } = harness.cfAuth;
    const { opener: reader } = await keyState(harness, "read");
    const { opener: manager, actor } = await keyState(harness, "manage");

    await expectCode(
      operations.open({ kind: "change", token: createOperationToken(), opener: reader }),
      "grant_insufficient",
    );
    await expectCode(
      operations.open({ kind: "apply", token: createOperationToken(), opener: reader }),
      "grant_insufficient",
    );

    // A kind that only reads accepts a read key, and completes under it.
    const read = await operations.open({ kind: "report", token: createOperationToken(), opener: reader });
    expect(await operations.complete({ id: read.id, outcome: { rows: 3 } })).toMatchObject({
      state: "completed",
    });

    // A session and a manage key open a manage kind.
    await operations.open({ kind: "change", token: createOperationToken(), opener: manager });
    await operations.open({ kind: "change", token: createOperationToken(), opener: actor });
  });

  it("rechecks the opener's grant when the write lands", async () => {
    const harness = await createTestAuth(enabled({ kinds }));
    const { operations } = harness.cfAuth;
    const { opener, actor, key } = await keyState(harness, "manage");

    const approved = await operations.open({ kind: "change", token: createOperationToken(), opener });
    const completed = await operations.open({ kind: "apply", token: createOperationToken(), opener });

    // The key no longer carries `manage` by the time either write lands.
    await harness.client.execute({
      sql: `UPDATE api_key SET "grant" = 'read' WHERE id = ?`,
      args: [key.id],
    });

    await expectCode(
      operations.approve({ id: approved.id, proof: approved.browserProof!, actor }),
      "conflict",
    );
    await expectCode(operations.complete({ id: completed.id, outcome: {} }), "conflict");
    expect(await harness.cfAuth.service.resolveApiKeyAuthState(key.plaintext)).toMatchObject({
      grant: "read",
    });
  });

  it("refuses the completion once the opener's row is no longer exactly a key", async () => {
    const harness = await createTestAuth(enabled({ kinds }));
    const { operations } = harness.cfAuth;
    const { opener, key } = await keyState(harness, "manage");
    const typeIs = (value: string) =>
      harness.client.execute({ sql: "UPDATE api_key SET credential_type = ? WHERE id = ?", args: [value, key.id] });

    const opened = await operations.open({ kind: "apply", token: createOperationToken(), opener });
    await typeIs("other");

    // Neither fresh authentication nor the write's recheck accepts it.
    expect((await harness.cfAuth.service.resolveApiKeyAuthState(key.plaintext)).authenticated).toBe(false);
    await expectCode(operations.complete({ id: opened.id, outcome: {} }), "conflict");
    const state = async () =>
      (await harness.client.execute({ sql: "SELECT state FROM operation WHERE id = ?", args: [opened.id] })).rows[0]
        ?.state;
    expect(await state()).toBe("pending");

    // Restored, the same operation completes: nothing but the type refused it.
    await typeIs("apiKey");
    await operations.complete({ id: opened.id, outcome: {} });
    expect(await state()).toBe("completed");
  });

  it("withholds a sealed manage outcome from a downgraded key, even once its kind is gone", async () => {
    const harness = await createTestAuth(enabled({ kinds }));
    const { opener, actor, key } = await keyState(harness, "manage");
    const withoutKinds = createCfAuth({
      appName: "Test App",
      secret: testSecret,
      db: harness.db,
      apiKeys: { enabled: true },
      operations: { enabled: true, realm: "test-deployment" },
      onError: () => {},
    }).operations;

    // Collected by poll: a kind the app completes.
    const pollToken = createOperationToken();
    const polled = await harness.cfAuth.operations.open({ kind: "apply", token: pollToken, opener });
    await harness.cfAuth.operations.complete({
      id: polled.id,
      outcome: { secret: "only-for-manage" },
      seal: true,
    });

    // Collected by redeem: a browser kind with a loopback redirect.
    const redeemToken = createOperationToken();
    const redeemed = await harness.cfAuth.operations.open({
      kind: "change",
      token: redeemToken,
      opener,
      client: { loopbackRedirect: "http://127.0.0.1:5000/cb" },
    });
    const approval = await harness.cfAuth.operations.approve({
      id: redeemed.id,
      proof: redeemed.browserProof!,
      actor,
    });

    await harness.client.execute({
      sql: `UPDATE api_key SET "grant" = 'read' WHERE id = ?`,
      args: [key.id],
    });

    for (const operations of [harness.cfAuth.operations, withoutKinds]) {
      const answer = await operations.poll({ id: polled.id, token: pollToken });
      expect(answer).not.toHaveProperty("outcome");
      await expectCode(
        operations.redeem({ id: redeemed.id, token: redeemToken, redeemCode: approval.redeemCode! }),
        "operation_expired",
      );
    }
    // Withheld, not spent: it is still sealed, waiting for a key that may have it.
    const sealed = (
      await harness.client.execute({
        sql: "SELECT id FROM operation WHERE sealed_outcome IS NOT NULL ORDER BY id",
        args: [],
      })
    ).rows.map((row) => row.id);
    expect(sealed.sort()).toEqual([polled.id, redeemed.id].sort());
  });

  it("rejects a grant on a public kind, and one that is not a grant", async () => {
    await expect(
      createTestAuth(
        enabled({ kinds: [defineOperationKind({ name: "open", open: "public", browser: false, grant: "read" })] }),
      ),
    ).rejects.toMatchObject({ code: "validation_error" });
    await expect(
      createTestAuth(enabled({ kinds: [{ ...apply, grant: "all" as "read" }] })),
    ).rejects.toMatchObject({ code: "validation_error" });
  });
});
