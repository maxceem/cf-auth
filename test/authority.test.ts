import { describe, expect, it } from "vitest";
import { createClient } from "@libsql/client";
import { credentialAuthorityCondition } from "../src/authority.js";
import { createCfAuthTables } from "../src/schema.js";
import type { OrganizationRole } from "../src/types.js";
import { createTestAuth } from "./helpers.js";

describe("credentialAuthorityCondition", () => {
  it("requires a live credential, active allowed membership, and matching identity scope", async () => {
    const harness = await createTestAuth();
    const human = await harness.sessions.human({ email: "authority@example.test" });
    const actor = await harness.actorFor(human.userId, human.organizationId);
    const key = await harness.cfAuth.service.createApiKey({
      organizationId: human.organizationId,
      actor,
      name: "Authority",
    });
    const allowed = async (
      credentialId: string,
      roles: readonly OrganizationRole[] = ["owner", "admin"],
      nowMs = Date.now(),
      organizationId = human.organizationId,
      userId = human.userId,
    ) => {
      const condition = credentialAuthorityCondition(harness.cfAuth.config.tables, {
        organizationId,
        userId,
        credentialId,
        allowedRoles: roles,
        nowMs,
      });
      const result = await harness.client.execute({
        sql: `select ${condition.sql} as allowed`,
        args: condition.params as (string | number | null | Uint8Array)[],
      });
      return Number(result.rows[0]?.allowed) === 1;
    };

    expect(await allowed(key.id)).toBe(true);
    expect(await allowed(human.sessionId)).toBe(true);
    expect(await allowed(key.id, [])).toBe(false);
    expect(await allowed(key.id, ["member"])).toBe(false);
    expect(await allowed(key.id, ["owner"], Date.now(), "wrong-organization")).toBe(false);
    expect(await allowed(key.id, ["owner"], Date.now(), human.organizationId, "wrong-user")).toBe(false);

    const expiryBoundary = Date.now() + 60_000;
    await harness.client.execute({
      sql: "update api_key set expires_at = ? where id = ?",
      args: [expiryBoundary, key.id],
    });
    expect(await allowed(key.id, ["owner"], expiryBoundary - 1)).toBe(true);
    expect(await allowed(key.id, ["owner"], expiryBoundary)).toBe(false);
    await harness.client.execute({
      sql: "update api_key set expires_at = null where id = ?",
      args: [key.id],
    });

    await harness.client.execute({
      sql: "update organization_user set role = 'member' where user_id = ?",
      args: [human.userId],
    });
    expect(await allowed(key.id)).toBe(false);
    await harness.client.execute({
      sql: "update organization_user set role = 'owner' where user_id = ?",
      args: [human.userId],
    });
    await harness.client.execute({
      sql: "update api_key set enabled = 0 where id = ?",
      args: [key.id],
    });
    expect(await allowed(key.id)).toBe(false);
    await harness.client.execute({
      sql: "update api_key set enabled = 1, revoked_at = ? where id = ?",
      args: [Date.now(), key.id],
    });
    expect(await allowed(key.id)).toBe(false);
    await harness.client.execute({
      sql: "update api_key set revoked_at = null, expires_at = ? where id = ?",
      args: [Date.now() - 1, key.id],
    });
    expect(await allowed(key.id)).toBe(false);

    await harness.client.execute({
      sql: "update user_session set expires_at = ? where id = ?",
      args: [Date.now() - 1, human.sessionId],
    });
    expect(await allowed(human.sessionId)).toBe(false);
  });

  it("uses the SQLite clock when it is later than the caller time", async () => {
    const harness = await createTestAuth();
    const human = await harness.sessions.human({ email: "clock@example.test" });
    await harness.client.execute({
      sql: "update user_session set expires_at = ? where id = ?",
      args: [Date.now() - 1, human.sessionId],
    });
    const condition = credentialAuthorityCondition(harness.cfAuth.config.tables, {
      organizationId: human.organizationId,
      userId: human.userId,
      credentialId: human.sessionId,
      allowedRoles: ["owner"],
      nowMs: 0,
    });
    const result = await harness.client.execute({
      sql: `select ${condition.sql} as allowed`,
      args: condition.params as (string | number | null | Uint8Array)[],
    });
    expect(Number(result.rows[0]?.allowed)).toBe(0);
  });

  it("executes against every physical table from a custom prefix", async () => {
    const client = createClient({ url: ":memory:" });
    try {
      for (const statement of [
        "create table private_user (id text primary key, kind text not null)",
        "create table private_organization_user (organization_id text, user_id text, role text, status text)",
        "create table private_api_key (id text, user_id text, organization_id text, enabled integer, revoked_at integer, expires_at integer)",
        "create table private_user_session (id text, user_id text, expires_at integer)",
        "insert into private_user values ('user', 'human')",
        "insert into private_organization_user values ('org', 'user', 'owner', 'active')",
        "insert into private_api_key values ('credential', 'user', 'org', 1, null, null)",
      ]) {
        await client.execute(statement);
      }
      const condition = credentialAuthorityCondition(
        createCfAuthTables({ tablePrefix: "private_" }),
        {
          organizationId: "org",
          userId: "user",
          credentialId: "credential",
          allowedRoles: ["owner"],
          nowMs: 1,
        },
      );
      const result = await client.execute({
        sql: `select ${condition.sql} as allowed`,
        args: condition.params as (string | number | null | Uint8Array)[],
      });
      expect(Number(result.rows[0]?.allowed)).toBe(1);
    } finally {
      client.close();
    }
  });
});
