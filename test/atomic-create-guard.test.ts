import { createClient } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { sql } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { createCfAuth } from "../src/cf-auth.js";
import type { CfAuthDatabase } from "../src/config.js";
import { createCfAuthTables } from "../src/schema.js";
import { createTestAuth, testSecret } from "./helpers.js";

const adapterFor = async (auth: ReturnType<typeof createCfAuth>) =>
  (await auth.auth.$context).adapter;

describe("atomic user create guard", () => {
  it("applies an arbitrary host predicate and preserves provisioning hooks", async () => {
    let allow = false;
    let denied = 0;
    const beforeCreate: string[] = [];
    const harness = await createTestAuth({
      userHooks: {
        beforeCreate: (user) => {
          beforeCreate.push(user.email!);
        },
        atomicCreateGuard: {
          condition: () => (allow ? sql`1` : sql`0`),
          onDenied: () => {
            denied += 1;
          },
        },
      },
    });

    const refused = await harness.request(`${harness.cfAuth.basePath}/sign-up/email`, {
      useJar: false,
      json: { email: "refused@example.test", password: "correct-horse-battery", name: "No" },
    });
    expect(refused.status).toBe(403);
    await expect(refused.json()).resolves.toMatchObject({ code: "REGISTRATION_DISABLED" });
    expect(denied).toBe(1);
    expect(beforeCreate).toEqual(["refused@example.test"]);

    allow = true;
    await harness.signUp({ email: "allowed@example.test", password: "correct-horse-battery" });
    const user = await harness.cfAuth.repository.findUserByEmail("allowed@example.test");
    expect(await harness.cfAuth.repository.listOrganizationsForUser(user!.id)).toHaveLength(1);
    expect(harness.events.map((event) => event.type)).toEqual([
      "user.signup",
      "organization.created",
    ]);
  });

  it("admits only one concurrent first human", async () => {
    const harness = await createTestAuth({
      organizations: { autoProvisionDefaultOrganization: false },
      userHooks: {
        atomicCreateGuard: {
          condition: (tables) =>
            sql`not exists (select 1 from ${tables.user} where ${tables.user.kind} = 'human')`,
        },
      },
    });
    const signup = (email: string) =>
      harness.request(`${harness.cfAuth.basePath}/sign-up/email`, {
        useJar: false,
        json: { email, password: "correct-horse-battery", name: email },
      });

    const responses = await Promise.all([signup("first@example.test"), signup("second@example.test")]);
    expect(responses.map((response) => response.status).sort()).toEqual([200, 403]);
    const count = await harness.client.execute(
      "select count(*) as count from user where kind = 'human'",
    );
    expect(Number(count.rows[0]?.count)).toBe(1);
  });

  it("cannot be bypassed through a transaction callback", async () => {
    const harness = await createTestAuth({
      organizations: { autoProvisionDefaultOrganization: false },
      userHooks: { atomicCreateGuard: { condition: () => sql`0` } },
    });
    const adapter = await adapterFor(harness.cfAuth);
    await expect(
      adapter.transaction((transaction) =>
        transaction.create({
          model: "user",
          data: { name: "Bypass", email: "bypass@example.test" },
        }),
      ),
    ).rejects.toMatchObject({ body: { code: "REGISTRATION_DISABLED" } });
    expect(await harness.cfAuth.repository.findUserByEmail("bypass@example.test")).toBeNull();
  });

  it("preserves ids, selected fields, dates, defaults, and human-only semantics", async () => {
    const harness = await createTestAuth({
      organizations: { autoProvisionDefaultOrganization: false },
      userHooks: { atomicCreateGuard: { condition: () => sql`1` } },
    });
    const adapter = await adapterFor(harness.cfAuth);
    const createdAt = new Date("2026-01-02T03:04:05.000Z");
    const updatedAt = new Date("2026-02-03T04:05:06.000Z");
    const selected = await adapter.create({
      model: "user",
      forceAllowId: true,
      select: ["id", "email"],
      data: {
        id: "chosen-id",
        name: "Chosen",
        email: "chosen@example.test",
        emailVerified: true,
        createdAt,
        updatedAt,
      },
    });
    expect(selected).toEqual({ id: "chosen-id", email: "chosen@example.test" });
    const row = await harness.client.execute({
      sql: "select id, kind, email_verified, created_at, updated_at from user where id = ?",
      args: ["chosen-id"],
    });
    expect(row.rows[0]).toMatchObject({
      id: "chosen-id",
      kind: "human",
      email_verified: 1,
      created_at: createdAt.getTime(),
      updated_at: updatedAt.getTime(),
    });
    await expect(
      adapter.create({
        model: "user",
        data: { name: "Service", email: "service@example.test", kind: "service" },
      }),
    ).rejects.toThrow(/human identity kind/);
  });

  it("uses the configured physical user table", async () => {
    const client = createClient({ url: ":memory:" });
    const tables = createCfAuthTables({ tablePrefix: "custom_" });
    await client.execute(`create table custom_user (
      id text primary key, name text not null, email text, kind text default 'human' not null,
      email_verified integer default false not null, image text,
      created_at integer not null, updated_at integer not null
    )`);
    const db = drizzle(client, { schema: tables }) as unknown as CfAuthDatabase;
    const auth = createCfAuth({
      appName: "Custom Tables",
      secret: testSecret,
      db,
      tables,
      organizations: { autoProvisionDefaultOrganization: false },
      userHooks: { atomicCreateGuard: { condition: () => sql`1` } },
    });
    try {
      const created = await (await adapterFor(auth)).create({
        model: "user",
        data: { name: "Custom", email: "custom@example.test" },
      }) as { email: string };
      expect(created.email).toBe("custom@example.test");
      expect((await client.execute("select kind from custom_user")).rows[0]?.kind).toBe("human");
    } finally {
      client.close();
    }
  });
});
