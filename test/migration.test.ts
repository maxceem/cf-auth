import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createClient } from "@libsql/client";
import { describe, expect, it } from "vitest";
import { drizzle } from "drizzle-orm/libsql";
import { createCfAuth } from "../src/cf-auth.js";
import type { CfAuthDatabase } from "../src/config.js";
import { cfAuthTables } from "../src/schema.js";
import { createTestSessions } from "../src/testing.js";
import { createTestAuth, migrationStatements, testBaseUrl, testSecret } from "./helpers.js";

const grantMigration = fileURLToPath(
  new URL("../drizzle/0002_cf_auth_api_key_grant.sql", import.meta.url).href,
);
const oneZeroMigration = fileURLToPath(new URL("../drizzle/0007_cf_auth_1_0.sql", import.meta.url).href);

describe("initial schema", () => {
  it("keeps Better Auth verification ordinary and adds only identity/account fields", async () => {
    const harness = await createTestAuth();
    const columns = async (table: string) =>
      (await harness.client.execute(`PRAGMA table_info(${table})`)).rows.map((row) => row.name);

    expect(await columns("verification")).toEqual([
      "id",
      "identifier",
      "value",
      "expires_at",
      "created_at",
      "updated_at",
    ]);
    expect(await columns("organization")).toEqual([
      "id",
      "name",
      "created_by_user_id",
      "created_at",
      "updated_at",
    ]);
    expect(await columns("user")).toEqual([
      "id",
      "name",
      "email",
      "kind",
      "email_verified",
      "image",
      "created_at",
      "updated_at",
    ]);
    expect(await columns("api_key")).toEqual([
      "id",
      "user_id",
      "organization_id",
      "name",
      "token_hash",
      "token_hint",
      "enabled",
      "expires_at",
      "created_at",
      "revoked_at",
      "source",
      "label",
      "grant",
      "client_id",
      "resource",
      "credential_type",
    ]);
  });
});

describe("api key grant migration", () => {
  it("adds the column as a plain ALTER, defaulting to manage", async () => {
    const sql = (await readFile(grantMigration, "utf8")).trim();

    // One statement, and no table rebuild: every existing key is kept as is.
    expect(sql).toBe("ALTER TABLE `api_key` ADD `grant` text DEFAULT 'manage' NOT NULL;");
  });

  it("gives a fresh database the column, not null, defaulting to manage", async () => {
    const harness = await createTestAuth();
    const column = (await harness.client.execute("PRAGMA table_info(api_key)")).rows.find(
      (row) => row.name === "grant",
    );

    expect(column).toMatchObject({ type: "TEXT", notnull: 1, dflt_value: "'manage'" });
  });

  it("keeps a key that existed before it at manage", async () => {
    const client = createClient({ url: ":memory:" });
    try {
      const statements = await migrationStatements();
      const before = statements.filter((statement) => !statement.includes("`grant`"));
      const grant = statements.filter((statement) => statement.includes("`grant`"));
      expect(grant).toHaveLength(1);

      await client.batch(before, "write");
      await client.batch(
        [
          "INSERT INTO user (id, name, email, kind, email_verified, created_at, updated_at) VALUES ('svc', 'Service', NULL, 'service', 0, 0, 0)",
          "INSERT INTO organization (id, name, created_by_user_id, created_at, updated_at) VALUES ('org', 'Org', 'svc', 'x', 'x')",
          "INSERT INTO api_key (id, user_id, organization_id, name, token_hash, token_hint, created_at) VALUES ('old', 'svc', 'org', 'Old', 'hash', 'hint', 0)",
        ],
        "write",
      );
      await client.batch(grant, "write");

      const rows = (await client.execute("SELECT id, \"grant\" FROM api_key")).rows;
      expect(rows.map((row) => ({ id: row.id, grant: row.grant }))).toEqual([
        { id: "old", grant: "manage" },
      ]);
    } finally {
      client.close();
    }
  });
});

describe("the 1.0 migration", () => {
  for (const foreignKeys of ["ON", "OFF"] as const) {
    it(`removes unclaimed organizations with everything of theirs, and leaves claimed ones (foreign keys ${foreignKeys})`, async () => {
      const client = createClient({ url: ":memory:" });
      try {
        await client.execute(`PRAGMA foreign_keys=${foreignKeys}`);
        const statements = await migrationStatements();
        const oneZero = new Set(
          (await readFile(oneZeroMigration, "utf8"))
            .split("--> statement-breakpoint")
            .map((value) => value.trim())
            .filter(Boolean),
        );
        await client.batch(statements.filter((statement) => !oneZero.has(statement)), "write");

        // 1.0's code never reads the deadline, so it can arrange the 0.11 state.
        const cfAuth = createCfAuth({
          appName: "Test App",
          secret: testSecret,
          baseUrl: testBaseUrl,
          apiKeys: { enabled: true },
          db: drizzle(client, { schema: cfAuthTables }) as unknown as CfAuthDatabase,
        });
        const { service } = cfAuth;
        const unclaimedAccount = async (expiresAt: string) => {
          const identity = await service.createServiceIdentity({ name: "CLI service" });
          const { organization } = await service.createOrganization(identity.id, "Waiting");
          await client.execute({
            sql: "UPDATE organization SET expires_at = ? WHERE id = ?",
            args: [expiresAt, organization.id],
          });
          const key = await service.issueServiceApiKey({ userId: identity.id, organizationId: organization.id, name: "boot" });
          return { identityId: identity.id, organizationId: organization.id, key };
        };
        const expired = await unclaimedAccount(new Date(Date.now() - 60_000).toISOString());
        const waiting = await unclaimedAccount(new Date(Date.now() + 86_400_000).toISOString());
        // A claimed one: a person owns it, and its deadline was cleared.
        const claimed = await unclaimedAccount(new Date(Date.now() + 86_400_000).toISOString());
        const person = await createTestSessions(cfAuth).human();
        await client.batch(
          [
            {
              sql: "INSERT INTO organization_user (id, organization_id, user_id, role, status, joined_at) VALUES ('claim', ?, ?, 'owner', 'active', 'x')",
              args: [claimed.organizationId, person.userId],
            },
            { sql: "UPDATE organization SET expires_at = NULL WHERE id = ?", args: [claimed.organizationId] },
          ],
          "write",
        );
        // A service identity not given an organization yet.
        const unplaced = await service.createServiceIdentity({ name: "Not placed yet" });
        // Before 1.0, only the deadline kept the expired account's key out.
        expect((await service.resolveApiKeyAuthState(waiting.key.plaintext, "cli")).authenticated).toBe(true);

        await client.batch([...oneZero], "write");

        for (const gone of [expired, waiting]) {
          expect((await service.resolveApiKeyAuthState(gone.key.plaintext, "cli")).authenticated).toBe(false);
          for (const [table, column, value] of [
            ["organization", "id", gone.organizationId],
            ["organization_user", "organization_id", gone.organizationId],
            ["api_key", "organization_id", gone.organizationId],
          ] as const) {
            const rows = await client.execute({ sql: `SELECT 1 FROM "${table}" WHERE ${column} = ?`, args: [value] });
            expect(rows.rows, `${table} of ${gone.organizationId}`).toHaveLength(0);
          }
        }
        // Service identities stay: one left with no organization and no key can do nothing.
        for (const kept of [expired.identityId, waiting.identityId, unplaced.id]) {
          expect(await service.getIdentity(kept), kept).toMatchObject({ kind: "service" });
          const keys = await client.execute({ sql: "SELECT 1 FROM api_key WHERE user_id = ?", args: [kept] });
          expect(keys.rows, kept).toHaveLength(0);
        }
        expect((await service.resolveApiKeyAuthState(claimed.key.plaintext, "cli")).authenticated).toBe(true);
        expect(await cfAuth.repository.findMembership(person.userId, claimed.organizationId)).toMatchObject({ role: "owner" });
        expect((await client.execute("PRAGMA foreign_key_check")).rows).toEqual([]);
      } finally {
        client.close();
      }
    });
  }
});
