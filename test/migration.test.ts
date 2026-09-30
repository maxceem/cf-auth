import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createClient } from "@libsql/client";
import { describe, expect, it } from "vitest";
import { createTestAuth, migrationStatements } from "./helpers.js";

const grantMigration = fileURLToPath(
  new URL("../drizzle/0002_cf_auth_api_key_grant.sql", import.meta.url).href,
);

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
      "expires_at",
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
