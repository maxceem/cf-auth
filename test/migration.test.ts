import { describe, expect, it } from "vitest";
import { createTestAuth } from "./helpers.js";

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
    ]);
  });
});
