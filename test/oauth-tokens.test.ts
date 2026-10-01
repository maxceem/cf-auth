/**
 * OAuth connections (step 9): configuration, issuance, access-token
 * resolution, refresh with rotation, grace and reuse, revocation, the sweep,
 * and how an OAuth state is bound like any other delegated credential.
 *
 * The token paths run on libsql and on a real D1 (Miniflare, on workerd),
 * because every write here is one batch and the two drivers batch
 * differently.
 */
import { and, eq } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createCfAuth, type CfAuth } from "../src/cf-auth.js";
import { resolveConfig, type CfAuthConfig, type CfAuthDatabase, type OAuthConfig } from "../src/config.js";
import { createOperationToken, sha256Hex } from "../src/crypto.js";
import { createAuthMiddleware } from "../src/middleware.js";
import { defineOperationKind, type ExecuteOperationFunction } from "../src/operations.js";
import type { OAuthTokenResponse, OAuthTokenResult } from "../src/oauth/service.js";
import type { TestHuman } from "../src/testing.js";
import type { AuthState, CfAuthEvent, CredentialGrant } from "../src/types.js";
import { createD1TestAuth, createTestAuth, testBaseUrl, testSecret } from "./helpers.js";

const issuer = "https://console.example.com";
const tokenPrefix = { access: "agw_oat_", refresh: "agw_ort_" };
const clientId = "https://client.example.com/oauth/metadata.json";
const clientName = "Example Agent";
const day = 86_400_000;

/** A write a caller reserves and executes later: the default grant, `manage`. */
const apply = defineOperationKind({ name: "apply", open: { minRole: "member" }, browser: false });
/** A read a caller opens: grant `read`. */
const report = defineOperationKind({ name: "report", open: { minRole: "member" }, browser: false, grant: "read" });

const oauthOptions = (oauth: Partial<OAuthConfig> = {}) => ({
  operations: { enabled: true, kinds: [apply, report] },
  oauth: { enabled: true, issuer, tokenPrefix, ...oauth },
});

type Row = Record<string, unknown>;

interface Harness {
  cfAuth: CfAuth;
  events: CfAuthEvent[];
  human(): Promise<TestHuman>;
  actorFor(userId: string, organizationId?: string | null): Promise<AuthState>;
  exec(query: string, ...args: unknown[]): Promise<Row[]>;
  /** Another instance on the same database, with other OAuth settings. */
  variant(oauth: Partial<OAuthConfig>): CfAuth;
  close(): Promise<void> | void;
}

/**
 * libsql databases are in memory and closed after every test by the shared
 * helpers, so that harness is made per test; a Miniflare D1 is costly to
 * start, so that one is made once per file.
 */
const harnesses: Record<string, { perTest: boolean; make: () => Promise<Harness> }> = {
  libsql: { perTest: true, make: async () => {
    const t = await createTestAuth(oauthOptions());
    return {
      cfAuth: t.cfAuth,
      events: t.events,
      human: () => t.sessions.human(),
      actorFor: (userId, organizationId = null) => t.actorFor(userId, organizationId),
      exec: async (query, ...args) =>
        (await t.client.execute({ sql: query, args: args as never })).rows as unknown as Row[],
      variant: (oauth) =>
        createCfAuth({
          appName: "Test App",
          secret: testSecret,
          baseUrl: testBaseUrl,
          apiKeys: { enabled: true },
          ...oauthOptions(oauth),
          db: t.db,
        }),
      close: () => t.close(),
    };
  } },
  d1: { perTest: false, make: async () => {
    const t = await createD1TestAuth(oauthOptions());
    return {
      cfAuth: t.cfAuth,
      events: t.events,
      human: () => t.sessions.human(),
      actorFor: (userId, organizationId = null) => t.actorFor(userId, organizationId),
      exec: t.execute,
      variant: (oauth) =>
        createCfAuth({
          appName: "Test App",
          secret: testSecret,
          baseUrl: testBaseUrl,
          apiKeys: { enabled: true },
          ...oauthOptions(oauth),
          d1: t.d1,
        }),
      close: () => t.dispose(),
    };
  } },
};

const connectionIdOf = (token: string) => token.slice(tokenPrefix.access.length).split(".")[0]!;

const refreshBody = (refreshToken: string, extra: Record<string, string> = {}) =>
  new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: clientId, ...extra });

const ok = (result: OAuthTokenResult): OAuthTokenResponse => {
  expect(result.status).toBe(200);
  return result.body as OAuthTokenResponse;
};

/** Two parties released together once both have arrived. */
const barrier = (parties: number) => {
  let arrived = 0;
  let release!: () => void;
  const all = new Promise<void>((resolve) => (release = resolve));
  return async () => {
    arrived += 1;
    if (arrived >= parties) release();
    await all;
  };
};

afterEach(() => {
  vi.restoreAllMocks();
});

for (const [driver, { perTest, make }] of Object.entries(harnesses)) {
  describe(`OAuth connections on ${driver}`, () => {
    let h: Harness;

    if (perTest) {
      beforeEach(async () => {
        h = await make();
      });
    } else {
      beforeAll(async () => {
        h = await make();
      }, 60_000);
      afterAll(async () => {
        await h.close();
      });
    }

    const connect = async (
      input: { grant?: CredentialGrant; now?: number; cfAuth?: CfAuth; human?: TestHuman } = {},
    ) => {
      const human = input.human ?? (await h.human());
      const tokens = await (input.cfAuth ?? h.cfAuth).oauth.createConnection({
        userId: human.userId,
        organizationId: human.organizationId,
        clientId,
        clientName,
        resource: `${issuer}/mcp`,
        grant: input.grant ?? "manage",
        ...(input.now !== undefined ? { now: input.now } : {}),
      });
      return { human, tokens, connectionId: connectionIdOf(tokens.access_token) };
    };
    const refresh = (token: string, extra: Record<string, string> = {}, cfAuth = h.cfAuth) =>
      cfAuth.oauth.token({ body: refreshBody(token, extra) });
    const resolve = (token: string, source: "mcp" | "api" = "mcp") =>
      h.cfAuth.oauth.resolveAccessTokenAuthState(token, { source });
    const generations = (connectionId: string) =>
      h.exec("SELECT * FROM oauth_token WHERE api_key_id = ? ORDER BY generation", connectionId);
    const connectionRow = async (connectionId: string) =>
      (await h.exec("SELECT * FROM api_key WHERE id = ?", connectionId))[0]!;
    /** The whole stored state of a connection: its `api_key` row and every generation row. */
    const snapshot = async (connectionId: string) => ({
      row: (await h.exec("SELECT * FROM api_key WHERE id = ?", connectionId))[0] ?? null,
      generations: await generations(connectionId),
    });
    /** Moves the last rotation `ms` into the past. */
    const ageRotation = (connectionId: string, ms: number) =>
      h.exec(
        "UPDATE oauth_token SET rotated_at = rotated_at - ? WHERE api_key_id = ? AND rotated_at IS NOT NULL",
        ms,
        connectionId,
      );
    /** Holds this instance's first batch while `meanwhile` runs, then lets it write. */
    const holdFirstBatch = (meanwhile: () => Promise<unknown>) => {
      const db = h.cfAuth.config.db as CfAuthDatabase & { batch(q: unknown[]): Promise<unknown[]> };
      const batch = db.batch.bind(db);
      let calls = 0;
      vi.spyOn(db, "batch").mockImplementation(async (statements: unknown[]) => {
        calls += 1;
        if (calls === 1) await meanwhile();
        return batch(statements);
      });
    };
    /**
     * Runs `steps[n]` once the n-th read through drizzle's `select` has
     * answered and before its caller resumes: a deterministic interleaving
     * between a request's reads.
     */
    const afterEachRead = (steps: (() => Promise<unknown>)[]) => {
      const db = h.cfAuth.config.db;
      const select = db.select.bind(db);
      let reads = 0;
      const wrap = <T extends object>(target: T): T =>
        new Proxy(target, {
          get(object, property) {
            const value = Reflect.get(object, property, object) as unknown;
            if (typeof value !== "function") return value;
            if (property === "then") {
              return (resolve: (value: unknown) => unknown, reject: (reason: unknown) => unknown) =>
                (value as PromiseLike<unknown>["then"])
                  .call(object, async (result: unknown) => {
                    const step = steps[reads];
                    reads += 1;
                    if (step) await step();
                    return result;
                  })
                  .then(resolve, reject);
            }
            return (...args: unknown[]) => {
              const result = (value as (...args: unknown[]) => unknown).apply(object, args);
              return result !== null && typeof result === "object" ? wrap(result) : result;
            };
          },
        });
      vi.spyOn(db, "select").mockImplementation(((...args: Parameters<typeof db.select>) =>
        wrap(select(...args))) as typeof db.select);
    };
    const forge = (token: string) => `${token.slice(0, token.lastIndexOf(".") + 1)}${"A".repeat(43)}`;

    describe("issuance", () => {
      it("issues prefixed tokens naming the connection, and stores only digests", async () => {
        const before = Date.now();
        const { human, tokens, connectionId } = await connect();

        expect(tokens).toEqual({
          access_token: expect.stringMatching(/^agw_oat_[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/),
          token_type: "Bearer",
          expires_in: 600,
          refresh_token: expect.stringMatching(/^agw_ort_[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/),
          scope: "manage",
        });
        expect(connectionIdOf(tokens.refresh_token.replace(tokenPrefix.refresh, tokenPrefix.access))).toBe(
          connectionId,
        );

        const [generation, ...rest] = await generations(connectionId);
        expect(rest).toHaveLength(0);
        expect(generation).toMatchObject({
          generation: 1,
          access_token_hash: await sha256Hex(tokens.access_token),
          refresh_token_hash: await sha256Hex(tokens.refresh_token),
          rotated_at: null,
          sealed_response: null,
        });
        expect(Number(generation!.access_expires_at)).toBeGreaterThanOrEqual(before + 600_000);

        const row = await connectionRow(connectionId);
        expect(row).toMatchObject({
          user_id: human.userId,
          organization_id: human.organizationId,
          name: clientName,
          label: clientName,
          source: "oauth",
          client_id: clientId,
          resource: issuer,
          grant: "manage",
          enabled: 1,
          revoked_at: null,
        });
        expect(row.token_hash).not.toBe(await sha256Hex(tokens.access_token));
        expect(row.token_hash).not.toBe(await sha256Hex(tokens.refresh_token));
        const expiresAt = Number(row.expires_at);
        expect(expiresAt - Number(row.created_at)).toBe(30 * day);

        // No secret anywhere in the database.
        const everything = JSON.stringify([...(await generations(connectionId)), row]);
        for (const token of [tokens.access_token, tokens.refresh_token]) {
          expect(everything).not.toContain(token.slice(token.indexOf(".") + 1));
        }

        expect(h.events).toContainEqual({
          type: "api_key.created",
          actorUserId: human.userId,
          organizationId: human.organizationId,
          apiKeyId: connectionId,
          name: clientName,
          credentialType: "oauth",
        });
      });

      it("caps expires_at by connectionMaxAgeMs from creation, at issuance and at every rotation", async () => {
        const capped = h.variant({ connectionMaxAgeMs: day });
        const createdAt = Date.now() - day + 3_600_000;
        const { tokens, connectionId } = await connect({ cfAuth: capped, now: createdAt });
        expect(Number((await connectionRow(connectionId)).expires_at)).toBe(createdAt + day);

        ok(await refresh(tokens.refresh_token, {}, capped));
        expect(Number((await connectionRow(connectionId)).expires_at)).toBe(createdAt + day);
      });

      it("refuses a connection for a user who is not a member, and an unknown resource", async () => {
        const human = await h.human();
        const other = await h.human();
        await expect(
          h.cfAuth.oauth.createConnection({
            userId: other.userId,
            organizationId: human.organizationId,
            clientId,
            clientName,
            resource: issuer,
            grant: "read",
          }),
        ).rejects.toMatchObject({ code: "connection_refused", status: 409 });
        await expect(
          h.cfAuth.oauth.createConnection({
            userId: human.userId,
            organizationId: human.organizationId,
            clientId,
            clientName,
            resource: "https://elsewhere.example.com",
            grant: "read",
          }),
        ).rejects.toMatchObject({ code: "validation_error" });
      });
    });

    describe("access-token resolution", () => {
      it("resolves the current access token to an OAuth state with the caller's source", async () => {
        const { human, tokens, connectionId } = await connect({ grant: "read" });

        const state = await resolve(tokens.access_token, "mcp");
        expect(state).toMatchObject({
          authenticated: true,
          assurance: "credential",
          credentialType: "oauth",
          source: "mcp",
          grant: "read",
          actor: { type: "user", id: human.userId, kind: "human", credentialId: connectionId, actionSource: "mcp" },
          organization: { id: human.organizationId },
          role: "owner",
        });
        expect(state.memberships).toHaveLength(1);
        expect((await resolve(tokens.access_token, "api")).source).toBe("api");
        expect(
          (await h.cfAuth.oauth.resolveAccessTokenAuthState(tokens.access_token, { source: "cli" as never }))
            .authenticated,
        ).toBe(false);
        // A refresh token is not an access token, and an API key resolver never takes either.
        expect((await resolve(tokens.refresh_token)).authenticated).toBe(false);
        expect((await h.cfAuth.service.resolveApiKeyAuthState(tokens.access_token)).authenticated).toBe(false);
      });

      it("answers an empty state for an expired access token", async () => {
        const { tokens, connectionId } = await connect();
        await h.exec("UPDATE oauth_token SET access_expires_at = ? WHERE api_key_id = ?", Date.now() - 1, connectionId);
        expect((await resolve(tokens.access_token)).authenticated).toBe(false);
      });

      it("answers an empty state for a forged secret under a real connection id, and leaves it untouched", async () => {
        const { tokens, connectionId } = await connect();
        const before = await snapshot(connectionId);
        expect((await resolve(forge(tokens.access_token))).authenticated).toBe(false);
        expect((await resolve(`${tokens.access_token}x`)).authenticated).toBe(false);
        expect(await snapshot(connectionId)).toEqual(before);
        expect((await resolve(tokens.access_token)).authenticated).toBe(true);
      });

      it("answers an empty state when the connection is bound to another issuer", async () => {
        const { tokens, connectionId } = await connect();
        await h.exec("UPDATE api_key SET resource = ? WHERE id = ?", "https://other.example.com", connectionId);
        expect((await resolve(tokens.access_token)).authenticated).toBe(false);
      });

      it("answers an empty state for a revoked or expired connection, or an expired organization", async () => {
        const revoked = await connect();
        await h.exec("UPDATE api_key SET revoked_at = ?, enabled = 0 WHERE id = ?", Date.now(), revoked.connectionId);
        expect((await resolve(revoked.tokens.access_token)).authenticated).toBe(false);

        const expired = await connect();
        await h.exec("UPDATE api_key SET expires_at = ? WHERE id = ?", Date.now() - 1, expired.connectionId);
        expect((await resolve(expired.tokens.access_token)).authenticated).toBe(false);

        const lapsed = await connect();
        await h.exec(
          "UPDATE organization SET expires_at = ? WHERE id = ?",
          new Date(Date.now() - 1000).toISOString(),
          lapsed.human.organizationId,
        );
        expect((await resolve(lapsed.tokens.access_token)).authenticated).toBe(false);
      });
    });

    describe("refresh", () => {
      it("rotates: new tokens, the old access token dead, the new one live, expires_at advanced", async () => {
        const { tokens, connectionId } = await connect({ now: Date.now() - 10 * day });
        const before = Number((await connectionRow(connectionId)).expires_at);

        const next = ok(await refresh(tokens.refresh_token, { resource: issuer, scope: "manage" }));
        expect(next.access_token).not.toBe(tokens.access_token);
        expect(next.refresh_token).not.toBe(tokens.refresh_token);
        expect(next).toMatchObject({ token_type: "Bearer", expires_in: 600, scope: "manage" });
        expect((await resolve(tokens.access_token)).authenticated).toBe(false);
        expect((await resolve(next.access_token)).authenticated).toBe(true);
        expect(Number((await connectionRow(connectionId)).expires_at)).toBeGreaterThan(before + 9 * day);

        const stored = await generations(connectionId);
        expect(stored.map((row) => row.generation)).toEqual([1, 2]);
        expect(stored[0]).toMatchObject({ rotated_at: expect.anything(), sealed_response: expect.any(String) });
        expect(stored[1]).toMatchObject({ rotated_at: null, sealed_response: null });
        // The sealed replay is not the response in the clear.
        expect(String(stored[0]!.sealed_response)).not.toContain(next.access_token.split(".")[1]!);
      });

      it("refuses a second rotation within 5 s, keeps the current token valid, and keeps two generations", async () => {
        const { tokens, connectionId } = await connect();
        const second = ok(await refresh(tokens.refresh_token));
        const before = await snapshot(connectionId);

        expect(await refresh(second.refresh_token)).toEqual({
          status: 400,
          body: { error: "invalid_grant", error_description: "slow down: refreshed too recently" },
        });
        expect(await snapshot(connectionId)).toEqual(before);
        expect((await resolve(second.access_token)).authenticated).toBe(true);

        await ageRotation(connectionId, 6_000);
        const third = ok(await refresh(second.refresh_token));
        expect((await generations(connectionId)).map((row) => row.generation)).toEqual([2, 3]);
        // The generation before the previous one is gone, so its token is unknown: no revocation.
        const beforeDiscarded = await snapshot(connectionId);
        expect((await refresh(tokens.refresh_token)).body).toMatchObject({ error: "invalid_grant" });
        expect(await snapshot(connectionId)).toEqual(beforeDiscarded);
        expect((await resolve(third.access_token)).authenticated).toBe(true);
      });

      it("replays the rotation byte for byte for the previous token inside 30 s", async () => {
        const { tokens, connectionId } = await connect();
        const rotated = await refresh(tokens.refresh_token);
        const before = await snapshot(connectionId);
        const replayed = await refresh(tokens.refresh_token);
        expect(await snapshot(connectionId)).toEqual(before);

        expect(replayed.status).toBe(200);
        expect(JSON.stringify(replayed.body)).toBe(JSON.stringify(rotated.body));
        expect((await generations(connectionId)).map((row) => row.generation)).toEqual([1, 2]);
        expect((await resolve((rotated.body as OAuthTokenResponse).access_token)).authenticated).toBe(true);
      });

      it("revokes the whole connection when the previous token returns after 30 s", async () => {
        const { human, tokens, connectionId } = await connect();
        const next = ok(await refresh(tokens.refresh_token));
        await ageRotation(connectionId, 31_000);

        expect(await refresh(tokens.refresh_token)).toEqual({
          status: 400,
          body: {
            error: "invalid_grant",
            error_description: "The refresh token was already used; the connection is revoked",
          },
        });
        const row = await connectionRow(connectionId);
        expect(row.revoked_at).not.toBeNull();
        expect(row.enabled).toBe(0);
        expect(await generations(connectionId)).toHaveLength(0);
        expect((await resolve(next.access_token)).authenticated).toBe(false);
        expect((await refresh(next.refresh_token)).body).toMatchObject({ error: "invalid_grant" });
        expect(h.events).toContainEqual({
          type: "api_key.revoked",
          actorUserId: human.userId,
          organizationId: human.organizationId,
          apiKeyId: connectionId,
          name: clientName,
          credentialType: "oauth",
        });
      });

      it("answers invalid_grant for a forged refresh secret and leaves the connection live", async () => {
        const { tokens, connectionId } = await connect();
        const before = await snapshot(connectionId);
        expect((await refresh(forge(tokens.refresh_token))).body).toMatchObject({ error: "invalid_grant" });
        expect((await refresh("agw_ort_nope")).body).toMatchObject({ error: "invalid_grant" });
        expect(await snapshot(connectionId)).toEqual(before);
        ok(await refresh(tokens.refresh_token));
      });

      it("answers 401 invalid_client for another client_id, and changes nothing", async () => {
        const { tokens, connectionId } = await connect();
        const before = await snapshot(connectionId);
        const result = await refresh(tokens.refresh_token, { client_id: "https://evil.example.com/client.json" });
        expect(result).toMatchObject({ status: 401, body: { error: "invalid_client" } });
        expect(await snapshot(connectionId)).toEqual(before);
      });

      it("refuses a narrowed or widened scope, and a resource the connection is not bound to", async () => {
        const manage = await connect();
        const manageBefore = await snapshot(manage.connectionId);
        expect((await refresh(manage.tokens.refresh_token, { scope: "read" })).body).toMatchObject({
          error: "invalid_scope",
        });
        expect((await refresh(manage.tokens.refresh_token, { scope: "read manage" })).body).toMatchObject({
          error: "invalid_scope",
        });
        const read = await connect({ grant: "read" });
        const readBefore = await snapshot(read.connectionId);
        expect((await refresh(read.tokens.refresh_token, { scope: "manage" })).body).toMatchObject({
          error: "invalid_scope",
        });
        expect(await snapshot(read.connectionId)).toEqual(readBefore);
        expect(ok(await refresh(read.tokens.refresh_token, { scope: "read", resource: `${issuer}/mcp` })).scope).toBe(
          "read",
        );

        expect(
          (await refresh(manage.tokens.refresh_token, { resource: "https://evil.example.com" })).body,
        ).toMatchObject({ error: "invalid_target" });
        expect((await refresh(manage.tokens.refresh_token, { resource: `${issuer}/` })).body).toMatchObject({
          error: "invalid_target",
        });
        expect(await snapshot(manage.connectionId)).toEqual(manageBefore);
        await h.exec("UPDATE api_key SET resource = ? WHERE id = ?", "https://other.example.com", manage.connectionId);
        expect((await refresh(manage.tokens.refresh_token, { resource: issuer })).body).toMatchObject({
          error: "invalid_target",
        });
        const rebound = await snapshot(manage.connectionId);
        // Without a resource, a connection bound to another issuer is still not this one's to rotate.
        expect((await refresh(manage.tokens.refresh_token)).body).toMatchObject({ error: "invalid_grant" });
        expect(await snapshot(manage.connectionId)).toEqual(rebound);
      });

      it("answers invalid_request, unsupported_grant_type and the step 10 seam", async () => {
        const { tokens, connectionId } = await connect();
        const before = await snapshot(connectionId);
        const body = refreshBody(tokens.refresh_token);
        body.append("client_id", clientId);
        expect(await h.cfAuth.oauth.token({ body })).toMatchObject({
          status: 400,
          body: { error: "invalid_request" },
        });
        expect(
          (await h.cfAuth.oauth.token({ body: new URLSearchParams({ refresh_token: tokens.refresh_token }) })).body,
        ).toMatchObject({ error: "invalid_request" });
        expect(
          (
            await h.cfAuth.oauth.token({
              body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokens.refresh_token }),
            })
          ).body,
        ).toMatchObject({ error: "invalid_request" });
        expect(
          (await h.cfAuth.oauth.token({ body: new URLSearchParams({ grant_type: "password" }) })).body,
        ).toMatchObject({ error: "unsupported_grant_type" });
        expect(
          (await h.cfAuth.oauth.token({ body: new URLSearchParams({ grant_type: "authorization_code", code: "x" }) }))
            .body,
        ).toMatchObject({ error: "unsupported_grant_type" });
        // Nothing above touched the connection.
        expect(await snapshot(connectionId)).toEqual(before);
        ok(await refresh(tokens.refresh_token));
      });

      it("answers invalid_grant without changing a connection that is revoked, expired, or whose membership or organization ended", async () => {
        const cases: [string, (c: Awaited<ReturnType<typeof connect>>) => Promise<unknown>][] = [
          ["revoked", (c) => h.exec("UPDATE api_key SET revoked_at = ?, enabled = 0 WHERE id = ?", Date.now(), c.connectionId)],
          ["expired", (c) => h.exec("UPDATE api_key SET expires_at = ? WHERE id = ?", Date.now() - 1, c.connectionId)],
          [
            "organization expired",
            (c) =>
              h.exec(
                "UPDATE organization SET expires_at = ? WHERE id = ?",
                new Date(Date.now() - 1000).toISOString(),
                c.human.organizationId,
              ),
          ],
          [
            "membership removed",
            (c) =>
              h.exec(
                "DELETE FROM organization_user WHERE user_id = ? AND organization_id = ?",
                c.human.userId,
                c.human.organizationId,
              ),
          ],
        ];
        for (const [name, end] of cases) {
          const connected = await connect();
          await end(connected);
          const before = await snapshot(connected.connectionId);
          expect((await refresh(connected.tokens.refresh_token)).body, name).toMatchObject({ error: "invalid_grant" });
          expect(await snapshot(connected.connectionId), name).toEqual(before);
        }
      });

      it("rotates once when the same token is presented twice at once; the loser replays", async () => {
        const { tokens, connectionId } = await connect();
        const db = h.cfAuth.config.db as CfAuthDatabase & { batch(q: unknown[]): Promise<unknown[]> };
        const batch = db.batch.bind(db);
        const arrive = barrier(2);
        let calls = 0;
        vi.spyOn(db, "batch").mockImplementation(async (statements: unknown[]) => {
          calls += 1;
          // Both presentations have read the same generation before either writes.
          if (calls <= 2) await arrive();
          return batch(statements);
        });

        const [one, two] = await Promise.all([refresh(tokens.refresh_token), refresh(tokens.refresh_token)]);
        vi.restoreAllMocks();

        expect(one.status).toBe(200);
        expect(two.status).toBe(200);
        expect(JSON.stringify(one.body)).toBe(JSON.stringify(two.body));
        expect(calls).toBe(2);
        const stored = await generations(connectionId);
        expect(stored.map((row) => row.generation)).toEqual([1, 2]);
        expect((await connectionRow(connectionId)).revoked_at).toBeNull();
        expect((await resolve((one.body as OAuthTokenResponse).access_token)).authenticated).toBe(true);
      });

      it("revokes when a racing rotation lost and the winner's is already outside the grace", async () => {
        const { tokens, connectionId } = await connect();
        const db = h.cfAuth.config.db as CfAuthDatabase & { batch(q: unknown[]): Promise<unknown[]> };
        const batch = db.batch.bind(db);
        let calls = 0;
        vi.spyOn(db, "batch").mockImplementation(async (statements: unknown[]) => {
          calls += 1;
          // Another presentation rotates first, and that was long ago.
          if (calls === 1) {
            const other = await h.variant({}).oauth.token({ body: refreshBody(tokens.refresh_token) });
            expect(other.status).toBe(200);
            await ageRotation(connectionId, 31_000);
          }
          return batch(statements);
        });

        const result = await refresh(tokens.refresh_token);
        vi.restoreAllMocks();
        expect(result.body).toMatchObject({ error: "invalid_grant" });
        expect((await connectionRow(connectionId)).revoked_at).not.toBeNull();
        expect(await generations(connectionId)).toHaveLength(0);
      });
    });

    describe("a verified presentation whose rotation writes nothing", () => {

      it("revokes a live connection whose generation was rotated past, three generations on", async () => {
        const { tokens, connectionId } = await connect();
        const other = h.variant({});
        let third: OAuthTokenResponse | undefined;
        holdFirstBatch(async () => {
          // Generation 1 was read as current; meanwhile it is rotated to 2,
          // and, outside the grace and the rate limit, 2 to 3, which deletes 1.
          const second = ok(await other.oauth.token({ body: refreshBody(tokens.refresh_token) }));
          await ageRotation(connectionId, 31_000);
          third = ok(await other.oauth.token({ body: refreshBody(second.refresh_token) }));
          expect((await generations(connectionId)).map((row) => row.generation)).toEqual([2, 3]);
        });

        expect(await refresh(tokens.refresh_token)).toEqual({
          status: 400,
          body: {
            error: "invalid_grant",
            error_description: "The refresh token was already used; the connection is revoked",
          },
        });
        vi.restoreAllMocks();
        expect((await connectionRow(connectionId)).revoked_at).not.toBeNull();
        expect(await generations(connectionId)).toHaveLength(0);
        expect((await resolve(third!.access_token)).authenticated).toBe(false);
      });

      it("changes nothing when the connection itself ended in the meantime", async () => {
        const { tokens, connectionId } = await connect();
        let before: Awaited<ReturnType<typeof snapshot>> | undefined;
        holdFirstBatch(async () => {
          const revoked = await h.variant({}).oauth.revoke({
            body: new URLSearchParams({ token: tokens.access_token, client_id: clientId }),
          });
          expect(revoked.status).toBe(200);
          before = await snapshot(connectionId);
        });

        expect(await refresh(tokens.refresh_token)).toEqual({
          status: 400,
          body: { error: "invalid_grant", error_description: "The connection is no longer live" },
        });
        vi.restoreAllMocks();
        expect(await snapshot(connectionId)).toEqual(before);
      });
    });

    describe("ended authority takes precedence over replay and reuse", () => {
      type Connected = Awaited<ReturnType<typeof connect>>;
      const endings: Record<string, (c: Connected) => Promise<unknown>> = {
        "membership removed": (c) =>
          h.exec(
            "DELETE FROM organization_user WHERE user_id = ? AND organization_id = ?",
            c.human.userId,
            c.human.organizationId,
          ),
        "organization expired": (c) =>
          h.exec(
            "UPDATE organization SET expires_at = ? WHERE id = ?",
            new Date(Date.now() - 1000).toISOString(),
            c.human.organizationId,
          ),
        // A revocation that left the generations in place, as a direct write would.
        "connection revoked": (c) =>
          h.exec("UPDATE api_key SET revoked_at = ?, enabled = 0 WHERE id = ?", Date.now() - 1, c.connectionId),
      };

      for (const [ending, end] of Object.entries(endings)) {
        for (const grace of ["inside", "outside"] as const) {
          it(`answers invalid_grant and changes nothing: ${ending} after another rotation, ${grace} the grace`, async () => {
            const connected = await connect();
            const { tokens, connectionId } = connected;
            let before: Row | undefined;
            let generationsBefore: Row[] = [];
            holdFirstBatch(async () => {
              // A read generation 1 as current; B rotates it, then the authority ends.
              ok(await h.variant({}).oauth.token({ body: refreshBody(tokens.refresh_token) }));
              if (grace === "outside") await ageRotation(connectionId, 31_000);
              await end(connected);
              before = await connectionRow(connectionId);
              generationsBefore = await generations(connectionId);
            });

            expect(await refresh(tokens.refresh_token)).toEqual({
              status: 400,
              body: { error: "invalid_grant", error_description: "The connection is no longer live" },
            });
            vi.restoreAllMocks();
            const stored = await generations(connectionId);
            expect(stored.map((row) => row.generation)).toEqual([1, 2]);
            expect(stored[0]!.rotated_at).not.toBeNull();
            expect(stored).toEqual(generationsBefore);
            expect(await connectionRow(connectionId)).toEqual(before);
          });
        }
      }

      it("answers invalid_grant and keeps the generations when the connection was revoked in place meanwhile", async () => {
        const connected = await connect();
        let before: Awaited<ReturnType<typeof snapshot>> | undefined;
        holdFirstBatch(async () => {
          await endings["connection revoked"]!(connected);
          before = await snapshot(connected.connectionId);
        });

        expect((await refresh(connected.tokens.refresh_token)).body).toEqual({
          error: "invalid_grant",
          error_description: "The connection is no longer live",
        });
        vi.restoreAllMocks();
        expect(before!.generations).toHaveLength(1);
        expect(await snapshot(connected.connectionId)).toEqual(before);
      });

      it("conditions the reuse revocation on live authority inside its own batch", async () => {
        const connected = await connect();
        const { tokens, connectionId } = connected;
        ok(await refresh(tokens.refresh_token));
        await ageRotation(connectionId, 31_000);
        // Reuse is detected on a live connection; the membership ends before
        // the revocation's batch lands.
        let before: Awaited<ReturnType<typeof snapshot>> | undefined;
        holdFirstBatch(async () => {
          await endings["membership removed"]!(connected);
          before = await snapshot(connectionId);
        });

        expect((await refresh(tokens.refresh_token)).body).toEqual({
          error: "invalid_grant",
          error_description: "The connection is no longer live",
        });
        vi.restoreAllMocks();
        expect(before!.generations.map((row) => row.generation)).toEqual([1, 2]);
        expect(await snapshot(connectionId)).toEqual(before);
      });

      it("decides from one snapshot: authority that is never wholly live during recovery is not live", async () => {
        const connected = await connect();
        const { human, tokens, connectionId } = connected;
        const [member] = await h.exec(
          "SELECT * FROM organization_user WHERE user_id = ? AND organization_id = ?",
          human.userId,
          human.organizationId,
        );
        let before: Awaited<ReturnType<typeof snapshot>> | undefined;
        holdFirstBatch(async () => {
          // B rotates and the membership is removed; then, as recovery reads,
          // the connection is revoked in place and the membership restored.
          ok(await h.variant({}).oauth.token({ body: refreshBody(tokens.refresh_token) }));
          await endings["membership removed"]!(connected);
          before = await snapshot(connectionId);
          afterEachRead([
            async () => {
              await endings["connection revoked"]!(connected);
              before = await snapshot(connectionId);
            },
            async () => {
              await h.exec(
                "INSERT INTO organization_user (id, organization_id, user_id, role, status, joined_at) VALUES (?, ?, ?, ?, ?, ?)",
                member!.id,
                member!.organization_id,
                member!.user_id,
                member!.role,
                member!.status,
                member!.joined_at,
              );
              before = await snapshot(connectionId);
            },
          ]);
        });

        expect((await refresh(tokens.refresh_token)).body).toEqual({
          error: "invalid_grant",
          error_description: "The connection is no longer live",
        });
        vi.restoreAllMocks();
        expect(await snapshot(connectionId)).toEqual(before);
      });

      it("deletes no generation when a concurrent revocation in the same millisecond matched instead", async () => {
        const connected = await connect();
        const { tokens, connectionId } = connected;
        ok(await refresh(tokens.refresh_token));
        await ageRotation(connectionId, 31_000);
        const at = Date.now();
        vi.spyOn(Date, "now").mockReturnValue(at);
        let before: Awaited<ReturnType<typeof snapshot>> | undefined;
        holdFirstBatch(async () => {
          // Another write revokes the row at this very millisecond and keeps the generations.
          await h.exec("UPDATE api_key SET revoked_at = ?, enabled = 0 WHERE id = ?", at, connectionId);
          before = await snapshot(connectionId);
        });

        expect((await refresh(tokens.refresh_token)).body).toEqual({
          error: "invalid_grant",
          error_description: "The connection is no longer live",
        });
        vi.restoreAllMocks();
        expect(before!.generations).toHaveLength(2);
        expect(await snapshot(connectionId)).toEqual(before);
      });
    });

    describe("the connection's binding and lifetime hold at every decision and write", () => {
      const rebind = (connectionId: string) =>
        h.exec("UPDATE api_key SET resource = ? WHERE id = ?", "https://other.example.com", connectionId);
      const clearExpiry = (connectionId: string) =>
        h.exec("UPDATE api_key SET expires_at = NULL WHERE id = ?", connectionId);
      const noLonger = {
        status: 400,
        body: { error: "invalid_grant", error_description: "The connection is no longer live" },
      };

      it("refuses an ordinary replay when the connection is rebound after the first reads", async () => {
        const { tokens, connectionId } = await connect();
        ok(await refresh(tokens.refresh_token));
        let before: Awaited<ReturnType<typeof snapshot>> | undefined;
        // Reads: the generations, the connection, the membership, then the snapshot that decides.
        const skip = async () => undefined;
        afterEachRead([
          skip,
          skip,
          async () => {
            await rebind(connectionId);
            before = await snapshot(connectionId);
          },
        ]);

        expect(await refresh(tokens.refresh_token)).toEqual(noLonger);
        vi.restoreAllMocks();
        expect(before).toBeDefined();
        expect(await snapshot(connectionId)).toEqual(before);
      });

      it("refuses a recovery replay when the connection is rebound while the rotation waits", async () => {
        const { tokens, connectionId } = await connect();
        let before: Awaited<ReturnType<typeof snapshot>> | undefined;
        holdFirstBatch(async () => {
          ok(await h.variant({}).oauth.token({ body: refreshBody(tokens.refresh_token) }));
          await rebind(connectionId);
          before = await snapshot(connectionId);
        });

        expect(await refresh(tokens.refresh_token)).toEqual(noLonger);
        vi.restoreAllMocks();
        expect(await snapshot(connectionId)).toEqual(before);
      });

      it("does not revoke for reuse a connection rebound before the revocation lands", async () => {
        const { tokens, connectionId } = await connect();
        ok(await refresh(tokens.refresh_token));
        await ageRotation(connectionId, 31_000);
        let before: Awaited<ReturnType<typeof snapshot>> | undefined;
        holdFirstBatch(async () => {
          await rebind(connectionId);
          before = await snapshot(connectionId);
        });

        expect(await refresh(tokens.refresh_token)).toEqual(noLonger);
        vi.restoreAllMocks();
        expect(before!.generations).toHaveLength(2);
        expect(await snapshot(connectionId)).toEqual(before);
      });

      for (const [change, apply] of [
        ["its expires_at cleared", clearExpiry],
        ["rebound to another issuer", rebind],
      ] as const) {
        it(`refuses to rotate the current token of a connection ${change} before the batch`, async () => {
          const { tokens, connectionId } = await connect();
          let before: Awaited<ReturnType<typeof snapshot>> | undefined;
          holdFirstBatch(async () => {
            await apply(connectionId);
            before = await snapshot(connectionId);
          });

          expect(await refresh(tokens.refresh_token)).toEqual(noLonger);
          vi.restoreAllMocks();
          expect(before!.generations[0]!.rotated_at).toBeNull();
          expect(await snapshot(connectionId)).toEqual(before);
        });
      }

      it("resolves an access token from one statement: authority never wholly live is no state", async () => {
        const connected = await connect();
        const { human, tokens, connectionId } = connected;
        const [member] = await h.exec(
          "SELECT * FROM organization_user WHERE user_id = ? AND organization_id = ?",
          human.userId,
          human.organizationId,
        );
        await h.exec(
          "DELETE FROM organization_user WHERE user_id = ? AND organization_id = ?",
          human.userId,
          human.organizationId,
        );
        // Were the parts read apart: the connection read live, then revoked,
        // then the membership restored before it is read.
        afterEachRead([
          async () => undefined,
          () => h.exec("UPDATE api_key SET revoked_at = ?, enabled = 0 WHERE id = ?", Date.now(), connectionId),
          () =>
            h.exec(
              "INSERT INTO organization_user (id, organization_id, user_id, role, status, joined_at) VALUES (?, ?, ?, ?, ?, ?)",
              member!.id,
              member!.organization_id,
              member!.user_id,
              member!.role,
              member!.status,
              member!.joined_at,
            ),
        ]);

        expect((await resolve(tokens.access_token)).authenticated).toBe(false);
        vi.restoreAllMocks();
      });

      it("resolves no state for a connection with no expiry or bound elsewhere", async () => {
        const cleared = await connect();
        await clearExpiry(cleared.connectionId);
        expect((await resolve(cleared.tokens.access_token)).authenticated).toBe(false);
        const rebound = await connect();
        await rebind(rebound.connectionId);
        expect((await resolve(rebound.tokens.access_token)).authenticated).toBe(false);
      });
    });

    describe("the organization deadline, by the database's clock", () => {
      it("refuses a rotation whose caller clock is behind a deadline the database has passed", async () => {
        const { human, tokens, connectionId } = await connect();
        // The request read the state at `stale`; by the time its batch lands
        // the deadline, between the two, has passed.
        const stale = Date.now() - 10_000;
        await h.exec(
          "UPDATE organization SET expires_at = ? WHERE id = ?",
          new Date(stale + 5_000).toISOString(),
          human.organizationId,
        );
        const before = await snapshot(connectionId);
        vi.spyOn(Date, "now").mockReturnValue(stale);
        const result = await refresh(tokens.refresh_token);
        vi.restoreAllMocks();

        expect(result.body).toMatchObject({ error: "invalid_grant" });
        expect(await snapshot(connectionId)).toEqual(before);
      });

      it("refuses an issuance prepared before a deadline the database has passed", async () => {
        const human = await h.human();
        const stale = Date.now() - 10_000;
        await h.exec(
          "UPDATE organization SET expires_at = ? WHERE id = ?",
          new Date(stale + 5_000).toISOString(),
          human.organizationId,
        );
        await expect(
          h.cfAuth.oauth.createConnection({
            userId: human.userId,
            organizationId: human.organizationId,
            clientId,
            clientName,
            resource: issuer,
            grant: "manage",
            now: stale,
          }),
        ).rejects.toMatchObject({ code: "connection_refused" });
        expect(await h.exec("SELECT id FROM api_key WHERE organization_id = ?", human.organizationId)).toHaveLength(0);
      });
    });

    describe("revocation", () => {
      const revoke = (body: Record<string, string>) => h.cfAuth.oauth.revoke({ body: new URLSearchParams(body) });

      it("ends the whole connection from either token, ignoring the hint", async () => {
        const byAccess = await connect();
        expect(
          await revoke({ token: byAccess.tokens.access_token, client_id: clientId, token_type_hint: "refresh_token" }),
        ).toEqual({ status: 200, body: null });
        expect((await connectionRow(byAccess.connectionId)).revoked_at).not.toBeNull();
        expect(await generations(byAccess.connectionId)).toHaveLength(0);
        expect((await resolve(byAccess.tokens.access_token)).authenticated).toBe(false);
        expect((await refresh(byAccess.tokens.refresh_token)).body).toMatchObject({ error: "invalid_grant" });

        const byRefresh = await connect();
        expect(await revoke({ token: byRefresh.tokens.refresh_token, client_id: clientId })).toEqual({
          status: 200,
          body: null,
        });
        expect((await resolve(byRefresh.tokens.access_token)).authenticated).toBe(false);
        // Already dead: 200, no change.
        const dead = await snapshot(byRefresh.connectionId);
        expect(await revoke({ token: byRefresh.tokens.refresh_token, client_id: clientId })).toEqual({
          status: 200,
          body: null,
        });
        expect(await snapshot(byRefresh.connectionId)).toEqual(dead);
      });

      it("answers 200 and changes nothing for an unknown token", async () => {
        const { tokens, connectionId } = await connect();
        const before = await snapshot(connectionId);
        expect(await revoke({ token: forge(tokens.access_token), client_id: clientId })).toEqual({
          status: 200,
          body: null,
        });
        expect(await revoke({ token: "anything", client_id: clientId })).toEqual({ status: 200, body: null });
        expect(await snapshot(connectionId)).toEqual(before);
        expect((await resolve(tokens.access_token)).authenticated).toBe(true);
      });

      it("answers 401 invalid_client for another client, and 400 for a malformed request", async () => {
        const { tokens, connectionId } = await connect();
        const before = await snapshot(connectionId);
        expect(await revoke({ token: tokens.access_token, client_id: "someone-else" })).toMatchObject({
          status: 401,
          body: { error: "invalid_client" },
        });
        expect(await revoke({ token: tokens.access_token })).toMatchObject({
          status: 400,
          body: { error: "invalid_request" },
        });
        const body = new URLSearchParams({ token: tokens.access_token, client_id: clientId });
        body.append("token", tokens.refresh_token);
        expect(await h.cfAuth.oauth.revoke({ body })).toMatchObject({ status: 400, body: { error: "invalid_request" } });
        expect(await snapshot(connectionId)).toEqual(before);
      });

      it("leaves a connection that expired between its read and the revocation batch unchanged, with 200", async () => {
        const { tokens, connectionId } = await connect();
        const db = h.cfAuth.config.db as CfAuthDatabase & { batch(q: unknown[]): Promise<unknown[]> };
        const batch = db.batch.bind(db);
        let before: Awaited<ReturnType<typeof snapshot>> | undefined;
        let calls = 0;
        vi.spyOn(db, "batch").mockImplementation(async (statements: unknown[]) => {
          calls += 1;
          if (calls === 1) {
            await h.exec("UPDATE api_key SET expires_at = ? WHERE id = ?", Date.now() - 1, connectionId);
            before = await snapshot(connectionId);
          }
          return batch(statements);
        });

        expect(await revoke({ token: tokens.access_token, client_id: clientId })).toEqual({ status: 200, body: null });
        vi.restoreAllMocks();
        expect(calls).toBe(1);
        expect(before!.generations).toHaveLength(1);
        expect(await snapshot(connectionId)).toEqual(before);
      });

      it("lists connections beside keys, and the console's revokeApiKey ends one", async () => {
        const { human, tokens, connectionId } = await connect({ grant: "read" });
        const session = await h.actorFor(human.userId);
        const listed = await h.cfAuth.service.listApiKeys({ organizationId: human.organizationId, actor: session });
        const connection = listed.find((key) => key.id === connectionId);
        expect(connection).toMatchObject({
          source: "oauth",
          clientId,
          grant: "read",
          name: clientName,
          label: clientName,
          enabled: true,
          revokedAt: null,
          expiresAt: expect.any(String),
        });

        const revoked = await h.cfAuth.service.revokeApiKey({
          organizationId: human.organizationId,
          actor: session,
          apiKeyId: connectionId,
        });
        expect(revoked).toMatchObject({ id: connectionId, revokedAt: expect.any(String), clientId });
        expect(await generations(connectionId)).toHaveLength(0);
        expect((await resolve(tokens.access_token)).authenticated).toBe(false);
        expect((await refresh(tokens.refresh_token)).body).toMatchObject({ error: "invalid_grant" });
      });
    });

    describe("sweep", () => {
      it("deletes the generations of revoked and expired connections, and nothing else", async () => {
        const live = await connect();
        const expired = await connect();
        const revoked = await connect();
        await h.exec("UPDATE api_key SET expires_at = ? WHERE id = ?", Date.now() - 1, expired.connectionId);
        await h.exec("UPDATE api_key SET revoked_at = ?, enabled = 0 WHERE id = ?", Date.now(), revoked.connectionId);

        expect(h.cfAuth.oauth.sweepStatements()).toHaveLength(1);
        await h.cfAuth.oauth.sweep();

        expect(await generations(live.connectionId)).toHaveLength(1);
        expect(await generations(expired.connectionId)).toHaveLength(0);
        expect(await generations(revoked.connectionId)).toHaveLength(0);
        // The rows themselves stay, as a revoked key's does.
        expect(await connectionRow(expired.connectionId)).toBeDefined();
        expect((await resolve(live.tokens.access_token)).authenticated).toBe(true);
      });
    });

    describe("an OAuth state is a delegated credential", () => {
      it("is bound to its own organization even where its user is a member of another", async () => {
        const { human, tokens } = await connect({ grant: "manage" });
        const state = await resolve(tokens.access_token, "api");
        const second = await h.cfAuth.service.createOrganization(human.userId, "Second");
        const session = await h.actorFor(human.userId);
        const otherId = second.organization.id;

        // The person may act in the second organization; the connection may not.
        await expect(h.cfAuth.service.listApiKeys({ organizationId: otherId, actor: session })).resolves.toEqual(
          expect.any(Array),
        );
        await expect(h.cfAuth.service.listApiKeys({ organizationId: otherId, actor: state })).rejects.toMatchObject({
          code: "forbidden",
        });
        await expect(
          h.cfAuth.service.createApiKey({ organizationId: otherId, actor: state, name: "x" }),
        ).rejects.toMatchObject({ code: "forbidden" });
        await expect(
          h.cfAuth.service.listOrganizationMembers({ organizationId: otherId, actor: state }),
        ).rejects.toMatchObject({ code: "forbidden" });
        await expect(h.cfAuth.service.listOrganizations(state)).rejects.toMatchObject({ code: "session_required" });

        // In its own organization it acts, and issues no more than it holds.
        const key = await h.cfAuth.service.createApiKey({
          organizationId: human.organizationId,
          actor: state,
          name: "From a connection",
          grant: "read",
        });
        expect(key.grant).toBe("read");
      });

      it("is held to its grant by the services", async () => {
        const read = await connect({ grant: "read" });
        const state = await resolve(read.tokens.access_token, "api");
        await expect(
          h.cfAuth.service.listApiKeys({ organizationId: read.human.organizationId, actor: state }),
        ).resolves.toEqual(expect.any(Array));
        await expect(
          h.cfAuth.service.createApiKey({ organizationId: read.human.organizationId, actor: state, name: "k" }),
        ).rejects.toMatchObject({ code: "grant_insufficient" });
      });

      it("is held to a kind's grant when it opens an operation", async () => {
        const read = await connect({ grant: "read" });
        const reader = await resolve(read.tokens.access_token, "mcp");
        const { operations } = h.cfAuth;

        await expect(operations.reserve({ kind: "apply", opener: reader })).rejects.toMatchObject({
          code: "grant_insufficient",
        });
        await expect(
          operations.open({ kind: "apply", token: createOperationToken(), opener: reader }),
        ).rejects.toMatchObject({ code: "grant_insufficient" });
        const opened = await operations.open({ kind: "report", token: createOperationToken(), opener: reader });
        expect(opened).toMatchObject({ state: "pending", organizationId: read.human.organizationId });
      });

      it("loses the write when its grant or the connection changes before the guarded batch", async () => {
        const { human, tokens, connectionId } = await connect({ grant: "manage" });
        const opener = await resolve(tokens.access_token, "mcp");
        const { operations } = h.cfAuth;
        const { organization } = h.cfAuth.config.tables;
        const rename =
          (name: string): ExecuteOperationFunction<unknown, { renamed: string }> =>
          ({ guard, db }) => ({
            outcome: { renamed: name },
            record: { renamed: name },
            statements: [
              db
                .update(organization)
                .set({ name })
                .where(and(eq(organization.id, human.organizationId), guard)),
            ],
          });
        const organizationName = async () =>
          (await h.exec("SELECT name FROM organization WHERE id = ?", human.organizationId))[0]!.name;
        const before = await organizationName();

        // Downgraded after the caller's state was read: the guard refuses.
        const first = await operations.reserve({ kind: "apply", opener });
        await h.exec(`UPDATE api_key SET "grant" = 'read' WHERE id = ?`, connectionId);
        await expect(
          operations.execute({ handle: first.handle, kind: "apply", opener }, rename("Downgraded")),
        ).rejects.toMatchObject({ code: "conflict" });
        expect(await organizationName()).toBe(before);
        // Read afresh, the connection is refused before anything runs.
        const downgraded = await resolve(tokens.access_token, "mcp");
        expect(downgraded.grant).toBe("read");
        await expect(
          operations.execute({ handle: first.handle, kind: "apply", opener: downgraded }, rename("Again")),
        ).rejects.toMatchObject({ code: "grant_insufficient" });

        // With manage back, it runs.
        await h.exec(`UPDATE api_key SET "grant" = 'manage' WHERE id = ?`, connectionId);
        await operations.execute({ handle: first.handle, kind: "apply", opener }, rename("Applied"));
        expect(await organizationName()).toBe("Applied");

        // Revoked after the state was read: the guard refuses too.
        const second = await operations.reserve({ kind: "apply", opener });
        await h.cfAuth.oauth.revoke({ body: new URLSearchParams({ token: tokens.refresh_token, client_id: clientId }) });
        await expect(
          operations.execute({ handle: second.handle, kind: "apply", opener }, rename("Revoked")),
        ).rejects.toMatchObject({ code: "conflict" });
        expect(await organizationName()).toBe("Applied");
      });

      it("may revoke itself, whatever its grant", async () => {
        const { tokens, connectionId } = await connect({ grant: "read" });
        const revoked = await h.cfAuth.service.revokeOwnApiKey({ actor: await resolve(tokens.access_token) });
        expect(revoked).toMatchObject({ id: connectionId, source: "oauth" });
        expect(await generations(connectionId)).toHaveLength(0);
        expect((await resolve(tokens.access_token)).authenticated).toBe(false);
      });

      it("cannot be minted as a key: source oauth is reserved", async () => {
        const human = await h.human();
        await expect(
          h.cfAuth.service.createApiKey({
            organizationId: human.organizationId,
            actor: await h.actorFor(human.userId),
            name: "Impostor",
            source: "oauth",
          }),
        ).rejects.toMatchObject({ code: "validation_error" });
      });
    });
  });
}

describe("OAuth bearer routing in the middleware", () => {
  it("routes the access prefix to OAuth resolution and everything else to API keys", async () => {
    const harness = await createTestAuth(oauthOptions());
    const human = await harness.sessions.human();
    const tokens = await harness.cfAuth.oauth.createConnection({
      userId: human.userId,
      organizationId: human.organizationId,
      clientId,
      clientName,
      resource: issuer,
      grant: "read",
    });
    const key = await harness.cfAuth.service.createApiKey({
      organizationId: human.organizationId,
      actor: await harness.actorFor(human.userId),
      name: "Key",
    });
    const me = (token: string, client?: string) =>
      harness.me({
        useJar: false,
        headers: { Authorization: `Bearer ${token}`, ...(client ? { "X-Client": client } : {}) },
      });

    expect(await me(tokens.access_token)).toMatchObject({
      authenticated: true,
      credentialType: "oauth",
      source: "api",
      grant: "read",
    });
    expect(await me(tokens.access_token, "mcp")).toMatchObject({ credentialType: "oauth", source: "mcp" });
    expect(await me(tokens.access_token, "cli")).toMatchObject({ credentialType: "oauth", source: "api" });
    expect(await me(key.plaintext, "cli")).toMatchObject({ credentialType: "apiKey", source: "cli" });
    // A tampered last character, guaranteed to differ from the original.
    const last = tokens.access_token.slice(-1);
    expect((await me(`${tokens.access_token.slice(0, -1)}${last === "A" ? "B" : "A"}`)).authenticated).toBe(false);
    expect((await me(tokens.refresh_token)).authenticated).toBe(false);
  });

  it("keeps createAuthMiddleware's dependencies as they were while OAuth is off", async () => {
    const off = await createTestAuth();
    const deps = {
      auth: off.cfAuth.auth,
      service: off.cfAuth.service,
      currentOrganizationCookie: off.cfAuth.currentOrganizationCookie,
    };
    expect(typeof createAuthMiddleware(off.cfAuth.config, deps)()).toBe("function");

    const on = await createTestAuth(oauthOptions());
    const onDeps = { ...deps, auth: on.cfAuth.auth, service: on.cfAuth.service };
    expect(() => createAuthMiddleware(on.cfAuth.config, onDeps)()).toThrow(/deps\.oauth/);
    expect(typeof createAuthMiddleware(on.cfAuth.config, onDeps)({ oauth: false })).toBe("function");
    expect(typeof createAuthMiddleware(on.cfAuth.config, { ...onDeps, oauth: on.cfAuth.oauth })()).toBe("function");
  });

  it("keeps a repeated parameter's description within the RFC 6749 character set", async () => {
    const harness = await createTestAuth(oauthOptions());
    const allowed = /^[\x20\x21\x23-\x5B\x5D-\x7E]*$/;
    for (const name of ['"', "\\", "\u0001", "é", "grant_type"]) {
      const body = new URLSearchParams([
        [name, "a"],
        [name, "b"],
      ]);
      for (const result of [await harness.cfAuth.oauth.token({ body }), await harness.cfAuth.oauth.revoke({ body })]) {
        expect(result.status).toBe(400);
        const description = (result.body as { error_description: string }).error_description;
        expect(description, name).toMatch(allowed);
      }
    }
    const body = new URLSearchParams("grant_type=a&grant_type=b");
    expect((await harness.cfAuth.oauth.token({ body })).body).toEqual({
      error: "invalid_request",
      error_description: "Parameter grant_type is given more than once",
    });
  });

  it("leaves OAuth tokens unresolved while OAuth is off", async () => {
    const harness = await createTestAuth();
    expect(harness.cfAuth.config.oauth).toBeNull();
    await expect(
      harness.cfAuth.oauth.token({ body: new URLSearchParams({ grant_type: "refresh_token" }) }),
    ).rejects.toMatchObject({ code: "validation_error" });
    await expect(
      harness.cfAuth.oauth.resolveAccessTokenAuthState("agw_oat_x.y", { source: "mcp" }),
    ).rejects.toMatchObject({ code: "validation_error" });
    expect(() => harness.cfAuth.oauth.sweepStatements()).toThrow(/OAuth is disabled/);
  });
});

describe("OAuth configuration", () => {
  const batching = { batch: async () => [] } as unknown as CfAuthDatabase;
  const base: CfAuthConfig = {
    appName: "My App",
    secret: "s".repeat(32),
    db: batching,
    apiKeys: { enabled: true, tokenPrefix: "agw_mgmt_" },
    operations: { enabled: true },
  };
  const resolve = (oauth: Partial<OAuthConfig>, extra: Partial<CfAuthConfig> = {}) =>
    resolveConfig({ ...base, ...extra, oauth: { enabled: true, issuer, tokenPrefix, ...oauth } });

  it("is null while disabled, and resolves its defaults when enabled", () => {
    expect(resolveConfig(base).oauth).toBeNull();
    expect(resolveConfig({ ...base, oauth: { enabled: false, issuer: "nonsense" } }).oauth).toBeNull();
    expect(resolve({}).oauth).toEqual({
      issuer,
      resourcePaths: ["/mcp"],
      resources: [issuer, `${issuer}/mcp`],
      accessTokenTtlMs: 600_000,
      refreshTokenTtlMs: 30 * day,
      connectionMaxAgeMs: null,
      authorizationTtlMs: 600_000,
      tokenPrefix,
      clients: [],
      cimd: { fetch: null, allowUrl: null },
    });
    expect(resolve({ issuer: "http://127.0.0.1:8787", cimd: false }).oauth).toMatchObject({
      issuer: "http://127.0.0.1:8787",
      cimd: null,
    });
    expect(
      resolve({
        clients: [
          {
            clientId: "cli",
            name: "CLI",
            redirectUris: ["http://127.0.0.1/cb", "https://app.example.com/cb", "com.example.app:/oauth"],
          },
        ],
      }).oauth?.clients,
    ).toHaveLength(1);
  });

  it("needs API keys, operations and a database that batches", () => {
    expect(() => resolve({}, { apiKeys: { enabled: false } })).toThrow(/apiKeys\.enabled/);
    expect(() => resolve({}, { operations: { enabled: false } })).toThrow(/operations\.enabled/);
    expect(() => resolve({}, { db: {} as CfAuthDatabase })).toThrow(/batches atomically/);
  });

  it("refuses an issuer that is not an https origin, or http on loopback", () => {
    for (const bad of [
      "",
      "console.example.com",
      "http://console.example.com",
      "https://console.example.com/",
      "https://console.example.com/mcp",
      "https://console.example.com?x=1",
      "https://user@console.example.com",
      "https://Console.example.com",
      "ftp://console.example.com",
    ]) {
      expect(() => resolve({ issuer: bad }), bad).toThrow(/oauth\.issuer/);
    }
    expect(() => resolveConfig({ ...base, oauth: { enabled: true, tokenPrefix } })).toThrow(/oauth\.issuer/);
  });

  it("refuses token prefixes that are missing, equal, or could collide with API keys", () => {
    expect(() => resolveConfig({ ...base, oauth: { enabled: true, issuer } })).toThrow(/tokenPrefix/);
    expect(() => resolve({ tokenPrefix: { access: "agw_oat_", refresh: "agw_oat_" } })).toThrow(/must differ/);
    expect(() => resolve({ tokenPrefix: { access: "agw_mgmt_", refresh: "agw_ort_" } })).toThrow(/apiKeys\.tokenPrefix/);
    expect(() => resolve({ tokenPrefix: { access: "agw_oat_", refresh: "agw_mgmt_" } })).toThrow(/apiKeys\.tokenPrefix/);
    // An API key is its prefix and base62: "agw_mgmt_oat" could begin one, "agw_" begins them all.
    expect(() => resolve({ tokenPrefix: { access: "agw_mgmt_oat", refresh: "agw_ort_" } })).toThrow(/could begin/);
    expect(() => resolve({ tokenPrefix: { access: "agw_", refresh: "agw_ort_" } })).toThrow(/could begin/);
    expect(() => resolve({ tokenPrefix: { access: "agw mgmt", refresh: "agw_ort_" } })).toThrow(/letters, digits/);
  });

  it("refuses bad lifetimes and resource paths", () => {
    expect(() => resolve({ accessTokenTtlMs: 0 })).toThrow(/accessTokenTtlMs/);
    expect(() => resolve({ refreshTokenTtlMs: -1 })).toThrow(/refreshTokenTtlMs/);
    expect(() => resolve({ connectionMaxAgeMs: 0 })).toThrow(/connectionMaxAgeMs/);
    expect(() => resolve({ authorizationTtlMs: Number.NaN })).toThrow(/authorizationTtlMs/);
    expect(resolve({ connectionMaxAgeMs: null }).oauth?.connectionMaxAgeMs).toBeNull();
    for (const path of ["mcp", "/mcp/", "/", "/mcp?x", "/mcp#x"]) {
      expect(() => resolve({ resourcePaths: [path] }), path).toThrow(/resourcePaths/);
    }
    expect(() => resolve({ resourcePaths: ["/mcp", "/mcp"] })).toThrow(/twice/);
  });

  it("refuses registered clients with bad redirect URIs, and a malformed cimd block", () => {
    const client = (redirectUris: string[], extra: object = {}) => ({
      clients: [{ clientId: "c", name: "Client", redirectUris, ...extra }],
    });
    for (const bad of [
      "http://example.com/cb",
      "https://app.example.com/cb#frag",
      "/relative",
      "myapp:/cb",
      "https://user:pw@app.example.com/cb",
    ]) {
      expect(() => resolve(client([bad])), bad).toThrow(/redirectUris/);
    }
    expect(() => resolve(client([]))).toThrow(/at least one/);
    expect(() => resolve(client(["https://a.example.com/cb"], { name: " " }))).toThrow(/name/);
    expect(() =>
      resolve({
        clients: [
          { clientId: "c", name: "A", redirectUris: ["https://a.example.com/cb"] },
          { clientId: "c", name: "B", redirectUris: ["https://b.example.com/cb"] },
        ],
      }),
    ).toThrow(/twice/);
    expect(() => resolve({ cimd: { fetch: "nope" as never } })).toThrow(/cimd\.fetch/);
    expect(() => resolve({ cimd: { allowUrl: 1 as never } })).toThrow(/cimd\.allowUrl/);
  });
});

describe("migration 0004", () => {
  it("adds the columns and the table without rebuilding api_key", async () => {
    const { readFile } = await import("node:fs/promises");
    const { fileURLToPath } = await import("node:url");
    const sql = await readFile(
      fileURLToPath(new URL("../drizzle/0004_cf_auth_oauth_token.sql", import.meta.url).href),
      "utf8",
    );
    const statements = sql.split("--> statement-breakpoint").map((s) => s.trim()).filter(Boolean);
    expect(statements.filter((s) => s.startsWith("CREATE TABLE"))).toHaveLength(1);
    expect(statements.filter((s) => /^ALTER TABLE `api_key` ADD `(client_id|resource)` text;$/.test(s))).toHaveLength(2);
    expect(sql).not.toMatch(/__new_|DROP TABLE|INSERT INTO/);
  });
});
