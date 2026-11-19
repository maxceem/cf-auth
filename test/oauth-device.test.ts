/**
 * cf-auth 1.0's sign-in for command-line tools: an issuer on a path, the
 * command-line tool as a built-in client (RFC 8252), and the device flow
 * (RFC 8628).
 *
 * The device flow writes in batches, so it runs on libsql and on a real D1
 * (Miniflare, on workerd), as the authorization-code flow does.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { CfAuth } from "../src/cf-auth.js";
import { resolveConfig, type CfAuthConfig, type CfAuthDatabase, type OAuthConfig } from "../src/config.js";
import type { OAuthDeviceAuthorizationResponse } from "../src/oauth/device.js";
import type { OAuthTokenResponse, OAuthTokenResult } from "../src/oauth/service.js";
import type { TestHuman } from "../src/testing.js";
import type { AuthState } from "../src/types.js";
import { createD1TestAuth, createTestAuth } from "./helpers.js";

const issuer = "https://api.example.com/v2";
const tokenPrefix = { access: "agw_oat_", refresh: "agw_ort_" };
const cli = { clientId: "agw-cli", name: "agw" };
const verificationUri = "https://console.example.com/v2/device";
const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code";
const other = { clientId: "web-only", name: "Web only", redirectUris: ["https://app.example.com/cb"] };

const oauthOptions = (oauth: Partial<OAuthConfig> = {}) => ({
  operations: { enabled: true, limits: { pendingPerOpener: 3 } },
  oauth: {
    enabled: true,
    issuer,
    tokenPrefix,
    cli,
    clients: [other],
    deviceFlow: { verificationUri },
    cimd: false as const,
    ...oauth,
  },
});

type Row = Record<string, unknown>;

interface Harness {
  cfAuth: CfAuth;
  human(): Promise<TestHuman>;
  actorFor(userId: string, organizationId?: string | null): Promise<AuthState>;
  exec(query: string, ...args: unknown[]): Promise<Row[]>;
  close(): Promise<void> | void;
}

const harnesses: Record<string, { perTest: boolean; make: () => Promise<Harness> }> = {
  libsql: {
    perTest: true,
    make: async () => {
      const t = await createTestAuth(oauthOptions());
      return {
        cfAuth: t.cfAuth,
        human: () => t.sessions.human(),
        actorFor: (userId, organizationId = null) => t.actorFor(userId, organizationId),
        exec: async (query, ...args) =>
          (await t.client.execute({ sql: query, args: args as never })).rows as unknown as Row[],
        close: () => t.close(),
      };
    },
  },
  d1: {
    perTest: false,
    make: async () => {
      const t = await createD1TestAuth(oauthOptions());
      return {
        cfAuth: t.cfAuth,
        human: () => t.sessions.human(),
        actorFor: (userId, organizationId = null) => t.actorFor(userId, organizationId),
        exec: t.execute,
        close: () => t.dispose(),
      };
    },
  },
};

const expectCode = async (promise: Promise<unknown>, code: string) => {
  await expect(promise).rejects.toMatchObject({ code });
};

const ok = (result: OAuthTokenResult): OAuthTokenResponse => {
  expect(result.status).toBe(200);
  return result.body as OAuthTokenResponse;
};

const noLimit = async () => {};

for (const [driver, { perTest, make }] of Object.entries(harnesses)) {
  describe(`the device flow on ${driver}`, () => {
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

    const rateKey = () => `ip-${crypto.randomUUID()}`;

    const ask = (body: Record<string, string>, rateLimitKey: string | null = rateKey()) =>
      h.cfAuth.oauth.deviceAuthorization({ body: new URLSearchParams(body), rateLimitKey });

    const started = async (body: Record<string, string> = {}) => {
      const result = await ask({ client_id: cli.clientId, ...body });
      expect(result.status).toBe(200);
      return result.body as OAuthDeviceAuthorizationResponse;
    };

    const poll = (deviceCode: string, extra: Record<string, string> = {}) =>
      h.cfAuth.oauth.token({
        body: new URLSearchParams({ grant_type: deviceGrant, device_code: deviceCode, client_id: cli.clientId, ...extra }),
      });

    const idOf = async (userCode: string) => (await h.cfAuth.oauth.lookupDevice({ userCode, rateLimit: noLimit }))!.id;

    /** Moves the last poll back in time, as if the client had waited `interval`. */
    const waited = async (userCode: string) =>
      h.exec("UPDATE operation SET updated_at = updated_at - 60000 WHERE id = ?", await remembered(userCode));

    /** The device authorization's id, once the page has found it: the user code finds only a pending one. */
    const ids = new Map<string, string>();
    const remembered = async (userCode: string) => {
      if (!ids.has(userCode)) ids.set(userCode, await idOf(userCode));
      return ids.get(userCode)!;
    };

    const approve = async (codes: OAuthDeviceAuthorizationResponse, person: TestHuman, grant: "read" | "manage" = "manage") =>
      h.cfAuth.oauth.approveDevice({
        id: await remembered(codes.user_code),
        userCode: codes.user_code,
        actor: await h.actorFor(person.userId, person.organizationId),
        organizationId: person.organizationId,
        grant,
      });

    it("issues a connection once the person approves, and only once", async () => {
      const person = await h.human();
      const codes = await started({ scope: "manage", resource: `${issuer}/mcp` });
      expect(codes).toMatchObject({
        verification_uri: verificationUri,
        verification_uri_complete: `${verificationUri}?user_code=${encodeURIComponent(codes.user_code)}`,
        expires_in: 600,
        interval: 5,
      });
      expect(codes.device_code).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(codes.user_code).toMatch(/^[A-Z2-9]{4}-[A-Z2-9]{4}$/);

      // Polled at once: too soon. After the interval: still waiting.
      expect((await poll(codes.device_code)).body).toMatchObject({ error: "slow_down" });
      await waited(codes.user_code);
      expect(await poll(codes.device_code)).toMatchObject({ status: 400, body: { error: "authorization_pending" } });
      expect((await poll(codes.device_code)).body).toMatchObject({ error: "slow_down" });

      // The page finds it by the code, however it is typed, and shows the client.
      let limited = 0;
      const found = await h.cfAuth.oauth.lookupDevice({
        userCode: codes.user_code.toLowerCase().replace("-", " "),
        rateLimit: async () => {
          limited += 1;
        },
      });
      expect(limited).toBe(1);
      expect(found).not.toBeNull();
      const details = await h.cfAuth.oauth.deviceDetails({
        id: found!.id,
        userCode: codes.user_code,
        viewer: await h.actorFor(person.userId, person.organizationId),
      });
      expect(details).toMatchObject({
        state: "pending",
        client: { id: cli.clientId, name: cli.name, source: "registered" },
        requestedGrant: "manage",
        userCode: codes.user_code,
      });
      expect(details.viewer?.user.id).toBe(person.userId);

      // The person narrows the grant; approving again answers the same.
      expect(await approve(codes, person, "read")).toEqual({ state: "completed", organizationId: person.organizationId });
      expect(await approve(codes, person)).toEqual({ state: "completed", organizationId: person.organizationId });
      // The code no longer finds anything: it was pending only.
      expect(await h.cfAuth.oauth.lookupDevice({ userCode: codes.user_code, rateLimit: noLimit })).toBeNull();

      const tokens = ok(await poll(codes.device_code));
      expect(tokens).toMatchObject({ token_type: "Bearer", scope: "read" });
      const state = await h.cfAuth.oauth.resolveAccessTokenAuthState(tokens.access_token, { source: "api" });
      expect(state).toMatchObject({ authenticated: true, credentialType: "oauth", grant: "read" });
      expect(state.organization?.id).toBe(person.organizationId);
      const [connection] = await h.exec(
        "SELECT client_id, resource, source, revoked_at FROM api_key WHERE organization_id = ? AND credential_type = 'oauth'",
        person.organizationId,
      );
      expect(connection).toMatchObject({ client_id: cli.clientId, resource: issuer, source: "oauth", revoked_at: null });

      // A second exchange of the same device code ends the connection it issued.
      expect((await poll(codes.device_code)).body).toMatchObject({ error: "invalid_grant" });
      expect((await h.cfAuth.oauth.resolveAccessTokenAuthState(tokens.access_token, { source: "api" })).authenticated).toBe(false);
    });

    it("keeps the device code and the user code out of the database in the clear", async () => {
      const codes = await started();
      const id = await idOf(codes.user_code);
      const [row] = await h.exec("SELECT * FROM operation WHERE id = ?", id);
      expect(JSON.stringify(row)).not.toContain(codes.device_code);
      expect(JSON.stringify(row)).not.toContain(codes.user_code);
      expect(id).toMatch(/^oauth-device-[0-9a-f]{64}$/);
    });

    it("answers access_denied once the person declines, and expired_token past the deadline", async () => {
      const denied = await started();
      expect(
        await h.cfAuth.oauth.denyDevice({ id: await idOf(denied.user_code), userCode: denied.user_code }),
      ).toEqual({ state: "denied" });
      expect((await poll(denied.device_code)).body).toMatchObject({ error: "access_denied" });

      const lapsed = await started();
      await h.exec("UPDATE operation SET expires_at = ? WHERE id = ?", Date.now() - 1, await idOf(lapsed.user_code));
      expect((await poll(lapsed.device_code)).body).toMatchObject({ error: "expired_token" });

      // Approved, but exchanged too late.
      const person = await h.human();
      const late = await started();
      const lateId = await remembered(late.user_code);
      await approve(late, person);
      await h.exec(
        "UPDATE operation SET outcome = json_set(outcome, '$.codeExpiresAt', ?) WHERE id = ?",
        Date.now() - 1,
        lateId,
      );
      expect((await poll(late.device_code)).body).toMatchObject({ error: "expired_token" });
    });

    it("refuses an unknown device code, or one presented by another client, and changes nothing", async () => {
      const person = await h.human();
      const codes = await started();
      await approve(codes, person);
      expect((await poll("A".repeat(43))).body).toMatchObject({ error: "invalid_grant" });
      expect((await poll("not-a-code")).body).toMatchObject({ error: "invalid_grant" });
      expect((await poll(codes.device_code, { client_id: other.clientId })).body).toMatchObject({ error: "invalid_grant" });
      expect((await poll(codes.device_code, { resource: "https://elsewhere.example.com" })).body).toMatchObject({
        error: "invalid_target",
      });
      // The right client still gets it.
      ok(await poll(codes.device_code));
    });

    it("refuses a client that is unknown or not allowed the device flow, and a bad scope or resource", async () => {
      expect(await ask({ client_id: "nobody" })).toMatchObject({ status: 401, body: { error: "invalid_client" } });
      expect(await ask({ client_id: other.clientId })).toMatchObject({ status: 400, body: { error: "unauthorized_client" } });
      expect(await ask({})).toMatchObject({ status: 400, body: { error: "invalid_request" } });
      expect(await ask({ client_id: cli.clientId, scope: "admin" })).toMatchObject({ body: { error: "invalid_scope" } });
      expect(await ask({ client_id: cli.clientId, resource: "https://api.example.com" })).toMatchObject({
        body: { error: "invalid_target" },
      });
      const repeated = new URLSearchParams([["client_id", cli.clientId], ["client_id", cli.clientId]]);
      expect(await h.cfAuth.oauth.deviceAuthorization({ body: repeated, rateLimitKey: null })).toMatchObject({
        body: { error: "invalid_request" },
      });
    });

    it("caps device authorizations waiting from one address", async () => {
      const key = rateKey();
      for (let index = 0; index < 3; index += 1) {
        expect((await ask({ client_id: cli.clientId }, key)).status).toBe(200);
      }
      expect(await ask({ client_id: cli.clientId }, key)).toMatchObject({ status: 429, body: { error: "slow_down" } });
      expect((await ask({ client_id: cli.clientId })).status).toBe(200);
    });

    it("calls the rate limit before every lookup, and finds nothing for a wrong code", async () => {
      await started();
      await expect(
        h.cfAuth.oauth.lookupDevice({
          userCode: "AAAA-AAAA",
          rateLimit: async () => {
            throw new Error("too many guesses");
          },
        }),
      ).rejects.toThrow("too many guesses");
      expect(await h.cfAuth.oauth.lookupDevice({ userCode: "BBBB-BBBB", rateLimit: noLimit })).toBeNull();
      expect(await h.cfAuth.oauth.lookupDevice({ userCode: "not a code", rateLimit: noLimit })).toBeNull();
      await expect(
        h.cfAuth.oauth.lookupDevice({ userCode: "BBBB-BBBB" } as never),
      ).rejects.toMatchObject({ code: "validation_error" });
    });

    it("needs a signed-in member, and answers a completed one to nobody but its approver", async () => {
      const person = await h.human();
      const stranger = await h.human();
      const codes = await started();
      const id = await remembered(codes.user_code);
      await expectCode(
        h.cfAuth.oauth.approveDevice({ id, userCode: codes.user_code, actor: null, organizationId: person.organizationId, grant: "manage" }),
        "session_required",
      );
      await expectCode(
        h.cfAuth.oauth.approveDevice({
          id,
          userCode: codes.user_code,
          actor: await h.actorFor(person.userId, person.organizationId),
          organizationId: stranger.organizationId,
          grant: "manage",
        }),
        "not_a_member",
      );
      // A wrong code, with the right id, is refused.
      await expectCode(
        h.cfAuth.oauth.deviceDetails({ id, userCode: "BBBB-BBBB", viewer: null }),
        "invalid_proof",
      );
      await approve(codes, person);
      await expectCode(approve(codes, stranger), "already_completed");
      await expectCode(h.cfAuth.oauth.denyDevice({ id, userCode: codes.user_code }), "already_completed");
    });

    it("re-reads the person's session in the batch that completes it", async () => {
      const person = await h.human();
      const codes = await started();
      const actor = await h.actorFor(person.userId, person.organizationId);
      await h.exec("DELETE FROM user_session WHERE id = ?", actor.actor!.credentialId);
      await expectCode(
        h.cfAuth.oauth.approveDevice({
          id: await idOf(codes.user_code),
          userCode: codes.user_code,
          actor,
          organizationId: person.organizationId,
          grant: "manage",
        }),
        "conflict",
      );
      await waited(codes.user_code);
      expect((await poll(codes.device_code)).body).toMatchObject({ error: "authorization_pending" });
    });
  });
}

describe("the command-line tool as a client, and an issuer on a path", () => {
  it("signs the tool in with a loopback redirect on any port, on 127.0.0.1 or [::1] only", async () => {
    const t = await createTestAuth(oauthOptions());
    const query = (redirectUri: string) =>
      new URLSearchParams({
        response_type: "code",
        client_id: cli.clientId,
        redirect_uri: redirectUri,
        code_challenge: "A".repeat(43),
        code_challenge_method: "S256",
        resource: issuer,
      });
    for (const redirect of ["http://127.0.0.1:54321/callback", "http://[::1]:8080/callback"]) {
      expect(await t.cfAuth.oauth.authorize({ query: query(redirect), rateLimitKey: null })).toHaveProperty("consent");
    }
    for (const redirect of ["http://localhost:54321/callback", "http://127.0.0.1:54321/other", "https://127.0.0.1/callback"]) {
      expect(await t.cfAuth.oauth.authorize({ query: query(redirect), rateLimitKey: null })).toMatchObject({
        error: { code: "invalid_request" },
      });
    }
  });

  it("publishes its documents and endpoints under the issuer's path", async () => {
    const t = await createTestAuth(oauthOptions());
    expect(t.cfAuth.oauth.routePaths()).toEqual({
      authorizationServerMetadata: "/.well-known/oauth-authorization-server/v2",
      protectedResourceMetadata: [
        { resourcePath: "", path: "/.well-known/oauth-protected-resource/v2" },
        { resourcePath: "/mcp", path: "/.well-known/oauth-protected-resource/v2/mcp" },
      ],
      authorize: "/v2/oauth/authorize",
      token: "/v2/oauth/token",
      revoke: "/v2/oauth/revoke",
      deviceAuthorization: "/v2/oauth/device_authorization",
    });
    expect(t.cfAuth.oauth.authorizationServerMetadata()).toMatchObject({
      issuer,
      authorization_endpoint: `${issuer}/oauth/authorize`,
      token_endpoint: `${issuer}/oauth/token`,
      device_authorization_endpoint: `${issuer}/oauth/device_authorization`,
      grant_types_supported: ["authorization_code", "refresh_token", deviceGrant],
    });
    expect(t.cfAuth.oauth.protectedResourceMetadata("/mcp")).toMatchObject({
      resource: `${issuer}/mcp`,
      authorization_servers: [issuer],
    });

    // Without the device flow, nothing of it is published or accepted.
    const off = await createTestAuth(oauthOptions({ deviceFlow: false }));
    expect(off.cfAuth.oauth.routePaths().deviceAuthorization).toBeNull();
    const metadata = off.cfAuth.oauth.authorizationServerMetadata();
    expect(metadata).not.toHaveProperty("device_authorization_endpoint");
    expect(metadata.grant_types_supported).toEqual(["authorization_code", "refresh_token"]);
    expect(
      await off.cfAuth.oauth.token({
        body: new URLSearchParams({ grant_type: deviceGrant, device_code: "A".repeat(43), client_id: cli.clientId }),
      }),
    ).toMatchObject({ body: { error: "unsupported_grant_type" } });
    await expectCode(
      off.cfAuth.oauth.deviceAuthorization({ body: new URLSearchParams({ client_id: cli.clientId }), rateLimitKey: null }),
      "validation_error",
    );
  });
});

describe("configuring the command-line client and the device flow", () => {
  const base: CfAuthConfig = {
    appName: "Test",
    secret: "a-test-secret-that-is-long-enough-1234",
    db: { batch: () => Promise.resolve([]) } as unknown as CfAuthDatabase,
    apiKeys: { enabled: true, tokenPrefix: "agw_mgmt_" },
    operations: { enabled: true },
  };
  const resolve = (oauth: Partial<OAuthConfig>) =>
    resolveConfig({ ...base, oauth: { enabled: true, issuer, tokenPrefix, ...oauth } }).oauth;

  it("registers the tool on both loopback addresses, with the device flow when it is on", () => {
    expect(resolve({ cli, deviceFlow: { verificationUri, codeTtlMs: 300_000, intervalSeconds: 7 } })).toMatchObject({
      cliClientId: cli.clientId,
      clients: [
        {
          clientId: cli.clientId,
          name: cli.name,
          redirectUris: ["http://127.0.0.1/callback", "http://[::1]/callback"],
          deviceFlow: true,
        },
      ],
      deviceFlow: { verificationUri, codeTtlMs: 300_000, intervalSeconds: 7 },
    });
    expect(resolve({ cli: { ...cli, redirectPath: "/oauth/done" } })?.clients).toEqual([
      {
        clientId: cli.clientId,
        name: cli.name,
        redirectUris: ["http://127.0.0.1/oauth/done", "http://[::1]/oauth/done"],
        deviceFlow: false,
      },
    ]);
  });

  it("refuses a bad tool client, device flow or client flag", () => {
    expect(() => resolve({ cli: { clientId: "", name: "agw" } })).toThrow(/oauth\.cli\.clientId/);
    expect(() => resolve({ cli, clients: [{ ...other, clientId: cli.clientId }] })).toThrow(/declared twice/);
    for (const redirectPath of ["callback", "/cb?x=1", "/cb#x", ""]) {
      expect(() => resolve({ cli: { ...cli, redirectPath } }), redirectPath).toThrow(/redirectPath/);
    }
    for (const uri of ["http://console.example.com/device", "https://console.example.com/device?x=1", "https://x/#y", "device"]) {
      expect(() => resolve({ deviceFlow: { verificationUri: uri } }), uri).toThrow(/verificationUri/);
    }
    expect(() => resolve({ deviceFlow: { verificationUri, intervalSeconds: 0 } })).toThrow(/intervalSeconds/);
    expect(() => resolve({ deviceFlow: { verificationUri, codeTtlMs: -1 } })).toThrow(/codeTtlMs/);
    expect(() => resolve({ clients: [{ ...other, deviceFlow: true }] })).toThrow(/needs `oauth\.deviceFlow`/);
    expect(() => resolve({ clients: [{ ...other, deviceFlow: "yes" as never }] })).toThrow(/must be a boolean/);
  });
});
