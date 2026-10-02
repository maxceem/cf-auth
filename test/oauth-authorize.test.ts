/**
 * OAuth authorization (step 10): the authorization request, Client ID
 * Metadata Documents, consent through both doors, the code exchange, and
 * the discovery documents.
 *
 * Everything that writes runs on libsql and on a real D1 (Miniflare, on
 * workerd), because each decision is one batch and the two drivers batch
 * differently. CIMD is exercised against a fake `fetch`, never the network.
 */
import { sql } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createCfAuth, type CfAuth } from "../src/cf-auth.js";
import type { CfAuthDatabase, OAuthConfig } from "../src/config.js";
import { createOperationToken, randomToken } from "../src/crypto.js";
import { guardedInsert } from "../src/guarded-insert.js";
import {
  oauthAuthorizeKindName,
  type OAuthAuthorizationRecord,
  type OAuthAuthorizeResult,
  type OAuthGuestProvisionContext,
} from "../src/oauth/authorization.js";
import { ClientMetadataRefusal, cimdMaxDocumentBytes, fetchClientMetadataDocument } from "../src/oauth/cimd.js";
import { isAcceptableRedirectUri, redirectUriMatches } from "../src/oauth/redirect-uri.js";
import type { OAuthTokenResponse, OAuthTokenResult } from "../src/oauth/service.js";
import type { TestHuman } from "../src/testing.js";
import type { AuthState } from "../src/types.js";
import { createD1TestAuth, createTestAuth, testBaseUrl, testSecret } from "./helpers.js";

const issuer = "https://console.example.com";
const tokenPrefix = { access: "agw_oat_", refresh: "agw_ort_" };
const cimdClientId = "https://client.example.com/oauth/metadata.json";
const cimdClientName = "Example Agent";
const cimdRedirect = "http://127.0.0.1/callback";
const registered = {
  clientId: "registered-cli",
  name: "Registered CLI",
  redirectUris: ["http://127.0.0.1/callback", "https://app.example.com/cb", "com.example.app:/cb"],
};
const minute = 60_000;
const day = 24 * 60 * minute;

// --- a fake network for CIMD ------------------------------------------------------------

type Respond = () => Response;
const documents = new Map<string, Respond>();
const fetchCalls: { url: string; init: RequestInit | undefined }[] = [];
const fakeFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input);
  fetchCalls.push({ url, init });
  const respond = documents.get(url);
  return respond ? respond() : new Response("not found", { status: 404 });
}) as unknown as typeof fetch;

const json = (body: unknown, init: { status?: number; type?: string | null; headers?: Record<string, string> } = {}) => {
  const headers = new Headers(init.headers);
  if (init.type !== null) headers.set("content-type", init.type ?? "application/json");
  return new Response(typeof body === "string" ? body : JSON.stringify(body), { status: init.status ?? 200, headers });
};

const metadata = (overrides: Record<string, unknown> = {}) => ({
  client_id: cimdClientId,
  client_name: cimdClientName,
  redirect_uris: [cimdRedirect, "https://client.example.com/cb"],
  token_endpoint_auth_method: "none",
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
  ...overrides,
});

const serve = (url: string, respond: Respond) => documents.set(url, respond);

beforeEach(() => {
  documents.clear();
  fetchCalls.length = 0;
  serve(cimdClientId, () => json(metadata()));
});

afterEach(() => {
  vi.restoreAllMocks();
});

// --- PKCE ------------------------------------------------------------------------------------

const s256 = async (verifier: string) => {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)));
  return btoa(String.fromCharCode(...digest)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const pkce = async () => {
  const verifier = randomToken(48);
  return { verifier, challenge: await s256(verifier) };
};

// --- harnesses ------------------------------------------------------------------------------

const oauthOptions = (oauth: Partial<OAuthConfig> = {}) => ({
  operations: { enabled: true },
  oauth: { enabled: true, issuer, tokenPrefix, clients: [registered], cimd: { fetch: fakeFetch }, ...oauth },
});

type Row = Record<string, unknown>;

interface Harness {
  cfAuth: CfAuth;
  human(): Promise<TestHuman>;
  actorFor(userId: string, organizationId?: string | null): Promise<AuthState>;
  exec(query: string, ...args: unknown[]): Promise<Row[]>;
  variant(oauth: Partial<OAuthConfig>): CfAuth;
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
    },
  },
};

const ok = (result: OAuthTokenResult): OAuthTokenResponse => {
  expect(result.status).toBe(200);
  return result.body as OAuthTokenResponse;
};

const params = (redirect: string) => new URL(redirect).searchParams;

const expectCode = async (promise: Promise<unknown>, code: string) => {
  await expect(promise).rejects.toMatchObject({ code });
};

for (const [driver, { perTest, make }] of Object.entries(harnesses)) {
  describe(`OAuth authorization on ${driver}`, () => {
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

    /** An authorization request; `undefined` leaves a parameter out. */
    const query = (overrides: Record<string, string | undefined> = {}, challenge = "A".repeat(43)) => {
      const values: Record<string, string | undefined> = {
        response_type: "code",
        client_id: registered.clientId,
        redirect_uri: "http://127.0.0.1:53111/callback",
        code_challenge: challenge,
        code_challenge_method: "S256",
        resource: `${issuer}/mcp`,
        state: "state-123",
        ...overrides,
      };
      const search = new URLSearchParams();
      for (const [name, value] of Object.entries(values)) if (value !== undefined) search.append(name, value);
      return search;
    };

    const rateKey = () => `ip-${crypto.randomUUID()}`;

    const authorize = (search: URLSearchParams, cfAuth = h.cfAuth, rateLimitKey: string | null = rateKey()) =>
      cfAuth.oauth.authorize({ query: search, rateLimitKey });

    const consentOf = (result: OAuthAuthorizeResult) => {
      if (!("consent" in result)) throw new Error(`expected consent, got ${JSON.stringify(result)}`);
      return result.consent;
    };
    const redirectOf = (result: OAuthAuthorizeResult) => {
      if (!("redirect" in result)) throw new Error(`expected a redirect, got ${JSON.stringify(result)}`);
      return result.redirect;
    };

    /** A pending authorization with a real PKCE pair. */
    const start = async (overrides: Record<string, string | undefined> = {}) => {
      const { verifier, challenge } = await pkce();
      const search = query(overrides, challenge);
      const consent = consentOf(await authorize(search));
      return { ...consent, verifier, search };
    };

    const exchange = (
      flow: { search: URLSearchParams; verifier: string },
      code: string,
      extra: Record<string, string> = {},
      cfAuth = h.cfAuth,
    ) =>
      cfAuth.oauth.token({
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: flow.search.get("redirect_uri")!,
          client_id: flow.search.get("client_id")!,
          code_verifier: flow.verifier,
          ...extra,
        }),
      });

    const operationRow = async (id: string) => (await h.exec("SELECT * FROM operation WHERE id = ?", id))[0];
    const recordOf = async (id: string) =>
      JSON.parse(String((await operationRow(id))!.outcome)) as OAuthAuthorizationRecord;
    const connectionsOf = (organizationId: string) =>
      h.exec("SELECT * FROM api_key WHERE organization_id = ? AND source = 'oauth'", organizationId);

    /** Approves as the human's own organization (owner there). */
    const approveAs = async (
      flow: { id: string; proof: string },
      human: TestHuman,
      grant: "read" | "manage" = "manage",
      organizationId = human.organizationId,
    ) =>
      h.cfAuth.oauth.approveAuthorization({
        id: flow.id,
        proof: flow.proof,
        actor: await h.actorFor(human.userId, human.organizationId),
        organizationId,
        grant,
      });

    /** A guest provisioning in the shape the gateway's will have: ids from the operation id, every row guarded. */
    const provisionGuest = (calls: { count: number } = { count: 0 }) => (ctx: OAuthGuestProvisionContext) => {
      calls.count += 1;
      const userId = `svc-${ctx.operationId}`;
      const organizationId = `acct-${ctx.operationId}`;
      const at = new Date(ctx.now);
      const iso = at.toISOString();
      return {
        userId,
        organizationId,
        statements: [
          guardedInsert(ctx.db, ctx.tables.user, {
            id: userId, name: "MCP service", email: null, kind: "service", emailVerified: false, createdAt: at, updatedAt: at,
          }, ctx.guard),
          guardedInsert(ctx.db, ctx.tables.organization, {
            id: organizationId, name: "My account", createdByUserId: userId,
            expiresAt: new Date(ctx.now + 30 * day).toISOString(), createdAt: iso, updatedAt: iso,
          }, ctx.guard),
          guardedInsert(ctx.db, ctx.tables.organizationUser, {
            id: `member-${organizationId}`, organizationId, userId, role: "owner", status: "active", joinedAt: iso,
          }, ctx.guard),
        ],
      };
    };

    const guest = (
      flow: { id: string; proof: string },
      options: { admit?: () => Promise<ReturnType<typeof sql> | null>; rateLimit?: () => Promise<void>; calls?: { count: number } } = {},
    ) =>
      h.cfAuth.oauth.approveGuestAuthorization({
        id: flow.id,
        proof: flow.proof,
        admit: options.admit ?? (async () => null),
        rateLimit: options.rateLimit ?? (async () => {}),
        provision: provisionGuest(options.calls),
      });

    // --- the authorization request -----------------------------------------------------------

    describe("the authorization request", () => {
      it("refuses a duplicated parameter first, on an error page, before the client is resolved", async () => {
        for (const name of ["redirect_uri", "client_id", "state", "code_challenge"]) {
          const search = query({ client_id: "https://unknown.example.com/meta.json" });
          search.append(name, "again");
          expect(await authorize(search)).toEqual({
            error: { status: 400, code: "invalid_request", description: `Parameter ${name} is given more than once` },
          });
        }
        expect(fetchCalls).toHaveLength(0);
      });

      it("answers an error page for a missing client or redirect, an unknown client and a redirect it does not declare", async () => {
        expect(await authorize(query({ client_id: undefined }))).toMatchObject({ error: { code: "invalid_request" } });
        expect(await authorize(query({ redirect_uri: undefined }))).toMatchObject({ error: { code: "invalid_request" } });
        expect(await authorize(query({ client_id: "nobody" }))).toMatchObject({ error: { status: 400, code: "invalid_client" } });
        for (const redirect of [
          "https://evil.example.com/cb",
          "http://127.0.0.1:53111/other",
          "http://127.0.0.1:53111/callback?x=1",
          "http://localhost:53111/callback",
          "https://app.example.com/cb/",
        ]) {
          const result = await authorize(query({ redirect_uri: redirect }));
          expect(result).toEqual({
            error: { status: 400, code: "invalid_request", description: "redirect_uri is not one the client declares" },
          });
        }
      });

      it("accepts a loopback redirect on another port, an https one and a private-use one", async () => {
        for (const redirect of ["http://127.0.0.1:53111/callback", "http://127.0.0.1/callback", "https://app.example.com/cb", "com.example.app:/cb"]) {
          consentOf(await authorize(query({ redirect_uri: redirect })));
        }
      });

      it("accepts an uppercase loopback scheme declared and presented as written, by a registered client and by CIMD", async () => {
        const upper = h.variant({
          clients: [{ clientId: "upper-cli", name: "Upper CLI", redirectUris: ["HTTP://localhost:3000/cb"] }],
        });
        const ask = (cfAuth: CfAuth, clientId: string, redirect: string) =>
          authorize(query({ client_id: clientId, redirect_uri: redirect }), cfAuth);
        consentOf(await ask(upper, "upper-cli", "HTTP://localhost:3000/cb"));
        consentOf(await ask(upper, "upper-cli", "HTTP://localhost:4000/cb"));
        for (const redirect of ["http://localhost:3000/cb", "HTTP://127.1/cb", "HTTP://localhost:3000/x/../cb", "HTTP://localhost:3000/cb#"]) {
          expect(await ask(upper, "upper-cli", redirect)).toMatchObject({ error: { code: "invalid_request" } });
        }

        serve(cimdClientId, () => json(metadata({ redirect_uris: ["HTTP://localhost:3000/cb"] })));
        consentOf(await ask(h.cfAuth, cimdClientId, "HTTP://localhost:3000/cb"));
        consentOf(await ask(h.cfAuth, cimdClientId, "HTTP://localhost:4000/cb"));
        expect(await ask(h.cfAuth, cimdClientId, "http://localhost:3000/cb")).toMatchObject({
          error: { code: "invalid_request", description: "redirect_uri is not one the client declares" },
        });
      });

      it("matches redirect URIs as written: only a loopback port may differ", async () => {
        for (const redirect of [
          "http://127.1/callback",
          "http://127.0.0.1/not-registered/../callback",
          "http://127.0.0.1/callback#",
          "http://127.0.0.1:53111/callback#x",
          "http://127.0.0.1:53111/./callback",
          "http://127.0.0.1:53111/Callback",
          "HTTP://127.0.0.1/callback",
          "https://app.example.com:443/cb",
          "https://app.example.com:8443/cb",
        ]) {
          expect(await authorize(query({ redirect_uri: redirect }))).toMatchObject({
            error: { code: "invalid_request", description: "redirect_uri is not one the client declares" },
          });
        }
        consentOf(await authorize(query({ redirect_uri: "http://127.0.0.1:65535/callback" })));
      });

      it("redirects every later error to the client, with state when sent and iss always", async () => {
        const cases: [Record<string, string | undefined>, string][] = [
          [{ response_type: undefined }, "invalid_request"],
          [{ response_type: "token" }, "unsupported_response_type"],
          [{ code_challenge_method: undefined }, "invalid_request"],
          [{ code_challenge_method: "plain" }, "invalid_request"],
          [{ code_challenge_method: "S512" }, "invalid_request"],
          [{ code_challenge: undefined }, "invalid_request"],
          [{ code_challenge: "A".repeat(42) }, "invalid_request"],
          [{ code_challenge: "A".repeat(44) }, "invalid_request"],
          [{ code_challenge: `${"A".repeat(42)}=` }, "invalid_request"],
          [{ resource: undefined }, "invalid_request"],
          [{ resource: "https://other.example.com" }, "invalid_target"],
          [{ resource: `${issuer}/v1/admin` }, "invalid_target"],
          [{ resource: `${issuer}/` }, "invalid_target"],
          [{ scope: "admin" }, "invalid_scope"],
          [{ scope: "read manage" }, "invalid_scope"],
        ];
        for (const [overrides, error] of cases) {
          const redirect = redirectOf(await authorize(query(overrides)));
          expect(redirect.startsWith("http://127.0.0.1:53111/callback?")).toBe(true);
          const sent = params(redirect);
          expect(sent.get("error")).toBe(error);
          expect(sent.get("error_description")).toBeTruthy();
          expect(sent.get("state")).toBe("state-123");
          expect(sent.get("iss")).toBe(issuer);
          expect(sent.has("code")).toBe(false);
        }
        const stateless = params(redirectOf(await authorize(query({ state: undefined, response_type: "token" }))));
        expect(stateless.has("state")).toBe(false);
        expect(stateless.get("iss")).toBe(issuer);
        // A state too long to echo is refused without echoing it.
        const long = params(redirectOf(await authorize(query({ state: "s".repeat(2049) }))));
        expect(long.get("error")).toBe("invalid_request");
        expect(long.has("state")).toBe(false);
      });

      it("accepts both spellings of resource and normalises them to the issuer; scope defaults to manage", async () => {
        const viaRoot = await start({ resource: issuer, scope: undefined });
        const viaMcp = await start({ resource: `${issuer}/mcp`, scope: "read" });
        const root = await h.cfAuth.oauth.authorizationDetails({ ...viaRoot, viewer: null });
        const mcp = await h.cfAuth.oauth.authorizationDetails({ ...viaMcp, viewer: null });
        expect(root.requestedGrant).toBe("manage");
        expect(mcp.requestedGrant).toBe("read");
        for (const flow of [viaRoot, viaMcp]) {
          expect(JSON.parse(String((await operationRow(flow.id))!.payload)).resource).toBe(issuer);
        }
      });

      it("opens one pending authorization of the internal kind, named by the code's digest, with nothing secret in the clear", async () => {
        const flow = await start();
        expect(flow.id).toMatch(/^oauth-[0-9a-f]{64}$/);
        expect(flow.proof).toMatch(/^[0-9a-f]{64}$/);
        const row = (await operationRow(flow.id))!;
        expect(row).toMatchObject({ kind: oauthAuthorizeKindName, state: "pending", organization_id: null, client_label: registered.name });
        expect(Number(row.expires_at) - Number(row.created_at)).toBe(10 * minute);
        expect(Number(row.retain_until) - Number(row.created_at)).toBe(day);
        const payload = JSON.parse(String(row.payload));
        expect(payload).toMatchObject({
          client: { id: registered.clientId, name: registered.name, domain: null, source: "registered" },
          redirectUri: "http://127.0.0.1:53111/callback",
          requestedGrant: "manage",
          state: "state-123",
          resource: issuer,
        });
        // The proof is stored only as a digest, so the sealed code opens for nobody holding the row.
        expect(JSON.stringify(row)).not.toContain(flow.proof);
      });

      it("caps pending authorizations per browser address", async () => {
        const key = rateKey();
        for (let index = 0; index < 5; index += 1) consentOf(await authorize(query(), h.cfAuth, key));
        expect(await authorize(query(), h.cfAuth, key)).toMatchObject({ error: { status: 429, code: "too_many_pending" } });
        consentOf(await authorize(query(), h.cfAuth, rateKey()));
      });

      it("resolves a CIMD client, showing its declared name beside its domain", async () => {
        const flow = await start({ client_id: cimdClientId, redirect_uri: "http://127.0.0.1:40000/callback" });
        expect(fetchCalls).toHaveLength(1);
        expect(fetchCalls[0]!.url).toBe(cimdClientId);
        const details = await h.cfAuth.oauth.authorizationDetails({ ...flow, viewer: null });
        expect(details.client).toEqual({ id: cimdClientId, name: cimdClientName, domain: "client.example.com", source: "cimd" });
        expect(details.redirectHost).toBe("127.0.0.1:40000");
      });

      it("answers an error page, never a redirect, when a CIMD document is refused", async () => {
        serve(cimdClientId, () => json(metadata({ token_endpoint_auth_method: "client_secret_basic" })));
        const result = await authorize(query({ client_id: cimdClientId, redirect_uri: cimdRedirect }));
        expect(result).toMatchObject({ error: { status: 400, code: "invalid_client" } });
        expect(JSON.stringify(result)).not.toContain("client_secret_basic");
      });

      it("refuses https client ids without fetching when CIMD is off, and keeps registered clients", async () => {
        const off = h.variant({ cimd: false });
        expect(await authorize(query({ client_id: cimdClientId, redirect_uri: cimdRedirect }), off)).toMatchObject({
          error: { code: "invalid_client" },
        });
        expect(fetchCalls).toHaveLength(0);
        consentOf(await authorize(query(), off));
      });
    });

    // --- the internal kind ------------------------------------------------------------------------

    describe("the internal kind", () => {
      it("is refused by every generic entry point of cfAuth.operations", async () => {
        const flow = await start();
        const operations = h.cfAuth.operations;
        expect(operations.kinds.has(oauthAuthorizeKindName)).toBe(false);
        await expectCode(operations.details({ id: flow.id, proof: flow.proof }), "operation_not_found");
        await expectCode(operations.approve({ id: flow.id, proof: flow.proof }), "operation_not_found");
        await expectCode(operations.deny({ id: flow.id, proof: flow.proof }), "operation_not_found");
        await expectCode(operations.guard({ id: flow.id }), "operation_not_found");
        await expectCode(operations.complete({ id: flow.id, outcome: null }), "operation_not_found");
        await expectCode(operations.amend({ id: flow.id, record: {} }), "operation_not_found");
        const human = await h.human();
        const owner = await h.actorFor(human.userId, human.organizationId);
        await expectCode(operations.status({ id: flow.id, opener: owner }), "operation_not_found");
        await expectCode(operations.reveal({ id: flow.id, actor: owner }), "operation_not_found");
        expect(await operations.retire({ id: flow.id })).toBe(false);
        await expectCode(
          operations.open({ kind: oauthAuthorizeKindName, token: createOperationToken(), payload: {} }),
          "validation_error",
        );
        await expectCode(operations.reserve({ kind: oauthAuthorizeKindName, opener: owner }), "validation_error");
        // Still pending and untouched.
        expect((await operationRow(flow.id))!.state).toBe("pending");
      });

      it("is not registered while OAuth is off, and its rows stay hidden from such an engine", async () => {
        const flow = await start();
        const off = createCfAuth({
          appName: "Test App",
          secret: testSecret,
          baseUrl: testBaseUrl,
          apiKeys: { enabled: true },
          operations: { enabled: true },
          ...(h.cfAuth.config.db ? { db: h.cfAuth.config.db as CfAuthDatabase } : {}),
        });
        expect(off.config.oauth).toBeNull();
        await expectCode(off.operations.details({ id: flow.id, proof: flow.proof }), "operation_not_found");
        await expectCode(off.oauth.authorizationDetails({ ...flow, viewer: null }), "validation_error");
      });
    });

    // --- consent -------------------------------------------------------------------------------------

    describe("consent", () => {
      it("shows the details to an anonymous and to a signed-in viewer", async () => {
        const flow = await start({ scope: "read" });
        const anonymous = await h.cfAuth.oauth.authorizationDetails({ ...flow, viewer: null });
        expect(anonymous).toMatchObject({
          id: flow.id,
          state: "pending",
          client: { id: registered.clientId, name: registered.name, domain: null, source: "registered" },
          redirectHost: "127.0.0.1:53111",
          requestedGrant: "read",
          viewer: null,
        });
        expect(Math.abs(Date.parse(anonymous.expiresAt) - (Date.now() + 10 * minute))).toBeLessThan(minute);
        const human = await h.human();
        const viewer = await h.actorFor(human.userId, human.organizationId);
        const signedIn = await h.cfAuth.oauth.authorizationDetails({ ...flow, viewer });
        expect(signedIn.viewer?.user.id).toBe(human.userId);
        expect(signedIn.viewer?.memberships.map((m) => m.organization.id)).toEqual([human.organizationId]);
        // An API key is not a viewer.
        const asKey = await h.cfAuth.oauth.authorizationDetails({
          ...flow,
          viewer: { ...viewer, credentialType: "apiKey", assurance: "credential" },
        });
        expect(asKey.viewer).toBeNull();
      });

      it("refuses a wrong proof, an unknown id and another kind's operation as the engine does", async () => {
        const flow = await start();
        await expectCode(h.cfAuth.oauth.authorizationDetails({ id: flow.id, proof: "0".repeat(64), viewer: null }), "invalid_proof");
        await expectCode(h.cfAuth.oauth.authorizationDetails({ id: flow.id, proof: "nope", viewer: null }), "invalid_proof");
        await expectCode(
          h.cfAuth.oauth.authorizationDetails({ id: `oauth-${"0".repeat(64)}`, proof: flow.proof, viewer: null }),
          "operation_not_found",
        );
        const login = await h.cfAuth.operations.open({ kind: "login", token: createOperationToken(), client: { label: "CLI" } });
        for (const call of [
          h.cfAuth.oauth.authorizationDetails({ id: login.id, proof: login.browserProof!, viewer: null }),
          h.cfAuth.oauth.denyAuthorization({ id: login.id, proof: login.browserProof! }),
        ]) {
          await expectCode(call, "operation_not_found");
        }
        expect((await h.cfAuth.operations.findByToken({ token: "x".repeat(43) }))).toBeNull();
      });

      it("lets a member approve into their account with the grant they choose", async () => {
        const owner = await h.human();
        const member = await h.human();
        await h.exec(
          "INSERT INTO organization_user (id, organization_id, user_id, role, status, joined_at) VALUES (?, ?, ?, 'member', 'active', ?)",
          crypto.randomUUID(),
          owner.organizationId,
          member.userId,
          new Date().toISOString(),
        );
        const flow = await start({ scope: "manage" });
        const { redirect } = await approveAs(flow, member, "read", owner.organizationId);
        const sent = params(redirect);
        expect(redirect.startsWith("http://127.0.0.1:53111/callback?code=")).toBe(true);
        expect(sent.get("code")).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(sent.get("state")).toBe("state-123");
        expect(sent.get("iss")).toBe(issuer);
        expect([...sent.keys()]).toEqual(["code", "state", "iss"]);
        const record = await recordOf(flow.id);
        expect(record).toMatchObject({
          door: "person",
          userId: member.userId,
          organizationId: owner.organizationId,
          grant: "read",
          requestedGrant: "manage",
          client: { id: registered.clientId, source: "registered" },
          redirectUri: "http://127.0.0.1:53111/callback",
          resource: issuer,
          exchangedAt: null,
          connectionId: null,
        });
        const completedAt = Number((await operationRow(flow.id))!.updated_at);
        expect(record.codeExpiresAt - completedAt).toBe(10 * minute);
        // The code never sits in the clear.
        expect(JSON.stringify(await operationRow(flow.id))).not.toContain(sent.get("code")!);
        const tokens = ok(await exchange(flow, sent.get("code")!));
        expect(tokens.scope).toBe("read");
      });

      it("refuses a non-member, an expired organization, an API key and nobody, and leaves the authorization pending", async () => {
        const person = await h.human();
        const stranger = await h.human();
        const flow = await start();
        await expectCode(approveAs(flow, person, "manage", stranger.organizationId), "not_a_member");
        const actor = await h.actorFor(person.userId, person.organizationId);
        for (const asWho of [{ ...actor, credentialType: "apiKey" as const, assurance: "credential" as const }, null]) {
          await expectCode(
            h.cfAuth.oauth.approveAuthorization({ ...flow, actor: asWho, organizationId: person.organizationId, grant: "manage" }),
            "session_required",
          );
        }
        await expectCode(
          h.cfAuth.oauth.approveAuthorization({ ...flow, actor, organizationId: person.organizationId, grant: "admin" as never }),
          "validation_error",
        );
        await h.exec("UPDATE organization SET expires_at = ? WHERE id = ?", new Date(Date.now() - minute).toISOString(), person.organizationId);
        await expectCode(approveAs(flow, person), "organization_expired");
        expect((await operationRow(flow.id))!.state).toBe("pending");
      });

      it("re-reads the session in the batch that completes it", async () => {
        const person = await h.human();
        const flow = await start();
        const actor = await h.actorFor(person.userId, person.organizationId);
        await h.exec("DELETE FROM user_session WHERE id = ?", actor.actor!.credentialId);
        await expectCode(
          h.cfAuth.oauth.approveAuthorization({ ...flow, actor, organizationId: person.organizationId, grant: "manage" }),
          "conflict",
        );
        expect((await operationRow(flow.id))!).toMatchObject({ state: "pending", outcome: null });
      });

      it("answers a repeated approval with the same redirect, before and after the exchange", async () => {
        const person = await h.human();
        const flow = await start();
        const first = await approveAs(flow, person);
        const record = await recordOf(flow.id);
        // A different choice on the repeat changes nothing: the first approval stands.
        const second = await approveAs(flow, person, "read");
        expect(second.redirect).toBe(first.redirect);
        expect(await recordOf(flow.id)).toEqual(record);
        ok(await exchange(flow, params(first.redirect).get("code")!));
        expect((await approveAs(flow, person)).redirect).toBe(first.redirect);
        // A wrong proof gets nothing, even once completed.
        await expectCode(approveAs({ id: flow.id, proof: "f".repeat(64) }, person), "invalid_proof");
      });

      it("denies with an access_denied redirect, idempotently, and refuses approval afterwards", async () => {
        const person = await h.human();
        const flow = await start();
        const { redirect } = await h.cfAuth.oauth.denyAuthorization(flow);
        const sent = params(redirect);
        expect(sent.get("error")).toBe("access_denied");
        expect(sent.get("state")).toBe("state-123");
        expect(sent.get("iss")).toBe(issuer);
        expect(sent.has("code")).toBe(false);
        expect((await h.cfAuth.oauth.denyAuthorization(flow)).redirect).toBe(redirect);
        expect((await operationRow(flow.id))!.state).toBe("denied");
        await expectCode(approveAs(flow, person), "operation_denied");
        await expectCode(guest(flow), "operation_denied");
      });

      it("refuses an approval past the pending deadline", async () => {
        const person = await h.human();
        const flow = await start();
        await h.exec("UPDATE operation SET expires_at = ? WHERE id = ?", Date.now() - 1, flow.id);
        await expectCode(approveAs(flow, person), "operation_expired");
        await expectCode(guest(flow), "operation_expired");
      });
    });

    // --- the guest door --------------------------------------------------------------------------

    describe("the guest door", () => {
      const accounts = (flowId: string) => h.exec("SELECT id FROM organization WHERE id = ?", `acct-${flowId}`);

      it("stops at a refused admission without counting a rate limit or provisioning", async () => {
        const flow = await start();
        const rateLimit = vi.fn(async () => {});
        const calls = { count: 0 };
        await expect(
          guest(flow, { admit: async () => { throw new Error("closed"); }, rateLimit, calls }),
        ).rejects.toThrow("closed");
        expect(rateLimit).not.toHaveBeenCalled();
        expect(calls.count).toBe(0);
        expect((await operationRow(flow.id))!.state).toBe("pending");
      });

      it("stops at the rate limit without provisioning", async () => {
        const flow = await start();
        const calls = { count: 0 };
        await expect(
          guest(flow, { rateLimit: async () => { throw new Error("slow down"); }, calls }),
        ).rejects.toThrow("slow down");
        expect(calls.count).toBe(0);
        expect(await accounts(flow.id)).toHaveLength(0);
      });

      it("commits nothing when the admission condition fails inside the batch", async () => {
        const flow = await start();
        await expectCode(guest(flow, { admit: async () => sql`0 = 1` }), "conflict");
        expect(await accounts(flow.id)).toHaveLength(0);
        expect(await h.exec("SELECT id FROM user WHERE id = ?", `svc-${flow.id}`)).toHaveLength(0);
        expect((await operationRow(flow.id))!.state).toBe("pending");
      });

      it("provisions under the guard and the admission, issues manage, and records what was asked", async () => {
        const flow = await start({ scope: "read" });
        const result = await guest(flow, { admit: async () => sql`1 = 1` });
        expect(result.organizationId).toBe(`acct-${flow.id}`);
        expect(params(result.redirect).get("iss")).toBe(issuer);
        expect(await recordOf(flow.id)).toMatchObject({
          door: "guest",
          userId: `svc-${flow.id}`,
          organizationId: `acct-${flow.id}`,
          grant: "manage",
          requestedGrant: "read",
        });
        const tokens = ok(await exchange(flow, params(result.redirect).get("code")!));
        expect(tokens.scope).toBe("manage");
        const state = await h.cfAuth.oauth.resolveAccessTokenAuthState(tokens.access_token, { source: "mcp" });
        expect(state).toMatchObject({
          authenticated: true,
          credentialType: "oauth",
          grant: "manage",
          role: "owner",
          user: { id: `svc-${flow.id}`, kind: "service" },
        });
      });

      it("answers a repeat with a byte-equal redirect and one account, without admitting or counting again", async () => {
        const flow = await start();
        const first = await guest(flow);
        const admit = vi.fn(async () => null);
        const rateLimit = vi.fn(async () => {});
        const calls = { count: 0 };
        const second = await guest(flow, { admit, rateLimit, calls });
        expect(second).toEqual(first);
        expect(admit).not.toHaveBeenCalled();
        expect(rateLimit).not.toHaveBeenCalled();
        expect(calls.count).toBe(0);
        expect(await accounts(flow.id)).toHaveLength(1);
        ok(await exchange(flow, params(first.redirect).get("code")!));
        expect(await guest(flow)).toEqual(first);
      });

      it("lets exactly one of two concurrent guest clicks provision", async () => {
        const flow = await start();
        const [a, b] = await Promise.all([guest(flow), guest(flow)]);
        expect(a).toEqual(b);
        expect(await accounts(flow.id)).toHaveLength(1);
      });

      it("answers a person and a guest racing with the winner's redirect", async () => {
        const person = await h.human();
        const flow = await start();
        const [byPerson, byGuest] = await Promise.all([approveAs(flow, person), guest(flow)]);
        expect(byPerson.redirect).toBe(byGuest.redirect);
        const record = await recordOf(flow.id);
        expect(byGuest.organizationId).toBe(record.organizationId);
        expect(await accounts(flow.id)).toHaveLength(record.door === "guest" ? 1 : 0);
        // And a person approving after a guest won answers the guest's redirect.
        const later = await start();
        const won = await guest(later);
        expect((await approveAs(later, person)).redirect).toBe(won.redirect);
        expect((await recordOf(later.id)).door).toBe("guest");
      });
    });

    // --- an empty deployment: an admission rule about the deployment's own state -------------------

    describe("the guest door on an empty deployment", () => {
      /** A deployment of its own, with no organization at all: the admission is "no account exists yet". */
      const withEmptyDeployment = async (run: (e: Harness) => Promise<void>) => {
        const e = await make();
        try {
          expect(await e.exec("SELECT id FROM organization")).toHaveLength(0);
          await run(e);
        } finally {
          if (!perTest) await e.close();
        }
      };
      const empty = (e: Harness) => async () =>
        sql`not exists (select 1 from ${e.cfAuth.config.tables.organization})`;
      const startOn = async (e: Harness) => {
        const { verifier, challenge } = await pkce();
        const search = query({}, challenge);
        const consent = consentOf(await e.cfAuth.oauth.authorize({ query: search, rateLimitKey: rateKey() }));
        return { ...consent, verifier, search };
      };
      const guestOn = (e: Harness, flow: { id: string; proof: string }) =>
        e.cfAuth.oauth.approveGuestAuthorization({
          id: flow.id,
          proof: flow.proof,
          admit: empty(e),
          rateLimit: async () => {},
          provision: provisionGuest(),
        });

      it("bootstraps under NOT EXISTS (organization), then refuses the next guest by the same rule", async () => {
        await withEmptyDeployment(async (e) => {
          const flow = await startOn(e);
          const result = await guestOn(e, flow);
          expect(result.organizationId).toBe(`acct-${flow.id}`);
          expect(await e.exec("SELECT id FROM organization")).toEqual([{ id: `acct-${flow.id}` }]);
          expect(await e.exec("SELECT id, kind FROM user WHERE id = ?", `svc-${flow.id}`)).toEqual([
            { id: `svc-${flow.id}`, kind: "service" },
          ]);
          expect(await e.exec("SELECT role FROM organization_user WHERE user_id = ?", `svc-${flow.id}`)).toEqual([
            { role: "owner" },
          ]);
          // The latch is spent with the completion.
          expect((await e.exec("SELECT state, execution_claim FROM operation WHERE id = ?", flow.id))[0]).toEqual({
            state: "completed",
            execution_claim: null,
          });
          const tokens = ok(
            await e.cfAuth.oauth.token({
              body: new URLSearchParams({
                grant_type: "authorization_code",
                code: params(result.redirect).get("code")!,
                redirect_uri: flow.search.get("redirect_uri")!,
                client_id: registered.clientId,
                code_verifier: flow.verifier,
              }),
            }),
          );
          expect(await e.exec("SELECT id FROM api_key WHERE organization_id = ? AND source = 'oauth'", `acct-${flow.id}`)).toHaveLength(1);
          expect((await e.cfAuth.oauth.resolveAccessTokenAuthState(tokens.access_token, { source: "mcp" })).authenticated).toBe(true);

          const next = await startOn(e);
          await expectCode(guestOn(e, next), "conflict");
          expect(await e.exec("SELECT id FROM organization")).toHaveLength(1);
          expect(await e.exec("SELECT id FROM user WHERE id = ?", `svc-${next.id}`)).toHaveLength(0);
          expect((await e.exec("SELECT state, execution_claim FROM operation WHERE id = ?", next.id))[0]).toEqual({
            state: "pending",
            execution_claim: null,
          });
        });
      });

      it("lets exactly one of two competing guest authorizations bootstrap it", async () => {
        await withEmptyDeployment(async (e) => {
          const [first, second] = [await startOn(e), await startOn(e)];
          const results = await Promise.allSettled([guestOn(e, first), guestOn(e, second)]);
          expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
          const refused = results.find((result) => result.status === "rejected") as PromiseRejectedResult;
          expect(refused.reason).toMatchObject({ code: "conflict" });
          expect(await e.exec("SELECT id FROM organization")).toHaveLength(1);
          expect(await e.exec("SELECT id FROM user WHERE kind = 'service'")).toHaveLength(1);
        });
      });

      it("lets a person and a guest racing on one authorization yield one winner", async () => {
        await withEmptyDeployment(async (e) => {
          const flow = await startOn(e);
          const person = await e.human();
          const actor = await e.actorFor(person.userId, person.organizationId);
          // The person's own organization now exists, so the admission refuses the guest: the
          // person wins, and the guest answers the person's redirect or is refused.
          const [byPerson, byGuest] = await Promise.allSettled([
            e.cfAuth.oauth.approveAuthorization({
              id: flow.id,
              proof: flow.proof,
              actor,
              organizationId: person.organizationId,
              grant: "manage",
            }),
            guestOn(e, flow),
          ]);
          expect(byPerson.status).toBe("fulfilled");
          const redirect = (byPerson as PromiseFulfilledResult<{ redirect: string }>).value.redirect;
          if (byGuest.status === "fulfilled") expect(byGuest.value.redirect).toBe(redirect);
          else expect(byGuest.reason).toMatchObject({ code: "conflict" });
          const record = JSON.parse(
            String((await e.exec("SELECT outcome FROM operation WHERE id = ?", flow.id))[0]!.outcome),
          ) as OAuthAuthorizationRecord;
          expect(record).toMatchObject({ door: "person", organizationId: person.organizationId });
          expect(await e.exec("SELECT id FROM organization WHERE id = ?", `acct-${flow.id}`)).toHaveLength(0);
          // A repeat of the guest door now answers the person's redirect without admitting.
          expect((await guestOn(e, flow)).redirect).toBe(redirect);
        });
      });
    });

    // --- the code exchange -----------------------------------------------------------------------

    describe("the code exchange", () => {
      const approved = async (overrides: Record<string, string | undefined> = {}) => {
        const person = await h.human();
        const flow = await start(overrides);
        const { redirect } = await approveAs(flow, person);
        return { person, flow, code: params(redirect).get("code")! };
      };

      it("issues a connection and its tokens", async () => {
        const { person, flow, code } = await approved();
        const tokens = ok(await exchange(flow, code, { resource: issuer }));
        expect(tokens).toMatchObject({ token_type: "Bearer", expires_in: 600, scope: "manage" });
        const [connection] = await connectionsOf(person.organizationId);
        expect(connection).toMatchObject({
          user_id: person.userId,
          client_id: registered.clientId,
          label: registered.name,
          name: registered.name,
          resource: issuer,
          grant: "manage",
        });
        const record = await recordOf(flow.id);
        expect(record.connectionId).toBe(connection!.id);
        expect(record.exchangedAt).not.toBeNull();
        const state = await h.cfAuth.oauth.resolveAccessTokenAuthState(tokens.access_token, { source: "mcp" });
        expect(state).toMatchObject({ authenticated: true, credentialType: "oauth", user: { id: person.userId } });
      });

      it("refuses a wrong verifier, client or redirect with invalid_grant, writing nothing and burning nothing", async () => {
        const { person, flow, code } = await approved();
        const wrong: Record<string, string>[] = [
          { code_verifier: (await pkce()).verifier },
          { client_id: "someone-else" },
          { redirect_uri: "http://127.0.0.1:53112/callback" },
          { code: randomToken(32) },
        ];
        for (const extra of wrong) {
          expect((await exchange(flow, code, extra)).body).toMatchObject({ error: "invalid_grant" });
        }
        expect(await connectionsOf(person.organizationId)).toHaveLength(0);
        expect((await recordOf(flow.id)).exchangedAt).toBeNull();
        ok(await exchange(flow, code));
      });

      it("checks the request's shape before looking the code up", async () => {
        const { flow, code } = await approved();
        const body = (extra: Record<string, string>) => ({
          grant_type: "authorization_code", code, redirect_uri: flow.search.get("redirect_uri")!,
          client_id: registered.clientId, code_verifier: flow.verifier, ...extra,
        });
        const select = vi.spyOn(h.cfAuth.config.db, "select");
        for (const verifier of ["short", "x".repeat(129), `${"a".repeat(42)} `, `${"a".repeat(42)}+`]) {
          expect((await h.cfAuth.oauth.token({ body: new URLSearchParams(body({ code_verifier: verifier })) })).body).toMatchObject({
            error: "invalid_request",
          });
        }
        for (const name of ["code", "redirect_uri", "client_id", "code_verifier"]) {
          const search = new URLSearchParams(body({}));
          search.delete(name);
          expect((await h.cfAuth.oauth.token({ body: search })).body).toMatchObject({ error: "invalid_request" });
        }
        const repeated = new URLSearchParams(body({}));
        repeated.append("code", code);
        expect((await h.cfAuth.oauth.token({ body: repeated })).body).toMatchObject({ error: "invalid_request" });
        expect((await h.cfAuth.oauth.token({ body: new URLSearchParams(body({ resource: "https://other.example.com" })) })).body).toMatchObject({
          error: "invalid_target",
        });
        expect(select).not.toHaveBeenCalled();
        select.mockRestore();
        ok(await exchange(flow, code, { resource: `${issuer}/mcp` }));
      });

      it("refuses a pending, denied or unknown code", async () => {
        const pending = await start();
        const code = randomToken(32);
        expect((await exchange(pending, code)).body).toMatchObject({ error: "invalid_grant" });
        await h.cfAuth.oauth.denyAuthorization(pending);
        expect((await exchange(pending, code)).body).toMatchObject({ error: "invalid_grant" });
      });

      it("refuses an expired code and revokes nothing", async () => {
        const { person, flow, code } = await approved();
        await h.exec(
          "UPDATE operation SET outcome = json_set(outcome, '$.codeExpiresAt', ?) WHERE id = ?",
          Date.now() - 1,
          flow.id,
        );
        expect((await exchange(flow, code)).body).toEqual({
          error: "invalid_grant",
          error_description: "The authorization code has expired",
        });
        expect(await connectionsOf(person.organizationId)).toHaveLength(0);
        expect((await recordOf(flow.id)).exchangedAt).toBeNull();
      });

      it("revokes the connection a replayed code issued, before and after the code expires", async () => {
        const { person, flow, code } = await approved();
        const tokens = ok(await exchange(flow, code));
        expect((await exchange(flow, code)).body).toMatchObject({ error: "invalid_grant" });
        const [connection] = await connectionsOf(person.organizationId);
        expect(connection!.revoked_at).not.toBeNull();
        expect(await h.exec("SELECT * FROM oauth_token WHERE api_key_id = ?", connection!.id)).toHaveLength(0);
        expect((await h.cfAuth.oauth.resolveAccessTokenAuthState(tokens.access_token, { source: "mcp" })).authenticated).toBe(false);

        const second = await approved();
        ok(await exchange(second.flow, second.code));
        await h.exec(
          "UPDATE operation SET outcome = json_set(outcome, '$.codeExpiresAt', ?) WHERE id = ?",
          Date.now() - 1,
          second.flow.id,
        );
        expect((await exchange(second.flow, second.code)).body).toMatchObject({ error: "invalid_grant" });
        expect((await connectionsOf(second.person.organizationId))[0]!.revoked_at).not.toBeNull();
      });

      it("lets one of two concurrent exchanges issue, and the other revoke what it issued", async () => {
        const { person, flow, code } = await approved();
        // The first exchange's batch waits until the second has run entirely.
        const db = h.cfAuth.config.db as CfAuthDatabase & { batch(q: unknown[]): Promise<unknown[]> };
        const batch = db.batch.bind(db);
        let calls = 0;
        let second: Promise<OAuthTokenResult> | undefined;
        vi.spyOn(db, "batch").mockImplementation(async (statements: unknown[]) => {
          calls += 1;
          if (calls === 1) {
            second = exchange(flow, code);
            await second;
          }
          return batch(statements);
        });
        const first = await exchange(flow, code);
        const results = [first, await second!];
        expect(results.filter((result) => result.status === 200)).toHaveLength(1);
        expect(results.filter((result) => result.status === 400)).toHaveLength(1);
        const connections = await connectionsOf(person.organizationId);
        expect(connections).toHaveLength(1);
        expect(connections[0]!.revoked_at).not.toBeNull();
      });

      it("keeps the record a day, so a replay is recognised until the sweep, and unknown after", async () => {
        const { person, flow, code } = await approved();
        ok(await exchange(flow, code));
        const createdAt = Number((await operationRow(flow.id))!.created_at);
        await h.cfAuth.operations.sweep(createdAt + day - minute);
        expect(await operationRow(flow.id)).toBeDefined();
        await h.cfAuth.operations.sweep(createdAt + day + 1);
        expect(await operationRow(flow.id)).toBeUndefined();
        expect((await exchange(flow, code)).body).toEqual({
          error: "invalid_grant",
          error_description: "The authorization code is not valid",
        });
        // Unknown, so nothing was revoked.
        expect((await connectionsOf(person.organizationId))[0]!.revoked_at).toBeNull();
      });

      it("issues nothing when the account ended between approval and exchange", async () => {
        const { person, flow, code } = await approved();
        await h.exec("UPDATE organization SET expires_at = ? WHERE id = ?", new Date(Date.now() - minute).toISOString(), person.organizationId);
        expect((await exchange(flow, code)).body).toMatchObject({ error: "invalid_grant" });
        expect(await connectionsOf(person.organizationId)).toHaveLength(0);
        expect((await recordOf(flow.id)).exchangedAt).toBeNull();
      });
    });

    // --- metadata, and the whole flow -------------------------------------------------------------

    it("publishes the discovery documents the record specifies", () => {
      expect(h.cfAuth.oauth.protectedResourceMetadata("")).toEqual({
        resource: issuer,
        authorization_servers: [issuer],
        scopes_supported: ["read", "manage"],
        bearer_methods_supported: ["header"],
      });
      expect(h.cfAuth.oauth.protectedResourceMetadata()).toEqual(h.cfAuth.oauth.protectedResourceMetadata(""));
      expect(h.cfAuth.oauth.protectedResourceMetadata("/mcp")).toEqual({
        resource: `${issuer}/mcp`,
        authorization_servers: [issuer],
        scopes_supported: ["read", "manage"],
        bearer_methods_supported: ["header"],
      });
      expect(() => h.cfAuth.oauth.protectedResourceMetadata("/v1/admin")).toThrow(/resourcePaths/);
      const server = {
        issuer,
        authorization_endpoint: `${issuer}/oauth/authorize`,
        token_endpoint: `${issuer}/oauth/token`,
        revocation_endpoint: `${issuer}/oauth/revoke`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
        revocation_endpoint_auth_methods_supported: ["none"],
        scopes_supported: ["read", "manage"],
        authorization_response_iss_parameter_supported: true,
        client_id_metadata_document_supported: true,
      };
      expect(h.cfAuth.oauth.authorizationServerMetadata()).toEqual(server);
      expect(h.variant({ cimd: false }).oauth.authorizationServerMetadata()).toEqual({
        ...server,
        client_id_metadata_document_supported: false,
      });
    });

    it("runs the whole flow: authorize, approve, exchange, resolve, refresh, revoke", async () => {
      const person = await h.human();
      const { verifier, challenge } = await pkce();
      const search = query({ client_id: cimdClientId, redirect_uri: "http://127.0.0.1:61000/callback", resource: issuer }, challenge);
      const consent = consentOf(await authorize(search));
      const details = await h.cfAuth.oauth.authorizationDetails({
        ...consent,
        viewer: await h.actorFor(person.userId, person.organizationId),
      });
      expect(details.viewer?.memberships).toHaveLength(1);
      const { redirect } = await approveAs(consent, person, "manage");
      expect(redirect.startsWith("http://127.0.0.1:61000/callback?")).toBe(true);
      const tokens = ok(await exchange({ search, verifier }, params(redirect).get("code")!));
      const state = await h.cfAuth.oauth.resolveAccessTokenAuthState(tokens.access_token, { source: "mcp" });
      expect(state).toMatchObject({ authenticated: true, credentialType: "oauth", source: "mcp", grant: "manage" });
      expect(state.organization?.id).toBe(person.organizationId);
      const listed = await h.cfAuth.service.listApiKeys({ organizationId: person.organizationId, actor: await h.actorFor(person.userId, person.organizationId) });
      expect(listed.find((key) => key.source === "oauth")).toMatchObject({ clientId: cimdClientId, label: cimdClientName });
      const refreshed = ok(
        await h.cfAuth.oauth.token({
          body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: cimdClientId }),
        }),
      );
      expect((await h.cfAuth.oauth.resolveAccessTokenAuthState(refreshed.access_token, { source: "mcp" })).authenticated).toBe(true);
      expect(await h.cfAuth.oauth.revoke({ body: new URLSearchParams({ token: refreshed.access_token, client_id: cimdClientId }) })).toEqual({
        status: 200,
        body: null,
      });
      expect((await h.cfAuth.oauth.resolveAccessTokenAuthState(refreshed.access_token, { source: "mcp" })).authenticated).toBe(false);
    });
  });
}

// --- CIMD bounds, against a fake fetch -----------------------------------------------------------

describe("Client ID Metadata Documents", () => {
  const fetchDocument = (clientId = cimdClientId, allowUrl: ((url: URL) => boolean | Promise<boolean>) | null = null) =>
    fetchClientMetadataDocument(clientId, { fetch: fakeFetch, allowUrl });

  const refused = async (promise: Promise<unknown>, pattern?: RegExp) => {
    const error = await promise.then(
      () => null,
      (reason: unknown) => reason,
    );
    expect(error).toBeInstanceOf(ClientMetadataRefusal);
    if (pattern) expect((error as Error).message).toMatch(pattern);
    return error as Error;
  };

  it("accepts a public client's document", async () => {
    expect(await fetchDocument()).toEqual({
      clientId: cimdClientId,
      name: cimdClientName,
      domain: "client.example.com",
      redirectUris: [cimdRedirect, "https://client.example.com/cb"],
    });
    const minimal = { client_id: cimdClientId, client_name: "  Minimal  ", redirect_uris: ["com.example.app:/cb"] };
    serve(cimdClientId, () => json(minimal, { type: "application/json; charset=utf-8" }));
    expect((await fetchDocument()).name).toBe("Minimal");
    serve(cimdClientId, () => json(metadata(), { type: "application/vnd.example+json" }));
    await fetchDocument();
  });

  it("fetches once, following no redirect, with a timeout and an accept header", async () => {
    await fetchDocument();
    expect(fetchCalls).toHaveLength(1);
    const init = fetchCalls[0]!.init!;
    expect(init.redirect).toBe("manual");
    expect(init.signal).toBeInstanceOf(AbortSignal);
    expect(new Headers(init.headers).get("accept")).toBe("application/json");
  });

  it("refuses a URL of the wrong shape without fetching", async () => {
    for (const clientId of [
      "http://client.example.com/meta.json",
      "https://user:pass@client.example.com/meta.json",
      "https://client.example.com/meta.json#frag",
      "https://client.example.com/",
      "https://client.example.com",
      "not a url",
    ]) {
      await refused(fetchDocument(clientId), /client_id must be an https URL/);
    }
    expect(fetchCalls).toHaveLength(0);
  });

  it("refuses literal addresses and localhost without fetching", async () => {
    for (const clientId of [
      "https://127.0.0.1/meta.json",
      "https://10.0.0.1/meta.json",
      "https://[::1]/meta.json",
      "https://[::ffff:127.0.0.1]/meta.json",
      "https://0x7f.1/meta.json",
      "https://2130706433/meta.json",
      "https://localhost/meta.json",
      "https://localhost./meta.json",
      "https://app.localhost/meta.json",
    ]) {
      await refused(fetchDocument(clientId), /not an address or localhost/);
    }
    expect(fetchCalls).toHaveLength(0);
  });

  it("asks allowUrl after the built-in refusals, and before the fetch", async () => {
    const allowUrl = vi.fn((url: URL) => url.hostname === "client.example.com");
    await fetchDocument(cimdClientId, allowUrl);
    expect(allowUrl).toHaveBeenCalledTimes(1);
    await refused(fetchDocument("https://other.example.com/meta.json", allowUrl), /does not accept/);
    await refused(fetchDocument("https://127.0.0.1/meta.json", allowUrl));
    expect(allowUrl).toHaveBeenCalledTimes(2);
    await refused(fetchDocument(cimdClientId, () => { throw new Error("policy down"); }), /does not accept/);
    await refused(fetchDocument(cimdClientId, async () => "yes" as unknown as boolean), /does not accept/);
    expect(fetchCalls).toHaveLength(1);
  });

  it("refuses every status but 200, and follows no redirect", async () => {
    for (const status of [201, 204, 301, 302, 307, 404, 500]) {
      fetchCalls.length = 0;
      serve(cimdClientId, () =>
        new Response(status === 204 ? null : "{}", {
          status,
          headers: { "content-type": "application/json", location: "https://client.example.com/elsewhere.json" },
        }),
      );
      await refused(fetchDocument(), /did not answer 200/);
      expect(fetchCalls.map((call) => call.url)).toEqual([cimdClientId]);
    }
  });

  it("refuses a failed or timed-out fetch", async () => {
    const failing = (async () => {
      throw new DOMException("The operation timed out", "TimeoutError");
    }) as unknown as typeof fetch;
    await refused(fetchClientMetadataDocument(cimdClientId, { fetch: failing, allowUrl: null }), /could not be fetched/);
  });

  it("refuses a body that is not JSON by its media type", async () => {
    for (const type of ["text/html", "text/plain", "application/jsonp", null]) {
      serve(cimdClientId, () => json(metadata(), { type }));
      await refused(fetchDocument(), /must be served as JSON/);
    }
  });

  it("caps the body at 64 KiB, by its declared length and while streaming", async () => {
    serve(cimdClientId, () => json(metadata(), { headers: { "content-length": String(64 * 1024 + 1) } }));
    await refused(fetchDocument(), /larger than 64 KiB/);

    let cancelled = false;
    let pulled = 0;
    serve(cimdClientId, () =>
      new Response(
        new ReadableStream<Uint8Array>({
          pull(controller) {
            pulled += 1;
            controller.enqueue(new Uint8Array(16 * 1024).fill(0x20));
          },
          cancel() {
            cancelled = true;
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );
    await refused(fetchDocument(), /larger than 64 KiB/);
    expect(cancelled).toBe(true);
    expect(pulled).toBeLessThan(10);

    // Exactly at the cap is read.
    const padded = JSON.stringify(metadata());
    serve(cimdClientId, () => json(padded + " ".repeat(64 * 1024 - padded.length)));
    await fetchDocument();
  });

  it("requests at most 64 KiB plus one byte of a byte stream, however large its chunk", async () => {
    const megabyte = 1024 * 1024;
    let supplied = 0;
    let largestRequest = 0;
    let cancelled = false;
    serve(cimdClientId, () =>
      new Response(
        new ReadableStream({
          type: "bytes",
          // One 1 MiB chunk, handed over as the reader asks for it.
          pull(controller) {
            const request = controller.byobRequest!;
            const view = request.view!;
            largestRequest = Math.max(largestRequest, view.byteLength);
            const size = Math.min(view.byteLength, megabyte - supplied);
            new Uint8Array(view.buffer, view.byteOffset, size).fill(0x20);
            supplied += size;
            request.respond(size);
          },
          cancel() {
            cancelled = true;
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );
    const parse = vi.spyOn(JSON, "parse");
    await refused(fetchDocument(), /larger than 64 KiB/);
    expect(parse).not.toHaveBeenCalled();
    expect(cancelled).toBe(true);
    expect(largestRequest).toBeLessThanOrEqual(cimdMaxDocumentBytes + 1);
    expect(supplied).toBe(cimdMaxDocumentBytes + 1);
  });

  it("refuses an oversized single chunk from a body that cannot be read BYOB", async () => {
    let cancelled = false;
    serve(cimdClientId, () =>
      new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new Uint8Array(1024 * 1024).fill(0x20));
          },
          cancel() {
            cancelled = true;
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );
    const parse = vi.spyOn(JSON, "parse");
    await refused(fetchDocument(), /larger than 64 KiB/);
    expect(parse).not.toHaveBeenCalled();
    expect(cancelled).toBe(true);
  });

  it("refuses a document that is not a JSON object naming itself", async () => {
    for (const body of ["not json", "[]", "null", "\"text\""]) {
      serve(cimdClientId, () => json(body));
      await refused(fetchDocument());
    }
    for (const clientId of ["https://client.example.com/other.json", undefined, `${cimdClientId}/`]) {
      serve(cimdClientId, () => json(metadata({ client_id: clientId })));
      await refused(fetchDocument(), /client_id is not its own URL/);
    }
  });

  it("accepts public clients only, and downgrades nothing", async () => {
    const cases: [Record<string, unknown>, RegExp][] = [
      [{ token_endpoint_auth_method: "client_secret_basic" }, /token_endpoint_auth_method/],
      [{ token_endpoint_auth_method: "private_key_jwt" }, /token_endpoint_auth_method/],
      [{ token_endpoint_auth_method: null }, /token_endpoint_auth_method/],
      [{ grant_types: ["authorization_code", "client_credentials"] }, /grant_types/],
      [{ grant_types: "authorization_code" }, /grant_types/],
      [{ response_types: ["code", "token"] }, /response_types/],
      [{ client_name: undefined }, /client_name is required/],
      [{ client_name: "   " }, /client_name is required/],
      [{ client_name: 42 }, /client_name is required/],
      [{ client_name: "n".repeat(201) }, /client_name is longer/],
      [{ redirect_uris: undefined }, /redirect_uris/],
      [{ redirect_uris: [] }, /redirect_uris/],
      [{ redirect_uris: ["http://client.example.com/cb"] }, /redirect_uris/],
      [{ redirect_uris: ["https://client.example.com/cb#x"] }, /redirect_uris/],
      [{ redirect_uris: ["/relative"] }, /redirect_uris/],
      [{ redirect_uris: ["myapp:/cb"] }, /redirect_uris/],
      [{ redirect_uris: [cimdRedirect, 7] }, /redirect_uris/],
    ];
    for (const [overrides, pattern] of cases) {
      serve(cimdClientId, () => json(metadata(overrides)));
      const error = await refused(fetchDocument(), pattern);
      // A refusal names a field, never what the document said.
      expect(error.message).not.toContain("client_secret_basic");
      expect(error.message).not.toContain("client.example.com/cb");
    }
    serve(cimdClientId, () => json(metadata({ token_endpoint_auth_method: undefined, grant_types: undefined, response_types: undefined })));
    await fetchDocument();
  });
});

describe("OAuth authorization while OAuth is off", () => {
  it("refuses every function with validation_error", async () => {
    const t = await createTestAuth({ operations: { enabled: true } });
    const oauth = t.cfAuth.oauth;
    expect(() => oauth.protectedResourceMetadata()).toThrow(/OAuth is disabled/);
    expect(() => oauth.authorizationServerMetadata()).toThrow(/OAuth is disabled/);
    for (const call of [
      oauth.authorize({ query: new URLSearchParams(), rateLimitKey: null }),
      oauth.authorizationDetails({ id: "x", proof: "y", viewer: null }),
      oauth.approveAuthorization({ id: "x", proof: "y", actor: null, organizationId: "o", grant: "manage" }),
      oauth.approveGuestAuthorization({ id: "x", proof: "y", admit: async () => null, rateLimit: async () => {}, provision: () => ({ userId: "u", organizationId: "o", statements: [] }) }),
      oauth.denyAuthorization({ id: "x", proof: "y" }),
      oauth.token({ body: new URLSearchParams({ grant_type: "authorization_code" }) }),
    ]) {
      await expect(call).rejects.toMatchObject({ code: "validation_error" });
    }
  });
});

describe("redirect URI matching", () => {
  it("is exact on the string, except a loopback port", () => {
    const declared = "http://127.0.0.1/callback";
    expect(redirectUriMatches(declared, declared)).toBe(true);
    for (const port of ["1", "53111", "65535"]) {
      expect(redirectUriMatches(declared, `http://127.0.0.1:${port}/callback`)).toBe(true);
      expect(redirectUriMatches(`http://127.0.0.1:${port}/callback`, declared)).toBe(true);
    }
    expect(redirectUriMatches("http://[::1]:1/cb?x=1", "http://[::1]:2/cb?x=1")).toBe(true);
    expect(redirectUriMatches("http://localhost/cb", "http://localhost:8080/cb")).toBe(true);
    for (const presented of [
      "http://127.1/callback",
      "http://127.0.0.1/not-registered/../callback",
      "http://127.0.0.1/callback#",
      "http://127.0.0.1/callback#frag",
      "http://127.0.0.1:65536/callback",
      "http://127.0.0.1:/callback",
      "http://user@127.0.0.1/callback",
      "http://0x7f.0.0.1/callback",
      "http://localhost/callback",
      "http://127.0.0.1/callback/",
      "http://127.0.0.1/callback?",
      "http://127.0.0.1/CALLBACK",
    ]) {
      expect(redirectUriMatches(declared, presented)).toBe(false);
    }
    // The scheme is recognised in any case and compared as written.
    expect(redirectUriMatches("HTTP://localhost:3000/cb", "HTTP://localhost:3000/cb")).toBe(true);
    expect(redirectUriMatches("HTTP://localhost:3000/cb", "HTTP://localhost:4000/cb")).toBe(true);
    expect(redirectUriMatches("HTTP://localhost/cb", "HTTP://localhost:4000/cb")).toBe(true);
    expect(redirectUriMatches("Http://127.0.0.1/cb", "Http://127.0.0.1:9/cb")).toBe(true);
    expect(redirectUriMatches("HTTP://localhost:3000/cb", "http://localhost:3000/cb")).toBe(false);
    expect(redirectUriMatches("http://localhost:3000/cb", "HTTP://localhost:4000/cb")).toBe(false);
    expect(redirectUriMatches("HTTP://127.0.0.1/callback", "HTTP://127.1/callback")).toBe(false);
    expect(redirectUriMatches("HTTP://127.0.0.1/callback", "HTTP://127.0.0.1/x/../callback")).toBe(false);
    expect(redirectUriMatches("HTTP://127.0.0.1/callback", "HTTP://127.0.0.1/callback#")).toBe(false);
    // Not loopback: the port is part of the exact match.
    expect(redirectUriMatches("https://app.example.com/cb", "https://app.example.com:8443/cb")).toBe(false);
    expect(redirectUriMatches("https://app.example.com/cb", "https://app.example.com:443/cb")).toBe(false);
    expect(redirectUriMatches("http://example.com/cb", "http://example.com:8080/cb")).toBe(false);
    // A declared URI with a fragment matches nothing, even itself.
    expect(redirectUriMatches("https://app.example.com/cb#x", "https://app.example.com/cb#x")).toBe(false);
  });

  it("accepts a loopback http URI only with its host written exactly", () => {
    for (const uri of ["http://127.0.0.1/cb", "http://127.0.0.1:8080/cb", "http://[::1]/cb", "http://localhost:3000/cb", "HTTP://localhost:3000/cb", "Http://[::1]/cb"]) {
      expect(isAcceptableRedirectUri(uri)).toBe(true);
    }
    for (const uri of ["http://127.1/cb", "http://0x7f000001/cb", "http://LOCALHOST/cb", "http://127.0.0.1:99999/cb", "https://app.example.com/cb#"]) {
      expect(isAcceptableRedirectUri(uri)).toBe(false);
    }
  });
});
