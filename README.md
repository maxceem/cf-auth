# cf-auth

Sign-in and organizations for Cloudflare Workers apps built on Hono, D1 and
drizzle. It wraps [better-auth](https://better-auth.com) and adds the
multi-tenant part that every one of these apps ends up writing again:

- Email and password sign-in, plus Google if you want it. A Google sign-in
  never joins a password account that happens to share its email address unless
  you ask for it.
- **Organizations** with `owner`, `admin` and `member` roles, and a default one
  made for each human signup; email-less service identities share memberships.
- Hono middleware that works out who is calling, from a session cookie **or** an
  API key.
- A signed cookie that remembers which organization the user picked.
- **Operations approved in a browser**: a CLI asks, a signed-in person approves
  on your page, and the CLI collects the result. The built-in `login` gives a
  CLI an API key of its own that way.

This is a library, not a service. Your app keeps its own users, organizations
and API keys in its **own** D1 database. There is no central server and nothing
is shared between apps.

## Install

```sh
pnpm add @maxceem/cf-auth
pnpm add better-auth @better-auth/drizzle-adapter drizzle-orm hono
```

Those four are peer dependencies, so your app picks their versions and the
bundle has only one copy of each.

## Use it

```ts
import { Hono } from "hono";
import { createCfAuth, requireOrganization } from "@maxceem/cf-auth";

const app = new Hono<AppEnv>();

app.use("*", async (c, next) => {
  // Workers give you a fresh `env` per request, so build auth per request.
  c.set(
    "cfAuth",
    createCfAuth({
      appName: "Acme App",
      d1: c.env.DB,
      secret: c.env.AUTH_SECRET,
      baseUrl: c.env.APP_URL,
    }),
  );
  await next();
});

// Sign-up, sign-in and OAuth endpoints.
app.all("/api/auth/*", (c) => c.get("cfAuth").handler(c.req.raw));

// Work out who is calling for everything else.
app.use("/api/*", (c, next) => c.get("cfAuth").middleware<AppEnv>()(c, next));

app.get("/api/things", (c) => {
  const { organization, role } = requireOrganization(c.get("authState"));
  return c.json({ tenantId: organization.id, role });
});
```

You also add the package's tables to your own drizzle schema and migrate them
with your normal pipeline — the package never runs migrations itself.

## Credential grants

A role says what a person or service may do in an organization; a **grant**
says how much of that one credential may use. It is `"read"` or `"manage"`,
and what a request may do is the role and the grant together. A session is
always `manage`. An API key is `manage` unless it was issued with
`grant: "read"` — through `createApiKey`, `issueServiceApiKey`, or the
`login` operation's payload `{ grant: "read" }` — and keys from before grants
existed are `manage`.

`c.get("authState").grant` carries it. cf-auth's own writes — members, keys,
claims — need `manage` and refuse a `read` credential with
`403 grant_insufficient`; a credential never issues a key with more than it
holds, and a `read` one issues none. Gate your own writes the same way:

```ts
import { requireGrant, requireOrganization } from "@maxceem/cf-auth";

app.post("/api/things", (c) => {
  const state = requireGrant(c.get("authState"), "manage"); // 403 grant_insufficient for a read key
  const { organization } = requireOrganization(state, "admin");
  // ...
});
```

An operation kind a caller opens takes `grant` too, `"manage"` unless it says
`"read"`, checked when it opens and again when its write lands. See
[Credential grants](docs/index.md#credential-grants).

## Testing

Tests that just need an authenticated caller should not pay for a password hash.
`@maxceem/cf-auth/testing` mints a session directly:

```ts
import { createTestSessions } from "@maxceem/cf-auth/testing";

const { cookie, organizationId } = await createTestSessions(cfAuth).human();
```

See [the documentation](./docs/index.md#testing-your-own-app).

## Logging in a CLI

Turn on operations and the built-in `login` is there. Your routes call the
service; the CLI keeps one random token and never sees a password:

```ts
const cfAuth = createCfAuth({
  // ...the usual settings
  apiKeys: { enabled: true },
  operations: { enabled: true, realm: env.DEPLOYMENT_ID },
});

// The CLI asks, and prints the link and the code.
const view = await cfAuth.operations.open({
  kind: "login",
  token,
  client: { label: "CLI on mac-studio" },
});
// A signed-in person approves on your page.
await cfAuth.operations.approve({ id, proof, actor: c.get("authState"), organizationId });
// The CLI collects its key, once.
const { outcome } = await cfAuth.operations.poll({ id, token });
```

See [Operations approved in a browser](docs/index.md#operations-approved-in-a-browser)
for the loopback redirect, user codes, your own kinds and the sweep.

## Reservations

A write a client may retry, but that must happen once, is reserved first and
executed later with the handle the server gave out. A repeat replays the
record instead of running again. A secret in the outcome is released on a
page, once, to an admin — so a tool that answers an agent forwards the record
and a reveal reference, never the outcome:

```ts
const { id, handle } = await cfAuth.operations.reserve({ kind: "app.create", opener, input });
const result = await cfAuth.operations.execute(
  { handle, kind: "app.create", opener },
  ({ input, guard, db }) => ({ outcome, record, statements: [/* guarded with `guard` */] }),
);
// Only these reach the client: `result.outcome` (first run only) stays on the server.
const answer = { record: result.record, replayed: result.replayed, revealAt: `/reveal/${id}` };

const { record } = await cfAuth.operations.status({ id, opener }); // never the sealed outcome
const { outcome } = await cfAuth.operations.reveal({ id, actor: c.get("authState") }); // on the page
```

Give every such kind whose outcome is a secret `deliver: "reveal"`, so that no
`poll` route hands the outcome to whoever holds the handle; only `reveal`
releases it. Kinds cf-auth registers for its own flows are internal, named `cf-auth:…`, and
none of these entry points accepts one. See
[Reservations and reveals](docs/index.md#reservations-and-reveals) for the
errors, the guard and the seal window.

## OAuth connections

OAuth 2.1 for public clients such as MCP clients: the authorization-code
flow with PKCE, a consent page where a person picks the account and the
grant, refresh with rotation, and revocation. What a client ends up holding
is a **connection**: an `api_key` row with `credential_type = 'oauth'`, bound to one
person in one organization with a grant, like a key. It shows up in
`listApiKeys` beside the keys, with `credentialType: "oauth"` and its client's `clientId`, and
`revokeApiKey` ends it. Its tokens are prefixed and name the connection,
`<prefix><connectionId>.<secret>`: the access token lives 10 minutes, the
refresh token 30 days, restarted by each rotation, and `expires_at` on the
row is the connection's lifetime, optionally capped by
`connectionMaxAgeMs`. Only digests are stored.

```ts
const cfAuth = createCfAuth({
  // ...the usual settings, with apiKeys and operations on, on D1 or libsql
  oauth: {
    enabled: true,
    issuer: "https://console.example.com",
    tokenPrefix: { access: "agw_oat_", refresh: "agw_ort_" },
    // Optional: clients you register yourself. Others identify themselves
    // with a Client ID Metadata Document (an https client_id), unless cimd: false.
    clients: [{ clientId: "my-cli", name: "My CLI", redirectUris: ["http://127.0.0.1/callback"] }],
  },
});

// Your routes: cf-auth decides, you send.
app.get("/oauth/authorize", async (c) => {
  const url = new URL(c.req.url);
  const result = await cfAuth.oauth.authorize({ query: url.searchParams, rateLimitKey: clientAddress(c) });
  if ("consent" in result) {
    return c.redirect(`/oauth/consent?id=${result.consent.id}#${result.consent.proof}`);
  }
  if ("redirect" in result) return c.redirect(result.redirect);
  return c.html(errorPage(result.error.description), result.error.status); // never back to the client
});
app.post("/oauth/token", async (c) => {
  const result = await cfAuth.oauth.token({ body: new URLSearchParams(await c.req.text()) });
  const retry = result.status === 429 ? { "Retry-After": String(result.retryAfterSeconds) } : {};
  return c.json(result.body, result.status, { "Cache-Control": "no-store", ...retry });
});
// Your bearer gate; the middleware also routes the access prefix here by itself.
const state = await cfAuth.oauth.resolveAccessTokenAuthState(token, { source: "mcp" });
```

**What your app mounts, and what cf-auth decides.** cf-auth mounts no
routes. Your app mounts the discovery documents
(`protectedResourceMetadata`, `authorizationServerMetadata`),
`/oauth/authorize`, `/oauth/token` and `/oauth/revoke`, the consent page and
its API (`authorizationDetails`, `approveAuthorization`,
`approveGuestAuthorization`, `denyAuthorization`), and the bearer gate; it
owns statuses, headers, CORS and the page. cf-auth decides everything that
is a security rule:

- whether an authorization request is valid and for which client — a
  duplicated parameter, an unknown client or an undeclared redirect URI is
  an error page and never a redirect, and a redirect URI matches only as
  the same string (a loopback port aside); later errors go back to the client's
  redirect URI with `state` and `iss`; PKCE is S256 only;
- which clients exist: registered ones, and Client ID Metadata Documents
  fetched within fixed bounds (https only, no address or localhost hosts,
  no redirects, 5 s, JSON, a public client that names itself, and a body of
  at most 64 KiB: from a byte stream at most 64 KiB plus one byte is ever
  requested, while a platform that delivers larger chunks without BYOB
  support may hand over more before the cancel). Its declared name is
  untrusted text: render it escaped;
- what a consent may do: the person's session and membership are re-read in
  the batch that completes it, and "continue without an account" runs your
  admission rule, then your rate limit, then provisions your account inside
  that same batch, whose first write judges and latches the admission so
  provisioning cannot undo it (an empty-deployment rule works);
- when a code is good: once, for 10 minutes, with its verifier; a code
  presented again revokes the connection it issued.

Both approvals are idempotent: approving again, by either door, answers the
same redirect byte for byte, because the code is kept sealed under the
browser proof. A refresh rotates the tokens, at most once per 5 s: sooner is `429
slow_down` with a `Retry-After`, and the token stays good. The previous refresh token
replays the same response for 30 s, and after that its return revokes the
whole connection. See [OAuth connections](docs/index.md#oauth-connections)
and [Authorization](docs/index.md#authorization).

Upgrading from 0.7.0: see [Upgrading to 0.8.0](#upgrading-to-080).

## Upgrading to 0.8.0

Every deployment, whether or not it turns OAuth on:

- **Apply three migrations, in order**: `0002_cf_auth_api_key_grant.sql`
  (`api_key.grant`, every existing key at `manage`),
  `0003_cf_auth_operation_execution_claim.sql` (`operation.execution_claim`)
  and `0004_cf_auth_oauth_token.sql` (the `oauth_token` table,
  `api_key.client_id`, `api_key.resource` and `api_key.credential_type`,
  every existing key at `apiKey`; an OAuth connection is `oauth`). If you generate with
  drizzle-kit instead, export `oauthToken` from `cfAuthTables` beside the
  other tables and generate. cf-auth's queries name these columns with OAuth
  off too.
- **A custom `CfAuthRepository`** (one you wrote rather than
  `createCfAuthRepository`) must store the `grant` `createApiKey` is given,
  write `credential_type` `apiKey` (the column's default), and return
  `grant`, `clientId` and `credentialType` on every `ApiKeySummary`; it
  must also look a key up only among `credential_type = 'apiKey'` rows in
  `findActiveApiKeyByHash`, never by `source`.
- **Operations need a database that batches atomically** (D1, libsql):
  `createCfAuth` refuses one without `batch` while `operations.enabled` is
  on, where it used to run the statements one by one.
- **A refused completion rolls back its whole batch.** When `approve`,
  `complete`, `execute` or `amend` finds its guard refused, the engine now
  makes the batch fail on purpose (`NOT NULL constraint failed:
  operation.id`), so none of the `statements` you passed stay written;
  `approve`, `complete` and `execute` throw (`409 conflict` while the
  operation is still pending), and `amend` answers `false`. Drop any code
  that relied on its statements landing when the completion did not, and
  expect that error if you alert on database errors.
- **The `cf-auth:` kind namespace is reserved.** `open` and `reserve` refuse
  such a kind with `422 validation_error`, and a lookup of one of its rows
  answers `404 operation_not_found` (or `null`). Kind names could never contain
  `:`, so your own kinds are unaffected.
- `AuthState` gained `grant`, and `credentialType` may be `"oauth"`: an
  exhaustive switch, or an `AuthState` you build by hand in a test, needs the
  new case or field.

OAuth itself is optional and off by default. To offer it, add an `oauth`
block to `createCfAuth` with `enabled: true`, an `issuer` origin and a
`tokenPrefix` for access and refresh tokens, plus `clients` you register
yourself if you want any; it needs `apiKeys` and `operations` on and a D1 or
libsql database, then mount the routes listed under
[OAuth connections](#oauth-connections). Its token endpoint answers a
refresh within 5 s of the last one with `429 slow_down` and
`retryAfterSeconds`, which your route sends as `Retry-After`.

## Documentation

[`docs/index.md`](docs/index.md) covers setup and migrations, the options,
reading the auth state, organizations and roles, API keys, operations approved
in a browser and reservations, OAuth connections, the organization cookie,
audit events, and the environment variables.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
