# cf-auth documentation

Sign-in and organizations for Cloudflare Workers apps built on Hono, D1 and
drizzle. Your app keeps its own users, organizations and API keys in its own
database.

- [Setting it up](#setting-it-up)
- [Tables and migrations](#tables-and-migrations)
- [Options](#options)
- [Who is calling](#who-is-calling)
- [Organizations](#organizations)
- [API keys](#api-keys)
- [The organization cookie](#the-organization-cookie)
- [Audit events](#audit-events)
- [Environment](#environment)
- [Working on this package](#working-on-this-package)

---

## Setting it up

Build auth per request, because Workers give you a fresh `env` each time.

```ts
// src/index.ts
import { Hono } from "hono";
import {
  createCfAuth,
  requireOrganization,
  requireUser,
  type CfAuth,
  type CfAuthVariables,
} from "@maxceem/cf-auth";

type Bindings = {
  DB: D1Database;
  AUTH_SECRET: string;
  APP_URL: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
};

type AppEnv = { Bindings: Bindings; Variables: CfAuthVariables & { cfAuth: CfAuth } };

const app = new Hono<AppEnv>();

app.use("*", async (c, next) => {
  const cfAuth = createCfAuth({
    appName: "Acme App",
    d1: c.env.DB,
    secret: c.env.AUTH_SECRET,
    baseUrl: c.env.APP_URL,
    apiKeys: { enabled: true, tokenPrefix: "sk_live_" },
    ...(c.env.GOOGLE_CLIENT_ID && c.env.GOOGLE_CLIENT_SECRET
      ? { google: { clientId: c.env.GOOGLE_CLIENT_ID, clientSecret: c.env.GOOGLE_CLIENT_SECRET } }
      : {}),
  });

  c.set("cfAuth", cfAuth);
  await next();
});

// 1. better-auth's own endpoints. Add this BEFORE the middleware.
app.all("/api/auth/*", (c) => c.get("cfAuth").handler(c.req.raw));

// 2. Work out who is calling, for everything else under /api.
app.use("/api/*", (c, next) => c.get("cfAuth").middleware<AppEnv>()(c, next));

// 3. Read it in your routes.
app.get("/api/me", (c) => {
  const state = c.get("authState");
  const user = requireUser(state); // 401 if nobody, 403 if an API key
  return c.json({ user, organization: state.organization, role: state.role });
});

export default app;
```

`cfAuth.mount(app)` is a shortcut for step 1 that uses the configured
`basePath`.

### Endpoints you get

Under `basePath`, which is `/api/auth` unless you change it:

| Method | Path | Body / purpose |
| --- | --- | --- |
| `POST` | `/api/auth/sign-up/email` | `{ email, password, name }` |
| `POST` | `/api/auth/sign-in/email` | `{ email, password }` |
| `POST` | `/api/auth/sign-out` | clears the session |
| `GET` | `/api/auth/get-session` | the current session |
| `GET` | `/api/auth/sign-in/social?provider=google` | starts Google sign-in |

You can also call these from your own code with `cfAuth.auth.api.*` when you
want to wrap them in your own routes. Remember to pass better-auth's
`Set-Cookie` headers on to your response.

---

## Tables and migrations

This package **never runs migrations**. It gives you drizzle table definitions
that you add to your own schema and migrate the way you already do.

```ts
// src/db/schema.ts
import { cfAuthTables } from "@maxceem/cf-auth/schema";
import { sqliteTable, text } from "drizzle-orm/sqlite-core";

export const {
  user, session, account, verification,
  organization, organizationUser, apiKey,
} = cfAuthTables;

// Your own tables use `organization.id` as the tenant key.
export const requestLog = sqliteTable("request_log", {
  id: text("id").primaryKey(),
  organizationId: text("organization_id")
    .notNull()
    .references(() => organization.id, { onDelete: "cascade" }),
  createdAt: text("created_at").notNull(),
});
```

Then generate and apply as usual:

```bash
pnpm drizzle-kit generate
wrangler d1 migrations apply <DB_NAME> --local   # or --remote
```

Because the auth tables sit in your schema file, drizzle-kit treats them and
your own tables as one thing: one migration folder, one history.

If you would rather not run drizzle-kit, the ready-made SQL for the default
table names ships at
`node_modules/@maxceem/cf-auth/drizzle/0000_cf_auth_init.sql`. Copy it in as
your first migration. The package's own tests apply this exact file, so it
cannot drift from the schema.

### Renaming the tables

Table names are fixed by default. To put them behind a prefix, make your own set
and pass it in — then generate a new migration, because the ready-made SQL
assumes no prefix.

```ts
import { createCfAuthTables } from "@maxceem/cf-auth/schema";

export const authTables = createCfAuthTables({ tablePrefix: "auth_" });

createCfAuth({ /* ... */, tables: authTables });
```

---

## Options

`createCfAuth(config)`. Only `appName`, `secret` and a database are required.
The full list is typed, so your editor will show you the rest — these are the
ones worth knowing about.

| Option | Default | What it does |
| --- | --- | --- |
| `appName` | — | **Required.** Also where the default cookie prefix comes from. |
| `d1` / `db` | — | **Required.** A D1 binding, or a drizzle instance you built yourself. Pass one, not both. |
| `secret` | — | **Required.** Signs sessions. |
| `baseUrl` | — | Your public address. Needed in production for Google sign-in. |
| `basePath` | `"/api/auth"` | Where the sign-in endpoints live. |
| `disableSignUp` | `false` | Turns away new users while existing ones can still sign in. |
| `google` | — | `{ clientId, clientSecret }`. Leave it out to turn Google off. |
| `apiKeys` | off | `{ enabled: true, tokenPrefix: "sk_live_" }`. |
| `organizations.defaultOrganizationName` | `"My Organization"` | A string, or a function of the user. |
| `cookies.prefix` | from `appName` | See below. |
| `onEvent` | — | Called for sign-ups and key changes. See [Audit events](#audit-events). |

### Cookie names

Nothing is tied to one app. With `appName: "Acme App"` and no changes:

- session cookies → `acme_app_auth` (so `acme_app_auth.session_token`)
- organization cookie → `acme_app_current_organization`

Set `cookies.prefix` to control both.

**Changing `appName` or `cookies.prefix` makes existing cookies stop matching.**
The prefix is used both in the cookie name and, unless you set `cookieSecret`,
in deriving the organization cookie's signing key. This fixes itself rather than
breaking: the middleware falls back to the user's first organization and writes
the cookie again, so all anyone sees is their selected organization being reset
once. Sessions are fine as long as `secret` has not changed. Set
`cookies.prefix` yourself if you want `appName` to stay free to change.

### Google sign-in from preview URLs

Google needs an exact callback address, so branch and local hosts usually cannot
be registered. Send those through one stable deployment instead:

```ts
const cfAuth = createCfAuth({
  // ...the usual database, secret, baseUrl and provider settings
  oauthProxy: {
    productionUrl: "https://app.example.com",
    secret: env.OAUTH_PROXY_SECRET,
  },
});
```

Register only the stable callback with Google. Use the same
`OAUTH_PROXY_SECRET` everywhere, and keep each environment's main `secret`
different. The stable deployment talks to Google and passes a short-lived
encrypted profile back to whichever instance started the flow, which then makes
its own user and session.

---

## Who is calling

The middleware sets `c.get("authState")`:

```ts
interface AuthState {
  authenticated: boolean;
  credentialType: "session" | "apiKey" | null;
  source: "web" | "api" | "cli" | "mcp" | "system" | null;
  actor: AuthActor | null;
  user: AuthUser | null;          // null when an API key is used
  memberships: OrganizationMembership[];
  organization: OrganizationSummary | null;
  role: "owner" | "admin" | "member" | null;
}
```

It looks for, in order:

1. `Authorization: Bearer <token>` — read as an API key when you turned keys on.
   You get `credentialType: "apiKey"`, no user, and the key's organization with
   the role `owner`.
2. The session cookie. You get `credentialType: "session"`, all the user's
   organizations, and the one named by the organization cookie — or their oldest
   one.
3. Nothing. The middleware **never throws**. Use the guards below to say no.

```ts
import {
  requireUser,
  requireOrganization,
  requireOrganizationManager,
  isCfAuthError,
} from "@maxceem/cf-auth";

requireUser(state);                       // a signed-in person only
requireOrganization(state);               // a person or an API key
requireOrganization(state, "admin");      // and the role must be admin or above
requireOrganizationManager(state);        // and they must be owner or admin
```

`requireUser` tells "nobody is here" apart from "wrong kind of caller":

| Caller | Result |
| --- | --- |
| Nobody | `401 unauthorized` |
| A valid API key | `403 session_required` |
| A signed-in person | returns the user |

The 403 is on purpose. A machine client that gets a 401 will usually retry or
fetch a new credential, and no API key will ever be accepted on a
people-only route.

Guards throw `CfAuthError`, which has a `code` and an HTTP `status`. Handle it
once:

```ts
app.onError((error, c) => {
  if (isCfAuthError(error)) {
    return c.json({ error: { code: error.code, message: error.message } }, error.status);
  }
  return c.json({ error: { code: "internal_error" } }, 500);
});
```

---

## Organizations

Every new user gets an organization automatically. Its id comes from the user
id, so two sign-ups at the same moment end up with one organization instead of
fighting. If that ever fails, the middleware makes it on the next request, so
nobody is left without one.

```ts
const { service } = cfAuth;

await service.listOrganizations(userId);
await service.createOrganization(userId, "Second Org");
await service.selectOrganization(userId, orgId);          // 403 if not a member
await service.listOrganizationMembers(actorId, orgId);    // owner or admin only
await service.addOrganizationMember({ actorUserId, organizationId, userId, role: "member" });
await service.updateOrganizationMemberRole({ actorUserId, organizationId, userId, role: "admin" });
await service.removeOrganizationMember({ actorUserId, organizationId, userId });
```

### What each role may do

`owner` is above `admin`, which is above `member`. Owners and admins both manage
members, but **an admin can never reach owner level**:

| Action | Who may do it |
| --- | --- |
| Add, remove or re-role a `member` or `admin` | `owner` or `admin` |
| Add someone as an `owner` | `owner` |
| Demote or remove an `owner` | `owner` |
| List members | `owner` or `admin` |

An organization must always keep at least one owner. Removing or demoting the
last one fails with `409 last_owner`, and the check happens inside the write
itself, so two owners removing each other at the same moment cannot both win.

Apps usually pass `organization.id` to a billing service as the paying
customer's id. That is just a habit — this package has no billing code and no
billing dependency.

---

## API keys

Turn them on with `apiKeys: { enabled: true }`. A token is your prefix plus 48
random characters. Only a hash of it is stored, so the real token is shown once
and can never be looked up again.

```ts
const key = await cfAuth.service.createApiKey({
  organizationId,
  actorUserId,
  name: "CI pipeline",
});
key.plaintext; // "sk_live_..." — show it once

await cfAuth.service.listApiKeys({ organizationId, actorUserId });
await cfAuth.service.revokeApiKey({ organizationId, actorUserId, apiKeyId });
```

**`actorUserId` decides whether the call is allowed — it is not just a note for
your logs.** A key acts as `owner` inside its organization, so making one is a
manager-level act:

| Method | The actor must be |
| --- | --- |
| `createApiKey` | `owner` or `admin` |
| `revokeApiKey` | `owner` or `admin` |
| `listApiKeys` | any member (they only get names, never tokens) |

Anything else throws `403 forbidden`. This matters because routes usually read
`organizationId` from the request. Without the check, any signed-in user could
make an owner-level key for somebody else's organization.

Callers send `Authorization: Bearer sk_live_...`. They can add `X-Client: cli`
or `X-Client: mcp` to set `state.source`, so you can tell those apart from
normal API traffic. A key belongs to exactly one organization. Revoking one
stops it working straight away.

When API keys are off, bearer headers are ignored and the key methods throw.

---

## The organization cookie

A signed cookie remembers which organization the user is working in, so their
choice survives page loads.

```ts
const cookie = cfAuth.currentOrganizationCookie;

await cookie.write(c, organizationId); // after they switch
await cookie.read(c);                  // string | null
cookie.clear(c);                       // on sign-out
```

It is signed, not encrypted, because an organization id is not a secret. Signing
is what stops someone quietly switching to another organization. The middleware
also checks it against real membership on every request, so a made-up or
out-of-date value can never let anyone in. It just falls back to a real
organization and writes the cookie again.

A switch route usually looks like this:

```ts
app.post("/api/organizations/:id/select", async (c) => {
  const user = requireUser(c.get("authState"));
  const state = await cfAuth.service.selectOrganization(user.id, c.req.param("id"));
  await cfAuth.currentOrganizationCookie.write(c, state.organization!.id);
  return c.json(state);
});
```

Remember to call `clear(c)` when they sign out.

---

## Audit events

The package keeps no audit table of its own. It hands you events and you store
them however you like:

```ts
createCfAuth({
  // ...
  onEvent: async (event) => {
    switch (event.type) {
      case "user.signup":          // { userId, email }
      case "organization.created": // { userId, organizationId, role, name }
      case "api_key.created":      // { actorUserId, organizationId, apiKeyId, name }
      case "api_key.revoked":      // { actorUserId, organizationId, apiKeyId, name }
        await writeAuditLog(event);
    }
  },
});
```

If `onEvent` fails it never breaks sign-in. The error goes to `onError`.

---

## Testing your own app

Signing in costs a password hash. That cost is the point — it is what makes a
stolen hash expensive to crack — but a test that only needs *an authenticated
caller* pays it for nothing, and on Workers better-auth falls back to a pure-JS
scrypt that costs seconds rather than milliseconds. A suite that signs up a
handful of users spends most of its time there.

`@maxceem/cf-auth/testing` mints the session instead:

```ts
import { createTestSessions } from "@maxceem/cf-auth/testing";

const sessions = createTestSessions(cfAuth);

// A user, the organization provisioned for them, and a session.
const { cookie, userId, organizationId } = await sessions.operator();

// Or a session for a user you already have.
const existing = await sessions.cookieFor(userId);

const response = await app.request("/api/me", { headers: { Cookie: cookie } });
```

`operator()` creates a distinct user each call, so tests needing separate
tenants stay independent of one another. The token is random per call and signed
with the instance's own secret — nothing here is a fixed credential, and nothing
outlives the test that asked for it.

It takes your `CfAuth` instance rather than configuration of its own, so the
cookie name and tables come from the same resolved config your app runs on and
cannot drift from it.

**This is not a way in.** Minting a session needs write access to the auth
database, which is what the sign-up route already has — a caller able to reach
these could write the same rows itself. All it skips is the password check. It
lives behind its own subpath so your application code never imports it and your
bundler never sees it; if you want that guaranteed, assert that nothing under
`src/` imports `@maxceem/cf-auth/testing`.

Keep at least one test that signs in for real. These helpers deliberately do not
exercise the password path, so something still has to.

---

## Environment

| Variable | Needed | What it is for |
| --- | --- | --- |
| `AUTH_SECRET` | yes | Signs sessions and cookies. Make one with `openssl rand -base64 32`. |
| `AUTH_COOKIE_SECRET` | no | A separate secret for the organization cookie. |
| `APP_URL` | in production | Your public address. Needed for Google sign-in and CSRF checks. |
| `AUTH_TRUSTED_ORIGINS` | no | Other addresses allowed to call the auth endpoints, like a Vite dev server. |
| `GOOGLE_CLIENT_ID` | no | Leave both out to turn Google sign-in off. |
| `GOOGLE_CLIENT_SECRET` | no | |
| `OAUTH_PROXY_SECRET` | no | Shared by production and your preview environments. Keep it different from `AUTH_SECRET`. |

Put these in `.dev.vars` on your machine (it is gitignored) and use
`wrangler secret put AUTH_SECRET` in production. `APP_URL` is fine as a plain
`vars` entry in `wrangler.jsonc`.

Your Worker needs a D1 binding:

```jsonc
{
  "d1_databases": [
    { "binding": "DB", "database_name": "my-app", "database_id": "..." }
  ]
}
```

---

## Working on this package

```bash
pnpm install
pnpm check         # types + tests + build
```

Tests run against real better-auth over an in-memory database, through a real
Hono app, so sign-up, sign-in, cookies and bearer keys all go through the same
code your app would use.
