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
- [Operations approved in a browser](#operations-approved-in-a-browser)
- [OAuth connections](#oauth-connections)
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

type AppEnv = {
  Bindings: Bindings;
  Variables: CfAuthVariables & { cfAuth: CfAuth };
};

const app = new Hono<AppEnv>();

app.use("*", async (c, next) => {
  const cfAuth = createCfAuth({
    appName: "Acme App",
    d1: c.env.DB,
    secret: c.env.AUTH_SECRET,
    baseUrl: c.env.APP_URL,
    apiKeys: { enabled: true, tokenPrefix: "sk_live_" },
    ...(c.env.GOOGLE_CLIENT_ID && c.env.GOOGLE_CLIENT_SECRET
      ? {
          google: {
            clientId: c.env.GOOGLE_CLIENT_ID,
            clientSecret: c.env.GOOGLE_CLIENT_SECRET,
          },
        }
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

| Method | Path                                       | Body / purpose              |
| ------ | ------------------------------------------ | --------------------------- |
| `POST` | `/api/auth/sign-up/email`                  | `{ email, password, name }` |
| `POST` | `/api/auth/sign-in/email`                  | `{ email, password }`       |
| `POST` | `/api/auth/sign-out`                       | clears the session          |
| `GET`  | `/api/auth/get-session`                    | the current session         |
| `GET`  | `/api/auth/sign-in/social?provider=google` | starts Google sign-in       |

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
  user,
  session,
  account,
  verification,
  organization,
  organizationUser,
  apiKey,
  operation,
  oauthToken,
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
table names ships in `node_modules/@maxceem/cf-auth/drizzle/`:
`0000_cf_auth_init.sql` creates the tables, `0001_cf_auth_operations.sql`
adds the `operation` table and the `source` and `label` columns of `api_key`,
`0002_cf_auth_api_key_grant.sql` adds its `grant` column, with every
existing key at `manage`, `0003_cf_auth_operation_execution_claim.sql` adds
`operation.execution_claim`, and `0004_cf_auth_oauth_token.sql` adds the
`oauth_token` table and the `client_id` and `resource` columns of `api_key`
(see [OAuth connections](#oauth-connections)). Each is plain `CREATE` and
`ALTER TABLE ... ADD`; none rebuilds a table. Copy them in, in order. The package's own tests apply these exact files, so
they cannot drift from the schema.

**Upgrading from 0.7.0.** Apply `0002`, `0003` and `0004`, even with OAuth
off. The other changes — `findOAuthAccess` on a custom repository, a refused
completion rolling back its batch, the reserved `cf-auth:` kind namespace —
are listed in [Upgrading to 0.8.0](../README.md#upgrading-to-080).

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

| Option                                  | Default             | What it does                                                                              |
| --------------------------------------- | ------------------- | ----------------------------------------------------------------------------------------- |
| `appName`                               | —                   | **Required.** Also where the default cookie prefix comes from.                            |
| `d1` / `db`                             | —                   | **Required.** A D1 binding, or a drizzle instance you built yourself. Pass one, not both. |
| `secret`                                | —                   | **Required.** Signs sessions.                                                             |
| `baseUrl`                               | —                   | Your public address. Needed in production for Google sign-in.                             |
| `basePath`                              | `"/api/auth"`       | Where the sign-in endpoints live.                                                         |
| `disableSignUp`                         | `false`             | Turns away new users while existing ones can still sign in.                               |
| `userHooks.beforeCreate`                | —                   | Runs an application hook immediately before a new human identity is persisted.            |
| `userHooks.atomicCreateGuard`           | —                   | Gates human persistence with a host-supplied Drizzle SQL predicate in the insert statement. |
| `emailAndPassword.revokeOtherSessionsOnPasswordChange` | `false` | Forces password changes to revoke every other session. |
| `google`                                | —                   | `{ clientId, clientSecret }`. Leave it out to turn Google off.                            |
| `accountLinking.implicit`               | `false`             | Whether a Google sign-in may join an existing password account. See below.                |
| `apiKeys`                               | off                 | `{ enabled: true, tokenPrefix: "sk_live_" }`.                                             |
| `operations`                            | off                 | `{ enabled: true, realm }`. See [Operations](#operations-approved-in-a-browser).          |
| `oauth`                                 | off                 | `{ enabled: true, issuer, tokenPrefix }`. See [OAuth connections](#oauth-connections).    |
| `organizations.defaultOrganizationName` | `"My Organization"` | A string, or a function of the user.                                                      |
| `cookies.prefix`                        | from `appName`      | See below.                                                                                |
| `onEvent`                               | —                   | Called for sign-ups and key changes. See [Audit events](#audit-events).                   |

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

### Google sign-in and an email that already has a password

Someone signs up with `ada@example.com` and a password; later a Google account
for the same address signs in. By default those stay two different people: the
Google sign-in is refused with `account not linked` rather than opening the
password account.

That is deliberate. Nothing here verifies an email address, so the first person
to type one is not proof of anything — and if a Google sign-in joined whatever
account already held the address, whoever registered it first would collect
every later sign-in for it. Turn it on only where you verify addresses yourself:

```ts
const cfAuth = createCfAuth({
  // ...the usual settings
  accountLinking: { implicit: true },
});
```

Linking a provider deliberately, from an account someone is already signed in
to, is a different thing and always works.

### Atomic registration admission

Use `userHooks.atomicCreateGuard` when admission depends on database state that
another registration can change concurrently. The callback receives the
configured tables and returns only the admission predicate:

```ts
import { sql } from "drizzle-orm";

createCfAuth({
  // ...
  userHooks: {
    beforeCreate: async (user) => {
      await recordRegistrationAttempt(user);
    },
    atomicCreateGuard: {
      condition: (tables) =>
        sql`not exists (select 1 from ${tables.user} where ${tables.user.kind} = 'human')`,
      onDenied: () => recordRegistrationDenial(),
    },
  },
});
```

cf-auth normalizes and persists the human with one guarded
`INSERT ... SELECT ... WHERE ... RETURNING` statement. A false predicate calls
`onDenied`, then returns the usual `403 REGISTRATION_DISABLED` error. The guard
also applies inside Better Auth's adapter callback path. The installed SQLite
adapter executes the rest of signup sequentially, so this guarantees the user
insert's atomic admission decision, not a transaction around the whole signup.

### Live credential authority in an atomic write

`credentialAuthorityCondition(tables, input)` returns `{ sql, params }` for a
SQLite condition that requires an active membership, one of the explicit
allowed roles, and either a live scoped API key or a live human session. It
uses the later of `input.nowMs` and SQLite's current clock and respects custom
table prefixes.

Place it in the same conditional mutation or database batch as the protected
write. A separate async preflight leaves a revocation or role-change race. The
condition covers credential and membership authority only; append account,
resource, and deadline rules required by your application to that same write.
Pass `grant: "manage"` when the write needs it: an API key must then carry the
`manage` grant, and a session always does. Without it, any grant will do.

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
  credentialType: "session" | "apiKey" | "oauth" | null;
  source: "web" | "api" | "cli" | "mcp" | "system" | null;
  actor: AuthActor | null;
  user: AuthUser | null; // populated for sessions and keys
  memberships: OrganizationMembership[];
  organization: OrganizationSummary | null;
  role: "owner" | "admin" | "member" | null;
  grant: "read" | "manage" | null; // see Credential grants
}
```

It looks for, in order:

1. `Authorization: Bearer <token>` — an OAuth access token when OAuth is on and
   the token carries `oauth.tokenPrefix.access` (see
   [OAuth connections](#oauth-connections)); otherwise read as an API key when
   you turned keys on. You get `credentialType: "oauth"` or `"apiKey"`, the
   credential's owner, and its one organization with the owner's role there.
2. The session cookie. You get `credentialType: "session"`, all the user's
   organizations, and the one named by the organization cookie — or their oldest
   one.
3. Nothing. The middleware **never throws**. Use the guards below to say no.

```ts
import {
  requireUser,
  requireOrganization,
  requireOrganizationManager,
  requireGrant,
  isCfAuthError,
} from "@maxceem/cf-auth";

requireUser(state); // a signed-in person only
requireOrganization(state); // a person or an API key
requireOrganization(state, "admin"); // and the role must be admin or above
requireOrganizationManager(state); // and they must be owner or admin
requireGrant(state, "manage"); // and the credential may write
```

`requireUser` tells "nobody is here" apart from "wrong kind of caller":

| Caller             | Result                 |
| ------------------ | ---------------------- |
| Nobody             | `401 unauthorized`     |
| A valid API key    | `403 session_required` |
| A signed-in person | returns the user       |

The 403 is on purpose. A machine client that gets a 401 will usually retry or
fetch a new credential, and no API key will ever be accepted on a
people-only route.

Guards throw `CfAuthError`, which has a `code` and an HTTP `status`. Handle it
once:

```ts
app.onError((error, c) => {
  if (isCfAuthError(error)) {
    return c.json(
      { error: { code: error.code, message: error.message } },
      error.status,
    );
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

await service.listOrganizations(state); // session callers only
await service.createOrganization(userId, "Second Org");
await service.selectOrganization(state, orgId); // 403 if not a member
await service.listOrganizationMembers({ actor: state, organizationId }); // owner or admin
await service.addOrganizationMember({
  actor: state,
  organizationId,
  userId,
  role: "member",
});
await service.updateOrganizationMemberRole({
  actor: state,
  organizationId,
  userId,
  role: "admin",
});
await service.removeOrganizationMember({
  actor: state,
  organizationId,
  userId,
});
```

### What each role may do

`owner` is above `admin`, which is above `member`. Owners and admins both manage
members, but **an admin can never reach owner level**:

| Action                                       | Who may do it      |
| -------------------------------------------- | ------------------ |
| Add, remove or re-role a `member` or `admin` | `owner` or `admin` |
| Add someone as an `owner`                    | `owner`            |
| Demote or remove an `owner`                  | `owner`            |
| List members                                 | `owner` or `admin` |

An organization must always keep at least one owner. Removing or demoting the
last one fails with `409 last_owner`, and the check happens inside the write
itself, so two owners removing each other at the same moment cannot both win.

Apps usually pass `organization.id` to a billing service as the paying
customer's id. That is just a habit — this package has no billing code and no
billing dependency.

---

## API keys

Turn them on with `apiKeys: { enabled: true }`. cf-auth generates each key from
secure random bytes and persists only its SHA-256 hash and display hint. Each
credential belongs to a human or service identity and is bound to one organization.

```ts
const key = await cfAuth.service.createApiKey({
  organizationId,
  actor: state,
  name: "CI pipeline",
  label: "GitHub Actions", // optional, for people reading the list
  grant: "read", // optional, "manage" unless you say so; see Credential grants
});
// Securely deliver key.plaintext once; never include it in logs.
await cfAuth.service.listApiKeys({ organizationId, actor: state });
await cfAuth.service.revokeApiKey({ organizationId, actor: state, apiKeyId });
await cfAuth.service.revokeOwnApiKey({ actor: state }); // the key the caller used
```

Creation and revocation require an owner/admin; listing requires membership.
`revokeOwnApiKey` needs no role: a key holder can always end the key it
authenticated with, which is what a CLI's `logout` does. Any other credential
gets `403 api_key_required`.

Every key records where it came from. `source` is a short word — `console`
unless you pass another, `cli` for the keys the built-in `login` operation
issues — and `label` is optional free text such as `CLI on mac-studio`. Both are
for display only; nothing authorizes on them. `oauth` is reserved: it marks
an [OAuth connection](#oauth-connections), and no caller may issue a key with it.
Session and API-key callers use the same membership role. Keys never acquire
browser assurance, including keys belonging to a human. Applications expose
their own authorized management routes around these server methods when needed.

For a deployment-authorized bootstrap or approved claim exchange, server code
can call `createServiceIdentity({ name, id? })`, create its organization/membership,
and call `issueServiceApiKey({ userId, organizationId, name, expiresAt?, enabled? })`.
This trusted primitive is not an unrestricted management endpoint. Services have
`kind: "service"`, null email, and no password/Google accounts or sessions.

Pass `enabled: false` when the key must not authenticate until the exchange that
ordered it has committed, then call `enableServiceApiKey({ apiKeyId,
organizationId })` once it has. Enabling answers with the key as it stands
rather than raising, so a key revoked in the meantime stays revoked and says so;
`revokeServiceApiKey({ apiKeyId, organizationId })` retires one from the same
trusted side. Every `ApiKeySummary` carries `enabled`, so a key still waiting is
visible in `listApiKeys` instead of looking live.

Callers send `Authorization: Bearer <key>`. `X-Client: cli` or `mcp` is telemetry
only. Every request resolves the owning identity and current active membership;
role changes and membership removal take effect immediately. Authorization uses
the current membership role and the key's grant (below); cf-auth adds no finer
permission system. Expiry and revocation affect credentials, not the identity or account.
`tokenHint` contains the token's last four characters for safe display.

`verification` keeps Better Auth's ordinary schema and is reserved for Better
Auth. Applications that implement browser handoffs or idempotency receipts own
that state in their own tables.

### Credential grants

A role says what a person or service may do in an organization. A **grant**
says how much of that one credential may use: `"read"` or `"manage"`. What a
request may do is the role and the grant together, so a `read` key held by an
owner still only reads.

| Credential     | `authState.grant`                                   |
| -------------- | --------------------------------------------------- |
| Nobody         | `null`                                              |
| A session      | `"manage"`: a person's own session is not delegated |
| An API key     | the grant it was issued with, `"manage"` by default |
| An OAuth connection | the grant the person approved                  |

A key gets its grant when it is issued and keeps it. `createApiKey` and
`issueServiceApiKey` take `grant`, and so does the built-in `login` through its
payload. Keys from before grants existed are `manage`, and `ApiKeySummary`
reports the grant of each.

cf-auth enforces it itself:

- Every write in the service needs `manage`: adding, re-roling and removing
  members, creating and revoking keys, and claiming. A `read` credential gets
  `403 grant_insufficient`. Listing members and keys needs only `read`.
- A key may never be issued with more than the issuer holds, and a `read`
  credential issues no keys at all, not even `read` ones.
  `issueServiceApiKey` has no issuer to bound it and takes the grant it is
  given; it is a trusted primitive.
- `revokeOwnApiKey` needs no grant. A `read` key can always end itself.
- Every credential but a session is held to its own organization before its
  grant is looked at, so a key naming another organization is told
  `forbidden`, not `grant_insufficient`. A claim, which also needs a session,
  refuses in that order too: another organization, then the grant, then
  `session_required`.
- An operation kind a caller opens needs `grant` from the opener's credential;
  see [Your own kinds](#your-own-kinds).

Gate your own writes with `requireGrant(state, "manage")`. It throws
`401 unauthorized` for nobody and `403 grant_insufficient` for a credential
whose grant is too narrow, and answers the state otherwise. It checks only the
grant; pair it with `requireOrganization` for the role.

### Provisional organizations

An organization may carry an `expiresAt` deadline: it exists provisionally,
usually because a machine identity created it and no person has taken it over
yet. Past that instant nothing acts inside it — an API key for it stops
authenticating, and a session resolves its other memberships instead. The
organization is still listed in `memberships`, so a client can name it and
explain why it is unavailable.

`claimOrganization` is how a person takes one over:

```ts
await cfAuth.service.claimOrganization({
  actor: c.get("authState"), // an interactive human session
  organizationId,
  provisioning: {
    userId: serviceIdentityId,
    credentialId: bootstrapKeyId,
    revokeAccess: false, // true also retires that identity's keys and membership
  },
});
```

It promotes the person to `owner` and clears the deadline in one transaction,
and refuses when somebody else already owns the organization, when the deadline
has passed, or when the provisioning credential is no longer live. Repeating a
claim that already landed settles on the same membership rather than failing,
so a caller that lost its answer can simply ask again.

When the claim is what an approval does, use
`claimOrganizationStatements({ actor, organizationId, provisioning, condition })`
instead. It returns `{ statements, afterCommit }` — the same guarded writes as
drizzle builders, with `condition` added to their guard — so an operation
kind's `approve` can return them and pass the operation's `guard` as
`condition`. The ownership change then lands in the batch that completes the
operation or not at all: a denial that commits first leaves the organization
unclaimed. `afterCommit` emits `organization.claimed` if it landed.

---

## Operations approved in a browser

Some things a command-line tool asks for should not happen until a person says
so in a browser: logging the tool in, or a change you want someone to look at
first. An **operation** is one of those requests. The tool opens it, a signed-in
person approves or denies it on a page you serve, and the tool collects the
outcome.

Turn it on and name a realm — a stable public identifier of this deployment:

```ts
createCfAuth({
  // ...the usual settings
  apiKeys: { enabled: true },
  operations: { enabled: true, realm: env.DEPLOYMENT_ID },
});
```

Then `cfAuth.operations` has everything below. It declares no routes: you mount
your own and call these from them.

### How it fits together

The tool makes one random token and keeps it (`createOperationToken()` makes
one; any 32 random bytes in base64url will do). The server stores only its
digest, so holding the token is the whole proof of being the tool that asked.

```ts
const { operations } = cfAuth;

// 1. The tool asks. Answers with the id, and while it is pending, the proof
//    for the approval link and a code to show in the terminal.
const view = await operations.open({
  kind: "login",
  token,
  rateLimitKey: c.req.header("CF-Connecting-IP"), // what the pending cap counts
  client: {
    label: "CLI on mac-studio",
    meta: { os: "darwin", ip: clientAddress, userAgent },
    loopbackRedirect: "http://127.0.0.1:53682/callback", // optional
  },
});
// The tool opens `${appUrl}/cli/approve/${view.id}#${view.browserProof}`
// and prints view.userCode, e.g. "KMXT-4R9Q".

// 2. Your approval page reads what to show, with the proof from its fragment.
const details = await operations.details({ id, proof, viewer: c.get("authState") });

// 3. The person approves, or denies.
const approval = await operations.approve({
  id,
  proof,
  actor: c.get("authState"),
  organizationId, // the one they picked
});
await operations.deny({ id, proof, actor: c.get("authState") }); // actor optional

// 4. The tool collects the outcome.
const status = await operations.poll({ id, token });
```

Put the proof in the URL **fragment**, never the path or query: a fragment is
not sent to the server, so it never lands in a log. The page reads it, sends it
in a request body, and should remove it from the address bar.

A person can also type the code instead of following the link. A code-entry
page calls `lookupByUserCode({ userCode })`, which ignores case and dashes and
answers `{ id, kind, expiresAt }` or null, and then carries on with
`{ id, userCode }` wherever the calls above take `{ id, proof }`. Eight
characters are guessable in bulk, so rate-limit the routes that accept a code.

The approval page can show the same code the terminal shows, whichever way the
person arrived: `details` answers with `userCode`. It is kept sealed like an
outcome, beside an HMAC of it under a subkey of `secret` that `lookupByUserCode`
searches by — so reading the table does not let anyone try every code offline.
After `secret` changes, `details` answers `userCode: null` rather than failing.
It also answers `createdAt`, as `poll` does, for showing when the request was
made.

Declining needs nobody signed in: a person who receives a link they did not ask
for must be able to refuse it without an account. `deny` takes the proof or the
code, and `actor`, when you pass one, only records who declined.

An operation is `pending`, then `completed` or `denied`; `expired` if nobody
answered in time; `retired` if you ended it with `retire({ id })` — a pending
one can then no longer be approved, and a completed one gives up whatever it
still holds. `poll` reports a pending operation past its deadline as `expired`
straight away, whether or not the sweep has recorded it yet.

Retrying `open` with the same token and the same request answers the way `poll`
would, completed operations included, so a tool whose response was lost just
asks again. The same token with a different request is `409 conflict`.
`findByToken({ token })` answers with the operation a token opened, or null,
without handing anything over.

Operation ids are random UUIDs unless you pass `id` to `open` — up to 128
letters, digits, `:`, `_`, `.` or `-` — for instance to keep an id derived from
the token. An id already taken by another token is `409 conflict`.

### Outcomes that carry a secret

An outcome can be **sealed**: stored encrypted under a key derived from
`secret`, handed to the tool once, and dropped as soon as it is collected or
after 15 minutes (`operations.sealTtlMs`). A kind with `deliver: "window"`
hands it to every `poll` or `redeem` that asks until those 15 minutes are up,
for a tool that may lose a response and must be able to ask again; the sweep
drops it after. A kind with `deliver: "reveal"` never hands it to the tool at
all: only [`reveal`](#reservations-and-reveals) releases it, to a person on a
page. Collecting an outcome drops the outcome only; the seal window itself
runs on until the sweep clears it. The answer that hands it over carries
`outcome`; every answer carries `record`, the part kept in the clear, and
`collect`, which says whether a sealed outcome is still waiting and how to get
it. Rotating `secret` makes sealed outcomes still waiting unreadable, so the
tool has to ask again.

When the tool registered a `loopbackRedirect`, polling never hands the outcome
over. `approve` answers with `redirectUrl` — the redirect with a one-time
`?code=` — and your page sends the browser there. The tool's local listener
receives the code and exchanges it:

```ts
const { outcome } = await operations.redeem({ id, token, redeemCode });
```

It needs the token as well as the code, so a code caught in transit is useless
on its own. Only `127.0.0.1` or `[::1]` with an explicit port is accepted as a
redirect.

For a kind a signed-in caller opened, `poll` and `redeem` check the credential
that opened it again before handing a sealed outcome over: revoke that key, and
what it asked for is not delivered. A sealed outcome that can no longer be read
because `secret` changed is `410 operation_expired`, and is left in place rather
than spent.

### The built-in `login`

`login` is registered whenever operations are on, and needs `apiKeys`. Anyone
may open one — the tool has no credential yet — and it needs `client.label`.
The person approving must be a member of the organization they choose, with at
least `operations.login.minRole`. That is `admin` unless you say otherwise —
the same people who may create an API key in the console. Set
`login: { minRole: "member" }` to let every member log a tool in. Approving
creates an API key that belongs to them, in that organization, named after the
label and marked `source: "cli"`. The tool gets it sealed:

```ts
{ credential: { token: "key_..." }, organizationId, apiKeyId }
```

A tool that only needs to read opens it with `payload: { grant: "read" }`;
without a payload the key is `manage`. Anything else in the payload is
`422 validation_error`. A login opened without a payload stores none, just as
before grants existed, so a tool repeating that same `open` across an upgrade
is answered rather than refused; no payload means `manage` wherever it is
read. An explicit `{ grant: "manage" }` is a different request from an omitted
one, and a repeat may not change the grant. `details` shows the payload
always with the grant spelled out, `{ grant: "manage" }` for an omitted one,
so your page can say what is being asked for, and the record kept in the
clear is `{ organizationId, apiKeyId, grant }`.

The key is written in the same batch that completes the operation, under a
guard that re-reads the person's session and membership, so a person signed
out or removed a moment earlier gets `409 conflict` rather than issuing a key.
It is handed over only while it is still usable: revoke it before the tool
collects it, and `poll` or `redeem` answer `410 operation_expired` and drop it.
`details` reports `blockedBy: "session_required"` when nobody is signed in and
`"no_eligible_organization"` when the viewer has nowhere they may log a tool in,
so the page knows what to offer before anyone presses a button.

Turn it off with `operations: { enabled: true, login: false }`; change its
windows with `login: { minRole, pendingTtlMs, recordTtlMs }`.

### Your own kinds

```ts
import { defineOperationKind } from "@maxceem/cf-auth";
import { and, eq } from "drizzle-orm";
import { z } from "zod";
import { secret } from "./db/schema";

const rotateSecret = defineOperationKind({
  name: "secret.rotate",
  payload: z.object({ secretId: z.string() }),
  open: { minRole: "member" }, // or "public"
  browser: true,
  approverMinRole: "admin", // null asks only for a live session
  approve: async ({ payload, guard, db }) => ({
    outcome: { rotated: payload.secretId },
    statements: [
      db
        .update(secret)
        .set({ rotatedAt: new Date() })
        .where(and(eq(secret.id, payload.secretId), guard)),
    ],
  }),
});

createCfAuth({ /* ... */, operations: { enabled: true, realm, kinds: [rotateSecret] } });
```

- `open` says who may open one: anybody, or a caller — session or API key —
  holding at least `minRole` in its current organization. Such an operation is
  pinned to that organization, and the credential that opened it is checked
  again when it is approved: revoke the key, and its pending requests can no
  longer be approved.
- `grant` is the least grant the opener's credential must carry: `"manage"`
  unless the kind says `"read"`. `open` refuses a narrower one with
  `403 grant_insufficient`, and the guard checks it again when the write lands,
  so a key that no longer carries it cannot finish what it started. A stored
  operation whose kind you have since removed is held to `manage` before its
  sealed outcome is handed over: removing a kind never releases to a `read`
  key what the kind would have withheld. A session
  is always `manage`. A `"public"` kind binds no credential, so it takes no
  `grant`.
- `payload` is a zod schema or any function that returns the value to store or
  throws. Returning `undefined` stores no payload, the same as a kind that
  takes none; the hooks then see `null`.
- `showPayload(payload)` returns what `details` shows as `payload`, when the
  stored form leaves a default implicit. `login` uses it to spell out
  `manage`.
- `approve` returns `{ outcome, seal?, record?, statements?, afterCommit? }`.
  AND `guard` into each statement's `WHERE`: it holds only while the operation
  is pending and in time and both the approver's and the opener's authority are
  live. The statements and the completion run as one batch, and the operation
  completes only if the last statement changed a row.
- Statements must be drizzle query builders — `db.update`, `db.delete`, or
  `guardedInsert(db, table, values, guard)` for an insert that carries the
  guard. Not `db.run(sql)`: D1's batch binds parameters through each item's
  prepared statement, and a raw statement has none. The engine refuses one
  with parameters on every driver, so your tests catch it before D1 does.
- `approverMinRole: null` asks only for a live session. The approver may still
  pass an `organizationId` when the operation has none yet, but must belong to
  it (any role), or it is `403 not_a_member`; one fixed by the opener cannot
  be swapped for another.
- `approver: "proof"` makes the browser proof the whole authority: `approve`
  and `deny` take `{ id, proof }` and no actor, nobody needs to be signed in,
  and the write runs under the opener's credential instead. A user code is not
  enough for such a kind, and it cannot choose an organization. Use it for a
  step that only collects something from the person the tool sent to the page.
- `input` is a schema for what the page submits with the approval — a secret
  typed there, say. It reaches `approve` as `input` and is never stored.
  `details` reports `approver` and `takesInput` so the page knows what to ask
  for.
- `refusal` returns a short code for whatever stands between this viewer and
  approving, or null. `details` reports it as `blockedBy`, and `approve` refuses
  with it, so the page and the answer never disagree.
- `deliverable({ operation, record, tables, now })` may return a SQL condition
  a sealed outcome must still meet to be handed over — that the credential it
  carries is still live, say. When it fails, `poll`, `redeem` and `reveal`
  drop that outcome and answer `410 operation_expired`. `login` uses it for
  its key.
- `deliver` is `"once"` (default: to the first `poll` or `redeem`),
  `"window"` (to every one until the seal window ends) or `"reveal"` (to
  nobody but a person calling `reveal`; `poll`, `findByToken` and a retried
  `open` answer the record without the outcome, `redeem` answers `409
  already_completed`, and none of them consumes it). `"reveal"` is for a kind
  without a browser step.
- `userCode` adds a code to type; `requireClientLabel` makes `client.label`
  mandatory; `countsTowardPending` (see
  [Limits](#limits)); `pendingTtlMs` (15 minutes)
  is how long it may wait; `recordTtlMs` (90 days) how long the record is
  kept.

A kind with `browser: false` is completed by your own code, for example a
bootstrap that creates an account for a tool with no credential yet:

```ts
const view = await operations.open({ kind: "bootstrap", token, payload });
// ...create the account...
await operations.complete({
  id: view.id,
  outcome: { credential: { token: plaintext } },
  record: { accountId },
  seal: true,
});
return operations.poll({ id: view.id, token }); // hands the credential over, once
```

`complete` also takes `statements`; guard them with
`await operations.guard({ id })`.

Once completed, `amend({ id, outcome?, seal?, record?, condition?, statements? })`
changes what the operation holds — renewing a key whose sealed copy lapsed, for
instance — in one batch with `statements`, guarded by
`await operations.guard({ id, state: "completed" })` and your own `condition`.
It answers whether the amendment landed, so of two racing renewals you know
which one won. Sealing a new outcome on an operation that had a loopback
redirect drops the redirect — its redeem code went with the first outcome — so
the new one is collected by `poll`.

### Reservations and reveals

Some writes are made by a client that may retry — an agent that lost a
response, say — and must happen once however often it asks. A **reservation**
splits such a write in two: `reserve` records what is asked and does nothing
else, and `execute` carries it out, once, under the handle `reserve` gave out.

```ts
// 1. The client asks. Nothing is written but the reservation.
const { id, handle, expiresAt } = await operations.reserve({
  kind: "app.create",
  opener: c.get("authState"),
  input: { name: "Weather" }, // stored as the payload, read by the kind's schema
});

// 2. The client confirms with the handle. The function runs once.
const result = await operations.execute(
  { handle, kind: "app.create", opener: c.get("authState") },
  ({ operation, input, guard, db }) => ({
    outcome: { appId: operation.id, key: plaintext }, // always sealed
    record: { appId: operation.id }, // kept in the clear
    statements: [guardedInsert(db, app, { id: operation.id, name: input.name }, guard)],
  }),
);
// First run: { id, state: "completed", record, outcome, replayed: false }
// A repeat:  { id, state: "completed", record, replayed: true }
```

- Only a kind a caller opens, with no browser step, can be reserved: a
  `"public"` kind or one with `browser: true` is `422 validation_error`. The
  opener is held to the kind's `open` role and `grant` exactly as `open` holds
  it, and the reservation is bound to its credential, its organization and
  the kind.
- The handle is 32 random bytes made by the server. It is the operation's
  token: only its digest is stored, and whoever holds it may execute. The
  reservation is pending for 15 minutes (`operations.reserveTtlMs`).
- `execute` answers `404 operation_not_found` for an unknown handle, then `409
  operation_mismatch` when the handle was reserved for another kind or in
  another organization than the caller's, then `410 operation_expired` once
  its 15 minutes have passed or it was retired. The caller is held to the
  kind's role and grant too.
- The function gets the stored `input`, the operation, `db`, `tables`, `now`
  and a `guard` to AND into each statement. The guard holds only while the
  reservation is pending and in time, this call still holds it, and the
  credential that reserved it is still live with the kind's role and grant,
  so a key revoked or downgraded to `read` in between writes nothing and
  `execute` answers `409 conflict`.
- The statements and the completion run as one batch, and the operation
  completes only if the last statement changed a row. When it is refused —
  by the guard, because an earlier statement of the batch made a later one
  change nothing, or because a statement deleted the operation itself — the
  whole batch rolls back: none of the statements stays written. The same
  holds for `approve`, `complete` and `amend`.
- The outcome is always sealed; `seal` is ignored. The call that ran the
  function gets the `outcome`, once. A repeat inside the seal window
  (`operations.sealTtlMs`, 15 minutes) answers the `record` only, with
  `replayed: true` and no `outcome`; after it, `409 already_completed`.
  Neither runs the function. The replay lasts the whole window: revealing
  the outcome, collecting it by `poll`, or dropping it as no longer
  deliverable spends the outcome, never the window. The record is kept at
  least as long as the window, whatever the kind's `recordTtlMs`, so the
  sweep never deletes one that can still be replayed.
- A call arriving while another runs does not run the function either: the
  first writes a claim of its own (`execution_claim`) before running
  anything, the other answers `409 conflict`, and only the claim's holder can
  complete or give it back. A function that throws, or a batch its guard
  refused, gives the claim back so the handle can be tried again. A process
  that dies mid-execution leaves the claim in place until the reservation
  lapses.

A sealed outcome that must reach a person rather than the client — a key the
client should never see — is released on a page with `reveal`:

```ts
const { outcome } = await operations.reveal({ id, actor: c.get("authState") });
```

The actor must be a signed-in person (`403 session_required` otherwise) who is
admin or owner in the operation's organization: a member is `403 forbidden`,
and someone outside it gets `404 operation_not_found`. The person is the
whole authority: the credential that opened the operation is not consulted,
so an admin still collects what a key created after that key was downgraded
or revoked. It works once, inside the seal window: the outcome is dropped as
it is handed over, and a reveal after it — or after the outcome was spent any
other way — is `409 already_revealed` inside the window and `410
operation_expired` after it, as is one on an operation that sealed nothing.
An outcome the kind's `deliverable` no longer accepts is `410
operation_expired`, and dropped; an organization past its deadline is `403
organization_expired`. The person's membership and session, the
organization's deadline, `deliverable`, the seal deadline and the very
ciphertext that was read are all judged in the write that takes the outcome;
if `amend` sealed a new outcome meanwhile, the reveal answers `409 conflict`
(or, when the old outcome was being dropped as undeliverable, `410
operation_expired`) and leaves the new one for the next reveal. Revealing
does not end the replay: `execute` keeps answering the record until the
window closes. It works on any completed operation of a kind without a
browser step — executed, or completed with `seal: true` — and refuses a kind
with one, such as `login`, with `422 validation_error`: its outcome is
collected by its own client.

#### What a tool adapter returns

The engine keeps the outcome sealed in storage, but `execute`'s first answer
carries it to the caller, so keeping a secret from an agent is the adapter's
job, in two parts:

- **Every reservation kind whose outcome is a secret sets `deliver:
  "reveal"`.** Otherwise the handle is a token like any other, and a generic
  `poll` route of your app would hand the outcome to whoever holds it. With
  `"reveal"`, no collection route releases it; only `reveal` does.
- **The tool answers with the `record` and a reference** the person can open
  to reveal the outcome, and never with `result.outcome`:

```ts
// The kind, registered in `operations.kinds`: its key is released only by `reveal`.
const appCreate = defineOperationKind({
  name: "app.create",
  open: { minRole: "admin" },
  browser: false,
  deliver: "reveal",
  payload: z.object({ name: z.string().min(1) }),
});

// An MCP tool that creates an app whose key only a person may see.
const createAppTool = async (args: { name: string; handle?: string }, authState: AuthState) => {
  if (!args.handle) {
    const { id, handle, expiresAt } = await operations.reserve({
      kind: "app.create",
      opener: authState,
      input: { name: args.name },
    });
    return { status: "confirm", handle, operationId: id, expiresAt };
  }
  const result = await operations.execute(
    { handle: args.handle, kind: "app.create", opener: authState },
    ({ operation, input, guard, db }) => {
      const key = createKey();
      return {
        outcome: { appId: operation.id, key },
        record: { appId: operation.id },
        statements: [guardedInsert(db, app, { id: operation.id, name: input.name }, guard)],
      };
    },
  );
  // `result.outcome` is deliberately not read: the key is shown on the reveal page.
  return {
    status: "done",
    record: result.record,
    replayed: result.replayed,
    revealUrl: `${consoleOrigin}/reveal/${result.id}`,
  };
};
```

The reveal page, signed in as an admin, calls `reveal({ id, actor })` and
shows the outcome once.

### Where an operation stands

`status({ id, opener })` answers `{ id, kind, state, createdAt, expiresAt,
organizationId, record }` to a caller whose current organization is the
operation's — any role, any grant. It never includes a sealed outcome and
never hands one over, so a `deliver: "once"` outcome is still waiting for its
client afterwards. Anyone else, and any operation without an organization, is
`404 operation_not_found`, so it does not disclose whether the id exists.

### Internal kinds

cf-auth's own flows register kinds of their own, named in the reserved
`cf-auth:` namespace and marked `internal: true` — today one,
`cf-auth:oauth.authorize`, registered while `oauth.enabled` (see
[Authorization](#authorization)). They share the table, the limits and the sweep, but `cfAuth.operations`
does not admit them: `open` and `reserve` refuse one with `422
validation_error`, every call that looks one up by id, token, handle or user
code answers `404 operation_not_found` (or null, for `findByToken` and
`lookupByUserCode`), `retire` answers `false`, and `operations.kinds` leaves
them out. What makes a stored operation internal is its kind's name, not what
is registered, so an engine built without the kind still hides its rows. Only
the flow that owns one drives it. Your own kind names cannot contain `:`, and
`internal` is refused in `operations.kinds`.

### Limits

`open` counts pending operations inside the insert itself, so two tools racing
for the last slot cannot both take it. An organization may have 10 at once and
one opener 5 (`operations.limits`). The opener is the signed-in caller, or, for
a public kind like `login`, whatever you pass as `rateLimitKey` — the address
your edge saw, say. Without one, public kinds are limited only by what you put
in front of them. `client.meta` is never counted: it is what the client says
about itself. Over either limit is `429 too_many_pending`.

Only kinds that wait on a person count: `countsTowardPending` defaults to
`true` for a kind with a browser step and `false` for one without, which your
own code completes — one it refuses to complete would otherwise hold a slot
until its deadline. Reservations follow their kind, so they do not count by
default either. A kind that does not count is not capped either. Set it
explicitly to change either default.

### The sweep

Nothing deletes itself. Run the sweep from a scheduled handler:

```ts
export default {
  async scheduled(_event, env) {
    await createCfAuth({ /* ... */ }).operations.sweep();
  },
};
```

It marks overdue pendings `expired`, drops sealed outcomes past their window,
and deletes records past `recordTtlMs`. `sweepStatements()` returns those as
drizzle query builders, one per step — always `operationSweepStatementCount`,
which is 3 — for a batch of your own or a job that budgets its queries.

### Errors

| Code                  | Status | When                                                          |
| --------------------- | ------ | ------------------------------------------------------------- |
| `operation_not_found` | 404    | Unknown id — and a wrong token, which is answered the same way |
| `invalid_proof`       | 403    | Wrong browser proof, user code or redeem code                 |
| `operation_expired`   | 410    | Nobody answered in time or a reservation lapsed unexecuted, it was retired, a sealed outcome's window passed, it can no longer be read or is no longer deliverable, or (for `poll` and `redeem`) its opener's credential is gone |
| `operation_denied`    | 409    | It was denied                                                  |
| `operation_pending`   | 409    | Redeeming or revealing before it completed                     |
| `already_completed`   | 409    | Approving or completing it again; redeeming a `once` outcome twice; executing it again once its seal window passed |
| `operation_mismatch`  | 409    | Executing a handle reserved for another kind or in another organization |
| `already_revealed`    | 409    | Revealing an outcome that was already revealed                  |
| `conflict`            | 409    | The same token for a different request; a guarded write found its authority changed (its batch rolled back); executing a handle another call is executing; revealing after the person's session or role changed |
| `too_many_pending`    | 429    | Over a pending limit                                           |
| `not_a_member`        | 403    | The approver lacks the membership or role the kind needs, or asked to attach an organization they do not belong to |
| `forbidden`           | 403    | Revealing without the admin or owner role                       |
| `session_required`    | 403    | The approver, or the person revealing, is not a signed-in person |
| `grant_insufficient`  | 403    | The opener's credential lacks the grant the kind needs         |
| `validation_error`    | 422    | A payload, input, token, id or client field was refused; reserving a kind that cannot be reserved; revealing a kind with a browser step |

Refused input is `422 validation_error`, as everywhere else in cf-auth. Map it
to 400 in your error handler if that is what your API answers with.

---

## OAuth connections

OAuth 2.1 for public clients, such as MCP clients. A client the person
approves gets a **connection**: an `api_key` row with `source: "oauth"`, so
everything that binds a key binds it too. It belongs to one person in one
organization, carries a grant, is listed by `listApiKeys` and ended by
`revokeApiKey`. Its tokens are issued, rotated, revoked and resolved here.
A client gets one through the authorization-code flow with PKCE: the
authorization request, a consent page where a person picks the account and
the grant (or continues without an account), and the code exchange. Clients
are registered in configuration or identify themselves with a Client ID
Metadata Document. cf-auth mounts no routes: your app mounts the discovery
documents, the authorization, token and revocation endpoints, the consent
page and its API, and the bearer gate, and sends what these functions answer.

```ts
oauth?: {
  enabled?: boolean;                  // default false; needs apiKeys, operations and a batching database
  issuer: string;                     // the issuer and the one protected resource: an origin, no path
  resourcePaths?: string[];           // also accepted as `resource`; default ["/mcp"]
  accessTokenTtlMs?: number;          // default 10 minutes
  refreshTokenTtlMs?: number;         // default 30 days, restarted by each rotation
  connectionMaxAgeMs?: number | null; // absolute cap from creation; default null
  authorizationTtlMs?: number;        // default 10 minutes: a pending authorization, and a code from completion
  tokenPrefix: { access: string; refresh: string };
  clients?: { clientId: string; name: string; redirectUris: string[] }[];
  cimd?: false | { fetch?: typeof fetch; allowUrl?: (url: URL) => boolean | Promise<boolean> };
}
```

`createCfAuth` refuses, with `422 validation_error`:

- `oauth` without `apiKeys.enabled`, without `operations.enabled`, or on a
  database whose drizzle instance has no `batch` (D1 and libsql have one):
  the rotation, the revocation and the code exchange are each one atomic
  batch;
- an `issuer` that is not exactly an origin — `https`, or `http` on
  `127.0.0.1`, `[::1]`, `localhost` or a name under `.localhost` (reserved
  for loopback use by RFC 6761 §6.3, though resolver support varies: Chrome,
  Firefox and systemd-resolved treat it as loopback, Safari on macOS before 26
  does not) — with no path, trailing slash, query, fragment or credentials;
- a missing `tokenPrefix`; prefixes other than 1 to 32 letters, digits, `_`
  or `-`; equal access and refresh prefixes; either equal to
  `apiKeys.tokenPrefix`; or an access prefix an API key could begin with,
  since a bearer token is routed by it;
- a `resourcePaths` entry that is not a path with a leading slash and no
  trailing one, or a repeated one; a lifetime that is not positive;
- a registered client without an id, a name or a redirect URI, an id given
  twice, or a redirect URI that is not absolute with no fragment and one of
  `https`, `http` on a loopback host, or a private-use scheme in reverse-DNS
  form (`com.example.app:/cb`); a `cimd` that is neither `false` nor
  `{ fetch?, allowUrl? }` of functions.

`cfAuth.config.oauth` is the resolved block, or `null` while it is off. Every
function under `cfAuth.oauth` throws `422 validation_error` while it is off.

### Tokens and lifetimes

A token names its connection: `<prefix><connectionId>.<secret>`, where the
secret is 32 random bytes, base64url. A presented token is looked up only
inside the connection it names, against that connection's current and
previous generation, by the SHA-256 digest of the whole token. A token
matching neither is unknown, and an unknown token changes nothing anywhere:
knowing a connection id gives nothing.

| What                  | Lifetime                                                          |
| --------------------- | ----------------------------------------------------------------- |
| Access token          | `accessTokenTtlMs`, 10 minutes; dead once its generation rotates  |
| Refresh token and connection | `refreshTokenTtlMs`, 30 days from the last rotation, held in `api_key.expires_at`, capped at creation + `connectionMaxAgeMs` |
| Refresh grace         | 30 s after a rotation, fixed                                       |
| Rotation rate limit   | one rotation per 5 s per connection, fixed                         |

`api_key.expires_at` is the connection's whole lifetime. Resolution, refresh,
revocation and listing read it and nothing else, and so does every operation
guard, so an operation a connection opened loses its authority when the
connection expires.

### The functions

```ts
cfAuth.oauth.token({ body: URLSearchParams }):
  Promise<{ status: 200; body: OAuthTokenResponse } | { status: 400 | 401; body: OAuthErrorBody }>;
cfAuth.oauth.revoke({ body: URLSearchParams }):
  Promise<{ status: 200; body: null } | { status: 400 | 401; body: OAuthErrorBody }>;
cfAuth.oauth.resolveAccessTokenAuthState(token: string, { source: "mcp" | "api" }): Promise<AuthState>;
cfAuth.oauth.sweepStatements(now?: number): BatchItem<"sqlite">[]; // oauthSweepStatementCount, 1
cfAuth.oauth.sweep(now?: number): Promise<void>;
cfAuth.oauth.connectionStatements(input & { condition?: SQL }): Promise<OAuthConnectionStatements>;
cfAuth.oauth.createConnection(input): Promise<OAuthTokenResponse>;
// input: { userId, organizationId, clientId, clientName, resource, grant, now?, id? }
```

**`token`**, `POST /token`, form-encoded, `grant_type=refresh_token`:
`refresh_token` and `client_id` are required, `resource` and `scope`
optional. A `resource` must be `<issuer>` or `<issuer><path>` for one of
`resourcePaths`, and the connection's own once normalised; a `scope` must
name exactly the connection's grant, since narrowing is not supported. The
response is `{ access_token, token_type: "Bearer", expires_in, refresh_token,
scope }`, `scope` always the grant. What the presented refresh token is
decides the rest:

- **The current generation's** rotates it, in one batch conditional on the
  generation being unrotated, the connection, membership and organization
  live, by the later of the request's clock and the database's: the generation is marked rotated and keeps the new response, sealed;
  the next generation is inserted; the one before is deleted; `expires_at`
  advances. Within 5 s of the last rotation it is refused instead,
  `invalid_grant` "slow down: refreshed too recently", and the token stays
  valid.
- **The previous generation's**, within 30 s of its rotation, replays that
  rotation's response byte for byte. It is sealed with AES-256-GCM under a
  key derived by HKDF-SHA256 from the presented refresh token, which the
  database holds only a digest of, so only that token's holder can open it.
  The loser of two concurrent presentations gets the same replay.
- **The previous generation's after 30 s** is reuse: the connection is
  revoked and every generation deleted, and the answer is `invalid_grant`.
  So is a rotation that lost to one more than 30 s old, or whose generation
  later rotations had already moved past while the connection stayed live;
  a rotation that lost because the connection ended changes nothing. Which
  of these applies is decided from one statement that reads the generation,
  the connection, the membership and the organization together, and the
  revocation itself lands only while all of them are still live.
- A connection that is revoked, past `expires_at`, bound to another issuer,
  or whose membership or organization has ended answers `invalid_grant` and
  changes nothing.

**`revoke`** (RFC 7009), form-encoded, `token` and `client_id` required:
either token ends the whole connection, row and generations, and
`token_type_hint` is ignored. An unknown token, or one whose connection is
already revoked or expired — also when it expires just before the write — is
`200` with no change.

**`resolveAccessTokenAuthState`** answers an empty state unless the token is
the current generation's access token, unexpired, on a live connection
(enabled, unrevoked, before `expires_at`) bound to this issuer, whose
membership is active and organization unexpired — all read in one statement,
then the token's digest verified against it.

The state carries
`assurance: "credential"`, `credentialType: "oauth"`, the `source` you pass —
the endpoint's, never the request's — `actor.credentialId` set to the
connection's id, the one membership, organization and role read now, and the
connection's grant. It is a delegated credential exactly like a key: held to
its organization and its grant by every service, refused by `requireUser`
and `listOrganizations`, and able to end itself with `revokeOwnApiKey`. The
middleware sends a bearer token with the access prefix here, with `source`
`mcp` when `X-Client: mcp` and `api` otherwise, and every other bearer token
to API keys; pass `middleware({ oauth: false })` to turn that off for a mount.
`createAuthMiddleware` takes the OAuth service as an optional `deps.oauth`
(`createOAuthService(config, repository)`), required only when OAuth routing
is on.

**Where connection liveness is checked.** One predicate,
`oauthConnectionLiveSql`, requires the row to be an OAuth connection,
enabled, unrevoked, bound to this issuer, with an `expires_at` that is set
and in the future; the membership to be active; and the organization to be
inside its deadline — judged by the later of the request's clock and the
database's. Unlike the shared `credentialAuthoritySql` it has no session
branch and accepts no missing expiry. It applies in exactly four places:

- access-token resolution (`resolveAccessTokenAuthState`), inside its one
  statement;
- the snapshot that decides a replay or reuse, both for a previous-generation
  token and for the recovery after a rotation that wrote nothing;
- the rotation's guarded write;
- the reuse revocation's guarded write.

Issuance has no connection row to test yet: its guard checks the user's
active membership and the organization's deadline on their own. A voluntary
`revoke`, and the sweep, use row liveness only — `revoke` updates a row
that is enabled, unrevoked and before `expires_at` by the database clock,
and the sweep deletes the generations of rows revoked or past `expires_at`
— on purpose: ending or cleaning up a connection must not depend on its
membership or organization still being live.

**`connectionStatements`** is the issuance primitive, a trusted boundary like
`issueServiceApiKey`: the connection row (`name` and `label` the client's
name, `client_id`, `resource` the issuer, `grant`, `expires_at`, and a
`token_hash` digesting a value never revealed, so no API-key lookup can match
it) and its first generation, as statements for a batch of yours, guarded by
your `condition`, the user's active membership and the organization's
deadline. `afterCommit` emits `api_key.created` with `credentialType:
"oauth"`. `createConnection` runs them on their own and throws `409
connection_refused` if the guard refused.

**The sweep** deletes the generations of connections that are revoked or past
`expires_at`. It is separate from the operation sweep; run both from your
scheduled handler. Revoking through `revoke`, reuse or `revokeApiKey` already
deletes them.

### Authorization

What your app mounts, all on the issuer's origin, and what answers each:

| Route | Function |
| ----- | -------- |
| `GET /.well-known/oauth-protected-resource` | `protectedResourceMetadata("")` |
| `GET /.well-known/oauth-protected-resource/mcp` | `protectedResourceMetadata("/mcp")` (one per `resourcePaths` entry) |
| `GET /.well-known/oauth-authorization-server` | `authorizationServerMetadata()` |
| `GET /oauth/authorize` | `authorize` |
| `POST /oauth/token` | `token` |
| `POST /oauth/revoke` | `revoke` |
| Your consent page's API | `authorizationDetails`, `approveAuthorization`, `approveGuestAuthorization`, `denyAuthorization` |

The authorization server document names `<issuer>/oauth/authorize`,
`/oauth/token` and `/oauth/revoke` (`oauthEndpointPaths`), so mount them
there. What cf-auth decides: whether a request is valid and for which client,
what a consent may do, when a code is good and what it issues. What your app
decides: the HTTP layer (statuses, `Cache-Control: no-store` on token and
revocation responses, CORS, `frame-ancestors 'none'` on the consent page,
checking the consent API's `Origin`), the consent page itself, and for the
guest door, the deployment's admission rule, the rate limit and what an
account is.

```ts
cfAuth.oauth.protectedResourceMetadata(path?: string): ProtectedResourceMetadata;
cfAuth.oauth.authorizationServerMetadata(): AuthorizationServerMetadata;
cfAuth.oauth.authorize({ query: URLSearchParams, rateLimitKey: string | null }):
  Promise<{ consent: { id: string; proof: string } } | { redirect: string }
        | { error: { status: 400 | 429; code: "invalid_request" | "invalid_client" | "too_many_pending"; description: string } }>;
cfAuth.oauth.authorizationDetails({ id, proof, viewer: AuthState | null }): Promise<{
  id: string; state: OperationState;
  client: { id: string; name: string; domain: string | null; source: "cimd" | "registered" };
  redirectHost: string; requestedGrant: "read" | "manage"; expiresAt: string;
  viewer: { user: AuthUser; memberships: OrganizationMembership[] } | null }>;
cfAuth.oauth.approveAuthorization({ id, proof, actor: AuthState, organizationId: string, grant: "read" | "manage" }):
  Promise<{ redirect: string }>;
cfAuth.oauth.approveGuestAuthorization({ id, proof,
  admit: () => Promise<SQL | null>,
  rateLimit: () => Promise<void>,
  provision: (ctx: { operationId: string; guard: SQL; db; tables; now: number }) =>
    { userId: string; organizationId: string; statements: unknown[] } | Promise<…> }):
  Promise<{ redirect: string; organizationId: string }>;
cfAuth.oauth.denyAuthorization({ id, proof }): Promise<{ redirect: string }>;
```

**`authorize`**, `GET /oauth/authorize`. Required: `response_type=code`,
`client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method=S256`
and `resource`; optional: `state` and `scope`. It answers one of three
shapes, which your route turns into a response:

- `{ error }`, an **error page**: show it, and send nothing to the client.
  This is the answer whenever the client or its redirect URI cannot be
  trusted. In order: a parameter given more than once (checked first, before
  the client is resolved: a duplicated `redirect_uri` could not be told from
  the real one); a missing `client_id` or `redirect_uri`; an unknown client,
  a refused metadata document, or an https `client_id` while CIMD is off
  (`invalid_client`); a `redirect_uri` the client does not declare. It also
  answers `429 too_many_pending` when the browser's address (`rateLimitKey`)
  already has `operations.limits.pendingPerOpener` authorizations pending.
- `{ redirect }`, an **error redirect** to the client's `redirect_uri`, with
  `error`, `error_description`, `state` when one was sent, and `iss`:
  `unsupported_response_type` for a `response_type` other than `code`;
  `invalid_request` for a missing parameter, a method other than `S256`
  (`plain` included), a `code_challenge` that is not exactly 43 base64url
  characters, or a `state` over 2048 characters (not echoed);
  `invalid_target` for a `resource` other than `<issuer>` or
  `<issuer><path>` for a `resourcePaths` entry; `invalid_scope` for a
  `scope` other than `read` or `manage`.
- `{ consent: { id, proof } }`: the authorization is open. Send the browser
  to your consent page as `/oauth/consent?id=<id>#<proof>`; the proof travels
  in the fragment, so it never reaches a server log.

A `redirect_uri` matches a declared one as a string, byte for byte — never
by parsing and normalising it, so `http://127.1/callback`,
`http://127.0.0.1/x/../callback` and `http://127.0.0.1/callback#` do not
match `http://127.0.0.1/callback`. The one exception is RFC 8252 §7.3's:
when both are loopback `http` URIs — the scheme in any letter case, the
host written exactly `127.0.0.1`, `[::1]` or `localhost` — the port alone
may differ: they are compared with the port removed from both and
everything else as written, so `HTTP://localhost:3000/cb` matches
`HTTP://localhost:4000/cb` but not `http://localhost:3000/cb`. A presented URI with any fragment, even an
empty one, never matches; a non-loopback URI with another port does not
either. Both `resource` spellings are normalised to the issuer. `scope`
defaults to `manage`; it is what the client asks for, and the consent page
decides.

**`authorizationDetails`** answers what the consent page shows: the
client's name with its domain (the `client_id` host for a CIMD client,
`null` for a registered one), where the browser will be sent, the grant
asked for, when the authorization lapses, and the signed-in person with every
membership — an interactive human session only, so an API key or an OAuth
state is shown as nobody. The name is the client's own claim; the domain is
what the fetch verified.

**`approveAuthorization`** is the signed-in person's "allow": `actor` must be
an interactive human session (`403 session_required` otherwise), an active
member of `organizationId` at any role (`403 not_a_member`), in an
organization inside its deadline (`403 organization_expired`); `grant` is
the person's choice, `read` or `manage`, whatever the client asked for. The
batch that completes the authorization re-reads that session, membership and
deadline; if any has ended it is refused with `409 conflict` and nothing is
written.

**`approveGuestAuthorization`** is "continue without an account", in exactly
this order:

1. the proof, or nothing else runs;
2. an authorization already completed, by either door, answers its redirect
   (and its `organizationId`) without calling anything below, so a retry
   after a lost response is never admitted or counted again;
3. `admit()`: throw to refuse; answer `null`, or an SQL condition the
   completing batch must satisfy (an emptiness rule such as `not exists
   (select 1 from organization)`, say). A refusal never reaches the rate
   limit;
4. `rateLimit()`: throw when exceeded;
5. `provision(ctx)`: answer the account's `userId` and `organizationId` and
   the statements that create them — drizzle query builders, each guarded
   with `ctx.guard`. Derive the ids from `ctx.operationId`, so a retry names
   the same rows. cf-auth commits them in the batch that completes the
   authorization:
   - the batch's **first** write judges the admission condition, with the
     engine's guard (the authorization still pending and in time), and
     latches the judgement on the operation row by writing a random claim
     of this call's own into its `execution_claim`, the column a
     reservation's execution claims its row with;
   - `ctx.guard` and every later statement ask for that claim, never the
     admission again, so provisioning may change what the admission read —
     the account's own organization makes an emptiness rule false, and
     that must not undo it;
   - the completion requires the claim, and `userId` an active member of
     `organizationId`, which is inside its deadline, and clears the claim.
     Otherwise the whole batch, the latch included, rolls back (`409
     conflict`): of two guests bootstrapping an empty deployment, the
     second one's latch finds the first one's organization and nothing of
     it lands.

A guest connection is always `manage`, since it is the account's only way
in: the record keeps `requestedGrant` beside `grant` so the page can say
so when the client asked for `read`.

**Both approvals are idempotent**, and either answers the other's result: a
person's approval racing a guest's, two guest clicks, or a retry after the
code was exchanged all answer the same redirect, byte for byte, and one
account. The redirect is `redirect_uri` with `code`, `state` when one was
sent, and `iss`. How it is rebuilt: the code is 32 random bytes made when
the authorization opens; the operation's id is `oauth-` and the code's
SHA-256 (hex), so the exchange finds it by the code's digest; and the
payload keeps the code sealed with AES-256-GCM under a key derived by
HKDF-SHA256 from the browser proof, which the database holds only a digest
of. Whoever presents the proof again reopens it; nothing else can, not even
with the database and `secret`. The engine's own token for the operation is
a separate random value nothing keeps, so the code does not lead to the
proof either.

**`denyAuthorization`** denies it and answers the `access_denied` redirect,
with `state` and `iss`; a repeat answers the same. Approving a denied
authorization is `409 operation_denied`; approving one past its deadline,
`410 operation_expired`; denying a completed one, `409 already_completed`.
A wrong proof is `403 invalid_proof` and an unknown id, or an operation of
another kind, `404 operation_not_found`, everywhere.

**The code exchange**, `token` with `grant_type=authorization_code`:
`code`, `redirect_uri`, `client_id` and `code_verifier` are required, and
`resource` optional. Before anything is looked up: a parameter given twice,
a missing one, or a `code_verifier` that is not 43–128 characters of
`[A-Za-z0-9-._~]` is `invalid_request`, and a `resource` that is not one of
the two spellings is `invalid_target`. Then:

- an unknown code — never issued, not approved yet, denied, or swept — is
  `invalid_grant`;
- `client_id` and `redirect_uri` must equal the authorization's, and
  `S256(code_verifier)` its challenge; otherwise `invalid_grant`, nothing
  written, and the code stays good, so presenting a stolen code without its
  verifier ends nothing;
- a code already exchanged is `invalid_grant`, and the connection it issued
  is revoked — sequentially or concurrently, expired or not;
- a code past `codeExpiresAt` (completion + `authorizationTtlMs`) is
  `invalid_grant`, and nothing is revoked;
- otherwise one batch writes the connection (the record's user,
  organization, grant and client; `label` the client's name; `client_id`
  the client's id) and its first generation, and stamps the record's
  `exchangedAt` and `connectionId`. Every statement in it is conditional on
  the authorization being completed, unexchanged and inside `codeExpiresAt`
  by either clock, and the connection's on the membership and organization
  being live. Of two exchanges racing, one lands; the other finds
  `exchangedAt` set and revokes what the first issued.

The response is the token response of [the functions](#the-functions), with
`scope` the grant.

**The discovery documents.** `protectedResourceMetadata(path)` answers
RFC 9728's document for `<issuer>` (`""`, the default) or `<issuer><path>`
for a `resourcePaths` entry, `resource` being exactly that URL, with
`authorization_servers: [<issuer>]`, `scopes_supported: ["read",
"manage"]` and `bearer_methods_supported: ["header"]`; any other path is
`422 validation_error`. `authorizationServerMetadata()` answers RFC 8414's:
`issuer`; the three endpoints; `response_types_supported: ["code"]`;
`grant_types_supported: ["authorization_code", "refresh_token"]`;
`code_challenge_methods_supported: ["S256"]`;
`token_endpoint_auth_methods_supported` and
`revocation_endpoint_auth_methods_supported: ["none"]`;
`scopes_supported: ["read", "manage"]`;
`authorization_response_iss_parameter_supported: true`; and
`client_id_metadata_document_supported`, true unless `cimd: false`. Serve
both with `Access-Control-Allow-Origin: *`.

#### Clients

Public clients only, from two sources:

- **Registered**, from `oauth.clients`: `clientId`, `name` (trusted
  configuration) and `redirectUris`. A registered id wins over a document.
- **Client ID Metadata Documents** (CIMD), on unless `cimd: false`: a
  `client_id` that is an https URL is fetched once per authorization, with
  `cimd.fetch` (default the global `fetch`). The bounds, in order:
  1. the URL is https, with no userinfo, no fragment and a path other than
     `/`;
  2. its host is a name: a literal IPv4 or IPv6 address (in any spelling
     the URL parser normalises), `localhost` and `*.localhost` are refused
     without a fetch;
  3. `cimd.allowUrl(url)`, when set, must answer `true`; a throw is a
     refusal;
  4. one `GET` with `redirect: "manual"` (workerd refuses `"error"`), a 5 s
     `AbortSignal.timeout` and `accept: application/json`; a fetch that
     throws is refused;
  5. any status but 200 is refused, so no redirect is followed;
  6. the media type must be `application/json` or `application/*+json`;
  7. a body over 64 KiB is refused and its stream cancelled before
     anything is parsed: a larger `content-length` is refused before
     reading; a byte stream (Workers' and Node's are) is read with a BYOB
     reader into one buffer of 64 KiB plus one byte, so at most that much
     is ever requested from it; only a body that cannot be read BYOB is
     read chunk by chunk, and a platform that delivers larger chunks
     without BYOB support may hand over more than that before the cancel;
  8. the body must be a JSON object whose `client_id` equals the URL;
  9. `token_endpoint_auth_method`, if present, must be `none`;
     `grant_types`, if present, within `authorization_code` and
     `refresh_token`; `response_types`, if present, within `code` — nothing
     is downgraded;
  10. `client_name` must be a non-empty string, at most 200 characters once
      trimmed. It is trimmed and bounded, not HTML-escaped or otherwise
      sanitised: whoever renders it — your consent page, the access page —
      must treat it as untrusted text;
  11. `redirect_uris` must list at least one URI, every one absolute with no
      fragment (not even an empty one) and `https`, `http` (in any letter
      case) on a host written exactly `127.0.0.1`, `[::1]` or `localhost`
      (any port), or a
      private-use scheme in reverse-DNS form
      (`com.example.app:/cb`).

  A refusal is `invalid_client` on an error page, and its description names
  the field or the bound, never a value from the document. Your per-address
  rate limit on `/oauth/authorize` runs before `authorize`, so it bounds
  fetches; the pending cap applies after the fetch, when the authorization
  opens.

#### The `cf-auth:oauth.authorize` kind

A pending authorization is an operation of the built-in internal kind
`cf-auth:oauth.authorize`, registered when `oauth.enabled` and refused by
every entry point of `cfAuth.operations` (see
[Internal kinds](#internal-kinds)). It is public, approved by the browser
proof (the doors carry the person's or the guest's authority into the
completing batch themselves), has no user code, counts toward
`pendingPerOpener` under `rateLimitKey`, is pending for
`authorizationTtlMs` and is kept for a day from opening — longer only when
`authorizationTtlMs` is over 12 hours, to twice it, so the record always
outlives the code. Its payload is the client, the redirect URI, the
challenge, the requested grant, the `state`, the normalised resource and the
sealed code. Its completion record, kept in the clear, is
`OAuthAuthorizationRecord`:

```ts
{ door: "person" | "guest"; userId; organizationId; grant; requestedGrant;
  client: { id, name, domain, source }; redirectUri; codeChallenge; resource;
  codeExpiresAt: number;            // completion + authorizationTtlMs, epoch ms
  exchangedAt: number | null;       // set by the exchange
  connectionId: string | null }     // the connection the exchange issued
```

It needs no migration. The operation sweep deletes it a day after it
opened, after which its code is unknown.

### Storage

Migration `0004_cf_auth_oauth_token.sql` adds `api_key.client_id` and
`api_key.resource` (null for keys) and the `oauth_token` table: `id`,
`api_key_id` (cascading), `generation`, `access_token_hash` (unique),
`access_expires_at`, `refresh_token_hash` (unique), `rotated_at`,
`sealed_response` and `created_at`, unique on `(api_key_id, generation)`. A
connection keeps at most two rows: the current generation and the previous
one. `ApiKeySummary.clientId` is the client's id for a connection and `null`
for a key.

**Upgrading a custom repository.** If you implement `CfAuthRepository`
yourself rather than using `createCfAuthRepository`, it now needs
`findOAuthAccess({ connectionId, condition })` — also with OAuth off, since
the interface requires it. Its contract:

- one coherent `SELECT`: the generation, the connection's grant, its user,
  and the membership with its organization, read together, never assembled
  from separate reads;
- only the connection's current generation: the row whose `generation` is
  the maximum across all of that connection's `oauth_token` rows, and only if
  it is unrotated (`rotated_at` null);
- the supplied `condition` enforced inside that same query (it is the
  liveness rule and the access token's expiry);
- answer `{ accessTokenHash, grant, user, membership }` or `null`, and leave
  the token's digest verification to the OAuth service.

### OAuth errors

`token` and `revoke` answer RFC 6749 §5.2 bodies, `{ error, error_description }`.
Send every token and revocation response with `Cache-Control: no-store`.

| `error`                  | Status | When                                                                 |
| ------------------------ | ------ | -------------------------------------------------------------------- |
| `invalid_request`        | 400    | A parameter given twice, a required one missing, a body that is not form parameters, a malformed `code_verifier` |
| `invalid_client`         | 401    | `client_id` is not the client the connection was issued to; nothing changes |
| `invalid_grant`          | 400    | An unknown refresh token; a dead connection; refreshed within 5 s ("slow down: refreshed too recently"); reuse, which revokes the connection. An unknown, unapproved, expired or swept code; a `client_id`, `redirect_uri` or verifier that is not the authorization's; a code already exchanged, which revokes the connection it issued |
| `invalid_scope`          | 400    | `scope` is not exactly the connection's grant                        |
| `invalid_target`         | 400    | `resource` is not the issuer or one of its paths, or not the connection's |
| `unsupported_grant_type` | 400    | A `grant_type` other than `authorization_code` and `refresh_token`  |

The authorization endpoint answers its own errors, never thrown:

| Answer        | `error` / `code`            | When |
| ------------- | --------------------------- | ---- |
| Error page    | `invalid_request` (400)     | A parameter given twice; no `client_id` or `redirect_uri`; one too long; a `redirect_uri` the client does not declare |
| Error page    | `invalid_client` (400)      | An unknown client; a refused metadata document; an https `client_id` while CIMD is off |
| Error page    | `too_many_pending` (429)    | The browser's address has too many authorizations pending |
| Redirect      | `invalid_request`           | A missing parameter; a method other than `S256`; a malformed challenge; a `state` over 2048 characters |
| Redirect      | `unsupported_response_type` | `response_type` is not `code` |
| Redirect      | `invalid_target`            | `resource` is not the issuer or one of its paths |
| Redirect      | `invalid_scope`             | `scope` is not `read` or `manage` |
| Redirect      | `access_denied`             | `denyAuthorization` |

The consent functions throw `CfAuthError`s: `invalid_proof` (403),
`operation_not_found` (404), `session_required` (403), `not_a_member`
(403), `organization_expired` (403), `operation_denied` (409),
`operation_expired` (410), `already_completed` (409, denying a completed
authorization), `conflict` (409, the completing batch found its authority
or admission gone and rolled back) and `validation_error` (422). Whatever
`admit`, `rateLimit` or `provision` throws is passed through.

---

## The organization cookie

A signed cookie remembers which organization the user is working in, so their
choice survives page loads.

```ts
const cookie = cfAuth.currentOrganizationCookie;

await cookie.write(c, organizationId); // after they switch
await cookie.read(c); // string | null
cookie.clear(c); // on sign-out
```

It is signed, not encrypted, because an organization id is not a secret. Signing
is what stops someone quietly switching to another organization. The middleware
also checks it against real membership on every request, so a made-up or
out-of-date value can never let anyone in. It just falls back to a real
organization and writes the cookie again.

A switch route usually looks like this:

```ts
app.post("/api/organizations/:id/select", async (c) => {
  const state = await cfAuth.service.selectOrganization(
    c.get("authState"),
    c.req.param("id"),
  );
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
      case "user.signup": // { userId, email }
      case "organization.created": // { userId, organizationId, role, name }
      case "api_key.created": // { actorUserId, organizationId, apiKeyId, name, credentialType? }
      case "api_key.revoked": // { actorUserId, organizationId, apiKeyId, name, credentialType? }
        await writeAuditLog(event);
    }
  },
});
```

`credentialType` is `"oauth"` when the row is an OAuth connection, and absent
for an API key. A connection's `actorUserId` is the person it was issued to,
also when the connection ends itself through `revoke` or reuse detection.

If `onEvent` fails it never breaks sign-in. The error goes to `onError`.

---

## Testing your own app

Signing in costs a password hash. That cost is the point — it is what makes a
stolen hash expensive to crack — but a test that only needs _an authenticated
caller_ pays it for nothing, and on Workers better-auth falls back to a pure-JS
scrypt that costs seconds rather than milliseconds. A suite that signs up a
handful of users spends most of its time there.

`@maxceem/cf-auth/testing` mints the session instead:

```ts
import { createTestSessions } from "@maxceem/cf-auth/testing";

const sessions = createTestSessions(cfAuth);

// A user, the organization provisioned for them, and a session.
const { cookie, userId, organizationId } = await sessions.human();

// Or a session for a user you already have.
const existing = await sessions.cookieFor(userId);

const response = await app.request("/api/me", { headers: { Cookie: cookie } });
```

`human()` creates a distinct user each call, so tests needing separate
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

| Variable               | Needed        | What it is for                                                                            |
| ---------------------- | ------------- | ----------------------------------------------------------------------------------------- |
| `AUTH_SECRET`          | yes           | Signs sessions and cookies. Make one with `openssl rand -base64 32`.                      |
| `AUTH_COOKIE_SECRET`   | no            | A separate secret for the organization cookie.                                            |
| `APP_URL`              | in production | Your public address. Needed for Google sign-in and CSRF checks.                           |
| `AUTH_TRUSTED_ORIGINS` | no            | Other addresses allowed to call the auth endpoints, like a Vite dev server.               |
| `GOOGLE_CLIENT_ID`     | no            | Leave both out to turn Google sign-in off.                                                |
| `GOOGLE_CLIENT_SECRET` | no            |                                                                                           |
| `OAUTH_PROXY_SECRET`   | no            | Shared by production and your preview environments. Keep it different from `AUTH_SECRET`. |

Put these in `.dev.vars` on your machine (it is gitignored) and use
`wrangler secret put AUTH_SECRET` in production. `APP_URL` is fine as a plain
`vars` entry in `wrangler.jsonc`.

Your Worker needs a D1 binding:

```jsonc
{
  "d1_databases": [
    { "binding": "DB", "database_name": "my-app", "database_id": "..." },
  ],
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
code your app would use. `test/operations-d1.test.ts` also runs the operations
engine on a real D1 database through Miniflare, because D1's batch accepts less
than libsql's and only D1 shows it.
