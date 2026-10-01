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
and `0002_cf_auth_api_key_grant.sql` adds its `grant` column, with every
existing key at `manage`. Copy them in, in order. The package's own tests apply these exact files, so
they cannot drift from the schema.

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
  credentialType: "session" | "apiKey" | null;
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
for display only; nothing authorizes on them.
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
`cf-auth:` namespace (`cf-auth:oauth.authorize`, say) and marked `internal:
true`. They share the table, the limits and the sweep, but `cfAuth.operations`
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
      case "api_key.created": // { actorUserId, organizationId, apiKeyId, name }
      case "api_key.revoked": // { actorUserId, organizationId, apiKeyId, name }
        await writeAuditLog(event);
    }
  },
});
```

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
