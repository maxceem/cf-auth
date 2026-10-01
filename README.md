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

## Documentation

[`docs/index.md`](docs/index.md) covers setup and migrations, the options,
reading the auth state, organizations and roles, API keys, operations approved
in a browser and reservations, the organization cookie, audit events, and the
environment variables.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
