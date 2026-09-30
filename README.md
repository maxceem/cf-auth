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

## Documentation

[`docs/index.md`](docs/index.md) covers setup and migrations, the options,
reading the auth state, organizations and roles, API keys, operations approved
in a browser, the organization cookie, audit events, and the environment
variables.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
