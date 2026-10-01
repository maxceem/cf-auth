# MCP OAuth delegation: decision record (step 2 spike)

Written 2026-09-30 for the MCP feature (`mcp-unified-design.md`, decisions 9,
10, 11 and 16, and the exit criteria in its section 6). cf-auth is at 0.7.0 on
better-auth 1.6.9. The candidates were checked against better-auth 1.7.6 with
`@better-auth/oauth-provider`, `@better-auth/mcp` and `@better-auth/cimd`
1.7.6.

This record is the specification for steps 3, 7, 9, 10 and 11. Where the
spike and this record differ, this record wins; section 2 says what the spike
does and does not show.

The prototypes are in `spike/`. That directory is untracked and not part of
this commit:

- `spike/a/`: candidate A, run on 1.7.6. `harness.ts`, `flow.spike.test.ts`
  (14 tests), `extra.spike.test.ts` (5 tests), `init-cost.spike.test.ts`, and
  `provider-ddl.sql`, which is generated from better-auth's own `getSchema`.
- `spike/b/`: candidate B. `oauth.ts` (686 lines) and `flow.spike.test.ts`:
  19 tests run on libsql and on a real D1 (Miniflare, workerd), plus 4 CIMD
  tests, 42 runs in all.
- Command: `pnpm exec vitest run --config spike/vitest.config.ts <file>`.

Citations below point into the published 1.7.6 packages:

- `op/…`: `@better-auth/oauth-provider/dist`. Its chunk files are
  `oauth-1Ud-hvZY.d.mts` (types), `oauth-CJ85_W0W.d.mts` (endpoints),
  `authorize-CLuqtSXQ.mjs` and `introspect-CbYi2MJT.mjs`.
- `mcp/…`: `@better-auth/mcp/dist/index.{d.mts,mjs}`.
- `cimd/…`: `@better-auth/cimd/dist/index.{d.mts,mjs}` and `node.mjs`.

## 1. Decision

**Build the grant on cf-auth's engine (candidate B).**

Candidate A clears criteria 1, 4, 5, 6, 9 and 10, several only with
cf-auth-side work, and criterion 3 for the account but not the grant. It
fails the three that the unclaimed lifecycle and the single authority model
depend on:

- **Criterion 7, through the authorization-code grant.** The provider's
  authorization code must name a live browser session. It refuses the
  exchange with `session no longer exists` when the session is gone
  (`op/introspect-CbYi2MJT.mjs:2022-2033`). cf-auth never gives a service
  identity a session. The provider does export a documented, session-less
  minting primitive, `issueTokens`, reachable through `getOAuthProviderApi`
  (`op/oauth-1Ud-hvZY.d.mts:771-889`), so the literal criterion can be met.
  What cannot be met is reaching it through an ordinary MCP authorization-code
  delegation: no supported extension replaces the stock code exchange
  (section 4).
- **Criterion 8.** The provider has no guest path, and its pending
  authorization is only a signed query string (`signParams`,
  `op/authorize-CLuqtSXQ.mjs:5745`), so there is nothing server-side to make
  retries safe.
- **The "long rotating refresh" requirement.** The stable identity of
  criterion 2 is there: `referenceId` and `authorizationCodeId` carry forward
  across rotation. The revocation is too wide: replay detection tears down
  every refresh token for the (client, user) pair, across accounts
  (`op/introspect-CbYi2MJT.mjs:1498`). Every token issued through consent also
  inherits the approving browser session: when that session expires, the
  access token and every token refreshed from it go inactive
  (`op/introspect-CbYi2MJT.mjs:2324-2333`).

Criteria 7 and 8 can be met under A only by adding a before-hook to
`/oauth2/token` that validates and exchanges cf-auth's own codes and mints
tokens with `issueTokens` (prototyped in `spike/a/extra.spike.test.ts`). That
is B's code exchange, written anyway, on top of:

- seven provider tables;
- a better-auth minor upgrade;
- a larger bundle behind `cfAuth()` (+217 KB minified in a neutral bundle of
  cf-auth; not measured in the gateway Worker);
- keeping the provider's token rows in step with the cf-auth row that maps
  them. That row can be an `api_key` row (`referenceId` = the key id, with B's
  unusable-hash convention), so the claim guard needs no second branch; the
  synchronisation remains.

Candidate B meets the ten criteria in its prototype, on D1 as well as libsql,
within the limits listed in "What the spike shows for B" (section 2):

- The engine holds the pending authorization and the code.
- The connection is an `api_key` row, so the existing
  `credentialAuthoritySql`, the claim's provisioning guard, `revokeApiKey` and
  `listApiKeys` apply to it unchanged.
- A connection outlives the browser session that approved it.
- Replaying a refresh token ends one connection, not every connection that
  person has with that client.

CIMD does not separate the candidates. Both fetch the metadata document
through the Worker's outbound HTTPS; the design turns CIMD on by default,
within budgets, with a deployment switch to turn it off (section 3, "Client
identity").

## 2. The ten criteria

"A:" is what the spike showed for candidate A. "B:" is what B takes: the
primitive that exists, what has to be written, and the size, measured as
production code excluding tests.

| # | Criterion | A: better-auth 1.7.6 provider (evidence) | B: cf-auth engine (cost) |
|---|---|---|---|
| 1 | Opaque token, verified in process, into an `AuthState` with one organization, the current role and the grant; an authoritative mapping row | **Pass, with glue.** With `disableJwtPlugin: true` the tokens are opaque (response `agw_oat_…`, not a JWT). `requireMcpAuth` verifies JWTs over JWKS HTTP (`mcp/index.mjs:233`), and `remoteVerify` is HTTP introspection (`mcp/index.d.mts:21`), so neither works in process. In-process verification uses the documented `getOAuthProviderApi(ctx, opts).validateAccessToken(token)` (`op/oauth-1Ud-hvZY.d.mts:844-889`). It needs a better-auth endpoint context, so cf-auth has to own a `SERVER_ONLY` plugin endpoint (prototyped). Without a client id the call is allowed (`op/introspect-CbYi2MJT.mjs:2225-2231`). The introspection payload carries no `referenceId` or `authorizationCodeId`. The connection id has to be added as a claim through `customAccessTokenClaims` (`op/oauth-1Ud-hvZY.d.mts:1698`), which is re-derived at introspection. The cf-auth mapping row is then read on every request, and it is authoritative: after it is revoked the provider still reports `active: true` while cf-auth refuses. Test `A1/A3` resolved `{credentialType:"oauth", assurance:"credential", source:"mcp", grant:"read", role:"owner"}`. Cost per request: the provider reads the token, the client, the bound session, the user and the resource policy (`op/introspect-CbYi2MJT.mjs:2293-2380`), then cf-auth reads the mapping and the membership. | **Pass.** `resolveAccessTokenAuthState` does one join of token → `oauth_token` → live `api_key` (enabled, unrevoked, `expires_at` in the future, `resource` equal to the issuer), then reads the user and membership through the existing repository (`spike/b/oauth.ts`, `resolveAccessToken`). `source` is the endpoint's, passed by the caller. Proved on D1 and libsql: `{grant:"read", role:"owner", credentialType:"oauth", source:"mcp", assurance:"credential"}`. About 80 lines. |
| 2 | One stable identity across rotation | **Identity: pass. Revocation scope: fail.** `authorizationCodeId` and `referenceId` carry forward on rotation (`op/introspect-CbYi2MJT.mjs:2178`; `op/oauth-1Ud-hvZY.d.mts:2410`), and the spike's refresh rows share one of each, so pending operations and guarded writes could bind to `referenceId`. But replay runs `invalidateRefreshFamily(ctx, client_id, userId)`, hardcoded to that pair, which deletes every refresh and access token for that client and user (`op/introspect-CbYi2MJT.mjs:1498-1527, 2160`). In the spike, one person's second connection to a *different account* through the same client died with the first; zero refresh rows remained (observed and printed, not asserted). A CIMD `client_id` is a shared URL (one per product, such as a desktop agent), so this applies to every connection a person has from that product. | **Pass.** The connection id is the `api_key` id. `oauth_token` rows are its generations. Replay revokes that one key. Asserted: one person with two connections through one client, to two accounts, where a replay on one leaves the other working; and to one account, where revoking one leaves the other resolving and refreshing. About 60 lines. |
| 3 | Consent takes account and grant; both live on the grant | **Account: pass through the provider's hooks. Grant: fail.** `postLogin.shouldRedirect` exists to ask for "an additional choice… an organization or team" after login and before consent, and `/oauth2/continue` with `postLogin: true` resumes (`op/oauth-1Ud-hvZY.d.mts:1540-1573`). `consentReferenceId` receives `{user, session, scopes}` (`:1551`), so the chosen account is read back from wherever that page stored it against the session; the spike carried it in a closure around an in-process call. Called in process, consent needs a `request` (`op/authorize-CLuqtSXQ.mjs:5483-5488`); passing one is supported. Consent rows are keyed (client, user, referenceId) and reused silently (`:5646-5690`); cf-auth can force consent by adding `prompt=consent` to the request it forwards (`:5645`) or by returning a never-matching reference (prototyped). The grant cannot be a scope: consent may only narrow to scopes that were originally requested ("Scope not originally requested", `:45`). The guest connection's required `read` → `manage` override is therefore impossible as a scope, and a `read` grant chosen when `manage` was requested leaves the token's `scope` contradicting the mapping row (spike: `scope: "manage offline_access"`, grant `read`). The grant has to live on the mapping row alone. | **Pass.** The route checks the viewer and passes `{organizationId, grant}` as the engine's `input`. The kind's `approve` re-checks the approver's session and membership with `credentialAuthoritySql` inside the completing batch. The grant is stored on the `api_key` row, and the token's `scope` is the grant. About 70 lines, with no engine change. |
| 4 | Console revoke kills the refresh family and the live token at once; the connection is listed with its client name | **Pass, only through cf-auth-side work.** `deleteOAuthConsent` deletes the consent row only, revokes no token, and requires the consenting user's own session (`op/authorize-CLuqtSXQ.mjs:2989-3010`). Revocation works by marking the mapping row, which takes effect immediately, and then deleting provider rows by `referenceId` directly. The listing joins mapping → `oauthClient.name` (`clientDiscoveryId: "cimd"` marks CIMD names). With the mapping in a separate table, the list merges two sources; with an `api_key` row as the mapping it does not. | **Pass.** The existing `revokeApiKey`. Token verification and the refresh guard both require a live key. The existing `listApiKeys` lists the connection once (`source: "oauth"`, `label` = the client's declared name, `clientId` = the document URL). About 10 lines, for `clientId` in the summary. |
| 5 | CIMD on Workers within the plugin's transport requirements, without a fork, or pre-registration as a fallback | **Partial.** `fetchClientMetadataResource` is ours to supply (`cimd/index.d.mts:72-78`). The plugin itself enforces a 5 s timeout, a 5 KB streaming cap, a JSON content type, refusal of literal private or loopback hosts, and non-200 answers (`cimd/index.mjs:38-55, 250-251, 330-395`; the spike printed each refusal). It passes `redirect: "error"` (`:344`), which workerd rejects, so our transport must translate to `manual` and refuse 3xx. The contract says the transport "MUST resolve the hostname exactly once… pin the approved address… refuse redirects" (`cimd/index.d.mts:72`). The only shipped transport uses `node:dns`, `node:https`, `node:net` and `node:stream` (`cimd/node.mjs:1-5`); a Worker's `fetch` takes a hostname and cannot pin an address. Pre-registered clients are ordinary `oauthClient` rows, so that fallback works. | **Pass.** `fetchClientMetadataDocument` in `spike/b/oauth.ts` enforces the budgets and the public-client profile of section 3 before and after the fetch: HTTPS only; no userinfo, fragment or root path; no literal IPs or `localhost`; `redirect: "manual"` with a refusal of every non-200; `AbortSignal.timeout(5000)`; a streaming 64 KiB cap; a JSON media type; `client_id` equal to the URL; a non-empty `client_name`; `token_endpoint_auth_method` `none` or absent; `grant_types` and `response_types` within the supported sets; and acceptable `redirect_uris`. Asserted with a stub `fetch`, not against the network. Pre-registered clients come from config. About 100 lines. |
| 6 | The 1.7 upgrade leaves cf-auth, Google sign-in and the engine working | **Pass.** Under 1.7.6: `pnpm typecheck` exit 0; `pnpm test` passed 20 files and 190 tests, including `operations.test.ts`, `operations-d1.test.ts`, `api-keys.test.ts` and `session.test.ts`; `pnpm build` exit 0. `POST /sign-in/social {provider:"google"}` returned an `accounts.google.com` URL (spike A6). Core table fields are unchanged in `@better-auth/core` 1.7.6 (`db/get-tables.mjs`). cf-auth uses neither better-auth's organization plugin nor its api-key plugin; it has its own tables. The only plugins it wraps are `oAuthProxy` and `openAPI` (`src/better-auth.ts`). Release notes flag two behaviour changes: "`session.delete` hooks now run on sign-out", and drizzle "throws on an invalid affected-row count". The suite shows no regression from either. | **Not needed.** B runs on 1.6.9 (the spike passes after the restore). The upgrade stays an independent choice. |
| 7 | A token for a session-less service identity, verifying into a `manage` actor | **Fail through the standard grant; pass through `issueTokens`.** `/oauth2/authorize` with no session redirects to `loginPage` (spike: `302 /login`; `op/authorize-CLuqtSXQ.mjs:5600-5604`). `VerificationValue.sessionId` is a required string (`op/oauth-1Ud-hvZY.d.mts:2187-2190`), and the code exchange refuses a missing or expired session (`op/introspect-CbYi2MJT.mjs:2022-2033`). cf-auth refuses to create a session for a service identity ("Human login is required", spike). `issueTokens` is exported and documented as "a raw minting primitive" that takes an optional `user` and no session (`op/oauth-1Ud-hvZY.d.mts:771-823, 856-871`). The spike minted a session-less token for a service identity through a cf-auth endpoint and refreshed it; it verified as `{grant:"manage", kind:"service", role:"owner"}`. An MCP client reaches that only if cf-auth intercepts `/oauth2/token` (section 4). | **Pass.** At exchange time the connection key is written for whichever user the record names. The token endpoint needs no session (asserted: a guest connection resolves as `{kind:"service", grant:"manage"}`). |
| 8 | Guest authorization: provision an unclaimed account inside the pending authorization, with retry safety | **Fail natively; hybrid possible.** The provider's pending authorization is the signed `oauth_query`. It is stateless, reusable until `exp`, and one consent can be submitted twice to get two codes. So the pending state and the code for a guest must live in cf-auth. The spike's before-hook on `/oauth2/token` (a before-hook may return a response and short-circuit, `better-auth/dist/api/dispatch.mjs`, `runBeforeHooks`) checked PKCE, the redirect, the client and single use. It then minted with `issueTokens`: 200, service actor, and a replay got `invalid_grant` (printed, not asserted). That is B's exchange, rebuilt against the provider's internals. | **Pass.** One `cf-auth:oauth.authorize` operation, opened at `/authorize`, is completed either by the person or by the guest door. The guest's `approve` inserts the service user, the organization with its deadline, and the owner membership, all under the engine's guard and the admission condition, with ids derived from the operation id. Asserted on D1 and libsql: two concurrent "continue" clicks answer the same redirect and create exactly one account; approving the same authorization twice in sequence answers a byte-equal redirect and the same account, before and after the code is exchanged; a person's approval racing a completed guest approval answers the guest's redirect. |
| 9 | The claim guard verifies the connection's stable authority without a hidden API key | **Pass if the mapping is an `api_key` row.** `credentialAuthoritySql` and the claim's provisioning guard (`src/repository.ts:554-570`) read `api_key` only. With a separate mapping table, A would need a second branch there. With an `api_key` row as the mapping, the guard applies unchanged; what remains is keeping the provider's refresh rows, and their session binding, consistent with that row, and extending the claim's `revokeAccess` path to delete them. | **Pass with no change.** The connection *is* an `api_key` row. The spike opened `claim` with the OAuth `AuthState` as opener and approved it with a human session, and the account became claimed. After the connection was revoked, the same approval failed with "authority changed". |
| 10 | Admission rules and the bootstrap rate limit apply at consent | **Pass, in the cf-auth wrapper.** Consent goes through cf-auth's own route, so the gateway can run `DEPLOYMENT_RULES.bootstrap` and `enforceEndpointRateLimit` before anything happens. The provider offers no hook of its own before consent: `postLogin.shouldRedirect` and `signup.shouldRedirect` run only for a signed-in user (`op/oauth-1Ud-hvZY.d.mts:1477-1590`). | **Pass; the order is proven, the gateway's rules stand in.** `approveGuestAuthorization` takes the admission and the rate limit as callbacks and runs them in the order of section 3, "The guest door". Asserted with stand-in callbacks: a bad proof reaches neither; a refused admission consumes no rate-limit budget, however often it is refused; an admission condition that fails inside the batch provisions nothing; a completed authorization answers before either callback. The gateway's `DEPLOYMENT_RULES.bootstrap` and `enforceEndpointRateLimit` themselves are not exercised. `/authorize` also counts against the engine's `pendingPerOpener` under `rateLimitKey = ip`. |

What else the spike measured for A:

- **Session binding** (`flow.spike.test.ts`, "session binding";
  `extra.spike.test.ts`, sign-out). These tests print their outcomes rather
  than asserting all of them; the observations are:
  - Session *expires*: the access token goes inactive. A refresh still
    returns 200, but the renewed token is inactive too, because it carries
    the same `sid`. The connection is dead.
  - Real `/sign-out`: the access token is revoked, while the `offline_access`
    refresh token is kept (`op/authorize-CLuqtSXQ.mjs:261`). Its `sessionId`
    becomes null through the foreign key's `on delete set null`, and the
    renewed token is active.
  - So a connection's life depends on how the approving browser session
    ended.
  - B stores no session on a token. The spike deleted the session and the
    connection kept working and refreshing (asserted).
- **Startup and bundle.** Indicative only; none of this is a gateway Workers
  startup measurement:
  - The spike bundled cf-auth alone with esbuild (`--minify`, neutral
    platform, Workers conditions). Adding the three plugins took that bundle
    from 1,148,394 to 1,365,963 bytes (+217 KB; +58 KB gzip).
  - Module evaluation in Node went from 86–104 ms to 110–118 ms.
  - The per-instance benchmark (`init-cost.spike.test.ts`) built instances
    over core tables only and discarded `$context` errors, so its 0.50 ms and
    2.54 ms per instance are construction costs, not a successful provider
    initialisation.
  - Plugin `init` runs `seedResources` on every instance
    (`op/authorize-CLuqtSXQ.mjs:4407`). That is one `oauthResource` read per
    `createCfAuth` that reaches `$context`, and the gateway builds one per
    request.
  - All of this sits behind `cfAuth()`, so the proxied path is unaffected.
    Every management request would pay it.
- **Schema** (`spike/a/provider-ddl.sql`):
  - Seven provider tables. `oauthClient` alone has 36 columns.
  - Column names are camelCase unless every field is remapped through the
    provider's `schema` option.
  - Arrays are stored as JSON text.
  - Foreign keys run to `user`, `user_session` and the client.
- **Issuer:** A's issuer is `origin + basePath`, which for the gateway is
  `https://console/v1/auth`. Clients have to use RFC 8414 path insertion.
  B's issuer is the bare console origin.

### What the spike shows for B

Asserted, on libsql and on D1:

- discovery: the root and `/mcp` protected-resource documents each name
  their own `resource` and the same authorization server; the server
  metadata advertises `none` for token and revocation authentication;
- consent with account and grant → code with `iss` and `state` → opaque token
  → `AuthState`; the connection row carries `resource` and an `expires_at`
  one refresh lifetime ahead;
- the authorization-request rules of section 3: S256 only, a 43-character
  challenge, a 43–128 character verifier, `resource` required, `state` and
  `scope` optional, both `resource` spellings accepted, and a duplicated
  parameter refused at `/authorize` and at `/token`;
- connection isolation for one person and one client, by replay and by
  revocation;
- tokens shaped `<prefix><connectionId>.<secret>`, resolved only within the
  connection they name: a random secret under a real connection id is
  unknown, `invalid_grant` for a refresh and no state for an access token,
  and the connection stays live and keeps refreshing;
- console revocation through `revokeApiKey`, and a single listing;
- a code is single use; a sequential replay revokes what it issued, and of
  two concurrent presentations one wins and the loser revokes the winner's
  connection;
- two concurrent presentations of one refresh token: one rotation wins and
  the loser revokes the connection (the spike runs with no grace window);
- an expired code is refused; `codeExpiresAt` is completion plus 10 minutes;
- refresh validates `resource` and `scope`;
- `expires_at` advances on rotation; an expired key, a foreign `resource` or
  an expired organization ends resolution and refresh;
- the connection outlives the approving browser session;
- the guest door's order, retry idempotence and single account, and the
  claim guard over a connection (criteria 8 to 10 above).

Specified in section 3 but not prototyped: two-generation storage (the spike
keeps every generation), the 30 s refresh grace and the rotation rate limit; the revocation endpoint; the HTTP layer (error bodies,
headers, CORS, challenges); grant enforcement inside cf-auth's services; the
step 7 engine additions; CIMD against the real network; and real MCP clients.

## 3. The design cf-auth will expose (candidate B)

### Configuration (`createCfAuth`)

```ts
oauth?: {
  /**
   * Needs apiKeys.enabled, operations.enabled and a database that batches
   * atomically (D1, libsql). Default false.
   */
  enabled?: boolean;
  /**
   * The issuer and the single protected resource: an origin with no path and
   * no trailing slash. The gateway passes deployment.identity().consoleOrigin.
   */
  issuer: string;
  /** Paths under the issuer also accepted as `resource`; tokens are bound to the issuer either way. Default ["/mcp"]. */
  resourcePaths?: string[];
  accessTokenTtlMs?: number;          // default 10 minutes
  refreshTokenTtlMs?: number;         // default 30 days, restarted by each rotation
  connectionMaxAgeMs?: number | null; // absolute cap from the connection's creation; default null (revocable, like a key)
  authorizationTtlMs?: number;        // pending authorization, and a code's validity from completion; default 10 minutes
  tokenPrefix?: { access: string; refresh: string }; // gateway: agw_oat_ / agw_ort_
  /** Pre-registered clients: the fallback where CIMD is off or refused. */
  clients?: { clientId: string; name: string; redirectUris: string[] }[];
  /** Client ID Metadata Documents. On by default; false turns them off for the deployment. */
  cimd?: false | {
    fetch?: typeof fetch;                                   // default globalThis.fetch
    allowUrl?: (url: URL) => boolean | Promise<boolean>;    // extra host policy, e.g. an allowlist
  };
}
```

Validation follows `resolveConfig`: the issuer must be https, or http on
loopback; `oauth` requires `apiKeys` and `operations`; the prefixes must be
distinct from `apiKeys.tokenPrefix` and from each other. `oauth` also refuses
a database without `batch`: the engine's sequential fallback keeps every
guard but not atomicity, and the code exchange, the rotation and the guest
provisioning each depend on one atomic batch.

The refresh grace (30 s) and the rotation rate limit (one rotation per 5 s per
connection) are fixed, not configurable.

### Types

- `AuthCredentialType = "session" | "apiKey" | "oauth"`.
- `AuthState.grant: "read" | "manage" | null`:
  - a key: its row's grant;
  - an OAuth connection: its row's grant;
  - a session: `"manage"`, since a person's own session is not a delegated
    credential;
  - unauthenticated: `null`.
- An OAuth state carries:
  - `assurance: "credential"`;
  - `source`: the endpoint's, `"mcp"` on `/mcp` and `"api"` on `/v1/admin`,
    passed by the caller of `resolveAccessTokenAuthState` and never read from
    a request body;
  - `actor.credentialId`: the connection's `api_key` id;
  - `memberships`: the one membership;
  - `organization` and `role`: read on every request.
- `ApiKeySummary` gains:
  - `grant: "read" | "manage"`;
  - `clientId: string | null`, null for a key;
  - `source: "oauth"` for a connection. `normalizeApiKeySource` must refuse a
    caller-supplied `"oauth"`.
- Issuance inputs gain `grant?: "read" | "manage"`, defaulting to `"manage"`:
  `createApiKey`, `issueServiceApiKey`, and the `login` kind, which the CLI
  opens at `manage`.
- `OperationKindDefinition.grant?: "read" | "manage"`, default `"manage"`.

### Grant enforcement in cf-auth (step 3)

cf-auth enforces the grant itself; no caller has to repeat it.

- `requireActor` restricts every non-session credential, an API key or an
  OAuth connection, whether a human or a service holds it, to its own
  organization, and applies its grant. Today it restricts only
  `credentialType === "apiKey"`; without the change an `"oauth"` state could
  reach another organization through the member and key services.
- Every cf-auth service mutation requires `manage`: members, roles,
  organizations, keys, claims. A `read` credential gets `403
  grant_insufficient`; a session is `manage`.
- Issuance: the issued grant must not exceed the issuer's. A `read`
  credential cannot issue keys at all, not even `read` ones. Trusted
  bootstrap issuance (`issueServiceApiKey`, which has no actor) is unchanged
  and takes the grant it is given.
- `OperationKindDefinition.grant` is enforced twice: at `open`, against the
  opener's `AuthState.grant`; and inside the guard, where the write-time
  authority predicate also requires the opener credential's `api_key.grant`
  to satisfy the kind's grant when the opener is a key or a connection. The
  grant is therefore checked when the write lands, not only when the
  operation opened.

### Service functions (`cfAuth.oauth`, refusing while disabled)

```ts
protectedResourceMetadata(path?: "" | "/mcp"): ProtectedResourceMetadata;
authorizationServerMetadata(): AuthorizationServerMetadata;
authorize(input: { query: URLSearchParams; rateLimitKey: string | null }):
  Promise<{ consent: { id: string; proof: string } } | { redirect: string }>;
authorizationDetails(input: { id: string; proof: string; viewer: AuthState | null }):
  Promise<{ id: string; state: OperationState;
            client: { id: string; name: string; domain: string | null; source: "cimd" | "registered" };
            redirectHost: string; requestedGrant: "read" | "manage"; expiresAt: string;
            viewer: { user: AuthUser; memberships: OrganizationMembership[] } | null }>;
approveAuthorization(input: { id: string; proof: string; actor: AuthState; organizationId: string;
                              grant: "read" | "manage" }): Promise<{ redirect: string }>;
approveGuestAuthorization(input: { id: string; proof: string;
  admit: () => Promise<SQL | null>;   // deployment admission; may return a condition for the batch
  rateLimit: () => Promise<void>;     // keyed on the browser's address; throws when exceeded
  provision: (ctx: { operationId: string; guard: SQL; db: CfAuthDatabase; tables: CfAuthTables; now: number })
    => { userId: string; organizationId: string; statements: unknown[] } }): Promise<{ redirect: string; organizationId: string }>;
denyAuthorization(input: { id: string; proof: string }): Promise<{ redirect: string }>;
token(input: { body: URLSearchParams }): Promise<{ status: number; body: Record<string, unknown> }>;
revoke(input: { body: URLSearchParams }): Promise<{ status: number; body: Record<string, unknown> | null }>;
resolveAccessTokenAuthState(token: string, context: { source: "mcp" | "api" }): Promise<AuthState>; // empty state when not live
sweepStatements(now?: number): BatchItem<"sqlite">[];   // separate from the operation sweep, whose count the gateway budgets
```

How the functions behave:

- **Both approvals** are idempotent. Once the operation has completed, a
  repeat answers the same redirect: the code is sealed in the payload. A
  person's approval racing a completed guest approval, or the reverse,
  answers the winner's redirect.
- **`approveAuthorization`** re-checks the approver's session and membership
  in the batch that completes the operation.
- **`approveGuestAuthorization`** runs the order of "The guest door" below.
  The provisioning statements are the gateway's `provisionUnclaimedAccount`
  (step 5); cf-auth commits them in the batch that completes the
  authorization, under the engine's guard and the admission condition, with
  ids derived from the operation id.
- **`token`** and **`revoke`** answer an HTTP status and body; the gateway
  writes them with the headers of "HTTP contract".
- **The middleware** routes a bearer token by prefix: `oauth.tokenPrefix.access`
  goes to `resolveAccessTokenAuthState`, and everything else goes to API keys,
  as today.
- **The `cf-auth:oauth.authorize` kind is internal.** The engine's generic
  `details`, `approve`, `deny`, `status` and reservation entry points refuse
  it; only these functions reach it, so no generic operation route can submit
  an approval input for it.

### Authorization request (step 10)

`GET /oauth/authorize`:

- Required: `response_type=code`, `client_id`, `redirect_uri`,
  `code_challenge`, `code_challenge_method=S256` and `resource`. Optional:
  `state` and `scope`. `scope` is `read` or `manage`, defaulting to
  `manage`; it is the grant the client asks for, and the consent page decides.
- Any parameter given more than once is `invalid_request`. That check runs
  first, before the client is resolved, and answers an error page rather than
  a redirect, since a duplicated `redirect_uri` cannot be trusted.
- The client is resolved next (registered, or CIMD). An unknown client, or a
  `redirect_uri` that does not match one it declares, is an error page, never
  a redirect.
- Every later error is a redirect to that `redirect_uri` with `error`,
  `error_description`, `state` when one was sent, and `iss`.
- PKCE is S256 only; `plain` or any other method is `invalid_request`.
  `code_challenge` must be exactly 43 base64url characters, no padding (the
  encoding of a SHA-256 digest).
- `resource` must be `<issuer>` or `<issuer>/mcp` (`resourcePaths`); anything
  else is `invalid_target`. Both are normalised to the issuer.
- The redirect to the client after approval carries `code`, `state` when one
  was sent, and `iss`.

`POST /oauth/token`, form-encoded:

- `grant_type=authorization_code`: `code`, `redirect_uri`, `client_id` and
  `code_verifier` are required. `code_verifier` is 43–128 characters from
  `[A-Za-z0-9-._~]`; anything else is `invalid_request` before the code is
  looked up. `client_id` and `redirect_uri` must equal the authorization's,
  and `S256(code_verifier)` its challenge; otherwise `invalid_grant`.
- `grant_type=refresh_token`: `refresh_token` and `client_id` are required;
  `resource` and `scope` are optional and validated as in "Resource and scope
  binding".
- A `resource` on either grant, when present, must be one of the two
  spellings, and is normalised to the issuer.
- Any parameter given more than once is `invalid_request`.

**The code.** A code is valid from the authorization's completion until
`codeExpiresAt` = completion + `authorizationTtlMs` (10 minutes), recorded on
the completion record. The exchange's conditional write requires the
operation to be completed, not yet exchanged, and `codeExpiresAt` in the
future, in the same batch that writes the connection `api_key` row and its
first generation. So:

- an unused code past `codeExpiresAt` fails with `invalid_grant` and revokes
  nothing;
- a code that was already exchanged, presented again, sequentially or
  concurrently, revokes the connection it issued (see "Tokens, rotation and
  replay"), whether or not it has expired;
- the operation record is retained for 1 day, separately from the code's
  validity, so a replay after expiry is still recognised as a replay rather
  than answered as an unknown code. After that day the code is unknown and
  fails with `invalid_grant`.

### Client identity (step 10)

Two sources, one profile: **public clients only**.

- **Registered clients** come from `oauth.clients`. Their `name` is trusted
  configuration.
- **CIMD**: a `client_id` that is an https URL is fetched as a Client ID
  Metadata Document. It is on by default; `cimd: false` turns it off for the
  deployment, leaving registered clients only.

The fetch is bounded before it happens:

- `client_id` must be https, with no userinfo, no fragment and a path other
  than `/`; a literal IP address, `localhost` or `*.localhost` is refused
  without a fetch; `allowUrl`, when configured, is asked next;
- the gateway's per-address rate limit on `/oauth/authorize` runs before
  `authorize`, so it bounds fetches; the engine's per-address pending cap
  applies when the authorization opens, after the fetch, and bounds pending
  rows;
- `redirect: "manual"` (workerd refuses `"error"`), and every answer but 200
  is refused, so no redirect is followed;
- a 5 s timeout, and a streaming cap of 64 KiB;
- a JSON media type, and a JSON object whose `client_id` equals the URL.

The document must describe a public client, and nothing is downgraded:

- `token_endpoint_auth_method` must be `"none"`. Absent is treated as
  `"none"`; any other value is `invalid_client`.
- `grant_types`, if present, must be a subset of
  `["authorization_code", "refresh_token"]`, and `response_types`, if
  present, a subset of `["code"]`; otherwise `invalid_client`.
- `client_name` is required and non-empty.
- Every `redirect_uris` entry must be absolute, with no fragment, and one of:
  `https`; `http` on a loopback host (`127.0.0.1`, `[::1]` or `localhost`),
  any port; or a private-use scheme in reverse-DNS form, with at least one
  dot (`com.example.app:/cb`). Any other entry refuses the document.
- The request's `redirect_uri` must equal one of them exactly. For a
  loopback `http` URI the port may differ (RFC 8252 §7.3); host, path and
  query may not.

**The client's name.** The consent page shows `client_name` as declared by
the client's domain, with that domain (the `client_id` host) beside it. The
name is display only and never trusted as identity; the domain is what the
fetch verified. The connection's `label` copies the name and its `client_id`
keeps the URL, so the access page shows both. A registered client shows its
configured name.

### Protected resource and binding (steps 9 to 11)

There is one protected resource, the console origin, and two documents for
it:

- `GET /.well-known/oauth-protected-resource/mcp`: the path-based document
  for the MCP endpoint, `resource` = `<origin>/mcp`. Its `resource` equals the
  identifier its location was derived from, as RFC 9728 §3.3 requires.
- `GET /.well-known/oauth-protected-resource`: the root document, for clients
  that probe the root, `resource` = `<origin>`.
- Both carry `authorization_servers: [<origin>]`,
  `scopes_supported: ["read", "manage"]` and
  `bearer_methods_supported: ["header"]`.
- The 401 challenge on `POST /mcp` names the path-based document,
  `resource_metadata="<origin>/.well-known/oauth-protected-resource/mcp"`, so
  a client comparing its `resource` with the URL it requested finds them
  equal. The challenge on `/v1/admin` names the root document: OAuth
  clients are MCP clients and discover through `/mcp`; `/v1/admin` accepts
  the same bearer token but is not a discovery target, and a client that
  compares `resource` with `<origin>/v1/admin` is out of scope.
- Which document a client reads does not change the binding: both spellings
  normalise to the origin, below.

**Resource and scope binding.**

- Tokens are bound to the origin. Both spellings of `resource`, `<origin>`
  and `<origin>/mcp`, are accepted at `/authorize` and at `/token` and
  normalised to the origin.
- The normalised resource is persisted on the connection,
  `api_key.resource`.
- Access-token resolution refuses a token whose connection's `resource` is
  not the request's issuer origin: `invalid_token`. The gateway passes the
  one origin it serves, so a database shared by two deployments cannot
  authenticate one's tokens on the other.
- Refresh validates `resource`: when supplied it must normalise to the
  stored value, or `invalid_target`.
- Refresh validates `scope`: when supplied it must be within the
  connection's grant, and narrowing is not supported. In practice it must
  name exactly the grant; anything else is `invalid_scope`. The response's
  `scope` is always the grant.

### Tokens, rotation and replay (step 9)

**Format.** A token carries its connection id:
`<prefix><connectionId>.<random>`, with `agw_oat_` for access tokens and
`agw_ort_` for refresh tokens in the gateway. `<random>` is 32 random bytes,
base64url. Only SHA-256 digests are stored.

**Resolution.** A presented token, access or refresh, is resolved only
within the connection it names, and only its secret decides:

- parse the connection id from the prefix; a token not shaped
  `<prefix><connectionId>.<random>` is unknown;
- load that connection's current and previous generation, and compare the
  SHA-256 digest of the whole token against theirs;
- a token matching neither is **unknown**: `invalid_grant` at `/token`, an
  empty state at resolution, 200 at `/oauth/revoke`, and no side effect in
  any of them;
- a refresh token matching the previous generation is a genuine, once-valid
  token: the grace replay inside the window, otherwise reuse (below);
- a refresh token matching the current generation rotates.

Reuse detection therefore never fires on an unverified token. Knowing a
connection id and its client id gives nothing: the secret cannot be forged,
and only a real earlier secret can end a connection.

**Storage.** A connection keeps at most two generations: the current one and
the previous one. Each generation holds its access and refresh digests, the
access token's expiry, `rotated_at`, and, once rotated, the sealed response
of the rotation that replaced it.

**Rotation.** A refresh presenting the current generation's refresh token,
on a live connection, rotates in one guarded batch:

- the conditional write requires the generation to be unrotated and the
  connection's authority live (`credentialAuthoritySql`: the key enabled,
  unrevoked and before `expires_at`; the membership active) and the
  organization unexpired;
- it marks the current generation rotated and stores the new response on it,
  sealed with a key derived from the presented refresh token, so only the
  holder of that token can open it;
- it inserts the next generation, deletes the one before the current, and
  advances `api_key.expires_at` (see "Connection lifetime").

**Rate limit.** At most one rotation per 5 s per connection. Presenting the
current refresh token within 5 s of the last rotation fails with
`invalid_grant` and the description "slow down: refreshed too recently"; it
revokes nothing, and the current token stays valid.

**Grace.** Presenting the previous generation's refresh token within 30 s of
its rotation replays the sealed response: the same access and refresh tokens,
byte for byte. This covers a client that lost the response, and the loser of
two concurrent presentations.

**Reuse.** A verified once-valid refresh token presented again on a live
connection is reuse and revokes the whole connection, its `api_key` row and
every generation:

- the previous generation's token after the 30 s grace;
- a conditional rotation that fails because the token was already used,
  outside the grace window.

A generation older than the previous one is no longer stored, so its token is
unknown: `invalid_grant`, no revocation.

A refresh token for a connection that is revoked, expired, or whose
membership or organization has ended fails with `invalid_grant` and changes
nothing.

**Codes have no grace.** A conditional exchange that fails because the code
was already used, whether the other exchange came first or concurrently,
revokes the connection it issued.

### Connection lifetime (step 9)

- `api_key.expires_at` holds the current refresh token's expiry. The code
  exchange sets it; every rotation advances it to now +
  `refreshTokenTtlMs`, capped at `api_key.created_at` +
  `connectionMaxAgeMs` when a cap is configured.
- Every check reads `api_key.expires_at` and nothing else for the
  connection's lifetime: access-token resolution, refresh (through
  `credentialAuthoritySql` in the rotation guard), revocation and listing. No
  `oauth_token` column holds a connection lifetime; a generation holds only
  its access token's own expiry.
- Because the claim guard and every engine guard read the same predicate, a
  pending operation opened by a connection loses its authority when the
  connection expires, without waiting for a sweep.
- Refresh never moves an account deadline, and both resolution and refresh
  refuse an expired organization. So an unclaimed account's connections end
  with the account.

### Revocation (step 9)

`POST /oauth/revoke` (RFC 7009), form-encoded, `token` and `client_id`
required:

- Either token, access or refresh, revokes the whole connection: its
  `api_key` row, and with it every generation. `token_type_hint` is ignored.
- `client_id` must equal the connection's; a mismatch is `invalid_client`
  and revokes nothing.
- A token that is unknown under "Resolution" (its secret matches neither
  stored generation of the connection it names), or that names a connection
  already revoked or past `expires_at`, is answered 200 with no change.
- The console's revoke is the existing `revokeApiKey` on the connection's
  id, with the same effect.

### The guest door (steps 10 and 11)

"Continue without an account" runs, in this order:

1. **Proof.** The authorization's browser proof is valid; otherwise it
   fails and nothing else runs.
2. **Already completed.** If the authorization has completed, by either
   door, the canonical redirect is returned. This is what makes a retry after
   a lost response idempotent: it is never re-admitted or rate-counted.
3. **Deployment admission.** The deployment's rule
   (`DEPLOYMENT_RULES.bootstrap`) must allow unclaimed accounts, or the door
   fails here. Where the rule requires an empty deployment, `admit` returns
   the emptiness condition, which travels into the batch.
4. **Rate limit**, keyed on the browser's address. A refused admission
   never reaches it, so it consumes no budget.
5. **Provision** the service user, the account with its deadline and the
   owner membership inside the guarded batch that completes the operation,
   every row under the engine's guard and the admission condition.

The completion record stores `{door: "guest", organizationId, grant}` with
the user id and the code's validity. A racing person's approval, or a second
guest click, answers that record's redirect; there is exactly one account.

The `cf-auth:oauth.authorize` record is retained for 1 day. The code is single use and
valid for 10 minutes, and the pending deadline, enforced by the engine's sweep
and by every approval, is what prevents a second provisioning under the same
authorization. The CLI bootstrap keeps its record for 180 days because there
the record itself is what stops a retried bootstrap from provisioning again.
Here the code's single use and the pending deadline already do that, so the
record only has to outlive the code long enough to recognise a replay.

### Engine contract for step 7

These are generic engine additions. Nothing in them is OAuth-specific, and
none of them accepts an internal kind such as `cf-auth:oauth.authorize`.

```ts
operations.status(input: { id: string; opener: AuthState | null | undefined }): Promise<OperationStatus>;
// OperationStatus: { id, kind, state, createdAt, expiresAt, organizationId, record }

operations.reserve(input: { kind: string; opener: AuthState | null | undefined; input?: unknown }):
  Promise<{ id: string; handle: string; expiresAt: string }>;

operations.execute<Outcome>(
  input: { handle: string; kind: string; opener: AuthState | null | undefined },
  fn: (ctx: { operation; input: unknown; guard: SQL; db; tables; now: number }) =>
    OperationApproveResult<Outcome> | Promise<OperationApproveResult<Outcome>>,
): Promise<
  | { id: string; state: "completed"; record: unknown; outcome: Outcome; replayed: false }
  | { id: string; state: "completed"; record: unknown; replayed: true }
>;

operations.reveal(input: { id: string; actor: AuthState | null | undefined }):
  Promise<{ id: string; kind: string; organizationId: string; outcome: unknown }>;
```

- **`status`** answers state, kind, expiry and the non-secret record. It is
  visible only when the caller's organization is the organization of the
  credential that opened the operation; otherwise `operation_not_found`, so
  existence is not disclosed. It never returns the sealed outcome and never
  consumes a delivery.
- **`reserve`** creates a deferred operation, pending for 15 minutes, bound to
  the opener's organization and the kind, with the input stored. It runs no
  write. The handle is server-generated.
- **`execute`** runs `fn` under the engine's guard, which re-checks the
  opener's authority and the kind's grant at write time, and this
  execution's claim.
  - **Claim.** Before `fn` runs, the call writes a random value into
    `operation.execution_claim` on a pending row that holds none. The guard,
    the completion and the release all require that value, so of two calls
    racing on one handle only one runs `fn`, and the other answers
    `409 conflict`. `decided_by_user_id` is attribution only: deleting the
    user who executes cannot unlock a running execution. A process that dies
    mid-execution leaves the claim until the reservation lapses.
  - **Atomic completion.** `fn`'s statements and the completion run as one
    batch, followed by an assertion statement: an `INSERT ... SELECT` of a
    row of nulls into `operation` under `WHERE changes() = 0`, which runs
    only when the completion matched no row and then always violates the
    primary key's NOT NULL. It depends on nothing existing, so it fires even
    when an earlier statement deleted the operation, directly or through a
    cascade. The batch then rolls back whole: no statement outlives a refused
    completion. `complete`, `approve` and `amend` carry the same assertion.
  - **Result.** The run that executed answers
    `{ id, state, record, outcome, replayed: false }`. A repeat within the
    15-minute seal window answers `{ id, state, record, replayed: true }`:
    the record only, never the outcome, and `fn` does not run. After the
    window a repeat answers `already_completed` and still does not run `fn`.
  - **Replay lifetime is not secret availability.** The replay deadline is
    `sealed_until`. Revealing the outcome, a `once` poll collecting it, and
    the cleanup of an outcome no longer deliverable null the ciphertext only
    and never shorten `sealed_until`; only `retire` and the sweep (after the
    deadline) clear it. A reveal after the outcome was spent answers
    `already_revealed` inside the window and `operation_expired` after it.
  - **Retention.** Completing with a sealed outcome moves `retain_until` to
    at least `sealed_until` in the same write, so the sweep never deletes a
    record whose replay window is still open.
  - Errors:
    - `operation_mismatch`: the handle belongs to another kind or another
      organization;
    - `operation_not_found`: no such handle;
    - `operation_expired`: the handle's 15 minutes passed before it
      executed, or it was retired.
- **`reveal`** releases a sealed outcome on a browser page, once, within the
  seal window; a second reveal is `already_revealed`. **Authority policy:**
  reveal is authorized by the person, not by the credential that opened the
  operation. It requires an interactive human session with the admin or
  owner role in the operation's organization, an organization that has not
  expired, and an outcome the kind still considers deliverable. It does not
  depend on the opener credential's current grant or existence: an admin
  still collects what a key created after that key was downgraded or
  revoked. The person's authority, the kind's `deliverable` predicate and
  the seal deadline (by the database's clock, `sqliteNowMs`) all sit in the
  UPDATE that consumes the outcome, so a reveal after any of them stopped
  holding matches no row and is refused. So does the organization: it must
  exist and, when it has an `expires_at` (ISO text), satisfy
  `cast(unixepoch(expires_at, 'subsec') * 1000 as integer) > sqliteNowMs(now)`
  in that UPDATE, with the earlier read kept for a readable
  `organization_expired`. An outcome no longer deliverable is dropped and
  answers `operation_expired`; the drop names the exact ciphertext that was
  judged and a completed row, so an outcome `amend` sealed meanwhile is never
  touched. An `amend` landing before the consuming UPDATE makes that reveal
  answer `conflict`; one landing between the refused UPDATE and the cleanup
  makes it answer `operation_expired` (the old outcome's verdict), and the
  replacement is preserved for the next reveal either way.
- **Delivery modes.** A kind's `deliver` is `"once"` (to the first `poll` or
  `redeem`), `"window"` (to every one until `sealed_until`) or `"reveal"`
  (only through `reveal`; `poll`, `findByToken` and a retried `open` answer
  the record without the outcome, `redeem` answers `already_completed`, and
  none of them consumes it).
  `"reveal"` needs a kind without a browser step. An MCP adapter must use
  it for every reservation kind whose outcome is a secret, and the
  gateway's step 8 kinds set it. A stored row whose kind is no longer
  registered and that had no browser step is treated as `"reveal"`, so
  removing a kind never opens its secret to `poll`.
- **What a tool adapter returns.** `execute`'s first answer carries the
  plaintext outcome to the caller; the engine does not withhold it there.
  An MCP tool returns only `record` and a reveal reference (the operation
  id, or a page URL built from it), never `result.outcome`, and its kinds
  use `deliver: "reveal"` so no collection route releases the outcome to
  the handle's holder.
- **Internal kinds** live in the reserved namespace `cf-auth:`. A stored
  operation whose kind starts with it is hidden from the public door whatever
  the engine has registered, so an engine built without the kind (another
  deployment, a feature turned off) still refuses its rows. App kind names
  cannot contain `:`; a built-in kind is internal exactly when it is in the
  namespace.
- **Digest lookup**, mapping a request digest to a recent handle for the
  notice of decision 13, is the gateway's, with a 1-hour lifetime. The engine
  stores no digest.
- **Claim guard on connection authority:** nothing to add. The spike showed
  the existing `credentialAuthoritySql` and `claimOrganizationStatements`
  accept a connection. `revokeAccess: true` also retires the service's
  connections, because they are its `api_key` rows.

### Storage

All of it is prefix-aware through `createCfAuthTables({ tablePrefix })`. The
gateway's tables become `mgmt_oauth_token`, and so on.

- **`api_key`:**
  - `grant text not null default 'manage'`. No database CHECK: drizzle-kit
    would rebuild the table for one and the generated copy step is wrong;
    cf-auth validates every value it writes, and an unknown stored value
    reads as `read`. Step 3. Existing rows migrate to `manage`.
  - `client_id text` and `resource text`, null for keys. Step 9.
  - A connection row has `source = 'oauth'`, `name`/`label` set to the
    client's name, and `expires_at` set as in "Connection lifetime".
  - Its `token_hash` holds the digest of a random value that is never
    revealed. That keeps the unique index honest; no token authenticates
    through that column.
- **`oauth_token`** (step 9):
  - Columns: `id`, `api_key_id` (FK, cascade), `generation`,
    `access_token_hash` (unique), `access_expires_at`, `refresh_token_hash`
    (unique), `rotated_at`, `sealed_response`, `created_at`.
  - Unique on `(api_key_id, generation)`. At most two rows per connection.
  - `sweepStatements` deletes the generations of connections that are
    revoked or past `expires_at`.
- **`operation`:** one column, `execution_claim text`, added by
  `drizzle/0003_cf_auth_operation_execution_claim.sql` as a plain
  `ALTER TABLE ... ADD` (no rebuild, no CHECK). Step 7. A pending
  authorization is a row of the built-in internal kind
  `cf-auth:oauth.authorize`. Its payload holds client,
  redirect, PKCE challenge, requested grant, optional state and the sealed
  code. It is public, `approver: "proof"`, pending for `authorizationTtlMs`,
  and retained for 1 day. Its completion record holds the door, user,
  organization, grant, client, redirect, challenge, `codeExpiresAt` and,
  once exchanged, `exchangedAt`.
- **No `oauth_client` table in the first cut.** CIMD documents are fetched
  once per authorization, within the budgets above. The client's name is
  copied onto the connection. A cache table is an optional later addition.
- **No MCP session table.**

### What cf-auth mounts versus what the gateway mounts

cf-auth mounts no routes, which is the engine's existing rule. The gateway
mounts all of these on the console host only, inside the lazily loaded
management app, so they stay behind `cfAuth()`:

- `GET /.well-known/oauth-protected-resource` and
  `/.well-known/oauth-protected-resource/mcp`: `protectedResourceMetadata("")`
  and `protectedResourceMetadata("/mcp")`.
- `GET /.well-known/oauth-authorization-server` returns
  `authorizationServerMetadata()`. The issuer has no path, so this is the
  root location. It advertises:
  - `issuer`, `authorization_endpoint`, `token_endpoint`,
    `revocation_endpoint`;
  - `response_types_supported: ["code"]`;
  - `grant_types_supported: ["authorization_code", "refresh_token"]`;
  - `code_challenge_methods_supported: ["S256"]`;
  - `token_endpoint_auth_methods_supported: ["none"]`;
  - `revocation_endpoint_auth_methods_supported: ["none"]`;
  - `scopes_supported: ["read", "manage"]`;
  - `authorization_response_iss_parameter_supported: true`;
  - `client_id_metadata_document_supported: true` (false when `cimd` is
    off).
- `GET /oauth/authorize` → `authorize`. It answers with a 302 to the console
  consent page `/oauth/consent?id=…#<proof>`, a 302 error redirect as in
  "Authorization request", or an error page.
- `POST /oauth/token` and `POST /oauth/revoke`.
- The consent page's API: details, allow, continue without an account, and
  deny.
- The bearer gate on `/mcp` and `/v1/admin`.

**HTTP contract.**

- Token and revocation errors are RFC 6749 §5.2 JSON bodies,
  `{"error": …, "error_description": …}`, with status 400, or 401 for
  `invalid_client`. Every token and revocation response, success or error,
  sends `Cache-Control: no-store`.
- A missing or dead bearer token is 401 with
  `WWW-Authenticate: Bearer resource_metadata="…"`, naming
  `<origin>/.well-known/oauth-protected-resource/mcp` on `/mcp` and
  `<origin>/.well-known/oauth-protected-resource` on `/v1/admin`, and adding
  `error="invalid_token"` when a token was presented.
- A live token whose grant is insufficient is 403 with
  `WWW-Authenticate: Bearer error="insufficient_scope", scope="manage", resource_metadata="…"`.
- CORS:
  - `Access-Control-Allow-Origin: *` on the three metadata documents;
  - the MCP origin allowlist (the console origin and `MCP_ALLOWED_ORIGINS`)
    on `/oauth/authorize`, `/oauth/token` and `/oauth/revoke`, with
    preflight, and on `/mcp` with `WWW-Authenticate` exposed;
  - the consent page's API accepts the console origin only, checked on
    `Origin`.
- `Content-Security-Policy: frame-ancestors 'none'` on the consent page and
  on the reveal page (step 8).

### Lifetimes

- Access token: 10 minutes.
- Refresh token and connection: 30 days, restarted by each rotation, held in
  `api_key.expires_at`, capped by `connectionMaxAgeMs` (default none). A
  connection used at least monthly lives until it is revoked.
- Refresh grace: 30 s. Rotation rate limit: one per 5 s per connection.
- Pending authorization: 10 minutes. Code validity: 10 minutes from
  completion. The `cf-auth:oauth.authorize` record is retained for 1 day.
- Reservation handles (step 7): pending for 15 minutes. A repeated execute
  replays the record, never the outcome, within the 15-minute seal window,
  revealed or not; after it, the repeat answers `already_completed` from the
  record, which is kept for the engine's record TTL, 90 days
  (`OPERATION_RECORD_TTL_MS`), and never less than the seal window.
- Reveal: once, within the 15-minute seal window.
- Digest lookup: 1 hour, gateway-side.
- CIMD fetch: 5 s, 64 KiB.

### How the later steps map onto this

- **Step 3 (grant level):**
  - `api_key.grant`, with the migration defaulting to `manage`.
  - `ApiKeySummary.grant`, and the `grant` issuance inputs, including
    `login` and `issueServiceApiKey`.
  - `AuthState.grant`.
  - Grant enforcement in cf-auth: `requireActor` over every non-session
    credential, `manage` on every service mutation, issuance bounded by the
    issuer's grant, and `OperationKindDefinition.grant` at `open` and in the
    guard.
  - No OAuth code.
- **Step 7 (engine additions):**
  - `status`, `reserve`, `execute` and `reveal` as in "Engine contract for
    step 7".
  - Internal kinds in the `cf-auth:` namespace, which the generic entry
    points refuse.
  - `operation.execution_claim` (migration 0003).
- **Step 9 (OAuth credentials):**
  - `oauth_token`, `api_key.client_id` and `api_key.resource`.
  - The token format with the connection id; two-generation storage;
    rotation with the 30 s grace and the 5 s rate limit; reuse and
    code-replay revocation.
  - `api_key.expires_at` as the connection's lifetime.
  - `resolveAccessTokenAuthState` with the endpoint's `source` and the
    resource check, and the middleware's prefix routing.
  - `credentialType: "oauth"`.
  - `token()` and `revoke()` with their error bodies, and
    `sweepStatements`.
  - The refusal of a database without `batch`.
  - `ApiKeySummary.clientId`.
- **Step 10 (OAuth authorization):**
  - The built-in internal `cf-auth:oauth.authorize` kind.
  - `authorize` and `authorizationDetails`.
  - Both approvals, with the guest door's order, and deny.
  - The authorization-request rules: required and optional parameters,
    duplicate refusal, PKCE S256 with the challenge and verifier formats,
    exact `redirect_uri` match, the `resource` check, `codeExpiresAt` in the
    exchange predicate, `iss` on every redirect.
  - Registered clients, and CIMD with its budgets, public-client profile,
    redirect-URI rules and off switch.
  - Both metadata documents: the root and the path-based `/mcp` protected
    resource documents, and the authorization-server document.
- **Step 11 (gateway):**
  - Mount the routes above, with the HTTP contract: error bodies,
    `Cache-Control`, challenges, CORS and `frame-ancestors`.
  - The consent page in three states: signed in (pick account and grant);
    nobody signed in (sign in, register, or continue without an account);
    and the claim page's refusals. It shows the client's declared name as
    declared by its domain, with the domain beside it.
  - The unclaimed door passes `DEPLOYMENT_RULES.bootstrap` as `admit`,
    `enforceEndpointRateLimit(env, "bootstrap", ip)` as `rateLimit`, and
    `provisionUnclaimedAccount` statements as `provision`.
  - It says so explicitly when the client asked for `read` and the connection
    is issued with `manage`.
  - `managementActor` accepts `credentialType: "oauth"`.
  - The access page lists keys and connections from `listApiKeys`, with
    grant, client name and domain.
  - The MCP bearer gate and its challenges, the `/mcp` one naming the
    path-based document.

## 4. Extension audit

### cf-auth extension points the design relies on

| Extension point | Kind | Today (0.7.0) | Added in |
|---|---|---|---|
| `defineOperationKind` with `open: "public"`, `approver: "proof"`, `input`, `pendingTtlMs`, `recordTtlMs` | kind | exists | — |
| The kind's `approve` callback returning `outcome` and guarded `statements` | hook | exists | — |
| `operations.open` with a caller-chosen `id` and `token`, `rateLimitKey`, `client.label`; `limits.pendingPerOpener` | engine | exists | — |
| `operations.details`, `approve` (with `input`), `poll`, `findByToken`, `amend` (with `condition` and `statements`) | engine | exists | — |
| The completion guard (`guard`, last statement must change) and `guardedInsert` | engine | exists | — |
| `credentialAuthoritySql` (key live, including `expires_at`; membership active) | predicate | exists | — |
| `claimOrganizationStatements` with `provisioning.credentialId` and `revokeAccess` | service | exists | — |
| `revokeApiKey`, `listApiKeys` | service | exists | — |
| `apiKeyActionSources` including `"mcp"` | type | exists | — |
| `createCfAuthTables({ tablePrefix })` | tables | exists | — |
| `sealText` / `openText` (sealed code, sealed rotation response) | internal | exists | — |
| `api_key.grant`, `ApiKeySummary.grant`, `AuthState.grant`, issuance `grant` | column, types | — | step 3 |
| `requireActor` over every non-session credential, with the grant; `manage` on service mutations; issuance bounded by the issuer's grant | service | apiKey only, no grant | step 3 |
| `OperationKindDefinition.grant`, at `open` and in the guard | kind | — | step 3 |
| `operations.status`, `reserve`, `execute`, `reveal` | engine | — | step 7 |
| Internal kinds, refused by the generic engine entry points | engine | — | step 7 (mechanism), step 10 (`cf-auth:oauth.authorize`) |
| `api_key.client_id`, `api_key.resource`; `ApiKeySummary.clientId`; `normalizeApiKeySource` refusing `"oauth"` | column, types | — | step 9 |
| `oauth_token` table | table | — | step 9 |
| `AuthCredentialType` `"oauth"` | credential type | — | step 9 |
| Bearer prefix routing in the middleware; `resolveAccessTokenAuthState(token, { source })` | middleware | API keys only | step 9 |
| `oauth` configuration, including the refusal of a database without `batch` | config | — | step 9 |
| `cfAuth.oauth.token`, `revoke`, `sweepStatements` | service | — | step 9 |
| The `cf-auth:oauth.authorize` kind; `authorize`, `authorizationDetails`, both approvals, deny; the metadata documents | kind, service | — | step 10 |
| `approveGuestAuthorization`'s `admit`, `rateLimit` and `provision` callbacks | hook | — | step 10 (callbacks), step 11 (gateway implementations) |

Nothing in the design needs a better-auth plugin, a better-auth hook or a
change to better-auth's tables.

### What candidate A would have relied on

For the record, the supported better-auth 1.7.6 surfaces and where they stop:

- `getOAuthProviderApi` and `issueTokens` are exported and documented. They
  verify tokens in process and mint session-less tokens (criteria 1 and 7).
- Extension grants must use absolute-URI grant types; none can replace
  `authorization_code` (`op/oauth-1Ud-hvZY.d.mts:1017`).
- Additive claims (`customAccessTokenClaims`) cannot bypass the code
  exchange's live-session check, and opaque verification checks the session
  before any claim contributor runs.
- Refresh-family invalidation is hardcoded to `(clientId, userId)`.
- `referenceId` gives a stable identity; the problem is the width of
  revocation, not identity.

So no supported extension preserves the stock code exchange while providing
the session-less guest flow. A before-hook on `/oauth2/token` can, by
replacing the exchange, which is what B builds directly.

## 5. Risks and open questions

- **We own an authorization server.** The spike covers the happy paths, the
  replays and the concurrent presentations. The production code still needs
  review against the RFC 9700 BCP:
  - code injection, where PKCE is the defence;
  - mix-up, where `iss` is the defence;
  - error redirects only to a redirect URI the client declared;
  - consent-page CSRF, where the defences are the proof in the fragment, the
    session and the Origin check;
  - clickjacking, where the defence is `frame-ancestors 'none'`.
  These need conformance tests in cf-auth, including the parts section 2
  lists as not prototyped.
- **CIMD depends on the Worker's outbound HTTPS**, which every Cloudflare
  deployment has. The risk is a client whose metadata host the Worker cannot
  reach; such a client cannot connect unless it is registered. The mechanism
  itself is bounded as in "Client identity". Workers facts it rests on:
  - `fetch` takes URLs, not IP addresses ("requests can only be made to URLs,
    not to IP addresses directly", developers.cloudflare.com, known issues),
    and resolution happens in Cloudflare's network, so an address cannot be
    pinned; literal addresses and `localhost` are refused before any fetch;
  - `redirect: "error"` throws in workerd ("use "manual""; workerd
    `http.c++`), so the fetch uses `manual` and refuses every 3xx.
- **The refresh grace is a trade-off.** Within 30 s of a rotation, whoever
  presents the previous refresh token receives the same tokens as the client
  that rotated. The `mcp()` plugin defaults to the same 30 s window for the
  same reason (`mcp/index.mjs:170`). Outside it, reuse ends the connection.
- **Dynamic Client Registration is not offered.** Clients that require it
  cannot connect. MCP 2026-07-28 calls DCR deprecated, with a "MAY" for
  servers. Section 9 of the design keeps this as an open item.
- **`credentialType` gains a member.** That is a breaking type change for
  cf-auth consumers, so it needs a 0.x minor release. The gateway's
  `managementActor` rejects unknown types today, so nothing opens by
  accident.
- **The upgrade is still available.** better-auth 1.7.6 passes cf-auth's
  suite, so it can be taken separately and on its own merits.
- **Not established in this spike:**
  - CIMD against real metadata hosts, and the hosted platform's behaviour
    for hostnames that resolve to private ranges;
  - real MCP clients (Claude, Cursor, VS Code) against B's endpoints;
  - the gateway's admission rule and rate limiter at the guest door (stand-in
    callbacks prove the order);
  - startup and bundle cost inside the gateway Worker.
  The client and gateway items are step 11's verification.
