/**
 * App-agnostic auth domain types.
 *
 * These intentionally have no dependency on any host application's domain
 * package — everything a consuming Worker needs to reason about "who is
 * calling and for which organization" lives here.
 */

/** Roles a user can hold inside an organization, most privileged first. */
export const organizationRoles = ["owner", "admin", "member"] as const;
export type OrganizationRole = (typeof organizationRoles)[number];

/** Membership lifecycle status. Only `active` is modelled today. */
export const organizationMemberStatuses = ["active"] as const;
export type OrganizationMemberStatus = (typeof organizationMemberStatuses)[number];

/**
 * Where a request originated. Session cookies always map to `web`; API keys
 * map to one of the machine sources.
 */
export const actionSources = ["web", "api", "cli", "mcp", "system"] as const;
export type ActionSource = (typeof actionSources)[number];

/** Action sources that an API key is allowed to authenticate as. */
export const apiKeyActionSources = ["api", "cli", "mcp"] as const;
export type ApiKeyActionSource = (typeof apiKeyActionSources)[number];

export const isApiKeyActionSource = (value: ActionSource): value is ApiKeyActionSource =>
  (apiKeyActionSources as readonly string[]).includes(value);

/**
 * Where a browser-approved operation stands.
 *
 * `pending` waits for a browser (or, for a kind without one, for the app);
 * `completed` and `denied` are the two answers; `expired` means nobody answered
 * in time; `retired` means the app ended a completed operation's authority.
 */
export const operationStates = ["pending", "completed", "denied", "expired", "retired"] as const;
export type OperationState = (typeof operationStates)[number];

/**
 * Which credential proved the caller's identity: a person's own session, an
 * API key, or an OAuth connection's access token. Every type but `session` is
 * a delegated credential, bound to one organization and carrying a grant.
 */
export type AuthCredentialType = "session" | "apiKey" | "oauth";

/** Where an OAuth access token may be presented: the MCP endpoint, or the management API. */
export const oauthActionSources = ["mcp", "api"] as const;
export type OAuthActionSource = (typeof oauthActionSources)[number];

/**
 * How much of its holder's authority a credential may exercise, least first.
 *
 * Distinct from {@link OrganizationRole}: the role says what the person or
 * service may do in the organization, the grant says how much of that one
 * credential may use. What a request may do is the role and the grant
 * together. A `read` credential reads; only a `manage` one writes. A person's
 * own session is always `manage`.
 */
export const credentialGrants = ["read", "manage"] as const;
export type CredentialGrant = (typeof credentialGrants)[number];

export const isCredentialGrant = (value: unknown): value is CredentialGrant =>
  (credentialGrants as readonly unknown[]).includes(value);

export type IdentityKind = "human" | "service";
export type AuthActor = {
  type: "user";
  id: string;
  kind: IdentityKind;
  credentialId: string | null;
  actionSource: ActionSource;
};

export interface AuthUser {
  id: string;
  name: string | null;
  email: string | null;
  kind: IdentityKind;
  emailVerified: boolean;
  image: string | null;
  createdAt: string;
}

/** A live interactive session, as read back from the session table. */
export interface AuthSession {
  id: string;
  userId: string;
  expiresAt: string;
}

export interface OrganizationSummary {
  /** True when the organization has a human owner membership. */
  claimed: boolean;
  expiresAt: string | null;
  id: string;
  name: string;
  createdAt: string;
}

export interface OrganizationMembership {
  organization: OrganizationSummary;
  role: OrganizationRole;
  status: OrganizationMemberStatus;
  joinedAt: string;
}

export interface OrganizationMember extends AuthUser {
  role: OrganizationRole;
  status: OrganizationMemberStatus;
  joinedAt: string;
}

/**
 * The resolved identity for the current request.
 *
 * The four fields a route handler usually cares about are
 * `user`, `organization`, `role` and `source`.
 */
export interface AuthState {
  authenticated: boolean;
  assurance: "interactive" | "credential" | null;
  credentialType: AuthCredentialType | null;
  /**
   * Where the request came from: `web` for sessions, `api`/`cli`/`mcp` for API
   * keys, and for an OAuth connection the endpoint's own, `mcp` or `api`.
   */
  source: ActionSource | null;
  actor: AuthActor | null;
  user: AuthUser | null;
  memberships: OrganizationMembership[];
  /** The organization this request acts on behalf of. */
  organization: OrganizationSummary | null;
  /** The caller's role inside {@link AuthState.organization}. */
  role: OrganizationRole | null;
  /**
   * How much of that role this credential may exercise: `"manage"` for a
   * session, the row's own grant for an API key or an OAuth connection, null
   * when unauthenticated.
   * See {@link CredentialGrant}.
   */
  grant: CredentialGrant | null;
}

export interface ApiKeySummary {
  id: string;
  organizationId: string;
  userId: string;
  expiresAt: string | null;
  name: string;
  /** Last four token characters for safe display; never a credential. */
  tokenHint: string;
  /**
   * Whether the key may authenticate at all.
   *
   * A key issued through {@link CfAuthService.issueServiceApiKey} with
   * `enabled: false` waits here until the trusted exchange that ordered it
   * commits and calls {@link CfAuthService.enableServiceApiKey}. Revoking sets
   * this to `false` too, so `enabled && !revokedAt` is the live key.
   */
  enabled: boolean;
  /**
   * Where the key was issued from, e.g. `console`, `cli` or `bootstrap`; `oauth`
   * for an OAuth connection, which no caller may claim for a key of its own.
   */
  source: string;
  /** A human-readable note about the holder, e.g. `CLI on mac-studio`. */
  label: string | null;
  /** How much of its holder's authority the key may exercise. Keys issued before grants existed are `manage`. */
  grant: CredentialGrant;
  /** The OAuth client a connection was issued to (`source: "oauth"`); null for a key. */
  clientId: string | null;
  createdAt: string;
  revokedAt: string | null;
}

export interface CreatedApiKey extends ApiKeySummary {
  /** Returned only during issuance; only its SHA-256 hash is persisted. */
  plaintext: string;
}

/**
 * Lifecycle events emitted by the library so a consuming app can write its own
 * audit log without this package owning an audit table.
 */
export type CfAuthEvent =
  | { type: "user.signup"; userId: string; email: string }
  | {
      type: "organization.created";
      userId: string;
      organizationId: string;
      role: OrganizationRole;
      name: string;
    }
  | { type: "organization.claimed"; userId: string; organizationId: string }
  | {
      type: "api_key.created";
      actorUserId: string;
      organizationId: string;
      apiKeyId: string;
      name: string;
      /** `"oauth"` when the row is an OAuth connection; absent for an API key. */
      credentialType?: "oauth";
    }
  | {
      type: "api_key.revoked";
      actorUserId: string;
      organizationId: string;
      apiKeyId: string;
      name: string;
      /** `"oauth"` when the row is an OAuth connection; absent for an API key. */
      credentialType?: "oauth";
    };

const roleRank: Record<OrganizationRole, number> = {
  owner: 3,
  admin: 2,
  member: 1,
};

/**
 * True once an organization's provisional deadline has passed.
 *
 * `expiresAt` marks a tenant that exists only provisionally — a trial, or an
 * account a person has not claimed yet. Past it, the organization is not
 * somewhere anyone can act, whichever credential they hold, so both the API-key
 * and the session paths refuse to resolve it as the current organization.
 */
export const isOrganizationExpired = (
  organization: Pick<OrganizationSummary, "expiresAt"> | null | undefined,
  now: number = Date.now(),
): boolean => {
  const expiresAt = organization?.expiresAt;
  return expiresAt !== null && expiresAt !== undefined && Date.parse(expiresAt) <= now;
};

/** True when the role may administer the organization (owner or admin). */
export const canManageOrganization = (role: OrganizationRole | null | undefined): boolean =>
  role === "owner" || role === "admin";

/** True when `role` is at least as privileged as `minimum`. */
export const hasRoleAtLeast = (
  role: OrganizationRole | null | undefined,
  minimum: OrganizationRole,
): boolean => (role ? roleRank[role] >= roleRank[minimum] : false);

const grantRank: Record<CredentialGrant, number> = {
  manage: 2,
  read: 1,
};

/** True when `grant` covers `needed`: `manage` covers both, `read` only `read`, null neither. */
export const hasGrantAtLeast = (
  grant: CredentialGrant | null | undefined,
  needed: CredentialGrant,
): boolean => (grant && isCredentialGrant(grant) ? grantRank[grant] >= grantRank[needed] : false);

/** An unauthenticated {@link AuthState}. Safe default for anonymous requests. */
export const createEmptyAuthState = (): AuthState => ({
  authenticated: false,
  assurance: null,
  credentialType: null,
  source: null,
  actor: null,
  user: null,
  memberships: [],
  organization: null,
  role: null,
  grant: null,
});
