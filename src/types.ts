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

/** Which credential proved the caller's identity. */
export type AuthCredentialType = "session" | "apiKey";

export type AuthActor =
  | { type: "user"; id: string; actionSource: "web" }
  | { type: "api_key"; id: string; actionSource: ApiKeyActionSource };

export interface AuthUser {
  id: string;
  name: string | null;
  email: string;
  emailVerified: boolean;
  image: string | null;
  createdAt: string;
}

export interface OrganizationSummary {
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
  credentialType: AuthCredentialType | null;
  /** Where the request came from (`web` for sessions, `api`/`cli`/`mcp` for API keys). */
  source: ActionSource | null;
  actor: AuthActor | null;
  user: AuthUser | null;
  memberships: OrganizationMembership[];
  /** The organization this request acts on behalf of. */
  organization: OrganizationSummary | null;
  /** The caller's role inside {@link AuthState.organization}. */
  role: OrganizationRole | null;
}

export interface ApiKeySummary {
  id: string;
  organizationId: string;
  name: string;
  /**
   * The last few characters of the token, kept for display so operators can
   * match a key against the copy in their secret manager. Null for keys
   * created before hints were recorded — the stored hash cannot recover one.
   */
  tokenHint: string | null;
  createdAt: string;
  revokedAt: string | null;
}

export interface CreatedApiKey extends ApiKeySummary {
  /**
   * The only time the plaintext token is ever available. Only a SHA-256 hash
   * is persisted, so this cannot be recovered later.
   */
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
  | { type: "api_key.created"; actorUserId: string; organizationId: string; apiKeyId: string; name: string }
  | { type: "api_key.revoked"; actorUserId: string; organizationId: string; apiKeyId: string; name: string };

const roleRank: Record<OrganizationRole, number> = { owner: 3, admin: 2, member: 1 };

/** True when the role may administer the organization (owner or admin). */
export const canManageOrganization = (role: OrganizationRole | null | undefined): boolean =>
  role === "owner" || role === "admin";

/** True when `role` is at least as privileged as `minimum`. */
export const hasRoleAtLeast = (
  role: OrganizationRole | null | undefined,
  minimum: OrganizationRole,
): boolean => (role ? roleRank[role] >= roleRank[minimum] : false);

/** An unauthenticated {@link AuthState}. Safe default for anonymous requests. */
export const createEmptyAuthState = (): AuthState => ({
  authenticated: false,
  credentialType: null,
  source: null,
  actor: null,
  user: null,
  memberships: [],
  organization: null,
  role: null,
});
