import type { ResolvedCfAuthConfig } from "./config.js";
import { generateApiKeyToken, hashApiKeyToken } from "./crypto.js";
import { CfAuthError, conflict, forbidden, unauthorized, validationError } from "./errors.js";
import type { CfAuthRepository, MembershipMutationResult } from "./repository.js";
import {
  canManageOrganization,
  createEmptyAuthState,
  isApiKeyActionSource,
  type ActionSource,
  type ApiKeySummary,
  type AuthState,
  type AuthUser,
  type CfAuthEvent,
  type CreatedApiKey,
  type OrganizationMember,
  type OrganizationMembership,
  type OrganizationRole,
  type OrganizationSummary,
} from "./types.js";

const ensureNonEmpty = (value: string | null | undefined, label: string) => {
  const normalized = value?.trim();

  if (!normalized) {
    throw validationError(`${label} is required`);
  }

  return normalized;
};

/**
 * Builds a session-backed {@link AuthState}. The "current" organization is the
 * one matching `currentOrganizationId` when the user is still a member of it,
 * otherwise the first membership (organizations are ordered by creation time,
 * so this is the user's oldest org).
 */
export const toSessionAuthState = (
  user: AuthUser,
  memberships: OrganizationMembership[],
  currentOrganizationId: string | null,
): AuthState => {
  const current =
    memberships.find((membership) => membership.organization.id === currentOrganizationId) ??
    memberships[0] ??
    null;

  return {
    authenticated: true,
    credentialType: "session",
    source: "web",
    actor: { type: "user", id: user.id, actionSource: "web" },
    user,
    memberships,
    organization: current?.organization ?? null,
    role: current?.role ?? null,
  };
};

export const toApiKeyAuthState = (
  apiKeyId: string,
  organization: OrganizationSummary,
  source: ActionSource,
): AuthState => {
  if (!isApiKeyActionSource(source)) {
    return createEmptyAuthState();
  }

  return {
    authenticated: true,
    credentialType: "apiKey",
    source,
    actor: { type: "api_key", id: apiKeyId, actionSource: source },
    user: null,
    memberships: [],
    organization,
    // An API key is scoped to exactly one organization and acts with full
    // authority inside it.
    role: "owner",
  };
};

export interface CfAuthService {
  /** Resolves session state for a user id plus the requested current org. */
  getAuthState(userId: string, currentOrganizationId: string | null): Promise<AuthState | null>;
  /** Creates the default organization if the user has none yet. */
  ensureDefaultOrganization(state: AuthState): Promise<AuthState>;
  /** Runs from better-auth's `user.create.after` hook. Idempotent. */
  provisionNewUser(user: AuthUser): Promise<AuthState | null>;

  listOrganizations(userId: string): Promise<OrganizationMembership[]>;
  createOrganization(userId: string, name: string): Promise<OrganizationMembership>;
  /** Switches the active organization, verifying membership first. */
  selectOrganization(userId: string, organizationId: string): Promise<AuthState>;
  listOrganizationMembers(userId: string, organizationId: string): Promise<OrganizationMember[]>;
  addOrganizationMember(input: {
    actorUserId: string;
    organizationId: string;
    userId: string;
    role: OrganizationRole;
  }): Promise<OrganizationMembership>;
  updateOrganizationMemberRole(input: {
    actorUserId: string;
    organizationId: string;
    userId: string;
    role: OrganizationRole;
  }): Promise<OrganizationMembership>;
  /**
   * Removes a member and returns the membership that was removed.
   *
   * Throws `404 not_a_member` when the target is not in the organization —
   * matching {@link CfAuthService.updateOrganizationMemberRole} rather than
   * reporting absence as a falsy return.
   */
  removeOrganizationMember(input: {
    actorUserId: string;
    organizationId: string;
    userId: string;
  }): Promise<OrganizationMembership>;

  resolveApiKeyAuthState(plaintext: string, source?: ActionSource): Promise<AuthState>;
  /** Requires `actorUserId` to be a member of the organization. */
  listApiKeys(input: { organizationId: string; actorUserId: string }): Promise<ApiKeySummary[]>;
  /** Requires `actorUserId` to be an owner or admin of the organization. */
  createApiKey(input: {
    organizationId: string;
    actorUserId: string;
    name: string;
  }): Promise<CreatedApiKey>;
  /** Requires `actorUserId` to be an owner or admin of the organization. */
  revokeApiKey(input: {
    organizationId: string;
    actorUserId: string;
    apiKeyId: string;
  }): Promise<ApiKeySummary | null>;
}

export const createAuthService = (
  repository: CfAuthRepository,
  config: ResolvedCfAuthConfig,
): CfAuthService => {
  const emit = async (event: CfAuthEvent) => {
    if (!config.onEvent) {
      return;
    }

    try {
      await config.onEvent(event);
    } catch (error) {
      // Never let audit/telemetry failures break authentication.
      config.onError(error, { scope: `onEvent:${event.type}` });
    }
  };

  const requireApiKeysEnabled = () => {
    if (!config.apiKeys.enabled) {
      throw validationError("API keys are disabled; set `apiKeys.enabled: true` to use them");
    }
  };

  const requireMember = async (actorUserId: string, organizationId: string) => {
    const membership = await repository.findMembership(actorUserId, organizationId);

    if (!membership) {
      throw forbidden("You are not a member of this organization");
    }

    return membership;
  };

  const requireManager = async (actorUserId: string, organizationId: string) => {
    const membership = await requireMember(actorUserId, organizationId);

    if (!canManageOrganization(membership.role)) {
      throw forbidden("Only organization owners and admins can perform this action");
    }

    return membership;
  };

  /**
   * Owner-only operations on an existing owner.
   *
   * Admins manage members, but must not be able to reach owner authority — by
   * adding a new owner, or by demoting/removing an existing one and taking over.
   */
  const requireOwnerToActOnOwner = (actorRole: OrganizationRole, action: string) => {
    if (actorRole !== "owner") {
      throw forbidden(`Only an owner can ${action}`);
    }
  };

  const memberNotFound = () =>
    new CfAuthError("not_a_member", "That user is not a member of this organization", 404);

  /**
   * Translates a guarded repository write.
   *
   * The last-owner rule is enforced inside the write's WHERE clause rather than
   * by a preceding count, so this only has to render the outcome.
   */
  const unwrapMembershipMutation = (result: MembershipMutationResult, action: string) => {
    if (result.ok) {
      return result.membership;
    }

    if (result.reason === "last_owner") {
      throw conflict(
        `Cannot ${action} the last owner of this organization; promote another owner first`,
        "last_owner",
      );
    }

    throw memberNotFound();
  };

  const provisionDefaultOrganization = async (user: AuthUser) => {
    const name = config.organizations.resolveDefaultOrganizationName(user);
    const { membership, created } = await repository.ensureDefaultOrganizationWithOwner({
      userId: user.id,
      name,
    });

    if (created) {
      await emit({
        type: "organization.created",
        userId: user.id,
        organizationId: membership.organization.id,
        role: membership.role,
        name: membership.organization.name,
      });
    }

    return membership;
  };

  return {
    async getAuthState(userId, currentOrganizationId) {
      const user = await repository.findUserById(userId);

      if (!user) {
        return null;
      }

      const memberships = await repository.listOrganizationsForUser(user.id);
      return toSessionAuthState(user, memberships, currentOrganizationId);
    },

    async ensureDefaultOrganization(state) {
      if (
        !config.organizations.autoProvisionDefaultOrganization ||
        !state.authenticated ||
        !state.user ||
        state.memberships.length > 0
      ) {
        return state;
      }

      const membership = await provisionDefaultOrganization(state.user);
      return toSessionAuthState(state.user, [membership], membership.organization.id);
    },

    async provisionNewUser(user) {
      const storedUser = (await repository.findUserById(user.id)) ?? user;
      await emit({ type: "user.signup", userId: storedUser.id, email: storedUser.email });

      if (!config.organizations.autoProvisionDefaultOrganization) {
        return toSessionAuthState(storedUser, [], null);
      }

      const existing = await repository.listOrganizationsForUser(storedUser.id);

      if (existing.length > 0) {
        return toSessionAuthState(storedUser, existing, existing[0]?.organization.id ?? null);
      }

      const membership = await provisionDefaultOrganization(storedUser);
      return toSessionAuthState(storedUser, [membership], membership.organization.id);
    },

    async listOrganizations(userId) {
      return repository.listOrganizationsForUser(userId);
    },

    async createOrganization(userId, name) {
      const membership = await repository.createOrganizationWithOwner({
        userId,
        name: ensureNonEmpty(name, "Organization name"),
      });

      await emit({
        type: "organization.created",
        userId,
        organizationId: membership.organization.id,
        role: membership.role,
        name: membership.organization.name,
      });

      return membership;
    },

    async selectOrganization(userId, organizationId) {
      const user = await repository.findUserById(userId);

      if (!user) {
        throw unauthorized();
      }

      const membership = await repository.findMembership(userId, organizationId);

      if (!membership) {
        throw forbidden("You are not a member of this organization");
      }

      const memberships = await repository.listOrganizationsForUser(user.id);
      return toSessionAuthState(user, memberships, membership.organization.id);
    },

    async listOrganizationMembers(userId, organizationId) {
      await requireManager(userId, organizationId);
      return repository.listMembers(organizationId);
    },

    async addOrganizationMember(input) {
      const actorMembership = await requireManager(input.actorUserId, input.organizationId);

      if (input.role === "owner") {
        requireOwnerToActOnOwner(actorMembership.role, "add a member as owner");
      }

      return repository.addOrganizationUser({
        organizationId: input.organizationId,
        userId: input.userId,
        role: input.role,
      });
    },

    async updateOrganizationMemberRole(input) {
      const actorMembership = await requireManager(input.actorUserId, input.organizationId);
      const target = await repository.findMembership(input.userId, input.organizationId);

      if (!target) {
        throw memberNotFound();
      }

      if (input.role === "owner" && target.role !== "owner") {
        requireOwnerToActOnOwner(actorMembership.role, "grant the owner role");
      }

      const demotingAnOwner = target.role === "owner" && input.role !== "owner";

      if (demotingAnOwner) {
        requireOwnerToActOnOwner(actorMembership.role, "demote an owner");
      }

      if (target.role === input.role) {
        return target;
      }

      return unwrapMembershipMutation(
        await repository.updateOrganizationUserRole({
          organizationId: input.organizationId,
          userId: input.userId,
          role: input.role,
          requireAnotherOwner: demotingAnOwner,
        }),
        "demote",
      );
    },

    async removeOrganizationMember(input) {
      const actorMembership = await requireManager(input.actorUserId, input.organizationId);
      const target = await repository.findMembership(input.userId, input.organizationId);

      if (!target) {
        throw memberNotFound();
      }

      const removingAnOwner = target.role === "owner";

      if (removingAnOwner) {
        requireOwnerToActOnOwner(actorMembership.role, "remove another owner");
      }

      return unwrapMembershipMutation(
        await repository.removeOrganizationUser({
          organizationId: input.organizationId,
          userId: input.userId,
          requireAnotherOwner: removingAnOwner,
        }),
        "remove",
      );
    },

    async resolveApiKeyAuthState(plaintext, source = "api") {
      if (!config.apiKeys.enabled || !isApiKeyActionSource(source)) {
        return createEmptyAuthState();
      }

      const token = plaintext.trim();

      if (!token) {
        return createEmptyAuthState();
      }

      const apiKey = await repository.findActiveApiKeyByHash(await hashApiKeyToken(token));

      if (!apiKey) {
        return createEmptyAuthState();
      }

      return toApiKeyAuthState(apiKey.id, apiKey.organization, source);
    },

    async listApiKeys(input) {
      requireApiKeysEnabled();
      // Reading key metadata (never the token) is safe for any member.
      await requireMember(input.actorUserId, input.organizationId);
      return repository.listApiKeys(input.organizationId);
    },

    async createApiKey(input) {
      requireApiKeysEnabled();
      // An API key carries owner authority within its organization, so minting
      // one must itself be a manager-level action — otherwise any member (or a
      // non-member, if a route trusts a body-supplied organizationId) could
      // escalate to owner.
      await requireManager(input.actorUserId, input.organizationId);
      const name = ensureNonEmpty(input.name, "API key name");
      const token = await generateApiKeyToken(config.apiKeys.tokenPrefix);
      const apiKey = await repository.createApiKey({
        organizationId: input.organizationId,
        name,
        tokenHash: token.tokenHash,
        tokenHint: token.tokenHint,
      });

      await emit({
        type: "api_key.created",
        actorUserId: input.actorUserId,
        organizationId: input.organizationId,
        apiKeyId: apiKey.id,
        name,
      });

      return { ...apiKey, plaintext: token.plaintext };
    },

    async revokeApiKey(input) {
      requireApiKeysEnabled();
      await requireManager(input.actorUserId, input.organizationId);
      const existing = await repository.findApiKeyById(input.apiKeyId, input.organizationId);

      if (!existing) {
        return null;
      }

      if (existing.revokedAt) {
        return existing;
      }

      const apiKey = await repository.revokeApiKey(input.apiKeyId, input.organizationId);

      if (!apiKey) {
        return null;
      }

      await emit({
        type: "api_key.revoked",
        actorUserId: input.actorUserId,
        organizationId: input.organizationId,
        apiKeyId: apiKey.id,
        name: apiKey.name,
      });

      return apiKey;
    },
  };
};
