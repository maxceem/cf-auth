import type { SQL } from "drizzle-orm";
import type { ResolvedCfAuthConfig } from "./config.js";
import { generateApiKeyToken, hashApiKeyToken } from "./crypto.js";
import {
  CfAuthError,
  conflict,
  forbidden,
  grantInsufficient,
  organizationExpired,
  unauthorized,
  validationError,
} from "./errors.js";
import {
  normalizeCredentialGrant,
  type CfAuthRepository,
  type MembershipMutationResult,
} from "./repository.js";
import {
  canManageOrganization,
  createEmptyAuthState,
  hasGrantAtLeast,
  isApiKeyActionSource,
  isOrganizationExpired,
  type ActionSource,
  type ApiKeySummary,
  type AuthState,
  type AuthUser,
  type CfAuthEvent,
  type CreatedApiKey,
  type CredentialGrant,
  type OrganizationMember,
  type OrganizationMembership,
  type OrganizationRole,
} from "./types.js";

const ensureNonEmpty = (value: string | null | undefined, label: string) => {
  const normalized = value?.trim();

  if (!normalized) {
    throw validationError(`${label} is required`);
  }

  return normalized;
};

/** A key's `source`: a short lowercase word, `console` unless the caller names one. */
export const normalizeApiKeySource = (value: string | undefined): string => {
  if (value === undefined) return "console";
  const normalized = value.trim();
  if (!/^[a-z][a-z0-9_.-]{0,31}$/.test(normalized)) {
    throw validationError("API key source must be a short lowercase word, e.g. `cli`");
  }
  return normalized;
};

/** A key's `label`: free text for people, at most 200 characters, blank meaning none. */
export const normalizeApiKeyLabel = (value: string | null | undefined): string | null => {
  const normalized = value?.trim();
  if (!normalized) return null;
  if (normalized.length > 200) throw validationError("API key label is too long");
  return normalized;
};

/**
 * The user and session behind an interactive human {@link AuthState}, or a
 * `403 session_required` when it is anything else — an API key, a service, or
 * a state no session backs.
 */
export const requireInteractiveSession = (
  state: AuthState,
): { userId: string; sessionId: string } => {
  const sessionId = state.actor?.credentialId;
  if (
    !state.authenticated ||
    state.assurance !== "interactive" ||
    state.credentialType !== "session" ||
    state.user?.kind !== "human" ||
    !sessionId
  )
    throw new CfAuthError("session_required", "An interactive human session is required", 403);
  return { userId: state.user.id, sessionId };
};

/**
 * Hands an event to `onEvent`. A failure there never breaks the operation
 * that raised it; it goes to `onError` instead.
 */
export const emitCfAuthEvent = async (config: ResolvedCfAuthConfig, event: CfAuthEvent) => {
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

/**
 * Builds a session-backed {@link AuthState}. The "current" organization is the
 * one matching `currentOrganizationId` when the user is still a member of it,
 * otherwise the first membership (organizations are ordered by creation time,
 * so this is the user's oldest org).
 *
 * An organization past its deadline is never the current one, exactly as it is
 * never one an API key can authenticate into. It stays in `memberships` so a
 * client can still name it and say why it is unavailable.
 */
export const toSessionAuthState = (
  user: AuthUser,
  memberships: OrganizationMembership[],
  currentOrganizationId: string | null,
  sessionId: string | null = null,
): AuthState => {
  const usable = memberships.filter(
    (membership) => !isOrganizationExpired(membership.organization),
  );
  const current =
    usable.find((membership) => membership.organization.id === currentOrganizationId) ??
    usable[0] ??
    null;

  if (user.kind !== "human") return createEmptyAuthState();
  return {
    authenticated: true,
    assurance: "interactive",
    credentialType: "session",
    source: "web",
    actor: {
      type: "user",
      id: user.id,
      kind: user.kind,
      credentialId: sessionId,
      actionSource: "web",
    },
    user,
    memberships,
    organization: current?.organization ?? null,
    role: current?.role ?? null,
    // A person's own session is not a delegated credential: it carries all
    // of their role.
    grant: "manage",
  };
};

export const toApiKeyAuthState = (
  user: AuthUser,
  membership: OrganizationMembership,
  apiKeyId: string,
  source: ActionSource,
  /** The key's own grant. Default: `"manage"`, what a key issued before grants existed carries. */
  grant: CredentialGrant = "manage",
): AuthState => {
  if (!isApiKeyActionSource(source)) return createEmptyAuthState();
  return {
    authenticated: true,
    credentialType: "apiKey",
    assurance: "credential",
    source,
    actor: {
      type: "user",
      id: user.id,
      kind: user.kind,
      credentialId: apiKeyId,
      actionSource: source,
    },
    user,
    memberships: [membership],
    organization: membership.organization,
    role: membership.role,
    grant,
  };
};

export interface IssueIdentityApiKeyInput {
  userId: string;
  organizationId: string;
  name: string;
  expiresAt?: Date | null;
  /** Issue inactive until a protected credential exchange atomically enables it. */
  enabled?: boolean;
  /** Where the key was issued from. Default: `"console"`. */
  source?: string;
  /** A human-readable note about the holder. */
  label?: string | null;
  /**
   * How much of the service's authority the key may exercise. Default:
   * `"manage"`. Trusted issuance has no actor to bound it, so it is taken as
   * given.
   */
  grant?: CredentialGrant;
}

export interface ClaimOrganizationInput {
  /** An interactive human session. The person taking the organization over. */
  actor: AuthState;
  organizationId: string;
  /**
   * The machine identity that provisioned the organization, and the credential
   * it asked for the claim with. The claim only counts while that credential is
   * still live, and `revokeAccess` says whether it survives the claim.
   */
  provisioning?: {
    userId: string;
    credentialId: string;
    revokeAccess: boolean;
  };
}

export interface CfAuthService {
  getIdentity(userId: string): Promise<AuthUser | null>;
  createServiceIdentity(input: { name: string; id?: string }): Promise<AuthUser>;
  /** Trusted bootstrap/claim boundary only; never expose as an unrestricted management route. */
  issueServiceApiKey(input: IssueIdentityApiKeyInput): Promise<CreatedApiKey>;
  /**
   * Activates a service key issued with `enabled: false`, once the exchange
   * that ordered it has committed. Trusted boundary, like the issuance itself.
   *
   * Answers with the key as it stands afterwards, so a caller reads `enabled`
   * rather than assuming: a key revoked in the meantime stays revoked and is
   * reported that way instead of raising. Null means no such key here.
   */
  enableServiceApiKey(input: { apiKeyId: string; organizationId: string }): Promise<ApiKeySummary | null>;
  /**
   * Retires a service key without an organization actor — for a trusted
   * exchange cleaning up after itself. Idempotent.
   */
  revokeServiceApiKey(input: { apiKeyId: string; organizationId: string }): Promise<ApiKeySummary | null>;

  /**
   * Resolves interactive state from a session id.
   *
   * Takes the session rather than a user id because the session *is* the
   * evidence: it is re-read here, and an unknown or expired one resolves to
   * null instead of an interactive state nothing backs.
   */
  getAuthState(
    sessionId: string,
    currentOrganizationId: string | null,
  ): Promise<AuthState | null>;
  /** Creates the default organization if the user has none yet. */
  ensureDefaultOrganization(state: AuthState): Promise<AuthState>;
  /** Runs from better-auth's `user.create.after` hook. Idempotent. */
  provisionNewUser(user: AuthUser): Promise<AuthState | null>;

  /**
   * Every organization the caller belongs to.
   *
   * Session-only: an API key is scoped to one organization, so listing the
   * others its owner happens to belong to would reach past that scope.
   */
  listOrganizations(actor: AuthState): Promise<OrganizationMembership[]>;
  /**
   * Provisions an organization owned by `userId`.
   *
   * A trusted boundary, alongside {@link CfAuthService.createServiceIdentity}:
   * it takes the owner's id rather than an actor because there is no
   * organization yet to scope an actor against. Never expose it as a route an
   * API key can reach.
   */
  createOrganization(userId: string, name: string): Promise<OrganizationMembership>;
  /** Switches the active organization, verifying membership first. Session-only. */
  selectOrganization(actor: AuthState, organizationId: string): Promise<AuthState>;
  /**
   * Hands an organization no person owns yet to the actor, clearing its
   * provisional deadline in the same transaction. Idempotent.
   */
  claimOrganization(input: ClaimOrganizationInput): Promise<OrganizationMembership>;
  /**
   * The same claim as guarded drizzle statements, for a batch of your own —
   * an operation's approval, whose `guard` goes in `condition` so the
   * ownership change lands in the batch that completes the operation or not
   * at all. `afterCommit` emits `organization.claimed` if the claim landed.
   * Shaped to spread into an operation kind's `approve` result.
   */
  claimOrganizationStatements(input: ClaimOrganizationInput & { condition?: SQL }): {
    statements: unknown[];
    afterCommit: () => Promise<void>;
  };
  listOrganizationMembers(input: {
    actor: AuthState;
    organizationId: string;
  }): Promise<OrganizationMember[]>;
  addOrganizationMember(input: {
    actor: AuthState;
    organizationId: string;
    userId: string;
    role: OrganizationRole;
  }): Promise<OrganizationMembership>;
  updateOrganizationMemberRole(input: {
    actor: AuthState;
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
    actor: AuthState;
    organizationId: string;
    userId: string;
  }): Promise<OrganizationMembership>;

  resolveApiKeyAuthState(plaintext: string, source?: ActionSource): Promise<AuthState>;
  /** Requires current organization membership. */
  listApiKeys(input: { organizationId: string; actor: AuthState }): Promise<ApiKeySummary[]>;
  /**
   * Requires a current owner or admin membership and a credential with the
   * `manage` grant. The new key's grant may not exceed the actor's: a `read`
   * credential issues no keys at all (`403 grant_insufficient`).
   */
  createApiKey(input: {
    organizationId: string;
    actor: AuthState;
    name: string;
    expiresAt?: Date | null;
    /** Where the key was issued from. Default: `"console"`. */
    source?: string;
    /** A human-readable note about the holder. */
    label?: string | null;
    /** How much of the holder's authority the key may exercise. Default: `"manage"`. */
    grant?: CredentialGrant;
  }): Promise<CreatedApiKey>;
  /** Requires a current owner or admin membership and the `manage` grant. */
  revokeApiKey(input: {
    organizationId: string;
    actor: AuthState;
    apiKeyId: string;
  }): Promise<ApiKeySummary | null>;
  /**
   * Revokes exactly the API key the caller authenticated with — a CLI logging
   * itself out. Needs no role and no grant: holding a key, even a `read` one,
   * is authority enough to end it. Throws `403 api_key_required` for any other
   * credential.
   */
  revokeOwnApiKey(input: { actor: AuthState }): Promise<ApiKeySummary>;
}

export const createAuthService = (
  repository: CfAuthRepository,
  config: ResolvedCfAuthConfig,
): CfAuthService => {
  /**
   * The acting user, once the credential may act in `organizationId` with at
   * least the `needed` grant.
   *
   * Every credential but a session is bound to its own organization — whoever
   * holds it, a person or a service, and whatever kind of credential it is,
   * so a new kind is restricted without anyone remembering to. The grant is
   * checked after that binding, so a key reaching into another organization
   * is told so rather than being told its grant is too narrow.
   */
  const requireActor = (
    state: AuthState,
    organizationId: string,
    needed: CredentialGrant,
  ): string => {
    if (!state.authenticated || !state.user) throw unauthorized();
    requireOwnOrganization(state, organizationId);
    if (!hasGrantAtLeast(state.grant, needed)) throw grantInsufficient();
    return state.user.id;
  };
  const requireOwnOrganization = (state: AuthState, organizationId: string) => {
    if (state.credentialType !== "session" && state.organization?.id !== organizationId)
      throw forbidden("This API key is restricted to another organization");
  };
  /**
   * The refusals a claim owes a credential before asking whether it is a
   * session, in {@link requireActor}'s order: a credential naming another
   * organization is told so first, then a narrow one about its grant — which
   * it can do something about — before being told it is not a session.
   */
  const refuseClaimCredential = (state: AuthState, organizationId: string) => {
    if (!state.authenticated) return;
    requireOwnOrganization(state, organizationId);
    if (!hasGrantAtLeast(state.grant, "manage")) throw grantInsufficient();
  };
  const requireInteractive = (state: AuthState): string => {
    if (
      !state.authenticated ||
      state.assurance !== "interactive" ||
      state.credentialType !== "session" ||
      state.user?.kind !== "human"
    )
      throw new CfAuthError("session_required", "An interactive human session is required", 403);
    return state.user.id;
  };
  const issueKey = async (input: IssueIdentityApiKeyInput): Promise<CreatedApiKey> => {
    requireApiKeysEnabled();
    await requireMember(input.userId, input.organizationId);
    const expiresAt = input.expiresAt ?? null;
    if (expiresAt && (!Number.isFinite(expiresAt.getTime()) || expiresAt.getTime() <= Date.now())) {
      throw validationError("Key expiry must be a valid future date");
    }
    const token = await generateApiKeyToken(config.apiKeys.tokenPrefix);
    const summary = await repository.createApiKey({
      userId: input.userId,
      organizationId: input.organizationId,
      name: ensureNonEmpty(input.name, "API key name"),
      tokenHash: token.tokenHash,
      tokenHint: token.tokenHint,
      enabled: input.enabled ?? true,
      expiresAt,
      source: normalizeApiKeySource(input.source),
      label: normalizeApiKeyLabel(input.label),
      grant: normalizeCredentialGrant(input.grant),
    });
    return { ...summary, plaintext: token.plaintext };
  };
  const emit = (event: CfAuthEvent) => emitCfAuthEvent(config, event);

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
    getIdentity: repository.findUserById,
    async createServiceIdentity(input) {
      const id = input.id ?? crypto.randomUUID();
      const now = new Date();
      await config.db
        .insert(config.tables.user)
        .values({
          id,
          name: ensureNonEmpty(input.name, "Service name"),
          kind: "service",
          email: null,
          emailVerified: false,
          createdAt: now,
          updatedAt: now,
        })
        .onConflictDoNothing({ target: config.tables.user.id });
      const stored = await repository.findUserById(id);
      if (stored?.kind !== "service") throw conflict("Identity ID already belongs to a human");
      return (await repository.findUserById(id))!;
    },
    async issueServiceApiKey(input) {
      const user = await repository.findUserById(input.userId);
      if (user?.kind !== "service") throw validationError("A service identity is required");
      return issueKey(input);
    },
    async enableServiceApiKey(input) {
      requireApiKeysEnabled();
      const existing = await repository.findApiKeyById(input.apiKeyId, input.organizationId);
      if (!existing) return null;
      const owner = await repository.findUserById(existing.userId);
      if (owner?.kind !== "service") throw validationError("A service identity is required");
      return repository.enableApiKey(input.apiKeyId, input.organizationId, new Date());
    },

    async revokeServiceApiKey(input) {
      requireApiKeysEnabled();
      const existing = await repository.findApiKeyById(input.apiKeyId, input.organizationId);
      if (!existing) return null;
      const owner = await repository.findUserById(existing.userId);
      if (owner?.kind !== "service") throw validationError("A service identity is required");
      if (existing.revokedAt) return existing;
      return repository.revokeApiKey(input.apiKeyId, input.organizationId);
    },

    async getAuthState(sessionId, currentOrganizationId) {
      const session = await repository.findActiveSession(sessionId, new Date());

      if (!session) {
        return null;
      }

      const user = await repository.findUserById(session.userId);

      if (!user) {
        return null;
      }

      const memberships = await repository.listOrganizationsForUser(user.id);
      return toSessionAuthState(user, memberships, currentOrganizationId, session.id);
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
      // Carries the session through: the state is still the one that session
      // proves, and an actor without its credential could not act.
      return toSessionAuthState(
        state.user,
        [membership],
        membership.organization.id,
        state.actor?.credentialId ?? null,
      );
    },

    async provisionNewUser(user) {
      const storedUser = (await repository.findUserById(user.id)) ?? user;
      if (storedUser.kind !== "human" || !storedUser.email)
        throw validationError("Human signup requires an email");
      await emit({
        type: "user.signup",
        userId: storedUser.id,
        email: storedUser.email,
      });

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

    async listOrganizations(actor) {
      return repository.listOrganizationsForUser(requireInteractive(actor));
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

    async selectOrganization(actor, organizationId) {
      const userId = requireInteractive(actor);
      const user = await repository.findUserById(userId);

      if (!user) {
        throw unauthorized();
      }

      const membership = await repository.findMembership(userId, organizationId);

      if (!membership) {
        throw forbidden("You are not a member of this organization");
      }

      if (isOrganizationExpired(membership.organization)) {
        throw organizationExpired();
      }

      const memberships = await repository.listOrganizationsForUser(user.id);
      return toSessionAuthState(
        user,
        memberships,
        membership.organization.id,
        actor.actor?.credentialId ?? null,
      );
    },

    claimOrganizationStatements(input) {
      refuseClaimCredential(input.actor, input.organizationId);
      const { userId, sessionId } = requireInteractiveSession(input.actor);
      const statements = repository.claimOrganizationStatements({
        organizationId: input.organizationId,
        userId,
        sessionId,
        ...(input.provisioning ? { provisioning: input.provisioning } : {}),
        ...(input.condition ? { condition: input.condition } : {}),
      });
      return {
        statements,
        afterCommit: async () => {
          const membership = await repository.findMembership(userId, input.organizationId);
          if (membership?.role === "owner" && membership.organization.expiresAt === null) {
            await emit({ type: "organization.claimed", userId, organizationId: input.organizationId });
          }
        },
      };
    },

    async claimOrganization(input) {
      refuseClaimCredential(input.actor, input.organizationId);
      const userId = requireInteractive(input.actor);
      const sessionId = input.actor.actor?.credentialId;

      if (!sessionId) {
        throw new CfAuthError(
          "session_required",
          "An interactive human session is required",
          403,
        );
      }

      const membership = await repository.claimOrganization({
        organizationId: input.organizationId,
        userId,
        sessionId,
        ...(input.provisioning ? { provisioning: input.provisioning } : {}),
      });

      if (!membership) {
        throw conflict(
          "This organization can no longer be claimed",
          "not_claimable",
        );
      }

      await emit({
        type: "organization.claimed",
        userId,
        organizationId: input.organizationId,
      });

      return membership;
    },

    async listOrganizationMembers(input) {
      await requireManager(
        requireActor(input.actor, input.organizationId, "read"),
        input.organizationId,
      );
      return repository.listMembers(input.organizationId);
    },

    async addOrganizationMember(input) {
      const actorMembership = await requireManager(
        requireActor(input.actor, input.organizationId, "manage"),
        input.organizationId,
      );

      const targetUser = await repository.findUserById(input.userId);
      if (!targetUser) throw new CfAuthError("user_not_found", "User was not found", 404);

      if (input.role === "owner" && targetUser.kind === "human") {
        requireInteractive(input.actor);
      }
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
      const actorMembership = await requireManager(
        requireActor(input.actor, input.organizationId, "manage"),
        input.organizationId,
      );
      const target = await repository.findMembership(input.userId, input.organizationId);

      if (!target) {
        throw memberNotFound();
      }
      const targetUser = await repository.findUserById(input.userId);
      if (!targetUser) throw memberNotFound();

      if (
        targetUser.kind === "human" &&
        (input.role === "owner" || target.role === "owner")
      ) {
        requireInteractive(input.actor);
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
      const actorMembership = await requireManager(
        requireActor(input.actor, input.organizationId, "manage"),
        input.organizationId,
      );
      const target = await repository.findMembership(input.userId, input.organizationId);

      if (!target) {
        throw memberNotFound();
      }
      const targetUser = await repository.findUserById(input.userId);
      if (!targetUser) throw memberNotFound();

      const removingAnOwner = target.role === "owner";

      if (removingAnOwner && targetUser.kind === "human") {
        requireInteractive(input.actor);
      }
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

      const stored = await repository.findActiveApiKeyByHash(
        await hashApiKeyToken(token),
        new Date(),
      );
      if (!stored) return createEmptyAuthState();
      const user = await repository.findUserById(stored.userId);
      const membership = await repository.findMembership(stored.userId, stored.organizationId);
      if (
        !user ||
        !membership ||
        (membership.organization.expiresAt &&
          new Date(membership.organization.expiresAt).getTime() <= Date.now())
      )
        return createEmptyAuthState();
      return toApiKeyAuthState(user, membership, stored.id, source, stored.grant);
    },

    async listApiKeys(input) {
      requireApiKeysEnabled();
      // Reading key metadata (never the token) is safe for any member.
      await requireMember(requireActor(input.actor, input.organizationId, "read"), input.organizationId);
      return repository.listApiKeys(input.organizationId);
    },

    async createApiKey(input) {
      requireApiKeysEnabled();
      const actorUserId = requireActor(input.actor, input.organizationId, "manage");
      await requireManager(actorUserId, input.organizationId);
      const name = ensureNonEmpty(input.name, "API key name");
      const grant = normalizeCredentialGrant(input.grant);
      // A credential hands on no more than it holds. Only `manage` gets this
      // far, so today this never refuses; it keeps the rule where issuance is.
      if (!hasGrantAtLeast(input.actor.grant, grant)) throw grantInsufficient();
      const apiKey = await issueKey({
        organizationId: input.organizationId,
        userId: actorUserId,
        name,
        ...(input.expiresAt !== undefined ? { expiresAt: input.expiresAt } : {}),
        ...(input.source !== undefined ? { source: input.source } : {}),
        ...(input.label !== undefined ? { label: input.label } : {}),
        grant,
      });

      await emit({
        type: "api_key.created",
        actorUserId,
        organizationId: input.organizationId,
        apiKeyId: apiKey.id,
        name,
      });

      return apiKey;
    },

    async revokeApiKey(input) {
      requireApiKeysEnabled();
      const actorUserId = requireActor(input.actor, input.organizationId, "manage");
      await requireManager(actorUserId, input.organizationId);
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
        actorUserId,
        organizationId: input.organizationId,
        apiKeyId: apiKey.id,
        name: apiKey.name,
      });

      return apiKey;
    },

    async revokeOwnApiKey({ actor }) {
      requireApiKeysEnabled();
      // No grant check, deliberately: a credential may always end itself, and
      // a `read` key logging out must not need `manage` to do it.
      if (!actor.authenticated || !actor.user) throw unauthorized();
      const apiKeyId = actor.actor?.credentialId;
      const organizationId = actor.organization?.id;
      if (actor.credentialType !== "apiKey" || !apiKeyId || !organizationId) {
        throw new CfAuthError(
          "api_key_required",
          "Only an API key can revoke itself; sign-in sessions sign out instead",
          403,
        );
      }

      const apiKey = await repository.revokeApiKey(apiKeyId, organizationId);
      if (!apiKey) throw unauthorized();

      await emit({
        type: "api_key.revoked",
        actorUserId: actor.user.id,
        organizationId,
        apiKeyId: apiKey.id,
        name: apiKey.name,
      });

      return apiKey;
    },
  };
};
