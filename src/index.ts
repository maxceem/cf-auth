/**
 * @maxceem/cf-auth
 *
 * better-auth + organizations for Cloudflare Workers apps built on Hono and D1.
 *
 * This is a library, not a service: every consuming app keeps its own users,
 * organizations and API keys inside its own D1 database.
 */

export { createCfAuth, type CfAuth } from "./cf-auth.js";

export {
  resolveConfig,
  type AccountLinkingConfig,
  type ApiKeysConfig,
  type CfAuthConfig,
  type CfAuthDatabase,
  type CookieConfig,
  type EmailAndPasswordConfig,
  type GoogleOAuthConfig,
  type OAuthProxyConfig,
  type OrganizationsConfig,
  type ResolvedCfAuthConfig,
  type UserHooksConfig,
} from "./config.js";

export {
  credentialAuthorityCondition,
  type CompiledSqlCondition,
  type CredentialAuthorityInput,
} from "./authority.js";

export {
  actionSources,
  apiKeyActionSources,
  canManageOrganization,
  createEmptyAuthState,
  hasRoleAtLeast,
  isApiKeyActionSource,
  isOrganizationExpired,
  organizationMemberStatuses,
  organizationRoles,
  type ActionSource,
  type ApiKeyActionSource,
  type ApiKeySummary,
  type AuthActor,
  type AuthSession,
  type AuthCredentialType,
  type AuthState,
  type AuthUser,
  type IdentityKind,
  type CfAuthEvent,
  type CreatedApiKey,
  type OrganizationMember,
  type OrganizationMemberStatus,
  type OrganizationMembership,
  type OrganizationRole,
  type OrganizationSummary,
} from "./types.js";

export {
  CfAuthError,
  conflict,
  forbidden,
  isCfAuthError,
  notFound,
  organizationExpired,
  sessionRequired,
  unauthorized,
  validationError,
} from "./errors.js";

export {
  createAuthMiddleware,
  requireOrganization,
  requireOrganizationManager,
  requireUser,
  type AuthMiddlewareOptions,
  type CfAuthEnv,
  type CfAuthVariables,
  type RequireOrganizationResult,
} from "./middleware.js";

export {
  createCurrentOrganizationCookie,
  isSecureRequest,
  type CurrentOrganizationCookie,
} from "./cookies.js";

export {
  createAuthService,
  toApiKeyAuthState,
  toSessionAuthState,
  type CfAuthService,
  type ClaimOrganizationInput,
  type IssueIdentityApiKeyInput,
} from "./service.js";

export {
  createCfAuthRepository,
  type CfAuthRepository,
  type ClaimOrganizationWrite,
  type CfAuthRepositoryOptions,
  type EnsureDefaultOrganizationResult,
  type MembershipMutationResult,
} from "./repository.js";

export {
  createBetterAuthInstance,
  createBetterAuthOptions,
  type CfBetterAuth,
} from "./better-auth.js";

export { deriveSecret } from "./crypto.js";

export * from "./schema.js";
