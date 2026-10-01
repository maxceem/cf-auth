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
  type LoginOperationConfig,
  type OAuthCimdConfig,
  type OAuthClientConfig,
  type OAuthConfig,
  type OAuthProxyConfig,
  type OperationsConfig,
  type OrganizationsConfig,
  type ResolvedCfAuthConfig,
  type ResolvedOAuthConfig,
  type ResolvedOperationsConfig,
  type UserHooksConfig,
} from "./config.js";

export {
  credentialAuthorityCondition,
  credentialAuthoritySql,
  liveHumanSessionSql,
  type CompiledSqlCondition,
  type CredentialAuthorityInput,
} from "./authority.js";

export {
  actionSources,
  apiKeyActionSources,
  canManageOrganization,
  createEmptyAuthState,
  credentialGrants,
  hasGrantAtLeast,
  hasRoleAtLeast,
  isApiKeyActionSource,
  isCredentialGrant,
  isOrganizationExpired,
  oauthActionSources,
  operationStates,
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
  type OAuthActionSource,
  type CreatedApiKey,
  type CredentialGrant,
  type OperationState,
  type OrganizationMember,
  type OrganizationMemberStatus,
  type OrganizationMembership,
  type OrganizationRole,
  type OrganizationSummary,
} from "./types.js";

export {
  alreadyCompleted,
  alreadyRevealed,
  CfAuthError,
  conflict,
  forbidden,
  grantInsufficient,
  invalidProof,
  isCfAuthError,
  notAMember,
  notFound,
  operationDenied,
  operationExpired,
  operationMismatch,
  operationNotFound,
  operationPending,
  organizationExpired,
  sessionRequired,
  tooManyPending,
  unauthorized,
  validationError,
} from "./errors.js";

export {
  createAuthMiddleware,
  requireGrant,
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
  toOAuthAuthState,
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

export { guardedInsert } from "./guarded-insert.js";

export {
  createOperationsService,
  defineOperationKind,
  operationSweepStatementCount,
  type AmendOperationInput,
  type ApproveOperationInput,
  type CfAuthOperations,
  type CompleteOperationInput,
  type ExecuteContext,
  type ExecutedOperation,
  type ExecuteOperationFunction,
  type ExecuteOperationInput,
  type OpenOperationInput,
  type OperationApproval,
  type OperationApproveContext,
  type OperationApproveResult,
  type OperationBrowserCredential,
  type OperationClient,
  type OperationClientMeta,
  type OperationDeliverableContext,
  type OperationDetails,
  type OperationKind,
  type OperationKindDefinition,
  type OperationPayloadSchema,
  type OperationRecord,
  type OperationRefusalContext,
  type OperationReservation,
  type OperationStatus,
  type OperationSweepStatements,
  type OperationView,
  type RevealedOperation,
  type RevealOperationInput,
  type ReserveOperationInput,
} from "./operations.js";

export {
  loginOperationKindName,
  type LoginOperationOutcome,
  type LoginOperationPayload,
  type LoginOperationRecord,
} from "./login-operation.js";

export {
  createOAuthService,
  oauthRefreshGraceMs,
  oauthRotationIntervalMs,
  oauthSweepStatementCount,
  type CfAuthOAuth,
  type CreateOAuthConnectionInput,
  type OAuthConnectionStatements,
  type OAuthErrorBody,
  type OAuthErrorCode,
  type OAuthRevokeResult,
  type OAuthTokenResponse,
  type OAuthTokenResult,
} from "./oauth/service.js";
export {
  oauthAuthorizationRecordTtlMs,
  oauthAuthorizeKindName,
  oauthEndpointPaths,
  oauthScopes,
  type ApproveAuthorizationInput,
  type ApproveGuestAuthorizationInput,
  type AuthorizationServerMetadata,
  type OAuthAuthorizationDetails,
  type OAuthAuthorizationPayload,
  type OAuthAuthorizationRecord,
  type OAuthAuthorizeErrorPage,
  type OAuthAuthorizeResult,
  type OAuthClientIdentity,
  type OAuthGuestProvision,
  type OAuthGuestProvisionContext,
  type ProtectedResourceMetadata,
} from "./oauth/authorization.js";
export {
  cimdFetchTimeoutMs,
  cimdMaxClientNameLength,
  cimdMaxDocumentBytes,
} from "./oauth/cimd.js";

export { createOperationToken, deriveSecret } from "./crypto.js";

export * from "./schema.js";
