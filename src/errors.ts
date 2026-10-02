/**
 * Error type raised by cf-auth. Carries a stable machine-readable `code` and an
 * HTTP `status` so a host app can map it onto its own error envelope without
 * string matching.
 */
export class CfAuthError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, message: string, status = 400) {
    super(message);
    this.name = "CfAuthError";
    this.code = code;
    this.status = status;
  }
}

export const unauthorized = (message = "Authentication is required") =>
  new CfAuthError("unauthorized", message, 401);

export const forbidden = (message = "You do not have access to this resource") =>
  new CfAuthError("forbidden", message, 403);

export const notFound = (message = "Not found") => new CfAuthError("not_found", message, 404);

export const conflict = (message: string, code = "conflict") =>
  new CfAuthError(code, message, 409);

/**
 * The caller is authenticated, but with a credential that cannot satisfy this
 * endpoint (an API key where a user session is required).
 *
 * Deliberately 403 rather than 401: a machine client must not react by
 * retrying or rotating its key — no key will ever work here.
 */
export const sessionRequired = (
  message = "This endpoint requires a user session; API key credentials are not accepted",
) => new CfAuthError("session_required", message, 403);

/**
 * The caller is authenticated and holds the role, but the credential it
 * presented carries a grant too narrow for this action — a `read` key where
 * a write needs `manage`.
 *
 * 403 rather than 401 for the same reason as {@link sessionRequired}: the
 * credential is valid, and retrying with it will never help.
 */
export const grantInsufficient = (
  message = "This credential's grant does not allow this action; use a session or a key with the manage grant",
) => new CfAuthError("grant_insufficient", message, 403);

/**
 * The organization exists, but its provisional deadline has passed, so nothing
 * may act inside it. Distinct from {@link forbidden}: no role or credential
 * change would help.
 */
export const organizationExpired = (
  message = "This organization's deadline has passed",
) => new CfAuthError("organization_expired", message, 403);

export const validationError = (message: string) =>
  new CfAuthError("validation_error", message, 422);

// --- operations ----------------------------------------------------------------

/** No operation answers to that id and token. Deliberately silent about which part was wrong. */
export const operationNotFound = (message = "Operation was not found") =>
  new CfAuthError("operation_not_found", message, 404);

/** The operation, or the one-time outcome being collected, has passed its deadline. */
export const operationExpired = (message = "This operation has expired") =>
  new CfAuthError("operation_expired", message, 410);

export const operationDenied = (message = "This operation was denied") =>
  new CfAuthError("operation_denied", message, 409);

/** The operation has not been approved or completed yet; ask again later. */
export const operationPending = (message = "This operation is still pending") =>
  new CfAuthError("operation_pending", message, 409);

/** The browser proof, user code or redeem code does not match this operation. */
export const invalidProof = (message = "The proof does not match this operation") =>
  new CfAuthError("invalid_proof", message, 403);

export const alreadyCompleted = (message = "This operation has already been completed") =>
  new CfAuthError("already_completed", message, 409);

/**
 * A reservation handle was presented for another kind, or from another
 * organization, than the one it was reserved for.
 */
export const operationMismatch = (
  message = "This handle belongs to a different kind of operation or another organization",
) => new CfAuthError("operation_mismatch", message, 409);

/** A sealed outcome was already released to a browser page. */
export const alreadyRevealed = (message = "This operation's outcome has already been revealed") =>
  new CfAuthError("already_revealed", message, 409);

export const tooManyPending = (message = "Too many operations are waiting for approval") =>
  new CfAuthError("too_many_pending", message, 429);

/** The approver does not hold the membership an operation's kind requires. */
export const notAMember = (
  message = "You are not a member of this organization with the required role",
) => new CfAuthError("not_a_member", message, 403);

export const isCfAuthError = (value: unknown): value is CfAuthError =>
  value instanceof CfAuthError;
