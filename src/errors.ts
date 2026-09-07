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

export const validationError = (message: string) =>
  new CfAuthError("validation_error", message, 422);

export const isCfAuthError = (value: unknown): value is CfAuthError =>
  value instanceof CfAuthError;
