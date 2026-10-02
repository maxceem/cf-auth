/**
 * Reading the parameters of an OAuth request — a token or revocation body,
 * or an authorization request's query — the same way everywhere: any
 * parameter given more than once is refused (RFC 6749 §3.1, §3.2), and a
 * description echoes a parameter's name only when it plainly is one, so it
 * stays within the characters RFC 6749 §5.2 allows.
 */

export type FormParams = Pick<URLSearchParams, "get" | "getAll" | "keys">;

/** The value as form parameters, or null when it is not `URLSearchParams`-shaped. */
export const formParams = (body: unknown): FormParams | null =>
  body !== null &&
  typeof body === "object" &&
  typeof (body as FormParams).get === "function" &&
  typeof (body as FormParams).getAll === "function" &&
  typeof (body as FormParams).keys === "function"
    ? (body as FormParams)
    : null;

/**
 * The description of a repeated parameter. A name is echoed only when it is
 * plainly a parameter name; anything else gets a fixed text.
 */
export const duplicateDescription = (name: string) =>
  /^[A-Za-z0-9_.-]{1,64}$/.test(name)
    ? `Parameter ${name} is given more than once`
    : "A parameter is given more than once";

/** The first parameter given more than once, or null. */
export const duplicatedParameter = (params: FormParams): string | null => {
  for (const name of new Set(params.keys())) if (params.getAll(name).length > 1) return name;
  return null;
};
