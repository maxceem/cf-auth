/**
 * Which redirect URIs an OAuth client may declare, and when a presented one
 * matches a declared one. Public clients only, so every rule here is about
 * where a code may be sent.
 *
 * Matching is on the strings themselves, never on parsed and normalised
 * components: `http://127.1/cb`, `http://127.0.0.1/x/../cb` and
 * `http://127.0.0.1/cb#` all parse to something close to
 * `http://127.0.0.1/cb`, and none of them is it.
 */

/** Hosts an `http` redirect URI may name: the machine itself (RFC 8252 §7.3), spelled exactly so. */
export const loopbackRedirectHosts: ReadonlySet<string> = new Set(["127.0.0.1", "[::1]", "localhost"]);

/** A private-use URI scheme in reverse-DNS form, with at least one dot (RFC 8252 §7.1). */
const privateUseScheme = /^[a-z][a-z0-9+-]*(?:\.[a-z0-9+-]+)+$/;

const loopbackPrefix = "http://";

/**
 * A loopback `http` URI with its port taken out, read from the string as
 * written and otherwise kept as written: `http://` in any letter case, then
 * exactly `127.0.0.1`, `[::1]` or `localhost`, then
 * optionally `:` and 1 to 5 digits (at most 65535), then a `/`, `?` or the
 * end. Null for anything else — another scheme, another spelling of the
 * host, userinfo, an empty or malformed port.
 */
export const loopbackWithoutPort = (value: string): string | null => {
  // The scheme is case-insensitive (RFC 3986 §3.1), so `HTTP://` is loopback
  // too; it is kept as written, so two spellings still differ when compared.
  const scheme = value.slice(0, loopbackPrefix.length);
  if (scheme.toLowerCase() !== loopbackPrefix) return null;
  const rest = value.slice(loopbackPrefix.length);
  const end = rest.search(/[/?#]/);
  const authority = end < 0 ? rest : rest.slice(0, end);
  const path = end < 0 ? "" : rest.slice(end);
  const match = /^(127\.0\.0\.1|\[::1\]|localhost)(?::(\d{1,5}))?$/.exec(authority);
  if (!match) return null;
  if (match[2] !== undefined && Number(match[2]) > 65535) return null;
  return `${scheme}${match[1]}${path}`;
};

/**
 * Whether a client may declare `value` as a redirect URI: absolute, with no
 * fragment (not even an empty one), and one of `https` (no userinfo); `http`
 * on a loopback host written exactly as `127.0.0.1`, `[::1]` or `localhost`,
 * any port; or a private-use scheme in reverse-DNS form (`com.example.app:/cb`).
 */
export const isAcceptableRedirectUri = (value: unknown): value is string => {
  if (typeof value !== "string" || value.includes("#")) return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.hash) return false;
  if (url.protocol === "https:") return Boolean(url.hostname) && !url.username && !url.password;
  if (url.protocol === "http:") {
    return (
      loopbackRedirectHosts.has(url.hostname) && !url.username && !url.password && loopbackWithoutPort(value) !== null
    );
  }
  return privateUseScheme.test(url.protocol.slice(0, -1));
};

/**
 * Whether a presented redirect URI matches a declared one: the same string,
 * byte for byte, except that when both are loopback `http` URIs the port
 * alone may differ (RFC 8252 §7.3) — the strings are then compared with the
 * port taken out of both and everything else, the scheme's letter case
 * included, as written. A presented URI with any fragment never matches.
 */
export const redirectUriMatches = (declared: string, presented: string): boolean => {
  if (typeof declared !== "string" || typeof presented !== "string") return false;
  if (presented.includes("#")) return false;
  if (declared === presented) return true;
  const a = loopbackWithoutPort(declared);
  const b = loopbackWithoutPort(presented);
  return a !== null && a === b;
};
