/**
 * Which redirect URIs an OAuth client may declare, and when a presented one
 * matches a declared one. Public clients only, so every rule here is about
 * where a code may be sent.
 */

/** Hosts an `http` redirect URI may name: the machine itself (RFC 8252 §7.3). */
export const loopbackRedirectHosts: ReadonlySet<string> = new Set(["127.0.0.1", "[::1]", "localhost"]);

/** A private-use URI scheme in reverse-DNS form, with at least one dot (RFC 8252 §7.1). */
const privateUseScheme = /^[a-z][a-z0-9+-]*(?:\.[a-z0-9+-]+)+$/;

/**
 * Whether a client may declare `value` as a redirect URI: absolute, with no
 * fragment, and one of `https` (no userinfo); `http` on a loopback host, any
 * port; or a private-use scheme in reverse-DNS form (`com.example.app:/cb`).
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
    return loopbackRedirectHosts.has(url.hostname) && !url.username && !url.password;
  }
  return privateUseScheme.test(url.protocol.slice(0, -1));
};

/**
 * Whether a presented redirect URI matches a declared one: exactly, except
 * that a loopback `http` URI may name another port (RFC 8252 §7.3). Host, path
 * and query may not differ.
 */
export const redirectUriMatches = (declared: string, presented: string): boolean => {
  if (declared === presented) return true;
  let a: URL;
  let b: URL;
  try {
    a = new URL(declared);
    b = new URL(presented);
  } catch {
    return false;
  }
  const loopback = (url: URL) => url.protocol === "http:" && loopbackRedirectHosts.has(url.hostname);
  return (
    loopback(a) &&
    loopback(b) &&
    a.hostname === b.hostname &&
    a.pathname === b.pathname &&
    a.search === b.search &&
    !a.username &&
    !b.username &&
    !a.password &&
    !b.password &&
    !b.hash
  );
};
