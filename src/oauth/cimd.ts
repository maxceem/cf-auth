/**
 * Client ID Metadata Documents: a `client_id` that is an https URL names a
 * JSON document describing the client, fetched when an authorization starts.
 *
 * Everything here is bounded before and after the fetch, in this order: the
 * URL's shape; no literal address and no `localhost`; the deployment's own
 * `allowUrl`; then one request that follows no redirect, gives up after 5 s,
 * and reads at most 64 KiB of a JSON body. The document must describe a
 * public client, and nothing in it is downgraded: a client that declares
 * anything this server does not do is refused, never adjusted.
 *
 * A refusal names the field or the bound that failed, never a value the
 * document or the request carried.
 */
import { isAcceptableRedirectUri } from "./redirect-uri.js";

/** How long the fetch may take, headers and body together. */
export const cimdFetchTimeoutMs = 5_000;
/** The most of a document that is read; a longer one is refused. */
export const cimdMaxDocumentBytes = 64 * 1024;
/** The longest `client_name` accepted, as the configuration accepts for a registered client. */
export const cimdMaxClientNameLength = 200;

/** What a document says about its client, once every bound has held. */
export interface ClientMetadata {
  /** The document's URL, exactly as the request named it. */
  clientId: string;
  /** `client_name`, trimmed. Display only: the domain is what the fetch verified. */
  name: string;
  /** The `client_id` URL's host, shown beside the name. */
  domain: string;
  redirectUris: string[];
}

/** Why a document was refused. Its message names a field or a bound, never a value. */
export class ClientMetadataRefusal extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ClientMetadataRefusal";
  }
}

export interface ClientMetadataFetchOptions {
  fetch: typeof fetch;
  allowUrl: ((url: URL) => boolean | Promise<boolean>) | null;
}

function refuse(message: string): never {
  throw new ClientMetadataRefusal(message);
}

const ipv4Literal = /^\d{1,3}(?:\.\d{1,3}){3}$/;

/**
 * A host no metadata document may live on: a literal address (Workers fetch
 * takes no address anyway, and resolution cannot be pinned) or the machine
 * itself. The URL parser has already turned every IPv4 spelling — hex, octal,
 * a bare number — into the dotted form, and wraps IPv6 in brackets.
 */
const isLiteralOrLocalHost = (hostname: string): boolean => {
  const host = hostname.endsWith(".") ? hostname.slice(0, -1) : hostname;
  return (
    host === "" ||
    host.startsWith("[") ||
    ipv4Literal.test(host) ||
    host === "localhost" ||
    host.endsWith(".localhost")
  );
};

/**
 * Whether `clientId` may name a metadata document at all: https, no
 * credentials, no fragment, a path other than `/`, and a host that is a name
 * rather than an address or the machine. Answers the parsed URL, or null.
 */
export const parseClientMetadataUrl = (clientId: string): URL | null => {
  if (clientId.includes("#")) return null;
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.username || url.password || url.hash) return null;
  if (url.pathname === "/" || url.pathname === "") return null;
  if (isLiteralOrLocalHost(url.hostname)) return null;
  return url;
};

const isJsonMediaType = (value: string | null): boolean =>
  value !== null && /^application\/(?:[A-Za-z0-9!#$&^_.+-]+\+)?json\s*(?:;|$)/i.test(value.trim());

const tooLarge = "The client metadata document is larger than 64 KiB";
const unreadable = "The client metadata document could not be read in time";

/**
 * Reads a body of at most {@link cimdMaxDocumentBytes}, refusing a larger one
 * and cancelling its stream. A declared `content-length` over the cap is
 * refused before anything is read. Then, where the body is a byte stream —
 * Workers and Node both make one — it is read with a BYOB reader into one
 * buffer of the cap plus one byte, so no more than that is ever requested
 * from the stream; a document that fills the extra byte is too large. Only a
 * body that cannot be read that way is read chunk by chunk, where a platform
 * may hand over a chunk larger than the cap before the running total
 * refuses it.
 */
const readCapped = async (response: Response): Promise<Uint8Array> => {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > cimdMaxDocumentBytes) {
    await response.body?.cancel().catch(() => undefined);
    refuse(tooLarge);
  }
  const body = response.body;
  if (!body) return new Uint8Array(0);

  let byob: ReadableStreamBYOBReader | null = null;
  try {
    byob = body.getReader({ mode: "byob" });
  } catch {
    byob = null;
  }
  if (byob) {
    const limit = cimdMaxDocumentBytes + 1;
    let buffer: ArrayBuffer = new ArrayBuffer(limit);
    let filled = 0;
    while (filled < limit) {
      let next: ReadableStreamReadResult<Uint8Array>;
      try {
        next = await byob.read(new Uint8Array(buffer, filled, limit - filled));
      } catch {
        return refuse(unreadable);
      }
      // A BYOB read transfers the buffer: carry on in the one it answers with.
      if (next.value) buffer = next.value.buffer as ArrayBuffer;
      if (next.done) break;
      filled += next.value.byteLength;
    }
    if (filled > cimdMaxDocumentBytes) {
      await byob.cancel().catch(() => undefined);
      refuse(tooLarge);
    }
    return new Uint8Array(buffer, 0, filled);
  }

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    let next: ReadableStreamReadResult<Uint8Array>;
    try {
      next = await reader.read();
    } catch {
      return refuse(unreadable);
    }
    if (next.done) break;
    size += next.value.byteLength;
    if (size > cimdMaxDocumentBytes) {
      await reader.cancel().catch(() => undefined);
      refuse(tooLarge);
    }
    chunks.push(next.value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
};

/** Absent, or an array of strings each within `allowed`. */
const subsetOf = (value: unknown, allowed: readonly string[]): boolean =>
  value === undefined ||
  (Array.isArray(value) && value.every((item) => typeof item === "string" && allowed.includes(item)));

/**
 * Fetches and checks the metadata document `clientId` names. Throws
 * {@link ClientMetadataRefusal} when any bound or rule fails; the caller
 * answers that as `invalid_client`, on an error page.
 */
export const fetchClientMetadataDocument = async (
  clientId: string,
  options: ClientMetadataFetchOptions,
): Promise<ClientMetadata> => {
  const url = parseClientMetadataUrl(clientId);
  if (!url) {
    return refuse(
      "client_id must be an https URL with a path, no credentials or fragment, on a host name that is not an address or localhost",
    );
  }

  if (options.allowUrl) {
    let allowed = false;
    try {
      allowed = (await options.allowUrl(new URL(url.href))) === true;
    } catch {
      allowed = false;
    }
    if (!allowed) refuse("This deployment does not accept client metadata from that host");
  }

  // A local binding, so a platform `fetch` is never called with another `this`.
  const fetchDocument = options.fetch;
  let response: Response;
  try {
    response = await fetchDocument(url.href, {
      method: "GET",
      // workerd refuses "error"; "manual" hands back the 3xx, refused below.
      redirect: "manual",
      signal: AbortSignal.timeout(cimdFetchTimeoutMs),
      headers: { accept: "application/json" },
    });
  } catch {
    return refuse("The client metadata document could not be fetched");
  }

  if (response.status !== 200) {
    await response.body?.cancel().catch(() => undefined);
    refuse("The client metadata document did not answer 200; redirects are not followed");
  }
  if (!isJsonMediaType(response.headers.get("content-type"))) {
    await response.body?.cancel().catch(() => undefined);
    refuse("The client metadata document must be served as JSON");
  }

  const bytes = await readCapped(response);
  let document: unknown;
  try {
    document = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes));
  } catch {
    return refuse("The client metadata document is not valid JSON");
  }
  if (document === null || typeof document !== "object" || Array.isArray(document)) {
    return refuse("The client metadata document must be a JSON object");
  }
  const fields = document as Record<string, unknown>;

  if (fields.client_id !== clientId) refuse("The client metadata document's client_id is not its own URL");

  // Public clients only: absent is `none`; anything else is refused.
  const authMethod = fields.token_endpoint_auth_method;
  if (authMethod !== undefined && authMethod !== "none") {
    refuse('token_endpoint_auth_method must be "none": only public clients are accepted');
  }
  if (!subsetOf(fields.grant_types, ["authorization_code", "refresh_token"])) {
    refuse("grant_types must be within authorization_code and refresh_token");
  }
  if (!subsetOf(fields.response_types, ["code"])) refuse("response_types must be within code");

  const name = typeof fields.client_name === "string" ? fields.client_name.trim() : "";
  if (!name) refuse("client_name is required");
  if (name.length > cimdMaxClientNameLength) refuse("client_name is longer than 200 characters");

  const redirectUris = fields.redirect_uris;
  if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
    return refuse("redirect_uris must list at least one redirect URI");
  }
  if (!redirectUris.every((uri) => isAcceptableRedirectUri(uri))) {
    refuse(
      "Every redirect_uris entry must be absolute with no fragment: https, http on a loopback host, or a private-use scheme in reverse-DNS form",
    );
  }

  return { clientId, name, domain: url.host, redirectUris: [...(redirectUris as string[])] };
};
