const textEncoder = new TextEncoder();
const base62Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const toHexByte = (byte: number) => byte.toString(16).padStart(2, "0");

const toHex = (bytes: Uint8Array) => Array.from(bytes, toHexByte).join("");

/**
 * A stable UUIDv5-shaped identifier derived from `value`.
 *
 * Used for default-organization ids so that concurrent signup requests for the
 * same user converge on one row via `on conflict do nothing` instead of
 * racing to create duplicates.
 */
export const deterministicUuid = async (value: string): Promise<string> => {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", textEncoder.encode(value)));
  const bytes = hash.slice(0, 16);
  bytes[6] = (bytes[6]! & 0x0f) | 0x50;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;

  return [
    toHex(bytes.slice(0, 4)),
    toHex(bytes.slice(4, 6)),
    toHex(bytes.slice(6, 8)),
    toHex(bytes.slice(8, 10)),
    toHex(bytes.slice(10, 16)),
  ].join("-");
};

// 256 is not a multiple of 62, so a plain `byte % 62` would over-represent the
// first 256 % 62 = 8 characters. Reject bytes at or above the largest multiple
// of 62 instead, giving a uniform distribution.
const base62RejectionThreshold = 256 - (256 % base62Alphabet.length);

const randomBase62 = (length: number) => {
  let result = "";

  while (result.length < length) {
    // Over-draw slightly so the common case needs a single getRandomValues call.
    const bytes = crypto.getRandomValues(new Uint8Array(length - result.length + 8));

    for (const byte of bytes) {
      if (byte >= base62RejectionThreshold) {
        continue;
      }

      result += base62Alphabet[byte % base62Alphabet.length];

      if (result.length === length) {
        break;
      }
    }
  }

  return result;
};

/**
 * Derives a domain-separated subkey from a master secret via HKDF-SHA256.
 *
 * Used so the current-organization cookie is not HMAC'd with the very same key
 * better-auth uses for session tokens — a flaw in one must not weaken the other.
 */
export const deriveSecret = async (secret: string, info: string): Promise<string> => {
  const key = await crypto.subtle.importKey("raw", textEncoder.encode(secret), "HKDF", false, [
    "deriveBits",
  ]);

  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: textEncoder.encode(info),
    },
    key,
    256,
  );

  return toHex(new Uint8Array(bits));
};

/** SHA-256 hex digest. API key plaintext is never persisted, only this hash. */
export const hashApiKeyToken = async (plaintext: string): Promise<string> =>
  toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", textEncoder.encode(plaintext))));

export interface GeneratedApiKeyToken {
  plaintext: string;
  tokenHash: string;
  /** Display-only tail of the plaintext, safe to persist alongside the hash. */
  tokenHint: string;
}

/** Generates `<prefix>_<48 random base62 chars>` plus its storage hash. */
export const generateApiKeyToken = async (
  tokenPrefix: string,
  entropyLength = 48,
): Promise<GeneratedApiKeyToken> => {
  const plaintext = `${tokenPrefix}${randomBase62(entropyLength)}`;
  return {
    plaintext,
    tokenHash: await hashApiKeyToken(plaintext),
    tokenHint: plaintext.slice(-4),
  };
};
