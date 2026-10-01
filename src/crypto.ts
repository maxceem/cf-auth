const textEncoder = new TextEncoder();
const base62Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

const toHexByte = (byte: number) => byte.toString(16).padStart(2, "0");

const toHex = (bytes: Uint8Array) => Array.from(bytes, toHexByte).join("");

const base62RejectionThreshold = 256 - (256 % base62Alphabet.length);

const randomBase62 = (length: number) => {
  let result = "";
  while (result.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(length - result.length + 8));
    for (const byte of bytes) {
      if (byte >= base62RejectionThreshold) continue;
      result += base62Alphabet[byte % base62Alphabet.length];
      if (result.length === length) break;
    }
  }
  return result;
};

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

/** Generates a prefixed token with 48 uniformly distributed base62 characters. */
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

/** SHA-256 hex digest of any secret the database keeps only a digest of. */
export const sha256Hex = hashApiKeyToken;

const base64UrlEncode = (bytes: Uint8Array): string => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

const base64UrlDecode = (value: string): Uint8Array => {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
};

/** `bytes` of secure randomness, base64url without padding. */
export const randomToken = (bytes = 32): string =>
  base64UrlEncode(crypto.getRandomValues(new Uint8Array(bytes)));

/**
 * A fresh operation token, the one secret a client holds for an operation: 32
 * random bytes, base64url. Clients may mint their own the same way; the server
 * only ever stores its digest.
 */
export const createOperationToken = (): string => randomToken(32);

const hmacBytes = async (key: string, message: string): Promise<Uint8Array> => {
  const imported = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, textEncoder.encode(message)));
};

/** HMAC-SHA256 of `message` keyed by `key`, hex. */
export const hmacHex = async (key: string, message: string): Promise<string> =>
  toHex(await hmacBytes(key, message));

/**
 * Compares two strings without an early exit, so how long a comparison takes
 * says nothing about how much of a secret digest matched. Unequal lengths
 * still walk the longer input.
 */
export const timingSafeEqual = (left: string, right: string): boolean => {
  const length = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;
  for (let index = 0; index < length; index += 1) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
};

/**
 * The alphabet of a user code: no `0`/`O`, `1`/`I`/`L`, so what a person reads
 * in a terminal is what they type in a browser.
 */
export const userCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
export const userCodeLength = 8;
const userCodeRejectionThreshold = 256 - (256 % userCodeAlphabet.length);

/**
 * A user code derived from the operation token, so a client that retries or
 * polls is shown the same code and the server never has to store it: only
 * its digest is kept. Formatted `ABCD-EFGH`.
 */
export const deriveUserCode = async (token: string, realm: string): Promise<string> => {
  let code = "";
  for (let round = 0; code.length < userCodeLength; round += 1) {
    for (const byte of await hmacBytes(token, `cf-auth:operation-user-code:${realm}:${round}`)) {
      if (byte >= userCodeRejectionThreshold) continue;
      code += userCodeAlphabet[byte % userCodeAlphabet.length];
      if (code.length === userCodeLength) break;
    }
  }
  return `${code.slice(0, 4)}-${code.slice(4)}`;
};

/**
 * A user code as typed: case and separators ignored. Null when what remains
 * cannot be a code at all.
 */
export const normalizeUserCode = (value: string): string | null => {
  const normalized = value.toUpperCase().replace(/[\s-]/g, "");
  if (normalized.length !== userCodeLength) return null;
  for (const character of normalized) {
    if (!userCodeAlphabet.includes(character)) return null;
  }
  return normalized;
};

const aesKey = (bytes: Uint8Array): Promise<CryptoKey> =>
  crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"]);

const sealKey = async (secret: string): Promise<CryptoKey> =>
  aesKey(
    Uint8Array.from((await deriveSecret(secret, "cf-auth:operation-seal")).match(/../g)!, (pair) =>
      Number.parseInt(pair, 16),
    ),
  );

const sealWith = async (key: CryptoKey, context: string, plaintext: string): Promise<string> => {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: textEncoder.encode(context) },
    key,
    textEncoder.encode(plaintext),
  );
  return `${base64UrlEncode(iv)}.${base64UrlEncode(new Uint8Array(ciphertext))}`;
};

const openWith = async (key: CryptoKey, context: string, sealed: string): Promise<string> => {
  const [iv, ciphertext] = sealed.split(".");
  if (!iv || !ciphertext) throw new Error("Malformed sealed value");
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64UrlDecode(iv), additionalData: textEncoder.encode(context) },
    key,
    base64UrlDecode(ciphertext),
  );
  return new TextDecoder().decode(plaintext);
};

/**
 * Encrypts `plaintext` with AES-256-GCM under a subkey of `secret`, bound to
 * `context` (the operation id) so a sealed value cannot be moved to another
 * row and opened there. Returns `iv.ciphertext`, both base64url.
 */
export const sealText = async (secret: string, context: string, plaintext: string): Promise<string> =>
  sealWith(await sealKey(secret), context, plaintext);

/** Opens a value from {@link sealText}; throws if it was sealed for another context or key. */
export const openText = async (secret: string, context: string, sealed: string): Promise<string> =>
  openWith(await sealKey(secret), context, sealed);

/**
 * An AES-256-GCM key derived from a bearer token by HKDF-SHA256 (no salt,
 * `info` naming the purpose). The database keeps only the token's SHA-256
 * digest, from which this key cannot be computed, so whatever is sealed under
 * it opens only for whoever presents the token itself.
 */
const tokenSealKey = async (token: string, info: string): Promise<CryptoKey> => {
  const material = await crypto.subtle.importKey("raw", textEncoder.encode(token), "HKDF", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: textEncoder.encode(info) },
    material,
    256,
  );
  return aesKey(new Uint8Array(bits));
};

/**
 * Seals `plaintext` so only the holder of `token` can open it: AES-256-GCM
 * under {@link tokenSealKey}, with `context` as additional data. Returns
 * `iv.ciphertext`, both base64url.
 */
export const sealTextForToken = async (
  token: string,
  info: string,
  context: string,
  plaintext: string,
): Promise<string> => sealWith(await tokenSealKey(token, info), context, plaintext);

/** Opens a value from {@link sealTextForToken}; throws for any other token, purpose or context. */
export const openTextForToken = async (
  token: string,
  info: string,
  context: string,
  sealed: string,
): Promise<string> => openWith(await tokenSealKey(token, info), context, sealed);
