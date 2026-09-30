/**
 * The built-in `login` operation: a CLI that holds nothing asks for access, a
 * person approves it in a browser, and the CLI receives an API key of its own
 * in the organization the person chose.
 *
 * The key belongs to the approving person, carries `source: "cli"`, the
 * client's label and the grant the client asked for (`manage` unless its
 * payload says `{ grant: "read" }`), and is created by the same batch that
 * completes the operation, under a guard that re-reads the approver's session
 * and membership — so a key exists exactly when an approval landed.
 */

import { sql } from "drizzle-orm";
import { alias } from "drizzle-orm/sqlite-core";
import { sqliteNowMs } from "./authority.js";
import type { LoginOperationConfig, ResolvedCfAuthConfig } from "./config.js";
import { generateApiKeyToken } from "./crypto.js";
import { grantInsufficient, validationError } from "./errors.js";
import { guardedInsert } from "./guarded-insert.js";
import type { OperationKind } from "./operations.js";
import { emitCfAuthEvent } from "./service.js";
import {
  hasGrantAtLeast,
  hasRoleAtLeast,
  isCredentialGrant,
  isOrganizationExpired,
  type CredentialGrant,
} from "./types.js";

/** What a completed `login` hands the CLI, once. Never log `credential.token`. */
export interface LoginOperationOutcome {
  credential: { token: string };
  organizationId: string;
  apiKeyId: string;
}

/** What a completed `login` keeps in the clear. */
export interface LoginOperationRecord {
  organizationId: string;
  apiKeyId: string;
  /** The grant the issued key carries. */
  grant: CredentialGrant;
}

/**
 * What a client may ask `login` for. The approval page reads it back as
 * `details().payload`, always with the grant spelled out, so it can show the
 * grant being asked for.
 *
 * A login opened with no payload stores none: `null` is the legacy spelling
 * of `{ grant: "manage" }`, kept so a login opened before grants existed
 * hashes as it did and a CLI repeating that same `open` is answered rather
 * than refused. Wherever the payload is read, `null` means `manage`. An
 * explicit `{ grant: "manage" }` is stored as given, and is a different
 * request from an omitted payload.
 */
export interface LoginOperationPayload {
  /** The grant the issued key will carry. Default: `"manage"`. */
  grant: CredentialGrant;
}

export const loginOperationKindName = "login";

/**
 * Reads a `login` payload: nothing, stored as no payload (the legacy spelling
 * of `manage`), or `{ grant }`, stored with the grant spelled out.
 */
const parseLoginPayload = (value: unknown): LoginOperationPayload | undefined => {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw validationError("The login payload must be an object");
  }
  const { grant, ...rest } = value as Record<string, unknown>;
  if (Object.keys(rest).length > 0) {
    throw validationError("The login payload takes only `grant`");
  }
  if (grant !== undefined && !isCredentialGrant(grant)) {
    throw validationError('The login payload\'s grant must be "read" or "manage"');
  }
  return { grant: grant ?? "manage" };
};

/** The grant a stored `login` payload asks for; `null`, no payload, asks for `manage`. */
const requestedGrant = (payload: unknown): CredentialGrant => {
  const grant = (payload as Partial<LoginOperationPayload> | null)?.grant;
  return grant === undefined ? "manage" : isCredentialGrant(grant) ? grant : "read";
};

export const createLoginOperationKind = (
  config: ResolvedCfAuthConfig,
  login: Required<LoginOperationConfig>,
): OperationKind => ({
  name: loginOperationKindName,
  payload: parseLoginPayload,
  showPayload: (payload): LoginOperationPayload => ({ grant: requestedGrant(payload) }),
  open: "public",
  browser: true,
  userCode: true,
  requireClientLabel: true,
  approverMinRole: login.minRole,
  pendingTtlMs: login.pendingTtlMs,
  recordTtlMs: login.recordTtlMs,

  // The key is handed over only while it could still be used: one revoked
  // between approval and collection is withdrawn, not delivered.
  deliverable: ({ record, tables, now }) => {
    const apiKeyId = (record as Partial<LoginOperationRecord> | null)?.apiKeyId;
    if (typeof apiKeyId !== "string") return sql`0`;
    const key = alias(tables.apiKey, "cf_auth_delivered_key");
    return sql`exists (
      select 1 from ${tables.apiKey} as ${sql.identifier("cf_auth_delivered_key")}
      where ${key.id} = ${apiKeyId}
        and ${key.enabled} = 1
        and ${key.revokedAt} is null
        and (${key.expiresAt} is null or ${key.expiresAt} > ${sqliteNowMs(now)})
    )`;
  },

  refusal: ({ viewer }) => {
    if (
      !viewer?.authenticated ||
      viewer.assurance !== "interactive" ||
      viewer.user?.kind !== "human"
    )
      return "session_required";
    const eligible = viewer.memberships.some(
      (membership) =>
        hasRoleAtLeast(membership.role, login.minRole) &&
        !isOrganizationExpired(membership.organization),
    );
    return eligible ? null : "no_eligible_organization";
  },

  approve: async ({ operation, payload, actor, user, organizationId, guard, db, tables, now }) => {
    // `login` is approved by a person (the default approver mode) and names an
    // approver role, so the engine always hands it both.
    const approver = user!;
    const organization = organizationId!;
    const label = operation.client.label!;
    const grant = requestedGrant(payload);
    // The approver hands on no more than they hold. A session holds `manage`,
    // so this never refuses today; it keeps the issuance rule in one shape.
    if (!hasGrantAtLeast(actor?.grant, grant)) throw grantInsufficient();
    const token = await generateApiKeyToken(config.apiKeys.tokenPrefix);
    const apiKeyId = crypto.randomUUID();
    const outcome: LoginOperationOutcome = {
      credential: { token: token.plaintext },
      organizationId: organization,
      apiKeyId,
    };
    const record: LoginOperationRecord = { organizationId: organization, apiKeyId, grant };

    return {
      outcome,
      seal: true,
      record,
      statements: [
        // Written only while the approval's guard holds, in the batch that
        // completes the operation.
        guardedInsert(
          db,
          tables.apiKey,
          {
            id: apiKeyId,
            userId: approver.id,
            organizationId: organization,
            name: label,
            tokenHash: token.tokenHash,
            tokenHint: token.tokenHint,
            enabled: true,
            expiresAt: null,
            createdAt: new Date(now),
            revokedAt: null,
            source: "cli",
            label,
            grant,
          },
          guard,
        ),
      ],
      afterCommit: () =>
        emitCfAuthEvent(config, {
          type: "api_key.created",
          actorUserId: approver.id,
          organizationId: organization,
          apiKeyId,
          name: label,
        }),
    };
  },
});
