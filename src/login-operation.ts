/**
 * The built-in `login` operation: a CLI that holds nothing asks for access, a
 * person approves it in a browser, and the CLI receives an API key of its own
 * in the organization the person chose.
 *
 * The key belongs to the approving person, carries `source: "cli"` and the
 * client's label, and is created by the same batch that completes the
 * operation, under a guard that re-reads the approver's session and
 * membership — so a key exists exactly when an approval landed.
 */

import { sql } from "drizzle-orm";
import { alias } from "drizzle-orm/sqlite-core";
import { sqliteNowMs } from "./authority.js";
import type { LoginOperationConfig, ResolvedCfAuthConfig } from "./config.js";
import { generateApiKeyToken } from "./crypto.js";
import { guardedInsert } from "./guarded-insert.js";
import type { OperationKind } from "./operations.js";
import { emitCfAuthEvent } from "./service.js";
import { hasRoleAtLeast, isOrganizationExpired } from "./types.js";

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
}

export const loginOperationKindName = "login";

export const createLoginOperationKind = (
  config: ResolvedCfAuthConfig,
  login: Required<LoginOperationConfig>,
): OperationKind => ({
  name: loginOperationKindName,
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

  approve: async ({ operation, user, organizationId, guard, db, tables, now }) => {
    // `login` is approved by a person (the default approver mode) and names an
    // approver role, so the engine always hands it both.
    const approver = user!;
    const organization = organizationId!;
    const label = operation.client.label!;
    const token = await generateApiKeyToken(config.apiKeys.tokenPrefix);
    const apiKeyId = crypto.randomUUID();
    const outcome: LoginOperationOutcome = {
      credential: { token: token.plaintext },
      organizationId: organization,
      apiKeyId,
    };
    const record: LoginOperationRecord = { organizationId: organization, apiKeyId };

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
