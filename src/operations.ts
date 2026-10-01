/**
 * Browser-approved operations.
 *
 * An operation is something a client — usually a CLI — asks a server for,
 * that a person may have to approve in a browser before it happens, and whose
 * outcome the client collects afterwards. The client holds one random token
 * and the server keeps only its digest, so holding the token is the whole
 * proof of being the client that asked. Everything else is derived from it:
 * the browser proof that travels in the approval URL's fragment, and the short
 * user code a person can read off the terminal instead.
 *
 * The app registers kinds; this module owns the table, the state machine, and
 * the guards that make approval and completion one atomic write each. It
 * declares no routes, because every app names and shapes its own.
 *
 * Every statement this module batches is a drizzle query builder, never
 * `db.run(sql)`: D1's batch binds parameters through the builder's prepared
 * statement, and a raw statement with parameters has none.
 */

import { and, entityKind, eq, getTableName, isNull, lte, ne, sql, type SQL } from "drizzle-orm";
import type { BatchItem } from "drizzle-orm/batch";
import { alias } from "drizzle-orm/sqlite-core";
import {
  credentialAuthoritySql,
  liveHumanSessionSql,
  sqliteNowMs,
} from "./authority.js";
import {
  internalOperationKindPrefix,
  isInternalOperationKind,
  operationDefaults,
  validateOperationKind,
  type CfAuthDatabase,
  type ResolvedCfAuthConfig,
} from "./config.js";
import {
  deriveSecret,
  deriveUserCode,
  hmacHex,
  normalizeUserCode,
  openText,
  randomToken,
  sealText,
  sha256Hex,
  timingSafeEqual,
} from "./crypto.js";
import {
  alreadyCompleted,
  alreadyRevealed,
  CfAuthError,
  conflict,
  forbidden,
  grantInsufficient,
  invalidProof,
  operationDenied,
  operationExpired,
  operationMismatch,
  operationNotFound,
  operationPending,
  organizationExpired,
  tooManyPending,
  unauthorized,
  validationError,
} from "./errors.js";
import { guardedInsert } from "./guarded-insert.js";
import { createLoginOperationKind } from "./login-operation.js";
import { requireOrganization } from "./middleware.js";
import type { CfAuthRepository } from "./repository.js";
import type { CfAuthTables } from "./schema.js";
import { requireInteractiveSession } from "./service.js";
import {
  createEmptyAuthState,
  hasGrantAtLeast,
  hasRoleAtLeast,
  isOrganizationExpired,
  organizationRoles,
  type AuthState,
  type AuthUser,
  type CredentialGrant,
  type OperationState,
  type OrganizationMembership,
  type OrganizationRole,
  type OrganizationSummary,
} from "./types.js";

// --- kinds ---------------------------------------------------------------------

/**
 * How a kind reads a value a client or a page sent: a zod schema (anything
 * with a `parse` method) or a plain function. Throwing refuses the value.
 */
export type OperationPayloadSchema<Value> =
  | { parse(value: unknown): Value }
  | ((value: unknown) => Value);

/**
 * What a client says about itself, shown to the person approving. Never
 * trusted for anything — not even rate limiting; see `rateLimitKey`.
 */
export interface OperationClientMeta {
  os?: string;
  ip?: string;
  userAgent?: string;
}

export interface OperationClient {
  /** E.g. `CLI on mac-studio`. */
  label: string | null;
  meta: OperationClientMeta | null;
}

/** One operation as a kind's hooks see it. */
export interface OperationRecord<Payload = unknown> {
  id: string;
  kind: string;
  /** Already `expired` when a pending operation's deadline has passed, whatever the row says. */
  state: OperationState;
  /** The opener's organization, or, once approved, the one a public kind was approved into. */
  organizationId: string | null;
  openerUserId: string | null;
  openerCredentialId: string | null;
  client: OperationClient;
  hasLoopbackRedirect: boolean;
  payload: Payload;
  decidedByUserId: string | null;
  createdAt: string;
  expiresAt: string;
}

export interface OperationApproveContext<Payload = unknown, Input = unknown> {
  operation: OperationRecord<Payload>;
  payload: Payload;
  /** What the approval page submitted, read by the kind's `input` schema. Never stored. */
  input: Input | undefined;
  /**
   * The approving person, re-read at write time: an interactive human
   * session. Null for a kind with `approver: "proof"`, where the proof is the
   * whole authority.
   */
  actor: AuthState | null;
  user: AuthUser | null;
  /** The organization the approval acts in, when there is one. */
  organizationId: string | null;
  /** The approver's membership there, when the kind requires one. */
  membership: OrganizationMembership | null;
  /**
   * AND this into the WHERE of every statement you return: it is true only
   * while the operation is still pending and inside its deadline, the
   * approver's session (and required membership) is live, and the opener's
   * credential still is. Completion carries the same guard, so a write and its
   * completion either both land or neither does.
   */
  guard: SQL;
  db: CfAuthDatabase;
  tables: CfAuthTables;
  /** The instant the guard was built for, in epoch milliseconds. */
  now: number;
}

export interface OperationApproveResult<Outcome = unknown> {
  /** What the client collects. Must be JSON-serializable. */
  outcome: Outcome;
  /**
   * Seal the outcome: store it encrypted and hand it over as the kind's
   * `deliver` says, then drop it. Use it for anything carrying a secret.
   */
  seal?: boolean;
  /**
   * What is kept in the clear when the outcome is sealed — ids, never the
   * secret. Ignored when not sealed, where the outcome itself is kept.
   */
  record?: unknown;
  /**
   * drizzle query builders (`db.insert`, `db.update`, `db.delete`, or
   * `guardedInsert`) run in the same batch as the completion, before it.
   * Never `db.run(sql)` with parameters: D1 cannot batch it. Guard each with
   * {@link OperationApproveContext.guard}; the operation completes only if the
   * last of them changed a row, and when it does not, the whole batch rolls
   * back — none of them stays written.
   */
  statements?: readonly unknown[];
  /** Runs once the batch has committed, e.g. to write an audit event. Failures go to `onError`. */
  afterCommit?: () => void | Promise<void>;
}

export interface OperationDeliverableContext {
  operation: OperationRecord;
  /** What the operation keeps in the clear: its `record`. */
  record: unknown;
  tables: CfAuthTables;
  now: number;
}

export interface OperationRefusalContext<Payload = unknown> {
  operation: OperationRecord<Payload>;
  payload: Payload;
  /** Who holds the browser, or null when nobody is signed in. */
  viewer: AuthState | null;
}

/**
 * One kind of operation, registered in `operations.kinds`.
 *
 * `Payload` is what the payload schema returns, `Outcome` what `approve`
 * resolves to, and `Input` what the approval page may submit with it.
 */
export interface OperationKindDefinition<Payload = unknown, Outcome = unknown, Input = unknown> {
  /** Lowercase letters, digits, `.`, `_` and `-`. */
  name: string;
  /**
   * How the payload is read. Leave it out for a kind that takes none. A
   * schema that answers `undefined` stores no payload, which the hooks then
   * see as `null`.
   */
  payload?: OperationPayloadSchema<Payload>;
  /**
   * What `details` shows the approval page as `payload`, from the stored one
   * (`null` when none was stored). Default: the stored payload as it is. Use
   * it to spell out a default the stored form leaves implicit.
   */
  showPayload?(payload: Payload | null): unknown;
  /**
   * How the approval page's own submission is read — a secret typed on the
   * page, say. It reaches `approve` and is never stored. Leave it out for a
   * kind that takes none.
   */
  input?: OperationPayloadSchema<Input>;
  /**
   * Who may open one: anybody (`"public"`, and no identity is bound to it), or
   * a caller — session or API key — with at least `minRole` in its current
   * organization.
   */
  open: "public" | { minRole: OrganizationRole };
  /**
   * For a kind a caller opens: the least grant the opener's credential must
   * carry. Checked at `open`, and again inside every guarded write that
   * rechecks the opener — approval, `complete`, `guard`, and handing over a
   * sealed outcome — so a key that no longer carries it cannot finish what it
   * started. A session is always `manage`. Default: `"manage"`; say `"read"`
   * for a kind that only reads.
   *
   * Not for a `"public"` kind, which binds no opener credential to check.
   */
  grant?: CredentialGrant;
  /** Whether it is approved in a browser. Without one, the app calls `complete`, or `reserve` and `execute`. */
  browser: boolean;
  /**
   * Reserved for cf-auth's own built-in kinds, and refused in
   * `operations.kinds`. An internal kind is named `cf-auth:<name>`, and a
   * stored operation in that namespace is internal whatever is registered —
   * an engine built without the kind still hides its rows. It lives in the
   * same table and the same sweep, but every entry point of
   * `cfAuth.operations` refuses it: `open` and `reserve` with `422
   * validation_error`, everything that looks one up as `404
   * operation_not_found`. Only the flow that owns it drives it.
   */
  internal?: true;
  /**
   * What approving needs. `"session"` (default): a signed-in person, as
   * `approverMinRole` says. `"proof"`: the browser proof alone — whoever holds
   * the link approves, signed in or not, and the opener's credential is the
   * authority the write runs under. Suits a step that only collects something
   * from the person the CLI sent there, such as a secret.
   */
  approver?: "session" | "proof";
  /** Also derive a short code the person can type instead of following the link. */
  userCode?: boolean;
  /**
   * Whether its pending operations count toward `limits.pendingPerOrganization`
   * and `limits.pendingPerOpener`, and whether opening one is capped by them.
   * Default: `true` for a kind with a browser step, whose pendings wait on a
   * person; `false` for one without, which the app completes itself — one it
   * refuses to complete would otherwise hold a slot until its deadline.
   */
  countsTowardPending?: boolean;
  /** Refuse to open without `client.label`. */
  requireClientLabel?: boolean;
  /**
   * For `approver: "session"`: the least role the approver must hold in the
   * operation's organization. `null` asks only for a live human session and
   * leaves the rest to `approve`. Default: `"admin"`.
   */
  approverMinRole?: OrganizationRole | null;
  /**
   * How a sealed outcome is handed over. `"once"` (default): to the first
   * `poll` or `redeem` that asks, then dropped. `"window"`: to every one that
   * asks until the seal expires, so a client whose response was lost can ask
   * again; the sweep drops it after. `"reveal"`: only through `reveal`, to a
   * person on a page — `poll`, `findByToken` and a retried `open` answer the
   * record without it, `redeem` answers `409 already_completed`, and none of
   * them consumes it. For a kind without a
   * browser step; use it for every reservation kind whose outcome is a secret
   * the client must not see.
   *
   * Whichever it is, collecting the outcome drops only the outcome: the seal
   * window (`sealed_until`), which also bounds `execute`'s replay, runs on.
   */
  deliver?: "once" | "window" | "reveal";
  /**
   * A condition a sealed outcome must still meet to be handed over — that the
   * credential it carries is still live, say. Checked by every `poll`,
   * `redeem` and `reveal` that would release it (by `reveal` inside the very
   * write that takes it); when it fails, that sealed outcome is dropped and
   * the answer is `410 operation_expired`. Return undefined to skip the check.
   */
  deliverable?(context: OperationDeliverableContext): SQL | undefined;
  /** How long it may stay pending — the browser step's window. Default: 15 minutes. */
  pendingTtlMs?: number;
  /** How long the record is kept, counted from opening. Default: 90 days. */
  recordTtlMs?: number;
  /** Decides the outcome once approved. Default: an empty outcome. */
  approve?(
    context: OperationApproveContext<Payload, Input>,
  ): OperationApproveResult<Outcome> | Promise<OperationApproveResult<Outcome>>;
  /**
   * What stands between this viewer and approving, as a short code the page
   * can act on (`session_required`, ...), or null when nothing does. `details`
   * reports it as `blockedBy`, and `approve` refuses with it as the error
   * code, so the page and the answer never disagree.
   */
  refusal?(context: OperationRefusalContext<Payload>): string | null | Promise<string | null>;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type OperationKind = OperationKindDefinition<any, any, any>;

/** Declares a kind with its payload, outcome and input types inferred. */
export const defineOperationKind = <Payload, Outcome, Input = undefined>(
  kind: OperationKindDefinition<Payload, Outcome, Input>,
): OperationKindDefinition<Payload, Outcome, Input> => kind;

// --- service shapes ---------------------------------------------------------------

export interface OpenOperationInput {
  kind: string;
  /** The client's random token: 32–256 base64url characters. See `createOperationToken`. */
  token: string;
  /**
   * The operation's id, when the app wants to choose it — derived from the
   * token, say, to keep an existing wire format. Up to 128 characters of
   * letters, digits, `:`, `_`, `.` and `-`. Default: a random UUID.
   */
  id?: string;
  payload?: unknown;
  /** Who is asking. Required for a kind that is not public; ignored for one that is. */
  opener?: AuthState | null;
  /**
   * What the pending-per-opener cap counts a public kind against — the
   * client's address as your edge saw it, say. Up to 256 characters. Without
   * one a public kind has no per-opener cap. Ignored for a kind that is not
   * public, which is counted per opener. Never derived from `client.meta`.
   */
  rateLimitKey?: string | null;
  client?: {
    label?: string | null;
    meta?: OperationClientMeta | null;
    /** `http://127.0.0.1:<port>/<path>` (or `[::1]`), where the approval page sends the redeem code. */
    loopbackRedirect?: string | null;
  };
}

/** What the client is told: opening and polling both answer with this. */
export interface OperationView {
  id: string;
  kind: string;
  state: OperationState;
  createdAt: string;
  expiresAt: string;
  organizationId: string | null;
  /** While pending with a browser step: put it in the approval URL's fragment. */
  browserProof: string | null;
  /** While pending, for a kind with a user code: `ABCD-EFGH`, to show in the terminal. */
  userCode: string | null;
  /** What is kept in the clear: an unsealed outcome, or a sealed one's `record`. */
  record: unknown;
  /** The sealed outcome, on an answer that hands it over. */
  outcome?: unknown;
  /**
   * How a sealed outcome that is still held can be collected: by polling, or
   * only by `redeem` when a loopback redirect was registered. Null when none is
   * held — never sealed, already collected, or past its window.
   */
  collect: "poll" | "redeem" | null;
}

/** How a browser addresses an operation: the proof from the URL, or the code a person typed. */
export type OperationBrowserCredential = { proof: string } | { userCode: string };

export interface OperationDetails {
  id: string;
  kind: string;
  state: OperationState;
  payload: unknown;
  client: OperationClient;
  /** The organization it acts in, when one is already fixed. */
  organization: OrganizationSummary | null;
  /** The signed-in person looking at the page, with every organization they belong to. */
  viewer: { user: AuthUser; memberships: OrganizationMembership[] } | null;
  /**
   * The code the terminal shows, so the page can show the same one. Null for a
   * kind without one, and when it can no longer be read (the secret changed).
   */
  userCode: string | null;
  /** What approving needs: a signed-in person, or only the proof. */
  approver: "session" | "proof";
  /** Whether `approve` takes an `input` for this kind. */
  takesInput: boolean;
  createdAt: string;
  expiresAt: string;
  hasLoopbackRedirect: boolean;
  /** The kind's `refusal` verdict for this viewer; null when nothing is in the way. */
  blockedBy: string | null;
}

export interface ApproveOperationInput {
  id: string;
  /** The approving person. Required unless the kind's `approver` is `"proof"`. */
  actor?: AuthState | null;
  /**
   * The organization to approve into, for a session-approved kind whose
   * organization is not fixed yet. The approver must be an active member of it
   * — with `approverMinRole`, or any role when that is null. A kind whose
   * organization is fixed refuses any other.
   */
  organizationId?: string | null;
  /** What the approval page submitted, for a kind with an `input` schema. */
  input?: unknown;
}

export interface OperationApproval {
  id: string;
  kind: string;
  state: "completed";
  organizationId: string | null;
  /** Set when a loopback redirect was registered: the one-time code the client redeems with. */
  redeemCode: string | null;
  /** The loopback redirect with `?code=<redeemCode>`; navigate the browser there. */
  redirectUrl: string | null;
}

export interface CompleteOperationInput {
  id: string;
  outcome: unknown;
  seal?: boolean;
  /** What is kept in the clear when sealed. */
  record?: unknown;
  /** Query builders to run in the same batch, guarded with {@link CfAuthOperations.guard}. */
  statements?: readonly unknown[];
}

export interface AmendOperationInput {
  id: string;
  /**
   * A new outcome: sealed afresh for another `sealTtlMs` when `seal`, else
   * kept in the clear. Sealing one on an operation with a loopback redirect
   * switches it to poll collection: the redirect is dropped, because its
   * redeem code was spent on the first outcome.
   */
  outcome?: unknown;
  seal?: boolean;
  /** A new record kept in the clear. */
  record?: unknown;
  /** Further condition the amendment needs, ANDed into its WHERE. */
  condition?: SQL;
  /** Query builders to run in the same batch, before it; guard them with `guard({ id, state: "completed" })`. */
  statements?: readonly unknown[];
}

/** What {@link CfAuthOperations.status} answers: where an operation stands, and nothing it holds sealed. */
export interface OperationStatus {
  id: string;
  kind: string;
  /** Already `expired` when a pending operation's deadline has passed, whatever the row says. */
  state: OperationState;
  createdAt: string;
  expiresAt: string;
  /** The organization it acts in. `status` shows only operations that have one. */
  organizationId: string;
  /** What is kept in the clear: an unsealed outcome, or a sealed one's `record`. Never the sealed outcome. */
  record: unknown;
}

export interface ReserveOperationInput {
  /** A kind a caller opens (not `"public"`) and that has no browser step. */
  kind: string;
  /** Who is reserving, held to the kind's `open` role and `grant` exactly as `open` holds an opener. */
  opener: AuthState | null | undefined;
  /** Stored as the operation's payload, read by the kind's `payload` schema. */
  input?: unknown;
}

/** What {@link CfAuthOperations.reserve} answers. */
export interface OperationReservation {
  /** The operation's id, which `status` and `reveal` take. Not a secret. */
  id: string;
  /**
   * What `execute` takes: 32 random bytes, base64url, made by the server. It
   * is the operation's token — only its digest is stored — so hand it to the
   * caller and nobody else.
   */
  handle: string;
  /** When the reservation lapses unexecuted: `operations.reserveTtlMs` from now. */
  expiresAt: string;
}

export interface ExecuteOperationInput {
  /** The handle `reserve` answered with. */
  handle: string;
  /** The kind the caller believes it is executing; a handle reserved for another is `409 operation_mismatch`. */
  kind: string;
  /** Who is executing: must act in the organization the handle was reserved in. */
  opener: AuthState | null | undefined;
}

export interface ExecuteContext<Payload = unknown> {
  operation: OperationRecord<Payload>;
  /** What `reserve` stored, as the kind's payload schema read it (`null` when none was stored). */
  input: Payload;
  /**
   * AND this into the WHERE of every statement you return: it is true only
   * while the reservation is still pending and inside its deadline, this
   * execution still holds it, and the credential that reserved it is still
   * live with the kind's role and grant.
   */
  guard: SQL;
  db: CfAuthDatabase;
  tables: CfAuthTables;
  /** The instant the guard was built for, in epoch milliseconds. */
  now: number;
}

/**
 * What `execute` runs, once: the reservation's write, as statements for the
 * completion batch. Its outcome is always sealed; its `record` is kept in the
 * clear, and `seal` is ignored. When the completion is refused, the whole
 * batch rolls back: none of the statements stays written.
 */
export type ExecuteOperationFunction<Payload = unknown, Outcome = unknown> = (
  context: ExecuteContext<Payload>,
) => OperationApproveResult<Outcome> | Promise<OperationApproveResult<Outcome>>;

/**
 * What {@link CfAuthOperations.execute} answers. The call that ran the function
 * gets its `outcome` once, with `replayed: false`; a repeat inside the seal
 * window gets only the `record`, with `replayed: true`. Neither is meant for a
 * client that must not see a secret: hand such a client the `record` and the
 * operation's id, and let a person `reveal` the outcome.
 */
export type ExecutedOperation<Outcome = unknown> =
  | {
      id: string;
      state: "completed";
      /** What is kept in the clear: the `record` the function returned. */
      record: unknown;
      /** What the function returned as its outcome, sealed in storage. Only on this answer. */
      outcome: Outcome;
      replayed: false;
    }
  | {
      id: string;
      state: "completed";
      /** What is kept in the clear: the `record` the execution kept. */
      record: unknown;
      /** A repeat: the function did not run, and the sealed outcome is not handed out again. */
      replayed: true;
    };

export interface RevealOperationInput {
  id: string;
  /**
   * The person on the page: an interactive session, admin or owner in the
   * operation's organization. Their authority is the whole of it: the
   * credential that opened the operation is not consulted.
   */
  actor: AuthState | null | undefined;
}

/** What {@link CfAuthOperations.reveal} answers, once. */
export interface RevealedOperation {
  id: string;
  kind: string;
  organizationId: string;
  outcome: unknown;
}

/** The statements {@link CfAuthOperations.sweepStatements} returns: always {@link operationSweepStatementCount}. */
export type OperationSweepStatements = BatchItem<"sqlite">[];

/**
 * How many statements one sweep issues: expire pendings, drop sealed outcomes
 * past their window, delete records past retention. For budgeting a
 * scheduled job's queries.
 */
export const operationSweepStatementCount = 3;

export interface CfAuthOperations {
  /** Every registered kind by name, the built-in `login` included and internal ones left out. */
  readonly kinds: ReadonlyMap<string, OperationKind>;
  /**
   * Opens an operation, or answers again for the one its token already opened.
   *
   * A retry with the same token must repeat the same request — kind, payload,
   * opener, organization and id — and is answered as `poll` would answer it,
   * completed ones included; a different request is a `409 conflict`. Caps
   * are checked inside the insert: `429 too_many_pending`.
   */
  open(input: OpenOperationInput): Promise<OperationView>;
  /**
   * Where the operation stands, for the client holding its token. Hands over a
   * sealed outcome as the kind's `deliver` says — never for an operation with a
   * loopback redirect, whose outcome only `redeem` releases. `404
   * operation_not_found` for an unknown id and for a wrong token alike.
   */
  poll(input: { id: string; token: string }): Promise<OperationView>;
  /** The operation a token opened, without handing anything over; null when there is none. */
  findByToken(input: { token: string }): Promise<OperationView | null>;
  /** What the approval page shows. Needs the browser proof or the user code. */
  details(
    input: { id: string; viewer?: AuthState | null } & OperationBrowserCredential,
  ): Promise<OperationDetails>;
  /**
   * Approves, runs the kind's `approve`, and completes the operation in one
   * guarded batch. A kind with `approver: "proof"` takes the proof and no
   * actor; the user code is never enough for it.
   */
  approve(input: ApproveOperationInput & OperationBrowserCredential): Promise<OperationApproval>;
  /**
   * Refuses a pending operation. Idempotent for one already denied. Nobody
   * needs to be signed in for a session-approved kind — a person sent a link
   * they did not ask for must be able to decline it — and a proof-approved
   * kind takes its proof, never a user code. `actor` only records who denied.
   */
  deny(
    input: { id: string; actor?: AuthState | null } & OperationBrowserCredential,
  ): Promise<{ id: string; kind: string; state: "denied" }>;
  /** Hands over the outcome to the client holding both its token and the redeem code. */
  redeem(input: { id: string; token: string; redeemCode: string }): Promise<{
    id: string;
    kind: string;
    organizationId: string | null;
    outcome: unknown;
  }>;
  /**
   * The pending operation a typed user code names, for a code-entry page, or
   * null. Rate-limit whatever route calls this. Continue with `{ id, userCode }`.
   */
  lookupByUserCode(input: { userCode: string }): Promise<{
    id: string;
    kind: string;
    expiresAt: string;
  } | null>;
  /** Completes a pending operation of a kind with no browser step. */
  complete(input: CompleteOperationInput): Promise<OperationView>;
  /**
   * Changes what a completed operation holds — a renewed secret, a new
   * record — under a guard, in one batch with `statements`. Answers whether
   * the amendment landed; when it did not, none of `statements` stays written.
   */
  amend(input: AmendOperationInput): Promise<boolean>;
  /**
   * The condition to AND into statements passed to `complete` (`state:
   * "pending"`, the default) or `amend` (`"completed"`): the operation is in
   * that state — and, while pending, in time — and its opener's credential is
   * still live.
   */
  guard(input: { id: string; state?: "pending" | "completed" }): Promise<SQL>;
  /**
   * Retires an operation in any state but retired: a pending one can no
   * longer be approved, a completed one's authority ends, and any outcome it
   * still holds is dropped. Answers whether it moved.
   */
  retire(input: { id: string }): Promise<boolean>;
  /**
   * The sweep, as {@link operationSweepStatementCount} query builders for your
   * scheduled job to batch: expire stale pendings, drop sealed outcomes past
   * their window, delete records past their retention.
   */
  sweepStatements(now?: number): OperationSweepStatements;
  /** Runs {@link CfAuthOperations.sweepStatements} in one batch. */
  sweep(now?: number): Promise<void>;
  /**
   * Where an operation stands, for a caller in its organization: state, kind,
   * expiry and the record kept in the clear. Never the sealed outcome, and it
   * hands nothing over, so a `once` delivery is still waiting afterwards.
   * Anyone else — another organization, nobody signed in, an operation with no
   * organization — gets `404 operation_not_found`, so it discloses nothing.
   */
  status(input: { id: string; opener: AuthState | null | undefined }): Promise<OperationStatus>;
  /**
   * Reserves an operation of a kind with no browser step, to run later with
   * `execute`: pending for `operations.reserveTtlMs`, bound to the opener's
   * credential and organization and to the kind, with `input` stored as its
   * payload. Writes nothing else. Answers a server-made handle.
   */
  reserve(input: ReserveOperationInput): Promise<OperationReservation>;
  /**
   * Runs a reservation once. `fn` builds the write under a guard that rechecks
   * the reserving credential and this execution's claim, and the operation
   * completes in the same batch with the outcome sealed; if the completion is
   * refused, the batch rolls back whole. The run that executed answers the
   * outcome; a repeat inside `operations.sealTtlMs` answers only the record,
   * with `replayed: true`, revealed or not; after it, `409
   * already_completed`. Neither runs `fn`, and neither does a call racing one
   * that is running: that one answers `409 conflict`.
   */
  execute<Outcome = unknown>(
    input: ExecuteOperationInput,
    fn: ExecuteOperationFunction<unknown, Outcome>,
  ): Promise<ExecutedOperation<Outcome>>;
  /**
   * Releases a sealed outcome to a page, once, inside its seal window, to a
   * signed-in person who is admin or owner in the operation's organization,
   * while the kind still considers it deliverable. The person is the whole
   * authority: the credential that opened the operation is not rechecked. For
   * kinds without a browser step; a second reveal is `409 already_revealed`.
   * Revealing does not end `execute`'s replay of the record.
   */
  reveal(input: RevealOperationInput): Promise<RevealedOperation>;
}

// --- internals ---------------------------------------------------------------------

const tokenPattern = /^[A-Za-z0-9_-]{32,256}$/;
const idPattern = /^[A-Za-z0-9:_.-]{1,128}$/;
const proofPattern = /^[a-f0-9]{64}$/;
const maxPayloadLength = 16_384;
const maxClientText = 512;

type OperationRow = CfAuthTables["operation"]["$inferSelect"];

type BatchCapableDatabase = {
  batch?: (queries: readonly unknown[]) => Promise<unknown[]>;
};

/**
 * Refuses a statement D1 cannot batch: `db.run(sql)` and friends with
 * parameters carry no prepared statement for D1's batch to bind. Checked on
 * every driver, so a test suite on another one still catches it.
 */
const assertBatchable = (statement: unknown) => {
  const constructor = (statement as { constructor?: Record<symbol, unknown> } | null)?.constructor;
  if (constructor?.[entityKind] !== "SQLiteRaw") return;
  const query = (statement as { getQuery(): { params: unknown[] } }).getQuery();
  if (query.params.length > 0) {
    throw validationError(
      "A batched statement must be a drizzle query builder; D1 cannot batch db.run(sql) with parameters. Use guardedInsert, db.update or db.delete",
    );
  }
};

/**
 * Runs statements as one transaction and answers each one's result. Both D1
 * and libsql batch; a driver that cannot runs them in order, which keeps every
 * guard but not the atomicity.
 */
const runBatch = async (db: CfAuthDatabase, statements: readonly unknown[]): Promise<unknown[]> => {
  if (statements.length === 0) return [];
  statements.forEach(assertBatchable);
  const batch = (db as unknown as BatchCapableDatabase).batch;
  if (typeof batch === "function") return batch.call(db, statements);
  const results: unknown[] = [];
  for (const statement of statements) results.push(await (statement as Promise<unknown>));
  return results;
};

const clientText = (value: unknown, label: string): string | undefined => {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") throw validationError(`${label} must be a string`);
  const trimmed = value.trim();
  if (trimmed.length > maxClientText) throw validationError(`${label} is too long`);
  return trimmed || undefined;
};

/**
 * Where a loopback approval may send the browser: plain http on the machine's
 * own loopback address with an explicit port, per RFC 8252. `localhost` is
 * refused because it can resolve elsewhere.
 */
const normalizeLoopbackRedirect = (value: string): string => {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw validationError("loopbackRedirect must be a URL");
  }
  if (
    url.protocol !== "http:" ||
    (url.hostname !== "127.0.0.1" && url.hostname !== "[::1]") ||
    !url.port ||
    url.username ||
    url.password ||
    url.hash ||
    url.search
  ) {
    throw validationError(
      "loopbackRedirect must be http://127.0.0.1:<port>/<path> (or [::1]) with no query or fragment",
    );
  }
  return url.toString();
};

const parseJson = (value: string | null): unknown => (value === null ? null : JSON.parse(value));

const iso = (value: Date) => value.toISOString();

const effectiveState = (row: OperationRow, now: number): OperationState =>
  row.state === "pending" && row.expiresAt.getTime() <= now ? "expired" : row.state;

/** Refuses anything but a pending operation still in time, naming what it is instead. */
const assertPending = (row: OperationRow, now: number) => {
  switch (effectiveState(row, now)) {
    case "pending":
      return;
    case "denied":
      throw operationDenied();
    case "completed":
      throw alreadyCompleted();
    case "retired":
      throw operationExpired("This operation has been retired");
    case "expired":
      throw operationExpired();
  }
};

const rolesAtLeast = (minimum: OrganizationRole) =>
  organizationRoles.filter((role) => hasRoleAtLeast(role, minimum));

/** Reads a value with a kind's schema, turning a throw into `422 validation_error`. */
const parseWith = <Value>(schema: OperationPayloadSchema<Value>, value: unknown, what: string): Value => {
  try {
    return typeof schema === "function" ? schema(value) : schema.parse(value);
  } catch (error) {
    if (error instanceof CfAuthError) throw error;
    throw Object.assign(validationError(`Invalid ${what}`), { cause: error });
  }
};

/** The one engine behind `cfAuth.operations`, with the door cf-auth's own flows use. */
export interface OperationsEngine {
  /** What `cfAuth.operations` is: every entry point refuses an internal kind. */
  operations: CfAuthOperations;
  /**
   * The same engine with internal kinds admitted, for the flow that owns one.
   * Never exported from the package index; reach it only from cf-auth's own
   * modules.
   */
  internal: CfAuthOperations;
}

/**
 * Builds the engine. Not exported from the package index: `builtInKinds` is
 * how cf-auth registers its own kinds, internal ones included, and `internal`
 * is the only door to those.
 */
export const createOperationsEngine = (
  config: ResolvedCfAuthConfig,
  repository: CfAuthRepository,
  options: { builtInKinds?: readonly OperationKind[] } = {},
): OperationsEngine => {
  const { db, tables } = config;
  const { operation } = tables;
  const settings = config.operations;

  const kinds = new Map<string, OperationKind>();
  if (settings.login) {
    kinds.set("login", createLoginOperationKind(config, settings.login));
  }
  for (const kind of [...(options.builtInKinds ?? []), ...settings.kinds]) {
    if (options.builtInKinds?.includes(kind)) {
      validateOperationKind(kind, `built-in operation kind ${kind.name}`, { builtIn: true });
    }
    if (kinds.has(kind.name)) {
      throw validationError(`Operation kind \`${kind.name}\` is declared twice`);
    }
    kinds.set(kind.name, kind);
  }
  /**
   * Whether a row is out of reach of a door that does not admit internal kinds.
   * Judged by the kind's name, never by what this engine registered, so a row
   * of an internal kind stays hidden from an engine that lacks the kind.
   */
  const hidden = (row: OperationRow, admitInternal: boolean) =>
    !admitInternal && isInternalOperationKind(row.kind);

  const requireEnabled = () => {
    if (!settings.enabled) {
      throw validationError("Operations are disabled; set `operations.enabled: true` to use them");
    }
  };

  const kindOf = (name: string): OperationKind => {
    const kind = kinds.get(name);
    if (!kind) throw validationError(`Unknown operation kind \`${name}\``);
    return kind;
  };

  const pendingTtl = (kind: OperationKind) => kind.pendingTtlMs ?? operationDefaults.pendingTtlMs;
  const recordTtl = (kind: OperationKind) => kind.recordTtlMs ?? operationDefaults.recordTtlMs;
  const approverMode = (kind: OperationKind) => kind.approver ?? "session";
  const approverMinRole = (kind: OperationKind) =>
    kind.approverMinRole === undefined ? "admin" : kind.approverMinRole;
  const countsTowardPending = (kind: OperationKind) => kind.countsTowardPending ?? kind.browser;
  const openerGrant = (kind: OperationKind): CredentialGrant => kind.grant ?? "manage";
  const countingKinds = [...kinds.values()].filter(countsTowardPending).map((kind) => kind.name);

  /**
   * How a row's sealed outcome is handed over. A row whose kind is no longer
   * registered still answers its client, delivering once — unless it had no
   * browser step, when it may have been a `"reveal"` kind: removing a kind
   * must never let `poll` release what the kind kept for a person.
   */
  const deliverMode = (row: OperationRow): "once" | "window" | "reveal" => {
    const kind = kinds.get(row.kind);
    if (kind) return kind.deliver ?? "once";
    return row.browserProofHash === null ? "reveal" : "once";
  };

  const browserProofFor = (token: string) =>
    hmacHex(token, `cf-auth:operation-browser:${settings.realm}`);
  const userCodeFor = (token: string) => deriveUserCode(token, settings.realm);
  const userCodeContext = (id: string) => `${id}:user-code`;
  let userCodeKey: Promise<string> | undefined;
  /**
   * The stored digest of a normalized user code: an HMAC under a subkey of
   * `secret`, so reading the table does not let anyone test all 31^8 codes
   * offline against it.
   */
  const userCodeHash = async (normalized: string) =>
    hmacHex(
      await (userCodeKey ??= deriveSecret(config.secret, "cf-auth:operation-user-code")),
      normalized,
    );

  const parsePayload = (kind: OperationKind, value: unknown): string | null => {
    if (!kind.payload) {
      if (value !== undefined && value !== null) {
        throw validationError(`Operation kind \`${kind.name}\` takes no payload`);
      }
      return null;
    }
    const parsed = parseWith(kind.payload, value, `payload for operation kind \`${kind.name}\``);
    // A schema that answers `undefined` stores no payload, exactly as a kind
    // without one does — so a kind that gains a schema still hashes the
    // requests it already stored, and a retry of one is not a conflict.
    if (parsed === undefined) return null;
    const json = JSON.stringify(parsed ?? null);
    if (json.length > maxPayloadLength) throw validationError("Operation payload is too large");
    return json;
  };

  const parseInput = (kind: OperationKind, value: unknown): unknown => {
    if (!kind.input) {
      if (value !== undefined) throw validationError(`Operation kind \`${kind.name}\` takes no input`);
      return undefined;
    }
    return parseWith(kind.input, value, `input for operation kind \`${kind.name}\``);
  };

  const findById = async (id: string): Promise<OperationRow | null> =>
    typeof id === "string" && idPattern.test(id)
      ? ((await db.select().from(operation).where(eq(operation.id, id)).get()) ?? null)
      : null;

  const findByTokenHash = async (hash: string): Promise<OperationRow | null> =>
    (await db.select().from(operation).where(eq(operation.pollTokenHash, hash)).get()) ?? null;

  /** The row a token names, or `404` — the same answer for a wrong token as for a missing row. */
  const rowForToken = async (id: string, token: string, admitInternal: boolean): Promise<OperationRow> => {
    const row = await findById(id);
    const presented = typeof token === "string" && tokenPattern.test(token) ? await sha256Hex(token) : "";
    if (!row || hidden(row, admitInternal) || !timingSafeEqual(presented, row.pollTokenHash))
      throw operationNotFound();
    return row;
  };

  /** The row a browser addresses, once its proof or user code checks out. */
  const rowForBrowser = async (
    input: { id: string } & OperationBrowserCredential,
    admitInternal: boolean,
  ): Promise<OperationRow> => {
    const row = await findById(input.id);
    if (!row || hidden(row, admitInternal)) throw operationNotFound();
    if ("proof" in input) {
      const proof = typeof input.proof === "string" && proofPattern.test(input.proof) ? input.proof : null;
      if (!proof || !row.browserProofHash || !timingSafeEqual(await sha256Hex(proof), row.browserProofHash))
        throw invalidProof();
      return row;
    }
    const code = typeof input.userCode === "string" ? normalizeUserCode(input.userCode) : null;
    if (!code || !row.userCodeHash || !timingSafeEqual(await userCodeHash(code), row.userCodeHash))
      throw invalidProof();
    return row;
  };

  /**
   * The viewer a kind's `refusal` is shown: an interactive human session, or
   * nobody. Applied identically by `details` and `approve`, so `blockedBy` and
   * the approval's answer cannot disagree.
   */
  const interactiveViewer = (state: AuthState | null | undefined): AuthState | null =>
    state?.authenticated &&
    state.assurance === "interactive" &&
    state.credentialType === "session" &&
    state.user?.kind === "human" &&
    state.actor?.credentialId
      ? state
      : null;

  const toRecord = (row: OperationRow, now: number): OperationRecord => ({
    id: row.id,
    kind: row.kind,
    state: effectiveState(row, now),
    organizationId: row.organizationId,
    openerUserId: row.openerUserId,
    openerCredentialId: row.openerCredentialId,
    client: {
      label: row.clientLabel,
      meta: parseJson(row.clientMeta) as OperationClientMeta | null,
    },
    hasLoopbackRedirect: row.loopbackRedirect !== null,
    payload: parseJson(row.payload),
    decidedByUserId: row.decidedByUserId,
    createdAt: iso(row.createdAt),
    expiresAt: iso(row.expiresAt),
  });

  const sealLive = (row: OperationRow, now: number) =>
    row.state === "completed" &&
    row.sealedOutcome !== null &&
    row.sealedUntil !== null &&
    row.sealedUntil.getTime() > now;

  /**
   * A sealed outcome, opened. Fails as `operation_expired` when it can no
   * longer be read — `secret` changed since it was sealed — which is what it
   * is to the client: gone, ask again.
   */
  const openSealed = async (row: OperationRow & { sealedOutcome: string }): Promise<unknown> => {
    try {
      return JSON.parse(await openText(config.secret, row.id, row.sealedOutcome));
    } catch {
      throw operationExpired("This operation's outcome can no longer be read; ask again");
    }
  };

  const view = async (row: OperationRow, token: string, now: number): Promise<OperationView> => {
    const state = effectiveState(row, now);
    const pending = state === "pending";
    return {
      id: row.id,
      kind: row.kind,
      state,
      createdAt: iso(row.createdAt),
      expiresAt: iso(row.expiresAt),
      organizationId: row.organizationId,
      browserProof: pending && row.browserProofHash ? await browserProofFor(token) : null,
      userCode: pending && row.userCodeHash ? await userCodeFor(token) : null,
      record: parseJson(row.outcome),
      collect:
        sealLive(row, now) && deliverMode(row) !== "reveal" ? (row.loopbackRedirect ? "redeem" : "poll") : null,
    };
  };

  /** A view for the token holder, handing over a sealed outcome as the kind delivers it. */
  const collectingView = async (row: OperationRow, token: string, now: number): Promise<OperationView> => {
    const answer = await view(row, token, now);
    const sealed = row.sealedOutcome;
    if (answer.collect !== "poll" || sealed === null) return answer;
    await assertDeliverable(row, now);
    // Opened before anything is erased, so a seal that cannot be read is
    // reported and left for the sweep rather than lost on the way out.
    const outcome = await openSealed({ ...row, sealedOutcome: sealed });
    const opener = openerSqlForRow(row, now);

    if (deliverMode(row) === "window") {
      if (opener && !(await holds(opener))) return { ...answer, collect: null };
      return { ...answer, outcome };
    }

    // Cleared by a guarded write that names the sealed value itself, so of
    // two polls racing only the one whose write changed the row hands it over
    // — and only while the credential that opened it is still live. Only the
    // outcome goes: the seal window, which bounds replay, runs on.
    const taken = await db
      .update(operation)
      .set({ sealedOutcome: null, updatedAt: new Date(now) })
      .where(
        and(
          eq(operation.id, row.id),
          eq(operation.state, "completed"),
          eq(operation.sealedOutcome, sealed),
          sql`${operation.loopbackRedirect} is null`,
          ...(opener ? [opener] : []),
        ),
      )
      .returning({ id: operation.id });
    if (taken.length !== 1) return { ...answer, collect: null };
    return { ...answer, collect: null, outcome };
  };

  const operationGuard = alias(operation, "cf_auth_operation_guard");
  const revealOrganization = alias(tables.organization, "cf_auth_reveal_organization");

  /**
   * True while the operation is in `state` — and, if pending, inside its
   * deadline by either clock, and held by `claim` when one is given.
   */
  const stateSql = (id: string, state: "pending" | "completed", now: number, claim?: string): SQL =>
    sql`exists (select 1 from ${operation} as ${sql.identifier("cf_auth_operation_guard")}
      where ${operationGuard.id} = ${id}
        and ${operationGuard.state} = ${state}
        ${state === "pending" ? sql`and ${operationGuard.expiresAt} > ${sqliteNowMs(now)}` : sql``}
        ${claim !== undefined ? sql`and ${operationGuard.executionClaim} = ${claim}` : sql``})`;

  /**
   * The opener's authority, rechecked at write time: the credential that
   * opened the operation is still live and still carries the role and the
   * grant its kind requires to open one.
   */
  const openerSql = (kind: OperationKind, row: OperationRow, now: number): SQL | undefined => {
    if (kind.open === "public") return undefined;
    if (!row.openerUserId || !row.openerCredentialId || !row.organizationId) return sql`0`;
    return credentialAuthoritySql(tables, {
      organizationId: row.organizationId,
      userId: row.openerUserId,
      credentialId: row.openerCredentialId,
      allowedRoles: rolesAtLeast(kind.open.minRole),
      grant: openerGrant(kind),
      nowMs: now,
    });
  };

  /**
   * {@link openerSql} for a stored row, whether or not its kind is still
   * registered: a row with an opener but no known kind still needs that
   * opener's credential, at any role but with the `manage` grant. What the
   * kind asked for is gone with it, so this assumes the most it could have
   * asked — the default — rather than the least: removing a kind must never
   * release to a `read` key what the kind would have withheld from one.
   *
   * Only the delivery paths (`poll`, `redeem`) reach the fallback; `approve`,
   * `complete` and `guard` refuse an unregistered kind outright.
   */
  const openerSqlForRow = (row: OperationRow, now: number): SQL | undefined => {
    const kind = kinds.get(row.kind);
    if (kind) return openerSql(kind, row, now);
    if (!row.openerUserId) return undefined;
    if (!row.openerCredentialId || !row.organizationId) return sql`0`;
    return credentialAuthoritySql(tables, {
      organizationId: row.organizationId,
      userId: row.openerUserId,
      credentialId: row.openerCredentialId,
      allowedRoles: organizationRoles,
      grant: "manage",
      nowMs: now,
    });
  };

  /** The kind's condition for handing a sealed outcome over, or undefined when it sets none. */
  const deliverableSql = (row: OperationRow, now: number): SQL | undefined =>
    kinds.get(row.kind)?.deliverable?.({
      operation: toRecord(row, now),
      record: parseJson(row.outcome),
      tables,
      now,
    });

  /**
   * Drops a sealed outcome that is no longer deliverable, so nothing asks
   * again, and says so. Only the very ciphertext that was judged, on a row
   * still completed: an outcome sealed afresh by `amend` meanwhile is a
   * different one, and is left alone. The seal window runs on, so `execute`
   * still replays the record through it.
   */
  const dropUndeliverable = async (id: string, sealed: string, now: number): Promise<never> => {
    await db
      .update(operation)
      .set({ sealedOutcome: null, redeemCodeHash: null, updatedAt: new Date(now) })
      .where(
        and(eq(operation.id, id), eq(operation.state, "completed"), eq(operation.sealedOutcome, sealed)),
      );
    throw operationExpired("This operation's outcome is no longer valid");
  };

  /**
   * Refuses to release a sealed outcome the kind no longer considers
   * deliverable, and drops it so nothing asks again.
   */
  const assertDeliverable = async (row: OperationRow, now: number) => {
    const condition = deliverableSql(row, now);
    if (!condition || row.sealedOutcome === null || (await holds(condition))) return;
    await dropUndeliverable(row.id, row.sealedOutcome, now);
  };

  /** Whether a condition holds right now, for a read that has no write to carry it. */
  const holds = async (condition: SQL) =>
    // `all` rather than `get`: drizzle's libsql `get` throws on an empty result.
    (await db.all<{ ok: number }>(sql`select 1 as ok where ${condition}`)).length > 0;

  /** The statements' own outcome: the last one must have changed a row. */
  const lastChanged = (statements: readonly unknown[]) =>
    // A D1 or libsql batch is one transaction on one connection, so
    // `changes()` is the row count of the statement right before this one.
    statements.length > 0 ? [sql`changes() > 0`] : [];

  /**
   * The statement that makes a refused write abort its whole batch. It goes
   * right after the guarded write it vouches for, and inserts a row only when
   * that write changed none (`changes() = 0`) — a row of nulls, which the
   * primary key's NOT NULL always refuses. The error rolls back every
   * statement before it, so a caller's statements never outlive a completion
   * that did not land, even one whose statements deleted the operation
   * itself. A D1 batch, like a libsql one, rolls back on an error and on
   * nothing less.
   */
  const assertLanded = () => guardedInsert(db, operation, {}, sql`changes() = 0`);

  const refusalMessage = `NOT NULL constraint failed: ${getTableName(operation)}.id`;
  /** Whether a batch failed on {@link assertLanded}, wrapped by however many layers the driver adds. */
  const isRefusedLanding = (error: unknown): boolean => {
    for (let current = error, depth = 0; current && depth < 8; depth += 1) {
      const message = (current as { message?: unknown }).message;
      if (typeof message === "string" && message.includes(refusalMessage)) return true;
      current = (current as { cause?: unknown }).cause;
    }
    return false;
  };

  /**
   * Runs `statements`, then `write`, then {@link assertLanded}, as one batch.
   * Answers whether `write` changed a row; when it did not, nothing in the
   * batch was kept.
   */
  const runGuarded = async (statements: readonly unknown[], write: unknown): Promise<boolean> => {
    let results: unknown[];
    try {
      results = await runBatch(db, [...statements, write, assertLanded()]);
    } catch (error) {
      if (isRefusedLanding(error)) return false;
      throw error;
    }
    const landed = results.at(-2);
    return Array.isArray(landed) && landed.length === 1;
  };

  /**
   * `retain_until` moved out to at least `until`, so the sweep cannot delete a
   * record while a seal on it — and the replay it bounds — is still live.
   */
  const retainThrough = (until: Date): SQL => sql`max(${operation.retainUntil}, ${until.getTime()})`;

  /**
   * Completes the operation in one batch with the statements that carry it
   * out. Answers whether this call is the one that completed it.
   */
  const commit = async (
    row: OperationRow,
    input: {
      outcome: unknown;
      seal: boolean;
      record: unknown;
      statements: readonly unknown[];
      guard: SQL;
      organizationId: string | null;
      /** Who decided it; SQL for one that may have been deleted meanwhile. */
      decidedByUserId: string | SQL | null;
      redeemCodeHash: string | null;
      /** The execution claim the completion must still find, which it then clears. */
      claim?: string;
      now: number;
    },
  ): Promise<boolean> => {
    const sealed = input.seal
      ? await sealText(config.secret, row.id, JSON.stringify(input.outcome ?? null))
      : null;
    const sealedUntil = sealed ? new Date(input.now + settings.sealTtlMs) : null;
    const stored = input.seal
      ? input.record === undefined
        ? null
        : JSON.stringify(input.record)
      : JSON.stringify(input.outcome ?? null);
    const completion = db
      .update(operation)
      .set({
        state: "completed",
        organizationId: input.organizationId,
        outcome: stored,
        sealedOutcome: sealed,
        sealedUntil,
        redeemCodeHash: input.redeemCodeHash,
        decidedByUserId: input.decidedByUserId,
        executionClaim: null,
        updatedAt: new Date(input.now),
        ...(sealedUntil ? { retainUntil: retainThrough(sealedUntil) } : {}),
      })
      .where(
        and(
          eq(operation.id, row.id),
          eq(operation.state, "pending"),
          ...(input.claim !== undefined ? [eq(operation.executionClaim, input.claim)] : []),
          input.guard,
          ...lastChanged(input.statements),
        ),
      )
      .returning({ id: operation.id });
    return runGuarded(input.statements, completion);
  };

  /** Explains a guarded write that changed nothing. */
  const explainRefusedWrite = async (id: string, now: number): Promise<never> => {
    const current = await findById(id);
    if (!current) throw operationNotFound();
    assertPending(current, now);
    throw conflict(
      "The operation could not be completed because its authority changed; ask again",
    );
  };

  const sweepStatements = (now = Date.now()): OperationSweepStatements => {
    const at = new Date(now);
    return [
      db
        .update(operation)
        .set({ state: "expired", updatedAt: at })
        .where(and(eq(operation.state, "pending"), lte(operation.expiresAt, at))),
      db
        .update(operation)
        .set({ sealedOutcome: null, sealedUntil: null, redeemCodeHash: null, updatedAt: at })
        .where(lte(operation.sealedUntil, at)),
      db.delete(operation).where(lte(operation.retainUntil, at)),
    ] as unknown as OperationSweepStatements;
  };

  const afterCommit = async (hook: (() => void | Promise<void>) | undefined) => {
    if (!hook) return;
    try {
      await hook();
    } catch (error) {
      config.onError(error, { scope: "operations.afterCommit" });
    }
  };

  /**
   * Holds a caller to what a kind asks of its opener — the role in its current
   * organization, the grant, a live credential, an organization in time — and
   * answers what the row binds.
   */
  const bindOpener = (
    kind: OperationKind & { open: { minRole: OrganizationRole } },
    opener: AuthState | null | undefined,
  ) => {
    if (!opener) throw unauthorized();
    const { user, organization } = requireOrganization(opener, kind.open.minRole);
    if (!hasGrantAtLeast(opener.grant, openerGrant(kind))) throw grantInsufficient();
    const credentialId = opener.actor?.credentialId;
    if (!user || !credentialId) throw unauthorized();
    if (isOrganizationExpired(organization)) throw organizationExpired();
    return {
      openerUserId: user.id,
      openerCredentialId: credentialId,
      organizationId: organization.id,
      openerKey: `user:${user.id}`,
    };
  };

  /**
   * The pending caps a new row of this kind must fit under, as the condition of
   * its insert, so two openers racing for the last slot cannot both take it.
   * Only rows of kinds that count take a slot; a kind that does not count is
   * not held to the caps either.
   */
  const pendingCaps = (
    kind: OperationKind,
    organizationId: string | null,
    openerKey: string | null,
    now: number,
  ): SQL => {
    if (!countsTowardPending(kind)) return sql`1`;
    const cap = alias(operation, "cf_auth_operation_cap");
    const counting = sql.join(
      countingKinds.map((name) => sql`${name}`),
      sql`, `,
    );
    const pendingBelow = (column: SQL, value: string, limit: number) =>
      sql`(select count(*) from ${operation} as ${sql.identifier("cf_auth_operation_cap")}
        where ${column} = ${value} and ${cap.state} = 'pending' and ${cap.expiresAt} > ${now}
          and ${cap.kind} in (${counting})) < ${limit}`;
    const caps = [
      ...(organizationId
        ? [pendingBelow(sql`${cap.organizationId}`, organizationId, settings.limits.pendingPerOrganization)]
        : []),
      ...(openerKey ? [pendingBelow(sql`${cap.openerKey}`, openerKey, settings.limits.pendingPerOpener)] : []),
    ];
    return caps.length > 0 ? and(...caps)! : sql`1`;
  };

  /**
   * Answers a completed execution again, without running anything: its
   * record, never its sealed outcome, for as long as the seal window lasts
   * (`sealed_until`). A reveal spends the sealed outcome but leaves the
   * window, so the record is replayed through it either way.
   */
  const replayExecution = (row: OperationRow, now: number): ExecutedOperation<never> => {
    if (row.sealedUntil === null || row.sealedUntil.getTime() <= now) {
      throw alreadyCompleted("This operation has already been executed and its replay window has passed");
    }
    return { id: row.id, state: "completed", record: parseJson(row.outcome), replayed: true };
  };

  /** Whether a stored kind can be reserved and executed: one a caller opens, with no browser step. */
  const assertReservable = (kind: OperationKind, what: "reserved" | "executed") => {
    if (kind.open === "public" || kind.browser) {
      throw validationError(
        `Operation kind \`${kind.name}\` cannot be ${what}: only a kind a caller opens, with no browser step, can`,
      );
    }
    return { ...kind, open: kind.open };
  };

  /**
   * One door onto the engine. `cfAuth.operations` is the one that does not
   * admit internal kinds; cf-auth's own flows hold the one that does.
   */
  const door = (admitInternal: boolean): CfAuthOperations => {
    /** A kind `open` or `reserve` may start through this door. */
    const startableKind = (name: string): OperationKind => {
      if (!admitInternal && typeof name === "string" && isInternalOperationKind(name)) {
        throw validationError(`Operation kind \`${name}\` is internal to cf-auth and cannot be started here`);
      }
      return kindOf(name);
    };

    /** The row an id names through this door, or `404`. */
    const visibleRow = async (id: string): Promise<OperationRow> => {
      const row = await findById(id);
      if (!row || hidden(row, admitInternal)) throw operationNotFound();
      return row;
    };

    return {
      kinds: admitInternal
        ? kinds
        : new Map([...kinds].filter(([name]) => !isInternalOperationKind(name))),

      async open(input) {
        requireEnabled();
        const kind = startableKind(input.kind);
        if (typeof input.token !== "string" || !tokenPattern.test(input.token)) {
          throw validationError("The operation token must be 32–256 base64url characters");
        }
        if (input.id !== undefined && (typeof input.id !== "string" || !idPattern.test(input.id))) {
          throw validationError(
            "An operation id is 1–128 letters, digits, `:`, `_`, `.` or `-`",
          );
        }
        const payload = parsePayload(kind, input.payload);

        const label = clientText(input.client?.label, "client.label") ?? null;
        if (kind.requireClientLabel && !label) throw validationError("client.label is required");
        if (label && label.length > 200) throw validationError("client.label is too long");
        const rawMeta = input.client?.meta ?? null;
        const meta: OperationClientMeta = {};
        if (rawMeta) {
          const os = clientText(rawMeta.os, "client.meta.os");
          const ip = clientText(rawMeta.ip, "client.meta.ip");
          const userAgent = clientText(rawMeta.userAgent, "client.meta.userAgent");
          if (os) meta.os = os;
          if (ip) meta.ip = ip;
          if (userAgent) meta.userAgent = userAgent;
        }
        const metaJson = Object.keys(meta).length > 0 ? JSON.stringify(meta) : null;
        const loopback = input.client?.loopbackRedirect
          ? normalizeLoopbackRedirect(input.client.loopbackRedirect)
          : null;
        if (loopback && !kind.browser) {
          throw validationError("A loopback redirect needs a kind with a browser step");
        }

        let openerUserId: string | null = null;
        let openerCredentialId: string | null = null;
        let organizationId: string | null = null;
        if (
          input.rateLimitKey !== undefined &&
          input.rateLimitKey !== null &&
          (typeof input.rateLimitKey !== "string" || input.rateLimitKey.length > 256)
        ) {
          throw validationError("rateLimitKey must be a string of at most 256 characters");
        }
        // Only what the app vouches for: `client.meta` is the client's own say-so.
        let openerKey: string | null = input.rateLimitKey ? `key:${input.rateLimitKey}` : null;
        if (kind.open !== "public") {
          ({ openerUserId, openerCredentialId, organizationId, openerKey } = bindOpener(
            { ...kind, open: kind.open },
            input.opener,
          ));
        }

        const now = Date.now();
        const id = input.id ?? crypto.randomUUID();
        const pollTokenHash = await sha256Hex(input.token);
        const requestHash = await sha256Hex(
          JSON.stringify([kind.name, payload, openerUserId, organizationId]),
        );
        const browserProofHash = kind.browser ? await sha256Hex(await browserProofFor(input.token)) : null;
        const userCode = kind.browser && kind.userCode ? await userCodeFor(input.token) : null;
        const codeHash = userCode ? await userCodeHash(normalizeUserCode(userCode)!) : null;

        // Guarded by the caps, so they are judged by the insert itself: two
        // clients racing for the last slot cannot both take it. The conflict
        // clause covers a retry racing on the same token, which then finds the
        // row the other one wrote.
        await guardedInsert(
          db,
          operation,
          {
            id,
            kind: kind.name,
            state: "pending",
            openerUserId,
            openerCredentialId,
            organizationId,
            openerKey,
            requestHash,
            pollTokenHash,
            browserProofHash,
            userCodeHash: codeHash,
            userCodeSealed: userCode
              ? await sealText(config.secret, userCodeContext(id), userCode)
              : null,
            clientLabel: label,
            clientMeta: metaJson,
            loopbackRedirect: loopback,
            payload,
            createdAt: new Date(now),
            updatedAt: new Date(now),
            expiresAt: new Date(now + pendingTtl(kind)),
            retainUntil: new Date(now + recordTtl(kind)),
          },
          pendingCaps(kind, organizationId, openerKey, now),
        ).onConflictDoNothing();

        const row = await findByTokenHash(pollTokenHash);
        if (!row) {
          if (input.id !== undefined && (await findById(input.id))) {
            throw conflict("This operation id is already in use");
          }
          if (
            codeHash &&
            (await db
              .select({ id: operation.id })
              .from(operation)
              .where(and(eq(operation.userCodeHash, codeHash), eq(operation.state, "pending")))
              .get())
          ) {
            throw conflict("This token's user code is taken; open the operation with a new token");
          }
          throw tooManyPending();
        }
        // Judged on the row as stored: of two requests racing on one token, the
        // one whose insert was ignored must not pass for the one that landed.
        if (
          row.kind !== kind.name ||
          row.requestHash !== requestHash ||
          (input.id !== undefined && row.id !== input.id)
        ) {
          throw conflict("This operation token is already bound to a different request");
        }
        // A retry is answered as a poll would be, so a client whose response
        // was lost recovers a completed operation the same way either way.
        return collectingView(row, input.token, now);
      },

      async poll(input) {
        requireEnabled();
        const row = await rowForToken(input.id, input.token, admitInternal);
        return collectingView(row, input.token, Date.now());
      },

      async findByToken(input) {
        requireEnabled();
        if (typeof input.token !== "string" || !tokenPattern.test(input.token)) return null;
        const row = await findByTokenHash(await sha256Hex(input.token));
        return row && !hidden(row, admitInternal) ? view(row, input.token, Date.now()) : null;
      },

      async details(input) {
        requireEnabled();
        const row = await rowForBrowser(input, admitInternal);
        const kind = kindOf(row.kind);
        const now = Date.now();
        const record = toRecord(row, now);
        const viewer = interactiveViewer(input.viewer);
        let userCode: string | null = null;
        if (row.userCodeSealed) {
          try {
            userCode = await openText(config.secret, userCodeContext(row.id), row.userCodeSealed);
          } catch {
            // `secret` changed since it was sealed. The page still works; it
            // just cannot echo the code the terminal shows.
            userCode = null;
          }
        }
        return {
          id: row.id,
          kind: row.kind,
          state: record.state,
          payload: kind.showPayload ? kind.showPayload(record.payload) : record.payload,
          client: record.client,
          organization: row.organizationId ? await repository.findOrganization(row.organizationId) : null,
          viewer: viewer ? { user: viewer.user!, memberships: viewer.memberships } : null,
          userCode,
          approver: approverMode(kind),
          takesInput: kind.input !== undefined,
          createdAt: record.createdAt,
          expiresAt: record.expiresAt,
          hasLoopbackRedirect: record.hasLoopbackRedirect,
          blockedBy:
            record.state === "pending" && kind.refusal
              ? await kind.refusal({ operation: record, payload: record.payload, viewer })
              : null,
        };
      },

      async approve(input) {
        requireEnabled();
        const row = await rowForBrowser(input, admitInternal);
        const kind = kindOf(row.kind);
        const now = Date.now();
        assertPending(row, now);
        const mode = approverMode(kind);
        if (mode === "proof" && !("proof" in input)) {
          throw invalidProof("This operation is approved with its browser proof, not a user code");
        }
        const submitted = parseInput(kind, input.input);
        const record = toRecord(row, now);
        const requested = input.organizationId ?? null;
        if (row.organizationId && requested && requested !== row.organizationId) {
          throw forbidden("This operation belongs to another organization");
        }

        let actor: AuthState | null = null;
        let user: AuthUser | null = null;
        let membership: OrganizationMembership | null = null;
        let organizationId = row.organizationId;
        let approverSql: SQL | undefined;

        if (mode === "proof" && !row.organizationId && requested) {
          // Nobody signed in to vouch for a membership, so there is no
          // organization this approval could be allowed to choose.
          throw validationError("A proof-approved operation cannot be approved into an organization");
        }

        if (mode === "session") {
          const { userId, sessionId } = requireInteractiveSession(input.actor ?? createEmptyAuthState());
          actor = input.actor!;
          user = actor.user;
          organizationId = row.organizationId ?? requested;
          const minRole = approverMinRole(kind);
          if (minRole !== null && !organizationId) {
            throw validationError("organizationId is required to approve this operation");
          }
          // Any organization the approval acts in — fixed by the opener or
          // chosen here — must be one the approver belongs to: with the kind's
          // role, or any role when it names none. That is also what keeps an id
          // nobody holds from reaching the foreign key.
          const allowedRoles = minRole === null ? organizationRoles : rolesAtLeast(minRole);
          if (organizationId && (minRole !== null || !row.organizationId)) {
            membership = await repository.findMembership(userId, organizationId);
            if (!membership || !allowedRoles.includes(membership.role)) {
              throw new CfAuthError(
                "not_a_member",
                minRole === null
                  ? "Approving needs a membership in this organization"
                  : `Approving needs the ${minRole} role or higher in this organization`,
                403,
              );
            }
            if (isOrganizationExpired(membership.organization)) throw organizationExpired();
            approverSql = credentialAuthoritySql(tables, {
              organizationId,
              userId,
              credentialId: sessionId,
              allowedRoles,
              nowMs: now,
            });
          } else {
            approverSql = liveHumanSessionSql(tables, { userId, sessionId, nowMs: now });
          }
        }

        const refusal = kind.refusal
          ? await kind.refusal({ operation: record, payload: record.payload, viewer: interactiveViewer(input.actor) })
          : null;
        if (refusal) {
          throw new CfAuthError(refusal, "This operation cannot be approved from this session", 403);
        }

        const opener = openerSql(kind, row, now);
        const guard = and(
          stateSql(row.id, "pending", now),
          ...(approverSql ? [approverSql] : []),
          ...(opener ? [opener] : []),
        )!;

        const result: OperationApproveResult = kind.approve
          ? await kind.approve({
              operation: record,
              payload: record.payload,
              input: submitted,
              actor,
              user,
              organizationId,
              membership,
              guard,
              db,
              tables,
              now,
            })
          : { outcome: null };

        const redeemCode = row.loopbackRedirect ? randomToken(32) : null;
        const completed = await commit(row, {
          outcome: result.outcome,
          seal: result.seal ?? false,
          record: result.record,
          statements: result.statements ?? [],
          guard,
          organizationId,
          decidedByUserId: user?.id ?? null,
          redeemCodeHash: redeemCode ? await sha256Hex(redeemCode) : null,
          now,
        });
        if (!completed) await explainRefusedWrite(row.id, now);
        await afterCommit(result.afterCommit);

        let redirectUrl: string | null = null;
        if (row.loopbackRedirect && redeemCode) {
          const url = new URL(row.loopbackRedirect);
          url.searchParams.set("code", redeemCode);
          redirectUrl = url.toString();
        }
        return {
          id: row.id,
          kind: row.kind,
          state: "completed",
          organizationId,
          redeemCode,
          redirectUrl,
        };
      },

      async deny(input) {
        requireEnabled();
        const row = await rowForBrowser(input, admitInternal);
        if (approverMode(kindOf(row.kind)) === "proof" && !("proof" in input)) {
          throw invalidProof("This operation is answered with its browser proof, not a user code");
        }
        const now = Date.now();
        if (row.state === "denied") return { id: row.id, kind: row.kind, state: "denied" };
        assertPending(row, now);
        const actor = input.actor;
        const decidedBy =
          actor?.authenticated && actor.assurance === "interactive" && actor.user?.kind === "human"
            ? actor.user.id
            : null;
        const denied = await db
          .update(operation)
          .set({ state: "denied", decidedByUserId: decidedBy, updatedAt: new Date(now) })
          .where(and(eq(operation.id, row.id), stateSql(row.id, "pending", now)))
          .returning({ id: operation.id });
        if (denied.length !== 1) {
          const current = await findById(row.id);
          if (current?.state === "denied") return { id: row.id, kind: row.kind, state: "denied" };
          await explainRefusedWrite(row.id, now);
        }
        return { id: row.id, kind: row.kind, state: "denied" };
      },

      async redeem(input) {
        requireEnabled();
        const row = await rowForToken(input.id, input.token, admitInternal);
        const now = Date.now();
        switch (effectiveState(row, now)) {
          case "pending":
            throw operationPending();
          case "denied":
            throw operationDenied();
          case "expired":
          case "retired":
            throw operationExpired();
          case "completed":
            break;
        }
        if (!row.redeemCodeHash || deliverMode(row) === "reveal") {
          throw alreadyCompleted(
            "This operation's outcome has already been collected or is no longer available",
          );
        }
        const code = typeof input.redeemCode === "string" ? input.redeemCode : "";
        if (!tokenPattern.test(code) || !timingSafeEqual(await sha256Hex(code), row.redeemCodeHash)) {
          throw invalidProof("The redeem code does not match this operation");
        }
        const sealed = row.sealedOutcome;
        if (sealed !== null && !sealLive(row, now)) {
          throw operationExpired("This operation's outcome is no longer available");
        }
        if (sealed !== null) await assertDeliverable(row, now);
        // Opened before anything is spent, so a seal that cannot be read is
        // reported rather than consumed.
        const answer = {
          id: row.id,
          kind: row.kind,
          organizationId: row.organizationId,
          outcome: sealed !== null ? await openSealed({ ...row, sealedOutcome: sealed }) : parseJson(row.outcome),
        };
        const opener = openerSqlForRow(row, now);
        const openerGone = () =>
          operationExpired("The credential that opened this operation is no longer valid");
        if (deliverMode(row) === "window") {
          if (opener && !(await holds(opener))) throw openerGone();
          return answer;
        }

        const taken = await db
          .update(operation)
          .set({ redeemCodeHash: null, sealedOutcome: null, updatedAt: new Date(now) })
          .where(
            and(
              eq(operation.id, row.id),
              eq(operation.state, "completed"),
              eq(operation.redeemCodeHash, row.redeemCodeHash),
              ...(opener ? [opener] : []),
            ),
          )
          .returning({ id: operation.id });
        if (taken.length !== 1) {
          if (opener && !(await holds(opener))) throw openerGone();
          throw alreadyCompleted("This operation's outcome has already been collected");
        }
        return answer;
      },

      async lookupByUserCode(input) {
        requireEnabled();
        const code = typeof input.userCode === "string" ? normalizeUserCode(input.userCode) : null;
        if (!code) return null;
        const hash = await userCodeHash(code);
        const row = await db
          .select()
          .from(operation)
          .where(and(eq(operation.userCodeHash, hash), eq(operation.state, "pending")))
          .get();
        const now = Date.now();
        if (!row?.userCodeHash || !timingSafeEqual(hash, row.userCodeHash)) return null;
        if (hidden(row, admitInternal)) return null;
        if (effectiveState(row, now) !== "pending") return null;
        return { id: row.id, kind: row.kind, expiresAt: iso(row.expiresAt) };
      },

      async guard(input) {
        requireEnabled();
        const row = await visibleRow(input.id);
        const now = Date.now();
        const opener = openerSql(kindOf(row.kind), row, now);
        return and(stateSql(row.id, input.state ?? "pending", now), ...(opener ? [opener] : []))!;
      },

      async complete(input) {
        requireEnabled();
        const row = await visibleRow(input.id);
        const kind = kindOf(row.kind);
        if (kind.browser) {
          throw validationError(`Operation kind \`${kind.name}\` is completed by approving it in a browser`);
        }
        const now = Date.now();
        assertPending(row, now);
        const opener = openerSql(kind, row, now);
        const completed = await commit(row, {
          outcome: input.outcome,
          seal: input.seal ?? false,
          record: input.record,
          statements: input.statements ?? [],
          guard: and(stateSql(row.id, "pending", now), ...(opener ? [opener] : []))!,
          organizationId: row.organizationId,
          decidedByUserId: null,
          redeemCodeHash: null,
          now,
        });
        if (!completed) await explainRefusedWrite(row.id, now);
        const current = (await findById(row.id))!;
        return {
          id: current.id,
          kind: current.kind,
          state: effectiveState(current, now),
          createdAt: iso(current.createdAt),
          expiresAt: iso(current.expiresAt),
          organizationId: current.organizationId,
          browserProof: null,
          userCode: null,
          record: parseJson(current.outcome),
          collect: sealLive(current, now) && deliverMode(current) !== "reveal" ? "poll" : null,
        };
      },

      async amend(input) {
        requireEnabled();
        const row = await visibleRow(input.id);
        switch (effectiveState(row, Date.now())) {
          case "pending":
            throw operationPending();
          case "denied":
            throw operationDenied();
          case "expired":
          case "retired":
            throw operationExpired();
          case "completed":
            break;
        }
        const seal = input.seal ?? false;
        if (input.outcome !== undefined && !seal && input.record !== undefined) {
          throw validationError("An unsealed outcome is the record; pass one or the other");
        }
        const now = Date.now();
        const changes: { [Column in keyof OperationRow]?: OperationRow[Column] | SQL } = {
          updatedAt: new Date(now),
        };
        if (input.outcome !== undefined) {
          if (seal) {
            changes.sealedOutcome = await sealText(config.secret, row.id, JSON.stringify(input.outcome ?? null));
            const sealedUntil = new Date(now + settings.sealTtlMs);
            changes.sealedUntil = sealedUntil;
            changes.retainUntil = retainThrough(sealedUntil);
            // A loopback redirect's redeem code went with the first outcome, so
            // a new one is collected by polling instead.
            changes.loopbackRedirect = null;
            changes.redeemCodeHash = null;
          } else {
            changes.outcome = JSON.stringify(input.outcome ?? null);
          }
        }
        if (input.record !== undefined) changes.outcome = JSON.stringify(input.record);
        const statements = input.statements ?? [];
        const amendment = db
          .update(operation)
          .set(changes)
          .where(
            and(
              eq(operation.id, row.id),
              eq(operation.state, "completed"),
              ...(input.condition ? [input.condition] : []),
              ...lastChanged(statements),
            ),
          )
          .returning({ id: operation.id });
        return runGuarded(statements, amendment);
      },

      async retire(input) {
        requireEnabled();
        const retired = await db
          .update(operation)
          .set({
            state: "retired",
            sealedOutcome: null,
            sealedUntil: null,
            redeemCodeHash: null,
            updatedAt: new Date(),
          })
          .where(
            and(
              eq(operation.id, input.id),
              ne(operation.state, "retired"),
              ...(!admitInternal
                ? [
                    sql`substr(${operation.kind}, 1, ${internalOperationKindPrefix.length}) <> ${internalOperationKindPrefix}`,
                  ]
                : []),
            ),
          )
          .returning({ id: operation.id });
        return retired.length === 1;
      },

      sweepStatements,

      async sweep(now) {
        requireEnabled();
        await runBatch(db, sweepStatements(now));
      },

      async status(input) {
        requireEnabled();
        const opener = input.opener;
        const organizationId =
          opener?.authenticated && opener.role ? (opener.organization?.id ?? null) : null;
        const row = await findById(input.id);
        // One answer for every way it is not yours to see, so it discloses
        // nothing — not even that the id exists.
        if (
          !row ||
          hidden(row, admitInternal) ||
          row.organizationId === null ||
          row.organizationId !== organizationId
        ) {
          throw operationNotFound();
        }
        return {
          id: row.id,
          kind: row.kind,
          state: effectiveState(row, Date.now()),
          createdAt: iso(row.createdAt),
          expiresAt: iso(row.expiresAt),
          organizationId: row.organizationId,
          record: parseJson(row.outcome),
        };
      },

      async reserve(input) {
        requireEnabled();
        const kind = assertReservable(startableKind(input.kind), "reserved");
        const bound = bindOpener(kind, input.opener);
        const payload = parsePayload(kind, input.input);
        const now = Date.now();
        const id = crypto.randomUUID();
        // Made here, never by the caller: holding it is the whole authority to
        // execute, so it must be as unguessable as an operation token.
        const handle = randomToken(32);
        const expiresAt = new Date(now + settings.reserveTtlMs);
        const inserted = await guardedInsert(
          db,
          operation,
          {
            id,
            kind: kind.name,
            state: "pending",
            ...bound,
            requestHash: await sha256Hex(
              JSON.stringify([kind.name, payload, bound.openerUserId, bound.organizationId]),
            ),
            pollTokenHash: await sha256Hex(handle),
            payload,
            createdAt: new Date(now),
            updatedAt: new Date(now),
            expiresAt,
            // Never shorter than the reservation itself, so a pending one is
            // not swept away before it lapses.
            retainUntil: new Date(now + Math.max(recordTtl(kind), settings.reserveTtlMs)),
          },
          pendingCaps(kind, bound.organizationId, bound.openerKey, now),
        ).returning({ id: operation.id });
        if (inserted.length !== 1) throw tooManyPending();
        return { id, handle, expiresAt: iso(expiresAt) };
      },

      async execute<Outcome = unknown>(
        input: ExecuteOperationInput,
        fn: ExecuteOperationFunction<unknown, Outcome>,
      ): Promise<ExecutedOperation<Outcome>> {
        requireEnabled();
        const caller = input.opener;
        if (!caller?.authenticated) throw unauthorized();
        const handle = typeof input.handle === "string" && tokenPattern.test(input.handle) ? input.handle : null;
        const row = handle ? await findByTokenHash(await sha256Hex(handle)) : null;
        if (!row || hidden(row, admitInternal)) throw operationNotFound();
        if (
          row.kind !== input.kind ||
          row.organizationId === null ||
          row.organizationId !== caller.organization?.id
        ) {
          throw operationMismatch();
        }
        const kind = assertReservable(kindOf(row.kind), "executed");
        // The caller is held to what reserving asked; the guard below then
        // holds the credential that reserved it, at write time.
        const executor = bindOpener(kind, caller);
        const now = Date.now();
        switch (effectiveState(row, now)) {
          case "expired":
          case "retired":
            throw operationExpired();
          case "denied":
            throw operationDenied();
          case "completed":
            return replayExecution(row, now);
          case "pending":
            break;
        }

        // Claimed before `fn` runs, so of two calls racing on one handle only
        // one ever runs it. The claim is a random value of this call's own,
        // which the guard, the completion and the release all require: nothing
        // but this call finishing or giving it back unlocks the reservation —
        // not even deleting the user who executes it.
        const claim = randomToken(32);
        const claimed = await db
          .update(operation)
          .set({ executionClaim: claim, updatedAt: new Date(now) })
          .where(
            and(
              eq(operation.id, row.id),
              eq(operation.state, "pending"),
              isNull(operation.executionClaim),
              sql`${operation.expiresAt} > ${sqliteNowMs(now)}`,
            ),
          )
          .returning({ id: operation.id });
        if (claimed.length !== 1) {
          const current = (await findById(row.id)) ?? row;
          const state = effectiveState(current, now);
          if (state === "completed") return replayExecution(current, now);
          if (state === "pending" && current.executionClaim !== null) {
            throw conflict("This operation is being executed; ask again shortly");
          }
          assertPending(current, now);
          throw operationExpired();
        }
        /** Gives the claim back when this execution did not complete, so the handle can be tried again. */
        const release = async () => {
          try {
            await db
              .update(operation)
              .set({ executionClaim: null })
              .where(
                and(
                  eq(operation.id, row.id),
                  eq(operation.state, "pending"),
                  eq(operation.executionClaim, claim),
                ),
              );
          } catch (error) {
            config.onError(error, { scope: "operations.execute" });
          }
        };

        const opener = openerSql(kind, row, now);
        const guard = and(stateSql(row.id, "pending", now, claim), ...(opener ? [opener] : []))!;
        let result: OperationApproveResult<Outcome>;
        let completed: boolean;
        try {
          result = await fn({
            operation: toRecord(row, now),
            input: parseJson(row.payload),
            guard,
            db,
            tables,
            now,
          });
          completed = await commit(row, {
            outcome: result.outcome,
            seal: true,
            record: result.record,
            statements: result.statements ?? [],
            guard,
            organizationId: row.organizationId,
            // Attribution only, and only while that user still exists: one
            // deleted mid-execution leaves it null rather than failing the
            // foreign key and, with it, a write its claim still covers.
            decidedByUserId: sql`(select ${tables.user.id} from ${tables.user} where ${tables.user.id} = ${executor.openerUserId})`,
            redeemCodeHash: null,
            claim,
            now,
          });
        } catch (error) {
          await release();
          throw error;
        }
        if (!completed) {
          await release();
          await explainRefusedWrite(row.id, now);
        }
        await afterCommit(result.afterCommit);
        return {
          id: row.id,
          state: "completed",
          record: result.record === undefined ? null : result.record,
          outcome: result.outcome,
          replayed: false,
        };
      },

      async reveal(input) {
        requireEnabled();
        const { userId, sessionId } = requireInteractiveSession(input.actor ?? createEmptyAuthState());
        const row = await findById(input.id);
        if (!row || hidden(row, admitInternal) || row.organizationId === null) throw operationNotFound();
        const organizationId = row.organizationId;
        // Someone outside the organization learns nothing, not even that it exists.
        const membership = await repository.findMembership(userId, organizationId);
        if (!membership) throw operationNotFound();
        if (!hasRoleAtLeast(membership.role, "admin")) {
          throw forbidden("Revealing needs the admin role or higher in this organization");
        }
        if (isOrganizationExpired(membership.organization)) throw organizationExpired();
        const kind = kindOf(row.kind);
        if (kind.browser) {
          throw validationError(
            `Operation kind \`${kind.name}\` hands its outcome to its client; it cannot be revealed`,
          );
        }
        const now = Date.now();
        switch (effectiveState(row, now)) {
          case "pending":
            throw operationPending();
          case "denied":
            throw operationDenied();
          case "expired":
          case "retired":
            throw operationExpired();
          case "completed":
            break;
        }
        const sealed = row.sealedOutcome;
        // Whatever consumes the sealed outcome — a reveal, a `once` poll, an
        // undeliverable cleanup — drops it but leaves `sealed_until`, so a
        // reveal after it inside the window is told apart from one that never
        // had anything to reveal, and `execute` keeps replaying the record
        // through the window; the sweep clears it with the window.
        const revealedAlready = (current: OperationRow) =>
          current.sealedOutcome === null && current.sealedUntil !== null && current.sealedUntil.getTime() > now;
        if (sealed === null) {
          if (revealedAlready(row)) throw alreadyRevealed();
          throw operationExpired("This operation holds no outcome to reveal");
        }
        if (!sealLive(row, now)) throw operationExpired("This operation's outcome is no longer available");
        // Opened before anything is spent, so a seal that cannot be read is
        // reported rather than consumed.
        const outcome = await openSealed({ ...row, sealedOutcome: sealed });
        // The person is the authority here, not the credential that opened
        // the operation: a key downgraded or revoked since does not stop an
        // admin from collecting what it created.
        const revealer = credentialAuthoritySql(tables, {
          organizationId,
          userId,
          credentialId: sessionId,
          allowedRoles: rolesAtLeast("admin"),
          nowMs: now,
        });
        const deliverable = deliverableSql(row, now);
        // The organization exists and is not past its deadline, by either
        // clock: `expires_at` is ISO text, read as epoch milliseconds here.
        const organizationLive = sql`exists (select 1 from ${tables.organization} as ${sql.identifier("cf_auth_reveal_organization")}
          where ${revealOrganization.id} = ${organizationId}
            and (${revealOrganization.expiresAt} is null
              or cast(unixepoch(${revealOrganization.expiresAt}, 'subsec') * 1000 as integer) > ${sqliteNowMs(now)}))`;
        // Every condition rides on the write that takes the outcome — the
        // seal's deadline by the database's clock too — so of two reveals
        // racing only one hands it over, and nothing that stopped holding
        // after it was read above slips through.
        const taken = await db
          .update(operation)
          .set({ sealedOutcome: null, updatedAt: new Date(now) })
          .where(
            and(
              eq(operation.id, row.id),
              eq(operation.state, "completed"),
              eq(operation.sealedOutcome, sealed),
              sql`${operation.sealedUntil} > ${sqliteNowMs(now)}`,
              organizationLive,
              revealer,
              ...(deliverable ? [deliverable] : []),
            ),
          )
          .returning({ id: operation.id });
        if (taken.length !== 1) {
          const current = await findById(row.id);
          if (!current) throw operationNotFound();
          if (current.state !== "completed") throw operationExpired();
          if (current.sealedOutcome === null) {
            if (revealedAlready(current)) throw alreadyRevealed();
            throw operationExpired("This operation's outcome is no longer available");
          }
          if (current.sealedOutcome !== sealed) {
            // `amend` sealed a new outcome meanwhile. It is not this call's to
            // judge or to drop; the next reveal reads it afresh.
            throw conflict("This operation's outcome changed while it was being revealed; reveal it again");
          }
          if (!(await holds(organizationLive))) throw organizationExpired();
          if (deliverable && !(await holds(deliverable))) await dropUndeliverable(row.id, sealed, now);
          if (!(await holds(revealer))) {
            throw conflict("Your session or role changed before the outcome was revealed; sign in again");
          }
          throw operationExpired("This operation's outcome is no longer available");
        }
        return { id: row.id, kind: row.kind, organizationId, outcome };
      },
    };
  };

  return { operations: door(false), internal: door(true) };
};

/** The operations service `cfAuth.operations` is: the engine's door that refuses internal kinds. */
export const createOperationsService = (
  config: ResolvedCfAuthConfig,
  repository: CfAuthRepository,
): CfAuthOperations => createOperationsEngine(config, repository).operations;
