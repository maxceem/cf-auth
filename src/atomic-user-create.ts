import { APIError } from "better-auth/api";
import type { DBAdapter, DBTransactionAdapter } from "better-auth/types";
import { sql } from "drizzle-orm";
import type { ResolvedCfAuthConfig } from "./config.js";

interface LogicalHumanUser {
  id: string;
  name: string;
  email: string;
  emailVerified: boolean;
  image: string | null;
  kind: "human";
  createdAt: Date;
  updatedAt: Date;
}

const userDate = (value: unknown): Date => {
  if (value instanceof Date && !Number.isNaN(value.getTime())) return value;
  if (typeof value === "number" || typeof value === "string") {
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.getTime())) return parsed;
  }
  return new Date();
};

const selectedUser = (
  user: LogicalHumanUser,
  select: string[] | undefined,
): Record<string, unknown> => {
  if (!select?.length) return { ...user };
  const result: Record<string, unknown> = {};
  for (const field of select) {
    if (Object.hasOwn(user, field)) result[field] = user[field as keyof LogicalHumanUser];
  }
  return result;
};

const insertGuardedHuman = async (
  config: ResolvedCfAuthConfig,
  data: Record<string, unknown>,
  select: string[] | undefined,
  forceAllowId: boolean,
): Promise<Record<string, unknown>> => {
  const guard = config.userHooks.atomicCreateGuard;
  if (!guard) throw new Error("guarded human creation requires an atomic create guard");
  if (data.kind !== undefined && data.kind !== "human") {
    throw new Error("Better Auth user creation must carry the human identity kind");
  }
  if (typeof data.name !== "string" || typeof data.email !== "string") {
    throw new Error("Better Auth user creation is missing normalized identity fields");
  }

  const user: LogicalHumanUser = {
    id:
      forceAllowId && typeof data.id === "string" && data.id.length > 0
        ? data.id
        : crypto.randomUUID(),
    name: data.name,
    email: data.email,
    emailVerified: data.emailVerified === true,
    image: typeof data.image === "string" ? data.image : null,
    kind: "human",
    createdAt: userDate(data.createdAt),
    updatedAt: userDate(data.updatedAt),
  };
  const table = config.tables.user;
  const column = (name: string) => sql.identifier(name);
  const [inserted] = await config.db.all<{ id: string }>(sql`
    insert into ${table} (
      ${column(table.id.name)}, ${column(table.name.name)}, ${column(table.email.name)},
      ${column(table.emailVerified.name)}, ${column(table.image.name)}, ${column(table.kind.name)},
      ${column(table.createdAt.name)}, ${column(table.updatedAt.name)}
    )
    select
      ${user.id}, ${user.name}, ${user.email}, ${user.emailVerified ? 1 : 0}, ${user.image},
      'human', ${user.createdAt.getTime()}, ${user.updatedAt.getTime()}
    where ${guard.condition(config.tables)}
    returning ${column(table.id.name)} as id
  `);
  if (!inserted) {
    await guard.onDenied?.();
    throw APIError.from("FORBIDDEN", {
      code: "REGISTRATION_DISABLED",
      message: "signup disabled",
    });
  }
  return selectedUser(user, select);
};

export const guardUserCreates = (
  config: ResolvedCfAuthConfig,
  adapter: DBAdapter,
): DBAdapter => {
  const createGuarded = (delegate: DBTransactionAdapter["create"]): DBAdapter["create"] => async <
    T extends Record<string, unknown>,
    R = T,
  >(args: {
    model: string;
    data: Omit<T, "id">;
    select?: string[] | undefined;
    forceAllowId?: boolean | undefined;
  }): Promise<R> => {
    if (args.model !== "user") return delegate<T, R>(args);
    return (await insertGuardedHuman(
      config,
      args.data,
      args.select,
      args.forceAllowId ?? false,
    )) as R;
  };

  return {
    ...adapter,
    create: createGuarded(adapter.create),
    // The installed SQLite adapter executes transaction callbacks sequentially
    // (transaction support is disabled), but Better Auth still supplies a
    // callback-scoped adapter. Wrap it so that path cannot bypass the atomic
    // user insert. The INSERT itself remains one atomic SQLite statement.
    transaction: <R>(callback: (trx: DBTransactionAdapter) => Promise<R>) =>
      adapter.transaction((trx) => callback({ ...trx, create: createGuarded(trx.create) })),
  };
};
