import { getTableColumns, sql, type InferInsertModel, type SQL } from "drizzle-orm";
import type { SQLiteTable } from "drizzle-orm/sqlite-core";
import type { CfAuthDatabase } from "./config.js";

/**
 * An `INSERT ... SELECT ... WHERE <condition>`: the row is written only if the
 * condition holds when the statement runs, which is how a guard travels with
 * the write it protects instead of being checked beforehand.
 *
 * Built with drizzle's insert builder rather than `db.run(sql)`, because that
 * is what `db.batch` can carry on every driver: D1's batch prepares each item
 * through the builder, and a raw statement with parameters has no prepared
 * statement to bind them to. The columns are selected in the table's own
 * order, which is the order drizzle names them in; a column left out takes
 * its default, or null.
 */
export const guardedInsert = <Table extends SQLiteTable>(
  db: CfAuthDatabase,
  table: Table,
  values: Partial<InferInsertModel<Table>>,
  condition: SQL,
) => {
  const columns = getTableColumns(table);
  for (const key of Object.keys(values)) {
    if (!Object.hasOwn(columns, key)) throw new Error(`guardedInsert: unknown column \`${key}\``);
  }
  const selected = Object.entries(columns).map(([key, column]) => {
    const value = (values as Record<string, unknown>)[key];
    if (value === undefined) {
      if (column.default === undefined) return sql`null`;
      return typeof column.default === "object" && column.default !== null && "getSQL" in column.default
        ? (column.default as SQL)
        : sql.param(column.default, column);
    }
    if (value === null) return sql`null`;
    // Through the column, so a Date or boolean is stored exactly as drizzle
    // would store it from `.values()`.
    return sql.param(value, column);
  });
  return db.insert(table).select(sql`select ${sql.join(selected, sql`, `)} where ${condition}`);
};
