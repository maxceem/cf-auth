import { defineConfig } from "drizzle-kit";

/**
 * Generates the *reference* migration shipped in `./drizzle`.
 *
 * Consuming apps do NOT use this config — they point drizzle-kit at their own
 * merged schema (which spreads `cfAuthTables`) and run their own migration
 * pipeline. See the "Migrations" section of the README.
 */
export default defineConfig({
  dialect: "sqlite",
  schema: "./src/schema.ts",
  out: "./drizzle",
  strict: true,
  verbose: true,
});
