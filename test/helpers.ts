import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { createClient, type Client } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import { Hono } from "hono";
import { afterEach } from "vitest";
import { createCfAuth } from "../src/cf-auth.js";
import type { CfAuthConfig, CfAuthDatabase } from "../src/config.js";
import type { CfAuthVariables } from "../src/middleware.js";
import { cfAuthTables } from "../src/schema.js";
import type { AuthState, CfAuthEvent } from "../src/types.js";

// `.href` rather than the URL object: the ambient `URL` here is Cloudflare's,
// which is not structurally assignable to `node:url`'s.
const migrationsDirectory = fileURLToPath(new URL("../drizzle/", import.meta.url).href);
const statementBreakpoint = "--> statement-breakpoint";

/**
 * `Headers.getSetCookie` is not in `@cloudflare/workers-types`' Headers (which
 * wins over `@types/node` here), so reach for it through a narrow cast with a
 * comma-splitting fallback.
 */
const readSetCookies = (headers: Headers): string[] => {
  const withGetSetCookie = headers as unknown as { getSetCookie?: () => string[] };

  if (typeof withGetSetCookie.getSetCookie === "function") {
    return withGetSetCookie.getSetCookie();
  }

  const raw = headers.get("set-cookie");
  return raw ? raw.split(/,\s*(?=[^;=]+=)/) : [];
};

const openClients = new Set<Client>();

afterEach(() => {
  for (const client of openClients) {
    client.close();
  }

  openClients.clear();
});

/**
 * Applies the reference migration shipped with the package. This doubles as a
 * regression test that `drizzle/*.sql` stays in sync with `src/schema.ts`.
 */
const applyMigrations = async (client: Client) => {
  const fileNames = (await readdir(migrationsDirectory))
    .filter((fileName) => fileName.endsWith(".sql"))
    .sort((left, right) => left.localeCompare(right));

  if (fileNames.length === 0) {
    throw new Error("No reference migrations found in ./drizzle");
  }

  await client.execute("PRAGMA foreign_keys=ON");

  for (const fileName of fileNames) {
    const sql = await readFile(`${migrationsDirectory}${fileName}`, "utf8");

    for (const statement of sql
      .split(statementBreakpoint)
      .map((value) => value.trim())
      .filter(Boolean)) {
      await client.execute(statement);
    }
  }
};

export const testBaseUrl = "http://localhost:8787";
export const testSecret = "test-secret-not-a-real-credential-0123456789";

export type TestOverrides = Partial<Omit<CfAuthConfig, "db" | "d1">>;

/** In-process cookie jar so tests can drive the real session-cookie flow. */
export class CookieJar {
  private readonly cookies = new Map<string, string>();

  absorb(response: Response) {
    for (const raw of readSetCookies(response.headers)) {
      const [pair] = raw.split(";");
      const separator = pair?.indexOf("=") ?? -1;

      if (!pair || separator <= 0) {
        continue;
      }

      const name = pair.slice(0, separator).trim();
      const value = pair.slice(separator + 1).trim();

      if (value === "" || /max-age=0|expires=thu, 01 jan 1970/i.test(raw)) {
        this.cookies.delete(name);
      } else {
        this.cookies.set(name, value);
      }
    }
  }

  header(): string {
    return [...this.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
  }

  get(name: string): string | undefined {
    return this.cookies.get(name);
  }

  has(name: string): boolean {
    return this.cookies.has(name);
  }

  clear() {
    this.cookies.clear();
  }
}

export const createTestAuth = async (overrides: TestOverrides = {}) => {
  const client = createClient({ url: ":memory:" });
  openClients.add(client);
  await applyMigrations(client);

  const db = drizzle(client, { schema: cfAuthTables }) as unknown as CfAuthDatabase;
  const events: CfAuthEvent[] = [];
  const errors: unknown[] = [];

  const cfAuth = createCfAuth({
    appName: "Test App",
    secret: testSecret,
    baseUrl: testBaseUrl,
    apiKeys: { enabled: true },
    ...overrides,
    db,
    onEvent: (event) => {
      events.push(event);
      return overrides.onEvent?.(event);
    },
    onError: (error, context) => {
      errors.push(error);
      overrides.onError?.(error, context);
    },
  });

  const app = new Hono<{ Variables: CfAuthVariables }>();
  cfAuth.mount(app);
  app.use("/api/*", cfAuth.middleware());
  app.get("/api/me", (c) => c.json(c.get("authState")));

  const jar = new CookieJar();

  /** Issues a request through the Hono app, replaying and absorbing cookies. */
  const request = async (
    path: string,
    init: RequestInit & { json?: unknown; useJar?: boolean } = {},
  ) => {
    const { json, useJar = true, ...rest } = init;
    const headers = new Headers(rest.headers);
    headers.set("Origin", testBaseUrl);

    if (json !== undefined) {
      headers.set("Content-Type", "application/json");
    }

    const cookieHeader = jar.header();

    if (useJar && cookieHeader && !headers.has("Cookie")) {
      headers.set("Cookie", cookieHeader);
    }

    const response = await app.request(`${testBaseUrl}${path}`, {
      ...rest,
      headers,
      ...(json !== undefined ? { method: rest.method ?? "POST", body: JSON.stringify(json) } : {}),
    });

    if (useJar) {
      jar.absorb(response);
    }

    return response;
  };

  const signUp = async (input: { email: string; password: string; name?: string }) => {
    const response = await request(`${cfAuth.basePath}/sign-up/email`, {
      json: { email: input.email, password: input.password, name: input.name ?? input.email },
    });

    if (!response.ok) {
      throw new Error(`sign-up failed (${response.status}): ${await response.text()}`);
    }

    return response;
  };

  const signIn = async (input: { email: string; password: string }) => {
    const response = await request(`${cfAuth.basePath}/sign-in/email`, { json: input });

    if (!response.ok) {
      throw new Error(`sign-in failed (${response.status}): ${await response.text()}`);
    }

    return response;
  };

  const me = async (init?: RequestInit & { useJar?: boolean }): Promise<AuthState> => {
    const response = await request("/api/me", init);
    return (await response.json()) as AuthState;
  };

  return {
    cfAuth,
    app,
    db,
    client,
    jar,
    events,
    errors,
    request,
    signUp,
    signIn,
    me,
    close: () => {
      openClients.delete(client);
      client.close();
    },
  };
};

export type TestAuth = Awaited<ReturnType<typeof createTestAuth>>;
