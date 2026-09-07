import { describe, expect, it } from "vitest";
import { resolveConfig, type CfAuthDatabase } from "../src/config.js";
import { createBetterAuthOptions } from "../src/better-auth.js";
import { cfAuthTables, createCfAuthTables } from "../src/schema.js";
import { getTableName } from "drizzle-orm";

const db = {} as CfAuthDatabase;
const base = { appName: "My App", secret: "s".repeat(32), db };

describe("resolveConfig", () => {
  it("derives every app-specific name from appName", () => {
    const config = resolveConfig(base);

    expect(config.cookies.prefix).toBe("my_app");
    expect(config.cookies.betterAuthPrefix).toBe("my_app_auth");
    expect(config.cookies.currentOrganizationCookieName).toBe("my_app_current_organization");
    expect(config.basePath).toBe("/api/auth");
    // Not the better-auth secret: the cookie key is derived from it on first use.
    expect(config.cookieSecret).toBeUndefined();
  });

  it("applies documented defaults", () => {
    const config = resolveConfig(base);

    expect(config.emailAndPassword).toEqual({
      enabled: true,
      minPasswordLength: 8,
      maxPasswordLength: 128,
      requireEmailVerification: false,
    });
    expect(config.apiKeys).toEqual({
      enabled: false,
      tokenPrefix: "key_",
      clientHeader: "X-Client",
    });
    expect(config.organizations.autoProvisionDefaultOrganization).toBe(true);
    expect(config.disableSignUp).toBe(false);
    expect(config.openAPI).toBe(false);
    expect(config.google).toBeUndefined();
    expect(config.oauthProxy).toBeUndefined();
    expect(config.cookies.maxAge).toBe(60 * 60 * 24 * 365);
  });

  it("normalizes base path and trusted origins", () => {
    const config = resolveConfig({
      ...base,
      basePath: "auth/better/",
      baseUrl: "https://app.example.com/",
      trustedOrigins: ["https://app.example.com", "http://localhost:5173/", ""],
    });

    expect(config.basePath).toBe("/auth/better");
    expect(config.baseUrl).toBe("https://app.example.com");
    expect(config.trustedOrigins).toEqual([
      "https://app.example.com",
      "http://localhost:5173",
    ]);
  });

  it("allows a separate cookie secret", () => {
    const config = resolveConfig({ ...base, cookieSecret: "different-cookie-secret" });
    expect(config.cookieSecret).toBe("different-cookie-secret");
    expect(config.secret).toBe(base.secret);
  });

  it("forwards the Google social sign-up control to Better Auth", () => {
    const config = resolveConfig({
      ...base,
      google: {
        clientId: "google-client",
        clientSecret: "google-secret",
        disableSignUp: true,
      },
    });
    const options = createBetterAuthOptions(config, () => {
      throw new Error("service is not used while building options");
    });

    expect(options.socialProviders?.google).toMatchObject({ disableSignUp: true });
  });

  it("configures the OAuth proxy with a dedicated shared secret", () => {
    const config = resolveConfig({
      ...base,
      oauthProxy: {
        productionUrl: "https://auth.example.com/",
        currentUrl: "http://feature.example.test/",
        secret: "proxy-secret",
        maxAge: 45,
      },
    });
    const options = createBetterAuthOptions(config, () => {
      throw new Error("service is not used while building options");
    });

    expect(config.oauthProxy).toEqual({
      productionUrl: "https://auth.example.com",
      currentUrl: "http://feature.example.test",
      secret: "proxy-secret",
      maxAge: 45,
    });
    expect(options.plugins).toHaveLength(1);
    expect(options.plugins?.[0]).toMatchObject({
      id: "oauth-proxy",
      options: {
        productionURL: "https://auth.example.com",
        currentURL: "http://feature.example.test",
        secret: "proxy-secret",
        maxAge: 45,
      },
    });
  });

  it("blocks user creation before persistence when sign-up is disabled", async () => {
    const config = resolveConfig({ ...base, disableSignUp: true });
    const options = createBetterAuthOptions(config, () => {
      throw new Error("service is not used while building options");
    });

    expect(options.emailAndPassword).toMatchObject({ disableSignUp: true });
    await expect(options.databaseHooks?.user?.create?.before?.({} as never, null)).rejects.toMatchObject({
      body: { code: "REGISTRATION_DISABLED", message: "signup disabled" },
    });
  });

  it("rejects missing or ambiguous inputs", () => {
    expect(() => resolveConfig({ ...base, appName: " " })).toThrowError(/appName/);
    expect(() => resolveConfig({ ...base, secret: "" })).toThrowError(/secret/);
    expect(() => resolveConfig({ appName: "X", secret: "y" })).toThrowError(/d1.*db|db.*d1/);
    expect(() =>
      resolveConfig({ ...base, d1: {} as never }),
    ).toThrowError(/only one/);
    expect(() => resolveConfig({
      ...base,
      oauthProxy: { productionUrl: "", secret: "proxy-secret" },
    })).toThrowError(/productionUrl/);
    expect(() => resolveConfig({
      ...base,
      oauthProxy: { productionUrl: "https://auth.example.com", secret: "" },
    })).toThrowError(/oauthProxy.secret/);
    expect(() => resolveConfig({
      ...base,
      oauthProxy: {
        productionUrl: "https://auth.example.com",
        secret: "proxy-secret",
        maxAge: 0,
      },
    })).toThrowError(/maxAge/);
  });
});

describe("schema", () => {
  it("exposes the seven tables an app must migrate", () => {
    expect(Object.keys(cfAuthTables).sort()).toEqual([
      "account",
      "apiKey",
      "organization",
      "organizationUser",
      "session",
      "user",
      "verification",
    ]);
  });

  it("uses unprefixed physical table names by default", () => {
    expect(Object.values(cfAuthTables).map(getTableName).sort()).toEqual([
      "api_key",
      "organization",
      "organization_user",
      "user",
      "user_account",
      "user_session",
      "verification",
    ]);
  });

  it("supports a configurable table prefix", () => {
    const prefixed = createCfAuthTables({ tablePrefix: "auth_" });

    expect(Object.values(prefixed).map(getTableName).sort()).toEqual([
      "auth_api_key",
      "auth_organization",
      "auth_organization_user",
      "auth_user",
      "auth_user_account",
      "auth_user_session",
      "auth_verification",
    ]);
  });
});
