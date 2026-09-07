import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, describe, expect, it } from "vitest";

const run = promisify(execFile);
const packageRoot = fileURLToPath(new URL("..", import.meta.url).href);

const scratchDirectories: string[] = [];

afterAll(async () => {
  await Promise.all(scratchDirectories.map((dir) => rm(dir, { recursive: true, force: true })));
});

/** Pulls the first ```ts fenced block that follows `heading`. */
const extractSnippet = (markdown: string, heading: string) => {
  const section = markdown.slice(markdown.indexOf(heading));
  const match = /```ts\n([\s\S]*?)```/.exec(section);

  if (!match?.[1]) {
    throw new Error(`No TypeScript snippet found under "${heading}"`);
  }

  return match[1];
};

describe("documentation", () => {
  it("has a setup snippet that compiles as pasted", async () => {
    const markdown = await readFile(join(packageRoot, "docs/index.md"), "utf8");
    const snippet = extractSnippet(markdown, "## Setting it up");

    // Sanity-check we grabbed the right block before spending a tsc run on it.
    expect(snippet).toContain("createCfAuth");
    expect(snippet).toContain("export default app");

    const scratch = await mkdtemp(join(tmpdir(), "cf-auth-readme-"));
    scratchDirectories.push(scratch);

    await writeFile(join(scratch, "snippet.ts"), snippet);
    await symlink(join(packageRoot, "node_modules"), join(scratch, "node_modules"), "dir");
    await writeFile(
      join(scratch, "tsconfig.json"),
      JSON.stringify({
        compilerOptions: {
          target: "ES2022",
          lib: ["ES2023"],
          module: "ESNext",
          moduleResolution: "Bundler",
          strict: true,
          exactOptionalPropertyTypes: true,
          noUncheckedIndexedAccess: true,
          skipLibCheck: true,
          noEmit: true,
          types: ["@cloudflare/workers-types"],
          // Resolve the package name against source, so this test needs no build.
          paths: { "@maxceem/cf-auth": [join(packageRoot, "src/index.ts")] },
        },
        include: ["snippet.ts"],
      }),
    );

    try {
      await run(join(packageRoot, "node_modules/.bin/tsc"), ["-p", "tsconfig.json"], {
        cwd: scratch,
      });
    } catch (error) {
      const { stdout } = error as { stdout?: string };
      throw new Error(`README quick-start snippet does not compile:\n${stdout ?? String(error)}`);
    }
  }, 120_000);
});
