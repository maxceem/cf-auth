#!/usr/bin/env node
// Cuts a release of @maxceem/cf-auth:
//
//   pnpm release <version>              # e.g. pnpm release 0.11.1
//   pnpm release <version> --dry-run    # print the plan, write nothing
//
// It bumps package.json, runs `pnpm run check`, commits `Release X.Y.Z`, tags
// `vX.Y.Z` and pushes the commit and the tag together. The pushed tag starts
// .github/workflows/release.yml, which checks the tagged commit again and
// attaches the packed tarball to a GitHub release.
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = fileURLToPath(new URL("..", import.meta.url));
const BRANCH = "main";
const VERSION_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u;

function parseArguments(argv) {
  const positional = argv.filter((arg) => !arg.startsWith("-"));
  const unknown = argv.filter((arg) => arg.startsWith("-") && arg !== "--dry-run");
  if (unknown.length > 0) throw new Error(`Unknown option: ${unknown[0]}`);
  if (positional.length !== 1) throw new Error("Usage: pnpm release <version> [--dry-run]");
  return { version: positional[0], dryRun: argv.includes("--dry-run") };
}

function parseVersion(version) {
  const match = VERSION_PATTERN.exec(version);
  if (!match) throw new Error(`"${version}" is not a version of the form X.Y.Z`);
  return match.slice(1).map(Number);
}

/**
 * A tarball URL names its version, and consumers pin that URL, so a release
 * must move forward: repeating or going back would publish a second tarball
 * under a version that already means something else.
 */
function assertNewer(version, previous) {
  const next = parseVersion(version);
  const current = parseVersion(previous);
  const order = next.map((part, index) => part - current[index]).find((diff) => diff !== 0) ?? 0;
  if (order <= 0) throw new Error(`${version} is not newer than the current version ${previous}`);
}

function git(args, { allowFailure = false } = {}) {
  const result = spawnSync("git", args, { cwd: projectRoot, encoding: "utf8" });
  if (result.error) throw result.error;
  if (result.status !== 0 && !allowFailure) {
    throw new Error(`git ${args.join(" ")} failed:\n${result.stderr ?? ""}`);
  }
  return result;
}

/**
 * Checked before anything is written, because the tag is what publishes: a tag
 * pushed from a stale or dirty checkout would release a tree nobody reviewed.
 */
function assertCheckoutIsReleasable(tag) {
  const branch = git(["rev-parse", "--abbrev-ref", "HEAD"]).stdout.trim();
  if (branch !== BRANCH) {
    throw new Error(`Releases are cut from ${BRANCH}; this checkout is on ${branch}.`);
  }

  const status = git(["status", "--porcelain"]).stdout.trim();
  if (status) throw new Error(`The working tree has uncommitted changes:\n${status}`);

  console.log("Fetching origin ...");
  git(["fetch", "--prune", "--tags", "origin"]);

  const local = git(["rev-parse", "HEAD"]).stdout.trim();
  const remote = git(["rev-parse", `origin/${BRANCH}`]).stdout.trim();
  if (local !== remote) {
    throw new Error(
      `HEAD is ${local.slice(0, 8)} but origin/${BRANCH} is ${remote.slice(0, 8)}. ` +
        "Pull or push until they agree.",
    );
  }

  if (git(["rev-parse", "--verify", `refs/tags/${tag}`], { allowFailure: true }).status === 0) {
    throw new Error(`Tag ${tag} already exists.`);
  }
}

try {
  const { version, dryRun } = parseArguments(process.argv.slice(2));
  const packagePath = resolve(projectRoot, "package.json");
  const packageText = readFileSync(packagePath, "utf8");
  const previousVersion = JSON.parse(packageText).version;
  assertNewer(version, previousVersion);
  const tag = `v${version}`;
  const message = `Release ${version}\n`;

  if (!dryRun) assertCheckoutIsReleasable(tag);

  console.log(`\nRelease ${previousVersion} -> ${version}`);
  console.log(`  commit: Release ${version}`);
  console.log(`  tag:    ${tag}`);
  console.log(`  push:   git push --atomic origin ${BRANCH} ${tag}\n`);

  if (dryRun) {
    console.log("Dry run: nothing was written, committed, tagged or pushed.");
    process.exit(0);
  }

  // Only the version line changes, so the rest of the file keeps its formatting.
  writeFileSync(packagePath, packageText.replace(/("version":\s*")[^"]*(")/u, `$1${version}$2`));

  console.log("Running pnpm run check ...");
  const check = spawnSync("pnpm", ["run", "check"], { cwd: projectRoot, stdio: "inherit" });
  if (check.status !== 0) {
    // The bump stays in place so it is clear which version was being cut.
    throw new Error(
      "`pnpm run check` failed after the version bump. Fix it, run `git restore package.json`, " +
        "then run this command again.",
    );
  }

  git(["add", "--", "package.json"]);
  git(["commit", "--message", message]);
  git(["tag", "--annotate", tag, "--message", message]);
  git(["push", "--atomic", "origin", BRANCH, tag]);

  console.log(
    `\nPushed ${tag}. The release workflow now checks it and publishes the tarball:\n` +
      "https://github.com/maxceem/cf-auth/actions/workflows/release.yml",
  );
} catch (error) {
  console.error("");
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
