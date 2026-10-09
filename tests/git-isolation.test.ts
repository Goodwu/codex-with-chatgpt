import { afterEach, expect, it, vi } from "vitest";
import { runGit } from "../src/workspace/git.js";
import { cleanup, makeGitRepo, makeTmpDir, write } from "./helpers.js";

let directory: string | undefined;
afterEach(() => {
  vi.unstubAllEnvs();
  if (directory) cleanup(directory);
});

it("reads Git repositories with an empty global config on every platform", () => {
  directory = makeTmpDir("git-isolation");
  makeGitRepo(directory);
  const config = write(directory, "untrusted-global.config", "[c2c]\n    mustNotLoad = true\n");
  vi.stubEnv("GIT_CONFIG_GLOBAL", config);
  vi.stubEnv("GIT_CONFIG_SYSTEM", config);
  const repository = runGit(directory, ["rev-parse", "--is-inside-work-tree"]);
  expect(repository.ok, repository.stderr || `Git exit: ${repository.code}`).toBe(true);
  expect(repository.stdout.trim()).toBe("true");
  const globalConfig = runGit(directory, ["config", "--global", "--list"]);
  expect(globalConfig.ok, globalConfig.stderr || `Git exit: ${globalConfig.code}`).toBe(true);
  expect(globalConfig.stdout).toBe("");
  const ignored = runGit(directory, ["config", "--get", "c2c.mustNotLoad"]);
  expect(ignored.code).toBe(1);
  expect(ignored.stdout).toBe("");
});
