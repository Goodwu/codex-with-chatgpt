import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { safeGitInvocation } from "../src/workspace/git-safety.js";
import { makeTmpDir, makeGitRepo, cleanup } from "./helpers.js";

describe("portable Git configuration isolation", () => {
  it("uses Git's null config convention on Linux, macOS and Windows", () => {
    const root = makeTmpDir("git-null-config");
    try {
      makeGitRepo(root);
      const safe = safeGitInvocation(root);
      expect(safe).not.toBeNull();
      expect(safe!.env.GIT_CONFIG_GLOBAL).toBe("/dev/null");
      expect(safe!.env.GIT_CONFIG_SYSTEM).toBe("/dev/null");
      const result = spawnSync("git", [...safe!.args, "status", "--porcelain"], {
        cwd: root, env: safe!.env, encoding: "utf8", timeout: 10000, windowsHide: true,
      });
      expect(result.status, result.stderr).toBe(0);
      expect(result.stdout).toBe("");
    } finally { cleanup(root); }
  });
});
