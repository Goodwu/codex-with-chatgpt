import { beforeEach, afterEach, describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { Workspace } from "../src/workspace/manager.js";
import { gitDiff, gitInfo, gitStatus } from "../src/workspace/git.js";
import { searchWorkspace, resetRipgrepCache } from "../src/workspace/search.js";
import { makeTmpDir, isolateStateDir, cleanup, write, makeGitRepo, git } from "./helpers.js";

let repo: string, outside: string, state: string;
beforeEach(() => { state = isolateStateDir(); repo = makeTmpDir("root-security"); outside = makeTmpDir("root-security-outside"); });
afterEach(() => {
  for (const dir of [repo, outside, state]) cleanup(dir);
  delete process.env.C2C_STATE_DIR; delete process.env.C2C_DISABLE_RG;
  resetRipgrepCache();
});
function symlink(target: string, link: string, dir = false): boolean {
  try { fs.symlinkSync(target, link, dir && process.platform === "win32" ? "junction" : dir ? "dir" : "file"); return true; } catch { return false; }
}

describe("per-root read and Git boundaries", () => {
  it("does not read project metadata or policy files through external symlinks", () => {
    write(outside, "metadata.json", JSON.stringify({ name: "EXTERNAL SECRET", scripts: { test: "EXTERNAL SECRET" } }));
    if (!symlink(path.join(outside, "metadata.json"), path.join(repo, ".c2c.json"))) return;
    symlink(path.join(outside, "metadata.json"), path.join(repo, "package.json"));
    const ws = new Workspace(repo);
    expect(ws.name).not.toContain("EXTERNAL SECRET"); expect(JSON.stringify(ws.detectProject())).not.toContain("EXTERNAL SECRET");
    symlink(write(outside, "ignore", "private.txt\n"), path.join(repo, ".c2cignore"));
    expect(() => new Workspace(repo)).toThrow(/Invalid .c2cignore/);
  });
  it("denies both lexical and canonical sensitive paths", async () => {
    write(repo, ".env", "SECRET\n"); write(repo, "plain.txt", "plain\n");
    if (!symlink(path.join(repo, ".env"), path.join(repo, "alias.txt"))) return;
    symlink(path.join(repo, "plain.txt"), path.join(repo, "secret.key"));
    const ws = new Workspace(repo);
    await expect(ws.readFile("alias.txt")).rejects.toThrow(/SENSITIVE/);
    await expect(ws.readFile("secret.key")).rejects.toThrow(/SENSITIVE/);
  });
  it("never returns local C2C state even when it is inside the selected workspace", async () => {
    process.env.C2C_STATE_DIR = path.join(repo, "state"); write(repo, "state/runtime/private.json", "ADMIN_TOKEN\n");
    const ws = new Workspace(repo);
    await expect(ws.readFile("state/runtime/private.json")).rejects.toThrow(/SENSITIVE/);
    expect((await ws.listDirectory(".")).entries.map(e => e.path)).not.toContain("state/");
  });
  it("enforces the byte cap even for a single enormous line", async () => {
    write(repo, "long.txt", "x".repeat(300000));
    await expect(new Workspace(repo).readFile("long.txt")).rejects.toThrow(/byte budget/);
  });
  it.each(["node", "default"])("search engine %s does not cross symlinks or leak denied matches", async engine => {
    if (engine === "node") process.env.C2C_DISABLE_RG = "1";
    write(repo, ".c2cignore", "private.txt\n"); write(repo, "private.txt", "private needle\n");
    write(repo, "public.txt", "public needle\n"); write(outside, "external.txt", "external needle\n");
    symlink(outside, path.join(repo, "external"), true);
    const result = await searchWorkspace(new Workspace(repo), { query: "needle" });
    expect(result.matches.map(m => m.text)).toEqual(["public needle"]);
  });
  it("normalizes Git paths relative to a subtree and preserves rename provenance", () => {
    makeGitRepo(repo); write(repo, "part/a.txt", "subtree old\n"); write(repo, "elsewhere.txt", "OUTSIDE_SOURCE\n");
    write(repo, "part/.c2cignore", "private.txt\n"); write(repo, "part/private.txt", "PRIVATE_SOURCE\n");
    git(repo, "add", "."); git(repo, "commit", "-m", "subtree baseline");
    write(repo, "part/a.txt", "subtree new\n"); write(repo, "part/private.txt", "PRIVATE_CHANGE\n");
    const ws = new Workspace(path.join(repo, "part"));
    const status = gitStatus(ws); expect(status.unstaged.map(e => e.path)).toEqual(["a.txt"]);
    const diff = gitDiff(ws); expect(diff.diff).toContain("subtree new"); expect(diff.diff).not.toContain("PRIVATE_CHANGE");
    expect(diff.diff).not.toContain("part/part");
    git(repo, "mv", "elsewhere.txt", "part/renamed.txt");
    const staged = gitDiff(ws, { mode: "staged" });
    expect(staged.diff).not.toContain("OUTSIDE_SOURCE"); expect(staged.diff).not.toContain("renamed.txt");
  });
  it("does not inherit a different repository through GIT_DIR or core.worktree", () => {
    makeGitRepo(repo); makeGitRepo(outside); write(outside, "hello.txt", "OUTSIDE_CONTENT\n");
    const old = process.env.GIT_DIR; process.env.GIT_DIR = path.join(outside, ".git");
    try { expect(gitDiff(new Workspace(repo)).diff).not.toContain("OUTSIDE_CONTENT"); }
    finally { if (old === undefined) delete process.env.GIT_DIR; else process.env.GIT_DIR = old; }
    git(repo, "config", "core.worktree", outside);
    expect(gitDiff(new Workspace(repo)).diff).not.toContain("OUTSIDE_CONTENT");
  });
  it("refuses arbitrary external .git redirects while supporting verified linked worktrees", () => {
    makeGitRepo(outside); write(repo, ".git", `gitdir: ${path.join(outside, ".git")}\n`);
    expect(gitInfo(repo).isRepo).toBe(false);
    fs.unlinkSync(path.join(repo, ".git")); cleanup(repo);
    git(outside, "worktree", "add", "-b", "linked", repo);
    expect(gitInfo(repo).isRepo).toBe(true); write(repo, "hello.txt", "linked change\n");
    expect(gitDiff(new Workspace(repo)).diff).toContain("linked change");
  });
  it("supports absorbed submodules only when the external metadata points back to this worktree", () => {
    makeGitRepo(repo); makeGitRepo(outside);
    git(repo, "-c", "protocol.file.allow=always", "submodule", "add", outside, "dependency");
    const sub = path.join(repo, "dependency");
    expect(gitInfo(sub).isRepo).toBe(true);
    write(sub, "hello.txt", "submodule change\n");
    expect(gitDiff(new Workspace(sub)).diff).toContain("submodule change");
    git(sub, "config", "core.worktree", outside);
    expect(gitInfo(sub).isRepo).toBe(false);
  });
  it("does not execute external diff, textconv, clean/process filters, or fsmonitor hooks", () => {
    makeGitRepo(repo);
    const marker = path.join(repo, "HELPER_EXECUTED");
    const helper = write(repo, "helper.cjs", `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'bad'); process.stdout.write('HELPER_SECRET');\n`);
    const command = `node "${helper.replace(/\\/g, "/")}"`;
    git(repo, "config", "diff.evil.command", command); git(repo, "config", "diff.evil.textconv", command);
    git(repo, "config", "filter.evil.clean", command); git(repo, "config", "filter.evil.process", command);
    git(repo, "config", "filter.evil.required", "true"); git(repo, "config", "core.fsmonitor", command);
    write(repo, ".gitattributes", "hello.txt diff=evil filter=evil\n"); write(repo, "hello.txt", "safe change\n");
    const diff = gitDiff(new Workspace(repo)); const status = gitStatus(new Workspace(repo));
    expect(diff.isRepo).toBe(true); expect(diff.diff).toContain("safe change"); expect(diff.diff).not.toContain("HELPER_SECRET");
    expect(status.isRepo).toBe(true); expect(fs.existsSync(marker)).toBe(false);
  });
});
