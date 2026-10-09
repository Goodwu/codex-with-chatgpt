import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawnSync } from "node:child_process";
import { RootGrantStore, MAX_ROOTS } from "../src/workspace/root-grants.js";
import { Workspace } from "../src/workspace/manager.js";
import { WorkspaceRoots, rootGrantStore } from "../src/workspace/roots.js";
import { AuthStore } from "../src/auth/store.js";
import { makeTmpDir, cleanup, write, makeGitRepo, git } from "./helpers.js";

let base: string, main: string, extra: string, state: string, store: RootGrantStore;
let previousState: string | undefined;
const mkdir = (p: string): string => { fs.mkdirSync(p, { recursive: true, mode: 0o700 }); return fs.realpathSync.native(p); };
const expectCode = (fn: () => unknown, code: string): void => {
  try { fn(); } catch (e) { expect(e).toHaveProperty("code", code); return; }
  throw new Error(`Expected ${code}`);
};
beforeEach(() => {
  base = makeTmpDir("root-grants");
  main = mkdir(path.join(base, "main")); extra = mkdir(path.join(base, "extra")); state = mkdir(path.join(base, "state"));
  previousState = process.env.C2C_STATE_DIR; process.env.C2C_STATE_DIR = state;
  store = rootGrantStore(new Workspace(main));
});
afterEach(() => {
  if (previousState === undefined) delete process.env.C2C_STATE_DIR; else process.env.C2C_STATE_DIR = previousState;
  cleanup(base);
});

describe("explicit local directory grants", () => {
  it("preserves legacy identity, ignores repository-proposed roots and requires consent", () => {
    write(main, ".c2c.json", JSON.stringify({ roots: [{ name: "leak", path: extra }] }));
    const roots = new WorkspaceRoots(new Workspace(main));
    expect(roots.catalog()).toEqual([{ name: "main", isPrimary: true, readOnly: true }]);
    expect(roots.authorizationRevision).toBeUndefined();
    expect(store.workspaceId).toBe(new Workspace(main).id);
    expectCode(() => store.add("extra", extra, false), "CONSENT_REQUIRED");
    expect(fs.existsSync(store.file)).toBe(false);
  });
  it("persists private grants, makes identical adds idempotent, and never reuses an epoch", () => {
    const before = store.snapshot();
    const added = store.add("extra", extra, true);
    expect(added).toMatchObject({ changed: true, revision: expect.stringMatching(/^[a-f0-9]{48}$/) });
    expect(store.add("extra", extra, true)).toEqual({ changed: false, revision: added.revision });
    expectCode(() => store.assertCurrent(before), "ROOT_AUTHORIZATION_CHANGED");
    const removed = store.remove("extra");
    expect(removed.revision).not.toBe(added.revision);
    expect(store.snapshot().roots.map(r => r.name)).toEqual(["main"]);
    expect(store.snapshot().revision).toBeDefined();
    const restored = store.add("extra", extra, true);
    expect(new Set([added.revision, removed.revision, restored.revision]).size).toBe(3);
    expect(fs.existsSync(extra)).toBe(true);
    if (process.platform !== "win32") {
      expect(fs.statSync(store.file).mode & 0o777).toBe(0o600);
      expect(fs.statSync(store.directory).mode & 0o777).toBe(0o700);
    }
  });
  it.each(["main", "..", "../extra", "/tmp", "Main", "constructor", "__proto__", "a".repeat(33)])("rejects unsafe/reserved name %s", name => {
    expectCode(() => store.add(name, extra, true), "INVALID_ROOT_NAME");
  });
  it("rejects retargeting and removing main; unknown removal is a no-op", () => {
    store.add("extra", extra, true);
    expectCode(() => store.add("extra", mkdir(path.join(base, "other")), true), "ROOT_NAME_EXISTS");
    expectCode(() => store.remove("main"), "PRIMARY_ROOT_REQUIRED");
    expect(store.remove("unknown").changed).toBe(false);
  });
  it("rejects duplicate/nested roots even under different aliases", () => {
    expectCode(() => store.add("duplicate", main, true), "OVERLAPPING_ROOTS");
    expectCode(() => store.add("nested", mkdir(path.join(main, "src")), true), "OVERLAPPING_ROOTS");
    store.add("extra", extra, true);
    expectCode(() => store.add("duplicate", extra, true), "OVERLAPPING_ROOTS");
  });
  it("rejects filesystem/home roots, private state and sensitive mounts", () => {
    for (const dir of [path.parse(main).root, os.homedir(), state, mkdir(path.join(state, "child")), mkdir(path.join(base, ".ssh")), mkdir(path.join(base, ".git"))]) {
      expectCode(() => store.add("bad", dir, true), "UNSAFE_ROOT");
    }
  });
  it("bounds the root catalog", () => {
    for (let i = 1; i < MAX_ROOTS; i++) store.add(`r${i}`, mkdir(path.join(base, `r${i}`)), true);
    expect(store.snapshot().roots).toHaveLength(MAX_ROOTS);
    expectCode(() => store.add("overflow", extra, true), "INVALID_ROOT_STATE");
  });
  it("fails closed on removed/replaced roots, but lets the user revoke them", () => {
    store.add("extra", extra, true);
    fs.renameSync(extra, `${extra}-old`); mkdir(extra);
    expectCode(() => store.snapshot(), "ROOT_REPLACED");
    expect(store.remove("extra").changed).toBe(true);
    store.add("extra", extra, true); fs.rmdirSync(extra);
    expectCode(() => store.snapshot(), "ROOT_UNAVAILABLE");
    expect(store.remove("extra").changed).toBe(true);
  });
  it("allows sequential revocation when several extra roots are unavailable", () => {
    const other = mkdir(path.join(base, "other"));
    store.add("extra", extra, true); store.add("other", other, true);
    fs.rmdirSync(extra); fs.rmdirSync(other);
    expect(store.remove("extra").changed).toBe(true);
    expectCode(() => store.snapshot(), "ROOT_UNAVAILABLE");
    expect(store.remove("other").changed).toBe(true);
    expect(store.snapshot().roots.map(r => r.name)).toEqual(["main"]);
  });
  it("does not expose package scripts excluded by this root's custom policy", () => {
    write(extra, ".c2cignore", "package.json\n");
    write(extra, "package.json", '{"scripts":{"private":"never return"}}');
    store.add("extra", extra, true);
    const roots = new WorkspaceRoots(new Workspace(main));
    expectCode(() => roots.select("extra").detectProject(), "ACCESS_DENIED_SENSITIVE_FILE");
  });
  it.each(["../extra/a", "src/../../extra/a", "/etc/passwd", "C:\\Users\\a", "C:relative", "file:stream", "\\\\host\\share", "a\0b"])("rejects untrusted path %s", requested => {
    store.add("extra", extra, true);
    expectCode(() => store.resolve(store.snapshot(), "main", requested), "INVALID_PATH");
  });
  it("uses the selected root and does not fall back on unknown aliases", () => {
    store.add("extra", extra, true); const snap = store.snapshot();
    expect(store.resolve(snap, "extra", "workspace:/src/new.txt").absolute).toBe(path.join(extra, "src/new.txt"));
    expectCode(() => store.resolve(snap, "unknown", "hello.txt"), "UNKNOWN_ROOT");
  });
  it("blocks directory symlinks between authorized roots and missing descendants", () => {
    store.add("extra", extra, true);
    fs.symlinkSync(extra, path.join(main, "link"), process.platform === "win32" ? "junction" : "dir");
    const snap = store.snapshot();
    expectCode(() => store.resolve(snap, "main", "link"), "PATH_OUTSIDE_WORKSPACE");
    expectCode(() => store.resolve(snap, "main", "link/missing/file"), "PATH_OUTSIDE_WORKSPACE");
  });
  it("fails closed on malformed, oversized or missing activated state", () => {
    store.add("extra", extra, true); const bytes = fs.readFileSync(store.file);
    fs.writeFileSync(store.file, "{bad"); expectCode(() => store.snapshot(), "INVALID_ROOT_STATE");
    fs.writeFileSync(store.file, " ".repeat(65537)); expectCode(() => store.snapshot(), "INVALID_ROOT_STATE");
    fs.writeFileSync(store.file, bytes); fs.unlinkSync(store.file);
    expectCode(() => store.snapshot(), "ROOT_STATE_MISSING");
  });
  it("rejects missing activation marker and occupied locks", () => {
    store.add("extra", extra, true);
    fs.writeFileSync(`${store.file}.lock`, "occupied", { mode: 0o600 });
    expectCode(() => store.remove("extra"), "ROOT_STATE_BUSY");
    fs.unlinkSync(`${store.file}.lock`);
    fs.unlinkSync(path.join(store.directory, `${store.workspaceId}.enabled`));
    expectCode(() => store.snapshot(), "INVALID_ROOT_STATE");
  });
  it.skipIf(process.platform === "win32")("rejects non-private and hard-linked manifests", () => {
    store.add("extra", extra, true);
    fs.chmodSync(store.file, 0o644); expectCode(() => store.snapshot(), "UNSAFE_ROOT_STATE");
    fs.chmodSync(store.file, 0o600); fs.linkSync(store.file, path.join(state, "second-link"));
    expectCode(() => store.snapshot(), "UNSAFE_ROOT_STATE");
  });
  it("keeps each root's .c2cignore independent and builtin restrictions non-overridable", async () => {
    write(main, ".c2cignore", "main-private.txt\n");
    write(extra, ".c2cignore", "extra-private.txt\n!.env\n");
    write(extra, "main-private.txt", "visible in extra"); write(extra, "extra-private.txt", "blocked"); write(extra, ".env", "secret");
    store.add("extra", extra, true); const roots = new WorkspaceRoots(new Workspace(main));
    expect((await roots.select("extra").readFile("main-private.txt")).content).toBe("visible in extra");
    for (const file of ["extra-private.txt", ".env"]) expectCode(() => roots.select("extra").resolve(file), "ACCESS_DENIED_SENSITIVE_FILE");
  });
  it.skipIf(process.platform === "win32")("rejects escaping metadata before constructing an extra Workspace", () => {
    write(main, "outside.json", '{"scripts":{"test":"not authorized"}}');
    fs.symlinkSync(path.join(main, "outside.json"), path.join(extra, "package.json"));
    store.add("extra", extra, true);
    expectCode(() => new WorkspaceRoots(new Workspace(main)), "PATH_OUTSIDE_WORKSPACE");
  });
  it("requires exact Git roots but accepts legitimate linked worktrees", () => {
    makeGitRepo(extra); const worktree = path.join(base, "worktree");
    git(extra, "worktree", "add", "-b", "linked", worktree);
    store.add("extra", extra, true); store.add("linked", worktree, true);
    const roots = new WorkspaceRoots(new Workspace(main));
    expect(roots.info("linked")).toMatchObject({ isRepo: true, branch: "linked" });
    expect(roots.info("main").isRepo).toBe(false); // main is merely a subdirectory of this checkout
    expectCode(() => roots.git("main"), "GIT_ROOT_MISMATCH");
  });
  it("binds persisted access/refresh tokens to authorization revisions, retains registrations", () => {
    const file = path.join(state, "auth.json");
    const legacy = new AuthStore(store.workspaceId, { file });
    const client = legacy.registerClient({ redirectUris: ["https://example.com/callback"] });
    const old = legacy.issueTokens({ clientId: client.clientId, scopes: ["workspace.read", "offline_access"] });
    const revision = store.add("extra", extra, true).revision;
    const managed = new AuthStore(store.workspaceId, { file, authorizationRevision: revision });
    expect(managed.getClient(client.clientId)).toEqual(client);
    expect(managed.verifyAccessToken(old.accessToken).ok).toBe(false);
    expect(managed.refresh(old.refreshToken!, client.clientId).ok).toBe(false);
    const tokens = managed.issueTokens({ clientId: client.clientId, scopes: ["workspace.read", "offline_access"] });
    expect(new AuthStore(store.workspaceId, { file, authorizationRevision: revision }).verifyAccessToken(tokens.accessToken).ok).toBe(true);
    const next = store.remove("extra").revision;
    const revoked = new AuthStore(store.workspaceId, { file, authorizationRevision: next });
    expect(revoked.verifyAccessToken(tokens.accessToken).ok).toBe(false);
    expect(revoked.refresh(tokens.refreshToken!, client.clientId).ok).toBe(false);
  });
  it("exposes the local CLI without changing project identity or deleting roots", () => {
    const cli = (...args: string[]) => spawnSync(process.execPath, ["--import", "tsx/esm", "src/cli/index.ts", "roots", ...args, "-w", main, "--json"], { encoding: "utf8", env: process.env });
    const denied = cli("add", "extra", extra); expect(denied.status).not.toBe(0);
    const added = cli("add", "extra", extra, "--allow-read"); expect(added.status, added.stderr).toBe(0);
    expect(JSON.parse(added.stdout)).toMatchObject({ changed: true, restartRequired: true, reauthorizationRequired: true });
    const listed = JSON.parse(cli("list").stdout);
    expect(listed.workspaceId).toBe(store.workspaceId);
    expect(listed.roots).toContainEqual({ name: "extra", path: extra, readOnly: true });
    expect(cli("remove", "extra").status).toBe(0); expect(fs.existsSync(extra)).toBe(true);
  });
});
