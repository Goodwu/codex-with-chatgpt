import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { Workspace } from "../src/workspace/manager.js";
import { WorkspaceRoots, rootsFile, rootsMarkerFile, listApprovedRoots, prepareRootAddition,
  prepareRootRemoval, commitRootChange } from "../src/workspace/roots.js";
import { AuthStore } from "../src/auth/store.js";
import { cleanup, isolateStateDir, makeTmpDir, write } from "./helpers.js";

let main: string, dep: string, other: string, state: string, ws: Workspace;
const add = (name = "dep", dir = dep) => commitRootChange(prepareRootAddition(ws, name, dir), true);
const expectCode = (run: () => unknown, code: string) => expect(run).toThrow(expect.objectContaining({ code }));

beforeEach(() => {
  state = isolateStateDir(); main = makeTmpDir("state-main"); dep = makeTmpDir("state-dep"); other = makeTmpDir("state-other");
  ws = new Workspace(main);
});
afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of [main, dep, other, state]) cleanup(dir);
  delete process.env.C2C_STATE_DIR;
});

describe("root authorization storage regression", () => {
  it("does not create authorization state for untouched legacy reads or previews", () => {
    expect(new WorkspaceRoots(ws).authorizationVersion).toBeUndefined();
    prepareRootAddition(ws, "dep", dep);
    expect(fs.existsSync(rootsFile(ws.id))).toBe(false);
    expect(fs.existsSync(rootsMarkerFile(ws.id))).toBe(false);
  });
  it("preserves a legacy main layout while denying its nested application state", async () => {
    process.env.C2C_STATE_DIR = path.join(main, "app-state");
    fs.mkdirSync(process.env.C2C_STATE_DIR, { mode: 0o700 });
    write(main, "app-state/private.json", "SYNTHETIC_PRIVATE_STATE");
    const legacy = new Workspace(main);
    expect(new WorkspaceRoots(legacy).authorizationVersion).toBeUndefined();
    await expect(legacy.readFile("app-state/private.json")).rejects.toMatchObject({ code: "ACCESS_DENIED_SENSITIVE_FILE" });
  });
  it("fails closed after activated JSON disappears, including after the last root is removed", () => {
    add(); commitRootChange(prepareRootRemoval(ws, "dep"));
    const roots = new WorkspaceRoots(ws);
    expect(roots.authorizationVersion).toBeDefined();
    fs.unlinkSync(rootsFile(ws.id));
    expectCode(() => roots.assertCurrent(), "ROOT_STATE_MISSING");
    expectCode(() => new WorkspaceRoots(ws), "ROOT_STATE_MISSING");
    expectCode(() => prepareRootAddition(ws, "dep", dep), "ROOT_STATE_MISSING");
    expect(fs.existsSync(rootsMarkerFile(ws.id))).toBe(true);
  });
  it("rejects orphaned/pre-review manifests without silently creating a marker", () => {
    add(); fs.unlinkSync(rootsMarkerFile(ws.id));
    expectCode(() => new WorkspaceRoots(ws), "ROOT_MARKER_MISSING");
    expectCode(() => prepareRootRemoval(ws, "dep"), "ROOT_MARKER_MISSING");
    expect(fs.existsSync(rootsMarkerFile(ws.id))).toBe(false);
  });
  it.each(["", "wrong-workspace", "x".repeat(65537)])("rejects a damaged activation marker (%#)", content => {
    add(); fs.writeFileSync(rootsMarkerFile(ws.id), content);
    expectCode(() => new WorkspaceRoots(ws), "UNSAFE_ROOT_STATE");
  });
  it("persists activation before publication and fails closed if first rename fails", () => {
    const change = prepareRootAddition(ws, "dep", dep);
    const rename = vi.spyOn(fs, "renameSync").mockImplementation(() => {
      expect(fs.readFileSync(rootsMarkerFile(ws.id), "utf8")).toContain(ws.id);
      throw new Error("injected rename failure");
    });
    expect(() => commitRootChange(change, true)).toThrow(/injected/); rename.mockRestore();
    expect(fs.existsSync(rootsFile(ws.id))).toBe(false);
    expect(fs.existsSync(rootsFile(ws.id) + ".lock")).toBe(false);
    expectCode(() => new WorkspaceRoots(ws), "ROOT_STATE_MISSING");
    expect(fs.readdirSync(path.dirname(rootsFile(ws.id)))).toEqual([path.basename(rootsMarkerFile(ws.id))]);
  });
  it("keeps the old complete manifest on interrupted later publication", () => {
    add(); const before = fs.readFileSync(rootsFile(ws.id), "utf8");
    const change = prepareRootAddition(ws, "other", other);
    const rename = vi.spyOn(fs, "renameSync").mockImplementation(() => { throw new Error("injected rename failure"); });
    expect(() => commitRootChange(change, true)).toThrow(/injected/); rename.mockRestore();
    expect(fs.readFileSync(rootsFile(ws.id), "utf8")).toBe(before);
    expect(new WorkspaceRoots(ws).approved.map(r => r.name)).toEqual(["main", "dep"]);
  });
  it.skipIf(process.platform === "win32")("syncs marker data and directory before publishing and syncing the manifest", () => {
    const opens = new Map<number, string>(); const events: string[] = [];
    const open = fs.openSync.bind(fs); const sync = fs.fsyncSync.bind(fs); const rename = fs.renameSync.bind(fs);
    vi.spyOn(fs, "openSync").mockImplementation((file, flags, mode) => {
      const fd = open(file, flags, mode); opens.set(fd, String(file)); return fd;
    });
    vi.spyOn(fs, "fsyncSync").mockImplementation(fd => { events.push("sync:" + opens.get(fd)); sync(fd); });
    vi.spyOn(fs, "renameSync").mockImplementation((from, to) => { events.push("publish"); rename(from, to); });
    add();
    const marker = events.indexOf("sync:" + rootsMarkerFile(ws.id));
    const publish = events.indexOf("publish");
    const dirEvent = "sync:" + path.dirname(rootsFile(ws.id));
    expect(marker).toBeGreaterThanOrEqual(0);
    expect(events.slice(marker + 1, publish)).toContain(dirEvent);
    expect(events.slice(marker + 1, publish).some(event => event.endsWith(".tmp"))).toBe(true);
    expect(events.slice(publish + 1)).toContain(dirEvent);
  });
  it.skipIf(process.platform === "win32").each(["manifest", "marker", "directory", "state"])("rejects insecure existing %s permissions without silently fixing them", item => {
    add();
    const file = item === "manifest" ? rootsFile(ws.id) : item === "marker" ? rootsMarkerFile(ws.id)
      : item === "directory" ? path.dirname(rootsFile(ws.id)) : state;
    const previous = fs.statSync(file).mode & 0o777;
    const mode = item === "manifest" || item === "marker" ? 0o666 : 0o777;
    try {
      fs.chmodSync(file, mode);
      expectCode(() => listApprovedRoots(ws), "UNSAFE_ROOT_STATE");
      expectCode(() => prepareRootAddition(ws, "other", other), "UNSAFE_ROOT_STATE");
      expect(fs.statSync(file).mode & 0o777).toBe(mode);
    } finally { fs.chmodSync(file, previous); }
  });
  it.skipIf(process.platform === "win32")("rejects an owner mismatch (simulated UID, no privileged chown)", () => {
    add(); const uid = process.getuid!();
    vi.spyOn(process, "getuid").mockReturnValue(uid + 1);
    expectCode(() => listApprovedRoots(ws), "UNSAFE_ROOT_STATE");
  });
  it.each(["manifest", "marker"])("rejects hard-linked %s state", item => {
    add(); const file = item === "manifest" ? rootsFile(ws.id) : rootsMarkerFile(ws.id);
    const link = path.join(other, "hard-link"); fs.linkSync(file, link);
    expectCode(() => listApprovedRoots(ws), "UNSAFE_ROOT_STATE");
    fs.unlinkSync(link); expect(new WorkspaceRoots(ws).approved).toHaveLength(2);
  });
  it.each(["directory", "state"])("rejects a symlink/junction at the managed %s boundary", item => {
    add(); const file = item === "state" ? state : path.dirname(rootsFile(ws.id));
    const saved = path.join(other, "saved"); fs.renameSync(file, saved);
    try {
      fs.symlinkSync(saved, file, process.platform === "win32" ? "junction" : "dir");
      expectCode(() => listApprovedRoots(ws), "UNSAFE_ROOT_STATE");
    } finally { fs.rmSync(file, { force: true }); fs.renameSync(saved, file); }
  });
  it("detects substitution between lstat and open using the opened descriptor identity", () => {
    add(); const file = rootsFile(ws.id); const replacement = write(other, "replacement.json", fs.readFileSync(file, "utf8"));
    fs.chmodSync(replacement, 0o600);
    const open = fs.openSync.bind(fs);
    vi.spyOn(fs, "openSync").mockImplementation((name, flags, mode) => open(String(name) === file ? replacement : name, flags, mode));
    expectCode(() => new WorkspaceRoots(ws), "UNSAFE_ROOT_STATE");
  });
  it("bounds descriptor reads even if the file grows after lstat", () => {
    add(); const file = rootsFile(ws.id); const open = fs.openSync.bind(fs); let grown = false;
    vi.spyOn(fs, "openSync").mockImplementation((name, flags, mode) => {
      const fd = open(name, flags, mode);
      if (String(name) === file && !grown) { grown = true; fs.appendFileSync(file, "x".repeat(65537)); }
      return fd;
    });
    expectCode(() => new WorkspaceRoots(ws), "UNSAFE_ROOT_STATE");
  });
});

describe("offline revocation keeps runtime authorization strict", () => {
  it("revokes two offline roots one by one, retaining pins and invalidating tokens each time", () => {
    add(); add("other", other);
    const initial = new WorkspaceRoots(ws);
    const old = new AuthStore(ws.id, { authorizationVersion: initial.authorizationVersion });
    const tokens = old.issueTokens({ clientId: "test", scopes: ["workspace.read", "offline_access"] });
    const saved = listApprovedRoots(ws).find(r => r.name === "other");
    cleanup(dep); cleanup(other);
    commitRootChange(prepareRootRemoval(ws, "dep"));
    expect(listApprovedRoots(ws).find(r => r.name === "other")).toEqual(saved);
    expectCode(() => new WorkspaceRoots(ws), "ROOT_UNAVAILABLE");
    expectCode(() => initial.assertCurrent(), "ROOTS_CHANGED");
    commitRootChange(prepareRootRemoval(ws, "other"));
    const final = new WorkspaceRoots(ws);
    const current = new AuthStore(ws.id, { authorizationVersion: final.authorizationVersion });
    expect(final.approved.map(r => r.name)).toEqual(["main"]);
    expect(final.authorizationVersion).not.toBe(initial.authorizationVersion);
    expect(current.verifyAccessToken(tokens.accessToken).ok).toBe(false);
    expect(current.refresh(tokens.refreshToken!, "test").ok).toBe(false);
  });
  it("does not mistake a replacement for a pure removal based on a caller flag", () => {
    add(); const change = prepareRootRemoval(ws, "dep");
    const replacement = prepareRootAddition(ws, "other", other).config.roots.find(r => r.name === "other")!;
    change.config.roots.push(replacement);
    expectCode(() => commitRootChange(change), "ROOT_APPROVAL_REQUIRED");
    expect(new WorkspaceRoots(ws).approved.map(r => r.name)).toEqual(["main", "dep"]);
  });
  it("does not let removing one root silently re-pin a replaced retained root", () => {
    add(); add("other", other);
    const moved = path.join(main, "old-other"); fs.renameSync(other, moved); fs.mkdirSync(other);
    commitRootChange(prepareRootRemoval(ws, "dep"));
    expectCode(() => new WorkspaceRoots(ws), "ROOTS_CHANGED");
    commitRootChange(prepareRootRemoval(ws, "other"));
    expect(new WorkspaceRoots(ws).approved).toHaveLength(1);
  });
});
