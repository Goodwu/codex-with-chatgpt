import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { getStateDir } from "../config/paths.js";
import { Workspace } from "./manager.js";
import ignore from "ignore";
import { SENSITIVE_PATTERNS } from "./ignore.js";
import { RootError, readRootState, withRootStateLock, writeRootState } from "./root-state.js";
export { RootError, rootsFile, rootsMarkerFile } from "./root-state.js";

export const MAX_WORKSPACE_ROOTS = 16;
const ALIAS = /^[a-z][a-z0-9_-]{0,31}$/;

/** Local-only authorization data. Never load root grants from repository files. */
export interface ApprovedRoot {
  name: string;
  path: string;
  dev: string;
  ino: string;
}

interface RootConfig {
  version: 1;
  workspaceId: string;
  revision: string;
  roots: ApprovedRoot[];
}

export interface RootChange {
  workspace: Workspace;
  expectedVersion: string | undefined;
  config: RootConfig;
  changed: boolean;
  expandsAccess: boolean;
}

function within(root: string, candidate: string): boolean {
  const rel = path.relative(root, candidate);
  return rel === "" || (!path.isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${path.sep}`));
}

function overlap(a: string, b: string): boolean {
  // Conservatively reject case-only overlap on common case-insensitive platforms.
  const fold = (p: string) => process.platform === "win32" || process.platform === "darwin" ? p.toLowerCase() : p;
  return within(fold(a), fold(b)) || within(fold(b), fold(a));
}

function pin(name: string, input: string): ApprovedRoot {
  let real: string;
  let stat: fs.BigIntStats;
  try {
    real = fs.realpathSync.native(path.resolve(input));
    stat = fs.statSync(real, { bigint: true });
  } catch {
    throw new RootError("ROOT_UNAVAILABLE", `Directory for root '${name}' is unavailable.`);
  }
  if (!stat.isDirectory()) throw new RootError("NOT_A_DIRECTORY", `Root '${name}' must be a directory.`);
  return { name, path: real, dev: stat.dev.toString(), ino: stat.ino.toString() };
}

function assertPinned(root: ApprovedRoot): void {
  const actual = pin(root.name, root.path);
  if (actual.path !== root.path || actual.dev !== root.dev || actual.ino !== root.ino) {
    throw new RootError("ROOTS_CHANGED", `Root '${root.name}' moved or was replaced. Remove and approve it again locally.`);
  }
}

function versionOf(config: RootConfig | null): string | undefined {
  // Undefined is deliberately the legacy single-directory authorization version.
  return config ? createHash("sha256").update(JSON.stringify(config)).digest("hex") : undefined;
}

function invalidConfig(): never {
  throw new RootError("ROOT_CONFIG_INVALID", "Invalid local root authorization state; refusing to fall back to a wider or older grant.");
}

function validateConfig(value: unknown, workspace: Workspace): RootConfig {
  if (!value || typeof value !== "object" || Array.isArray(value)) return invalidConfig();
  const v = value as Record<string, unknown>;
  if (v.version !== 1 || v.workspaceId !== workspace.id || typeof v.revision !== "string" ||
      !/^[a-f0-9]{32}$/.test(v.revision) || !Array.isArray(v.roots) ||
      v.roots.length < 1 || v.roots.length > MAX_WORKSPACE_ROOTS ||
      Object.keys(v).some(k => !["version", "workspaceId", "revision", "roots"].includes(k))) return invalidConfig();
  const roots: ApprovedRoot[] = [];
  for (const entry of v.roots) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return invalidConfig();
    const r = entry as Record<string, unknown>;
    if (typeof r.name !== "string" || !ALIAS.test(r.name) || typeof r.path !== "string" ||
        r.path.includes("\0") || !path.isAbsolute(r.path) || path.normalize(r.path) !== r.path ||
        typeof r.dev !== "string" || !/^\d+$/.test(r.dev) ||
        typeof r.ino !== "string" || !/^\d+$/.test(r.ino) ||
        Object.keys(r).some(k => !["name", "path", "dev", "ino"].includes(k))) return invalidConfig();
    const root = { name: r.name, path: r.path, dev: r.dev, ino: r.ino };
    if (roots.some(other => other.name === root.name || overlap(other.path, root.path))) return invalidConfig();
    roots.push(root);
  }
  if (roots[0].name !== "main" || roots[0].path !== workspace.root) return invalidConfig();
  return { version: 1, workspaceId: workspace.id, revision: v.revision, roots };
}

function readConfig(workspace: Workspace): RootConfig | null {
  const content = readRootState(workspace.id);
  if (content === null) return null;
  let parsed: unknown;
  try { parsed = JSON.parse(content); } catch { return invalidConfig(); }
  return validateConfig(parsed, workspace);
}

/** Local CLI metadata; removal must not require access to an offline directory. */
export function listApprovedRoots(primary: Workspace): readonly ApprovedRoot[] {
  return readConfig(primary)?.roots ?? [pin("main", primary.root)];
}

/** Read-only collection. Each tool selects exactly one independently contained root. */
export class WorkspaceRoots {
  readonly authorizationVersion: string | undefined;
  readonly approved: readonly ApprovedRoot[];
  private readonly workspaces = new Map<string, Workspace>();

  constructor(readonly primary: Workspace) {
    const config = readConfig(primary);
    this.authorizationVersion = versionOf(config);
    this.approved = config?.roots ?? [pin("main", primary.root)];
    for (const root of this.approved) {
      // Preserve legacy layouts (e.g. state nested in main and separately denied).
      if (this.authorizationVersion) assertSafeAddition(root); else assertNotSensitiveRoot(root);
      assertPinned(root);
    }
    this.workspaces.set("main", primary);
  }

  assertCurrent(): void {
    if (versionOf(readConfig(this.primary)) !== this.authorizationVersion) {
      throw new RootError("ROOTS_CHANGED", "Root authorization changed. Restart the bridge and pair again.");
    }
    for (const root of this.approved) {
      // Preserve legacy layouts (e.g. state nested in main and separately denied).
      if (this.authorizationVersion) assertSafeAddition(root); else assertNotSensitiveRoot(root);
      assertPinned(root);
    }
  }

  select(name = "main"): Workspace {
    this.assertCurrent();
    const root = this.approved.find(r => r.name === name);
    if (!root) throw new RootError("UNKNOWN_ROOT", `Unknown root '${name}'. Use workspace_info to see approved root names.`);
    let workspace = this.workspaces.get(name);
    if (!workspace) {
      workspace = new Workspace(root.path);
      this.workspaces.set(name, workspace);
    }
    return workspace;
  }
}

function assertSafeAddition(root: ApprovedRoot): void {
  const state = fs.existsSync(getStateDir()) ? fs.realpathSync.native(getStateDir()) : path.resolve(getStateDir());
  const home = fs.realpathSync.native(os.homedir());
  if (root.path === path.parse(root.path).root || root.path === home || overlap(root.path, state)) {
    throw new RootError("UNSAFE_ROOT", "Do not authorize the filesystem root, home directory, or a directory overlapping C2C state.");
  }
  assertNotSensitiveRoot(root);
}

function assertNotSensitiveRoot(root: ApprovedRoot): void {
  // A root named .ssh/.codex (or inside it) must not evade root-relative deny rules.
  const rel = path.relative(path.parse(root.path).root, root.path).split(path.sep).join("/");
  if (ignore().add(SENSITIVE_PATTERNS).ignores(rel) || ignore().add(SENSITIVE_PATTERNS).ignores(`${rel}/`)) {
    throw new RootError("UNSAFE_ROOT", "A root inside a sensitive directory cannot be authorized.");
  }
}

export function prepareRootAddition(workspace: Workspace, name: string, input: string): RootChange {
  if (!ALIAS.test(name) || name === "main") {
    throw new RootError("INVALID_ROOT_NAME", "Use a lowercase name (1-32 letters, digits, '-' or '_'); 'main' is reserved.");
  }
  const before = readConfig(workspace);
  const roots = before?.roots ?? [pin("main", workspace.root)];
  for (const root of roots) { assertSafeAddition(root); assertPinned(root); }
  const addition = pin(name, input);
  assertSafeAddition(addition);
  const existing = roots.find(root => root.name === name);
  if (existing && JSON.stringify(existing) === JSON.stringify(addition)) {
    return { workspace, expectedVersion: versionOf(before), config: before!, changed: false, expandsAccess: false };
  }
  if (roots.some(root => root.name === name || overlap(root.path, addition.path))) {
    throw new RootError("ROOT_CONFLICT", "Root names and canonical directories must be unique and non-overlapping.");
  }
  if (roots.length >= MAX_WORKSPACE_ROOTS) throw new RootError("ROOT_LIMIT", `At most ${MAX_WORKSPACE_ROOTS} roots are supported.`);
  return {
    workspace, expectedVersion: versionOf(before), changed: true, expandsAccess: true,
    config: { version: 1, workspaceId: workspace.id, revision: randomBytes(16).toString("hex"), roots: [...roots, addition] },
  };
}

export function prepareRootRemoval(workspace: Workspace, name: string): RootChange {
  if (name === "main") throw new RootError("PRIMARY_ROOT_REQUIRED", "The main root anchors this workspace and cannot be removed.");
  const before = readConfig(workspace);
  if (!before?.roots.some(root => root.name === name)) throw new RootError("UNKNOWN_ROOT", `Unknown root '${name}'.`);
  // Do not stat the removed directory: an offline/deleted root must remain removable.
  const roots = before.roots.filter(root => root.name !== name);
  assertPinned(roots[0]);
  return {
    workspace, expectedVersion: versionOf(before), changed: true, expandsAccess: false,
    config: { ...before, revision: randomBytes(16).toString("hex"), roots },
  };
}

/** Local CLI only. Atomic update + CAS + exclusive lock; never callable through MCP. */
export function commitRootChange(change: RootChange, approved = false): void {
  if (!change.changed) return;
  if (change.expandsAccess && !approved) throw new RootError("ROOT_APPROVAL_REQUIRED", "Review the canonical directory and repeat with --approve to authorize read access.");
  withRootStateLock(change.workspace.id, () => {
    const before = readConfig(change.workspace);
    if (versionOf(before) !== change.expectedVersion) {
      throw new RootError("ROOTS_CHANGED", "Another update changed the root list. Review it and retry.");
    }
    const next = validateConfig(change.config, change.workspace);
    if (before?.revision === next.revision) {
      throw new RootError("ROOTS_CHANGED", "A root update requires a fresh authorization revision.");
    }
    // Recovery may ONLY remove unchanged entries. Never trust a caller's
    // expandsAccess flag to skip identity/approval checks for a replacement.
    const removalOnly = before !== null && next.roots.length < before.roots.length &&
      next.roots.every(root => before.roots.some(old => JSON.stringify(root) === JSON.stringify(old)));
    assertPinned(next.roots[0]);
    if (!removalOnly) {
      if (!approved) throw new RootError("ROOT_APPROVAL_REQUIRED", "Directory additions or replacements require --approve.");
      for (const root of next.roots) { assertSafeAddition(root); assertPinned(root); }
    }
    // Unavailable retained roots remain pinned to their OLD identities. Runtime
    // checks still refuse all reads until they are restored or also revoked.
    writeRootState(change.workspace.id, JSON.stringify(next, null, 2) + "\n");
  });
}
