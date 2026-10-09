import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { createHash, randomBytes } from "node:crypto";

/** Local authorization, never loaded from repository-controlled configuration. */
export interface RootGrant { name: string; path: string; dev: string; ino: string }
interface Manifest { version: 1; workspaceId: string; revision: string; roots: RootGrant[] }
export interface RootSnapshot {
  revision: string | undefined;
  fingerprint: string;
  roots: readonly RootGrant[];
}
export class RootGrantError extends Error {
  constructor(readonly code: string, message: string) { super(message); this.name = "RootGrantError"; }
}
const MAX_BYTES = 64 * 1024;
export const MAX_ROOTS = 16;
const fold = (s: string): string => process.platform === "linux" ? s : s.toLowerCase();
const inside = (base: string, child: string): boolean => {
  const rel = path.relative(fold(base), fold(child));
  return rel === "" || (!path.isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${path.sep}`));
};
function fail(code: string, message: string): never { throw new RootGrantError(code, message); }
function missing(e: unknown): boolean { return (e as NodeJS.ErrnoException).code === "ENOENT"; }
function identity(name: string, input: string): RootGrant {
  try {
    const real = fs.realpathSync.native(path.resolve(input));
    const stat = fs.statSync(real, { bigint: true });
    if (!stat.isDirectory()) throw new Error("not a directory");
    return { name, path: real, dev: String(BigInt.asUintN(64, stat.dev)), ino: String(BigInt.asUintN(64, stat.ino)) };
  } catch { return fail("ROOT_UNAVAILABLE", "An authorized directory is unavailable. Restore it or remove its grant locally."); }
}
export function validRootName(name: unknown): name is string {
  return typeof name === "string" && /^[a-z][a-z0-9_-]{0,31}$/.test(name)
    && !["constructor", "prototype", "__proto__"].includes(name);
}
function privateObject(file: string, directory: boolean): fs.Stats {
  const stat = fs.lstatSync(file);
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile())) {
    fail("UNSAFE_ROOT_STATE", "Directory authorization state must not use symlinks or special files.");
  }
  // Windows uses the existing per-user app-directory ACL, as in upstream storage.
  if (process.platform !== "win32" && ((stat.mode & 0o077) !== 0 ||
      (typeof process.getuid === "function" && stat.uid !== process.getuid()))) {
    fail("UNSAFE_ROOT_STATE", "Directory authorization state must be user-owned and private (0700 directories, 0600 files).");
  }
  if (!directory && stat.nlink !== 1) fail("UNSAFE_ROOT_STATE", "Authorization state must not be hard-linked.");
  return stat;
}
function readPrivate(file: string): Buffer {
  const stat = privateObject(file, false);
  if (stat.size > MAX_BYTES) fail("INVALID_ROOT_STATE", "Directory authorization state exceeds its size limit.");
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(fd);
    if (opened.dev !== stat.dev || opened.ino !== stat.ino) fail("UNSAFE_ROOT_STATE", "Authorization state changed during reading.");
    const bytes = Buffer.alloc(MAX_BYTES + 1);
    const n = fs.readSync(fd, bytes, 0, bytes.length, 0);
    if (n > MAX_BYTES) fail("INVALID_ROOT_STATE", "Directory authorization state exceeds its size limit.");
    return bytes.subarray(0, n);
  } finally { fs.closeSync(fd); }
}
function syncDirectory(dir: string): void {
  if (process.platform === "win32") return;
  const fd = fs.openSync(dir, "r");
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function atomicWrite(file: string, bytes: string): void {
  const temp = `${file}.${randomBytes(16).toString("hex")}.tmp`;
  try {
    const fd = fs.openSync(temp, "wx", 0o600);
    try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(temp, file);
    syncDirectory(path.dirname(file));
  } finally { fs.rmSync(temp, { force: true }); }
}

/** Stable workspace identity plus a fresh, non-reusable authorization epoch on every edit. */
export class RootGrantStore {
  readonly primary: RootGrant;
  readonly workspaceId: string;
  readonly stateDir: string;
  readonly directory: string;
  readonly file: string;
  private readonly marker: string;
  constructor(primaryRoot: string, stateDir: string, private readonly denyAbsolute?: (p: string) => boolean) {
    this.primary = identity("main", primaryRoot);
    this.workspaceId = createHash("sha256").update(fold(this.primary.path)).digest("hex").slice(0, 12);
    this.stateDir = path.resolve(stateDir);
    this.directory = path.join(this.stateDir, "root-grants");
    this.file = path.join(this.directory, `${this.workspaceId}.json`);
    this.marker = path.join(this.directory, `${this.workspaceId}.enabled`);
  }
  private validate(roots: RootGrant[], verifyIdentity: boolean): void {
    if (roots.length < 1 || roots.length > MAX_ROOTS || roots[0]?.name !== "main" ||
        roots[0]?.path !== this.primary.path) fail("INVALID_ROOT_STATE", "Invalid primary directory or root count.");
    const names = new Set<string>();
    const home = fs.realpathSync.native(os.homedir());
    let state = this.stateDir;
    try { state = fs.realpathSync.native(state); } catch { /* checked before writing */ }
    for (const root of roots) {
      if (!root || !validRootName(root.name) || names.has(root.name) || typeof root.path !== "string" ||
          !path.isAbsolute(root.path) || typeof root.dev !== "string" || !/^\d+$/.test(root.dev) ||
          typeof root.ino !== "string" || !/^\d+$/.test(root.ino)) fail("INVALID_ROOT_STATE", "Invalid or duplicate directory grant.");
      names.add(root.name);
      if (root.path === path.parse(root.path).root || inside(root.path, home) ||
          inside(root.path, state) || inside(state, root.path) || this.denyAbsolute?.(root.path)) {
        fail("UNSAFE_ROOT", "Do not authorize filesystem/home roots, private application state, or sensitive directories.");
      }
      if (verifyIdentity) {
        const now = identity(root.name, root.path);
        if (now.path !== root.path || now.dev !== root.dev || now.ino !== root.ino) {
          fail("ROOT_REPLACED", `Directory '${root.name}' was replaced. Remove and explicitly authorize it again.`);
        }
      }
    }
    for (let i = 0; i < roots.length; i++) for (let j = i + 1; j < roots.length; j++) {
      if (inside(roots[i].path, roots[j].path) || inside(roots[j].path, roots[i].path)) {
        fail("OVERLAPPING_ROOTS", "Directories must be distinct and non-nested; overlapping roots can bypass per-root policies.");
      }
    }
  }
  private readManifest(): { manifest: Manifest | null; bytes: Buffer } {
    // An untouched legacy workspace does not acquire new requirements on its state directory.
    try { fs.lstatSync(this.directory); } catch (e) {
      if (!missing(e)) throw e;
      return { manifest: null, bytes: Buffer.from("legacy") };
    }
    privateObject(this.stateDir, true);
    privateObject(this.directory, true);
    let marked = false;
    try { privateObject(this.marker, false); marked = true; } catch (e) { if (!missing(e)) throw e; }
    let bytes: Buffer;
    try { bytes = readPrivate(this.file); } catch (e) {
      if (!missing(e)) throw e;
      if (marked) fail("ROOT_STATE_MISSING", "Directory grants are missing; refusing to restore legacy authorization.");
      return { manifest: null, bytes: Buffer.from("legacy") };
    }
    if (!marked) fail("INVALID_ROOT_STATE", "Directory authorization activation marker is missing.");
    let value: unknown;
    try { value = JSON.parse(bytes.toString("utf8")); } catch { return fail("INVALID_ROOT_STATE", "Malformed directory authorization state."); }
    const m = value as Partial<Manifest> | null;
    if (!m || m.version !== 1 || m.workspaceId !== this.workspaceId || typeof m.revision !== "string" ||
        !/^[a-f0-9]{48}$/.test(m.revision) || !Array.isArray(m.roots)) {
      fail("INVALID_ROOT_STATE", "Invalid directory authorization state.");
    }
    this.validate(m.roots, false);
    return { manifest: m as Manifest, bytes };
  }
  snapshot(): RootSnapshot {
    const { manifest, bytes } = this.readManifest();
    const roots = manifest?.roots ?? [this.primary];
    if (manifest) this.validate(roots, true);
    return Object.freeze({
      revision: manifest?.revision,
      fingerprint: createHash("sha256").update(bytes).digest("hex"),
      roots: Object.freeze(roots.map(r => Object.freeze({ ...r }))),
    });
  }
  assertCurrent(snapshot: RootSnapshot): void {
    const current = this.snapshot();
    if (current.fingerprint !== snapshot.fingerprint) fail("ROOT_AUTHORIZATION_CHANGED", "Directory authorization changed. Restart this bridge and pair again.");
    for (const root of snapshot.roots) {
      const now = identity(root.name, root.path);
      if (now.path !== root.path || now.dev !== root.dev || now.ino !== root.ino) {
        fail("ROOT_REPLACED", "An authorized directory was replaced. Explicit authorization is required.");
      }
    }
  }
  /** A request resolves against ONE selected root, never against the union of grants. */
  resolve(snapshot: RootSnapshot, name: string, requested: string): { root: RootGrant; absolute: string } {
    this.assertCurrent(snapshot);
    const root = snapshot.roots.find(r => r.name === name);
    if (!root) fail("UNKNOWN_ROOT", "Choose an authorized root name from workspace_info.");
    if (typeof requested !== "string" || requested.includes("\0")) fail("INVALID_PATH", "Invalid relative path.");
    const rel = requested.trim().replace(/\\/g, "/").replace(/^workspace:\/*/i, "") || ".";
    if (path.posix.isAbsolute(rel) || path.win32.isAbsolute(rel) || rel.includes(":") || rel.split("/").includes("..")) {
      fail("INVALID_PATH", "Use a root name and a relative path; absolute paths, '..', drives and streams are not allowed.");
    }
    let ancestor = path.resolve(root.path, rel);
    const suffix: string[] = [];
    for (;;) {
      try { ancestor = fs.realpathSync.native(ancestor); break; } catch (e) {
        if (!missing(e) && (e as NodeJS.ErrnoException).code !== "ENOTDIR") throw e;
        const parent = path.dirname(ancestor);
        if (parent === ancestor) fail("INVALID_PATH", "Cannot resolve path.");
        suffix.unshift(path.basename(ancestor)); ancestor = parent;
      }
    }
    const absolute = path.join(ancestor, ...suffix);
    // Exact realpath comparison also protects case-sensitive volumes on macOS.
    const relative = path.relative(root.path, absolute);
    if (path.isAbsolute(relative) || relative === ".." || relative.startsWith(`..${path.sep}`)) {
      fail("PATH_OUTSIDE_WORKSPACE", "Path leaves the selected root. Cross-root symlinks are not allowed.");
    }
    return { root, absolute };
  }
  private mutate(change: (roots: RootGrant[]) => RootGrant[], verifyIdentity = true): { changed: boolean; revision?: string } {
    fs.mkdirSync(this.stateDir, { recursive: true, mode: 0o700 });
    privateObject(this.stateDir, true);
    fs.mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    privateObject(this.directory, true);
    const lock = `${this.file}.lock`;
    let fd: number;
    try { fd = fs.openSync(lock, "wx", 0o600); } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EEXIST") fail("ROOT_STATE_BUSY", "Another grant edit is active. Stale locks require local inspection.");
      throw e;
    }
    try {
      const before = this.readManifest().manifest;
      const original = before?.roots ?? [{ ...this.primary }];
      const next = change(original.map(r => ({ ...r })));
      this.validate(next, verifyIdentity);
      if (JSON.stringify(next) === JSON.stringify(original)) return { changed: false, revision: before?.revision };
      const revision = randomBytes(24).toString("hex");
      // Marker first; an interrupted first activation fails closed, not back to legacy.
      try {
        const mark = fs.openSync(this.marker, "wx", 0o600);
        try { fs.writeFileSync(mark, "Explicit directory authorization enabled.\n"); fs.fsyncSync(mark); }
        finally { fs.closeSync(mark); }
        syncDirectory(this.directory);
      } catch (e) { if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e; privateObject(this.marker, false); }
      atomicWrite(this.file, JSON.stringify({ version: 1, workspaceId: this.workspaceId, revision, roots: next } satisfies Manifest, null, 2) + "\n");
      return { changed: true, revision };
    } finally { fs.closeSync(fd); fs.unlinkSync(lock); }
  }
  add(name: string, directory: string, allowRead: boolean): { changed: boolean; revision?: string } {
    if (!allowRead) fail("CONSENT_REQUIRED", "Review the exact directory with the user, then pass --allow-read to grant this connector read access.");
    if (!validRootName(name) || name === "main") fail("INVALID_ROOT_NAME", "Use a lowercase name of 1-32 characters; 'main' is reserved.");
    const grant = identity(name, directory);
    return this.mutate(roots => {
      const prior = roots.find(r => r.name === name);
      if (prior) {
        if (JSON.stringify(prior) === JSON.stringify(grant)) return roots;
        fail("ROOT_NAME_EXISTS", "This name already has a grant. Remove it before authorizing another directory.");
      }
      return [roots[0], ...roots.slice(1).concat(grant).sort((a, b) => a.name.localeCompare(b.name))];
    });
  }
  remove(name: string): { changed: boolean; revision?: string } {
    if (name === "main") fail("PRIMARY_ROOT_REQUIRED", "The primary directory cannot be removed.");
    if (!validRootName(name)) fail("INVALID_ROOT_NAME", "Invalid root name.");
    // Does not resolve removed roots: an unavailable extra directory can be revoked.
    return this.mutate(roots => roots.filter(r => r.name !== name), false);
  }
}
