import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { getStateDir } from "../config/paths.js";

export class RootError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "RootError";
  }
}

const MAX_STATE_BYTES = 64 * 1024;
export const rootsFile = (id: string): string => path.join(getStateDir(), "workspace-roots", `${id}.json`);
export const rootsMarkerFile = (id: string): string => rootsFile(id) + ".enabled";
const markerBody = (id: string): string => `Root authorization enabled for ${id}.\n`;
const missing = (error: unknown): boolean => (error as NodeJS.ErrnoException).code === "ENOENT";

function unsafe(): never {
  throw new RootError("UNSAFE_ROOT_STATE", "Invalid local root authorization storage: require private user-owned directories/files, without symlinks or hard links.");
}

function checkStat(stat: fs.BigIntStats, directory: boolean): void {
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile())) unsafe();
  // Windows mode bits cannot validate ACLs. Keep the upstream private-user-directory
  // trust boundary there; type, links, identity and size checks still apply.
  if (process.platform !== "win32" && ((stat.mode & 0o077n) !== 0n ||
      (typeof process.getuid === "function" && stat.uid !== BigInt(process.getuid())))) unsafe();
  if (!directory && stat.nlink !== 1n) unsafe();
}

function statIfPresent(file: string, directory: boolean): fs.BigIntStats | null {
  let stat: fs.BigIntStats;
  try { stat = fs.lstatSync(file, { bigint: true }); }
  catch (error) { if (missing(error)) return null; throw error; }
  checkStat(stat, directory);
  return stat;
}

/** Validate BOTH managed parent directories, before following any child path. */
function stateDirectory(create = false): string | null {
  const state = getStateDir();
  const dir = path.join(state, "workspace-roots");
  for (const item of [state, dir]) {
    if (statIfPresent(item, true)) continue;
    if (!create) return null;
    fs.mkdirSync(item, { recursive: true, mode: 0o700 });
    if (!statIfPresent(item, true)) unsafe();
    syncDirectory(path.dirname(item));
  }
  return dir;
}

function sameFile(a: fs.BigIntStats, b: fs.BigIntStats): boolean {
  return a.dev === b.dev && a.ino === b.ino;
}

/** Bounded descriptor read; check again after opening and after reading. */
function readPrivate(file: string): string | null {
  const before = statIfPresent(file, false);
  if (!before) return null;
  if (before.size > BigInt(MAX_STATE_BYTES)) unsafe();
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    checkStat(opened, false);
    if (!sameFile(before, opened) || opened.size > BigInt(MAX_STATE_BYTES)) unsafe();
    const bytes = Buffer.alloc(MAX_STATE_BYTES + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = fs.readSync(fd, bytes, length, bytes.length - length, length);
      if (count === 0) break;
      length += count;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    checkStat(after, false);
    const current = statIfPresent(file, false);
    if (!current || !sameFile(opened, current) || !sameFile(opened, after) ||
        after.size !== BigInt(length) || after.mtimeNs !== opened.mtimeNs || after.ctimeNs !== opened.ctimeNs ||
        length > MAX_STATE_BYTES) unsafe();
    return bytes.subarray(0, length).toString("utf8");
  } finally { fs.closeSync(fd); }
}

/** Missing configuration is legacy ONLY if its independent activation marker is absent. */
export function readRootState(id: string): string | null {
  if (!stateDirectory()) return null;
  const marker = readPrivate(rootsMarkerFile(id));
  const content = readPrivate(rootsFile(id));
  if (marker !== null && marker !== markerBody(id)) unsafe();
  if (marker !== null && content === null) {
    throw new RootError("ROOT_STATE_MISSING", "Root grants are missing after activation. Restore verified local state; do not reset to legacy authorization.");
  }
  if (content !== null && marker === null) {
    throw new RootError("ROOT_MARKER_MISSING", "Root activation marker is missing. Refusing to adopt unverified or pre-review authorization state.");
  }
  return content;
}

function syncDirectory(dir: string): void {
  if (process.platform === "win32") return; // Directory fsync is not supported by Node on Windows.
  const fd = fs.openSync(dir, fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0));
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

/** Called under the root edit lock; never repairs insecure existing permissions. */
export function withRootStateLock<T>(id: string, callback: () => T): T {
  stateDirectory(true);
  const lock = rootsFile(id) + ".lock";
  let fd: number;
  try { fd = fs.openSync(lock, "wx", 0o600); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new RootError("ROOT_UPDATE_BUSY", "Another root update is active. No changes were made.");
    }
    throw error;
  }
  try { return callback(); }
  finally { fs.closeSync(fd); fs.unlinkSync(lock); }
}

/** Marker is durable BEFORE publishing the manifest. Interrupted activation fails closed. */
export function writeRootState(id: string, content: string): void {
  if (Buffer.byteLength(content) > MAX_STATE_BYTES) unsafe();
  const dir = stateDirectory();
  if (!dir) unsafe();
  // Revalidate both objects; do not silently recreate a lost marker or manifest.
  readRootState(id);
  const marker = rootsMarkerFile(id);
  if (!statIfPresent(marker, false)) {
    const fd = fs.openSync(marker, "wx", 0o600);
    try { fs.writeFileSync(fd, markerBody(id)); fs.fsyncSync(fd); }
    finally { fs.closeSync(fd); }
  }
  syncDirectory(dir);
  const temp = `${rootsFile(id)}.${randomBytes(16).toString("hex")}.tmp`;
  try {
    const fd = fs.openSync(temp, "wx", 0o600);
    try { fs.writeFileSync(fd, content); fs.fsyncSync(fd); }
    finally { fs.closeSync(fd); }
    fs.renameSync(temp, rootsFile(id));
    syncDirectory(dir);
  } finally { fs.rmSync(temp, { force: true }); }
}
