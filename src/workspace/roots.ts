import fs from "node:fs";
import path from "node:path";
import ignore from "ignore";
import { Workspace } from "./manager.js";
import { SENSITIVE_PATTERNS } from "./ignore.js";
import { runGit, gitInfo, type GitInfo } from "./git.js";
import { getStateDir } from "../config/paths.js";
import { RootGrantError, RootGrantStore, type RootGrant, type RootSnapshot } from "./root-grants.js";

export function rootGrantStore(primary: Workspace): RootGrantStore {
  const deny = ignore().add([...SENSITIVE_PATTERNS, ".git/", ".codex/"]);
  return new RootGrantStore(primary.root, getStateDir(), absolute => {
    const rel = absolute.slice(path.parse(absolute).root.length).split(path.sep).join("/");
    return deny.ignores(rel) || deny.ignores(`${rel}/`);
  });
}

function checkMetadata(grant: RootGrant, store: RootGrantStore, snapshot: RootSnapshot): void {
  const deny = ignore().add(SENSITIVE_PATTERNS);
  for (const name of [".c2c.json", ".c2cignore", "package.json"]) {
    const { absolute } = store.resolve(snapshot, grant.name, name);
    const relative = path.relative(grant.path, absolute).split(path.sep).join("/");
    if (deny.ignores(relative)) throw new RootGrantError("ACCESS_DENIED_SENSITIVE_FILE", "Project metadata resolves to a sensitive file.");
    try {
      const stat = fs.statSync(absolute);
      fs.accessSync(absolute, fs.constants.R_OK);
      if (!stat.isFile() || stat.size > 256 * 1024) throw new RootGrantError("INVALID_ROOT_METADATA", "Project metadata must be a bounded regular file.");
    } catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e; }
  }
}

/** Additional guards only: the original per-root sensitive/ignore policy is retained. */
class GrantedWorkspace extends Workspace {
  constructor(private readonly grant: RootGrant, private readonly store: RootGrantStore, private readonly snapshot: RootSnapshot) {
    checkMetadata(grant, store, snapshot);
    super(grant.path);
  }
  override resolve(requested: string, opts: { allowSensitive?: boolean } = {}): { abs: string; rel: string } {
    this.store.resolve(this.snapshot, this.grant.name, requested);
    return super.resolve(requested, opts);
  }
  override detectProject(): ReturnType<Workspace["detectProject"]> {
    checkMetadata(this.grant, this.store, this.snapshot);
    // Project detection reads package.json directly upstream. Do not let it
    // bypass this root's custom policy or a sensitive symlink target.
    if (fs.existsSync(path.join(this.root, "package.json"))) this.resolve("package.json");
    return super.detectProject();
  }
}

export class WorkspaceRoots {
  readonly store: RootGrantStore;
  readonly snapshot: RootSnapshot;
  readonly authorizationRevision: string | undefined;
  private readonly workspaces = new Map<string, Workspace>();
  constructor(primary: Workspace) {
    this.store = rootGrantStore(primary);
    if (this.store.workspaceId !== primary.id) throw new RootGrantError("WORKSPACE_ID_MISMATCH", "Primary workspace identity changed.");
    this.snapshot = this.store.snapshot();
    this.authorizationRevision = this.snapshot.revision;
    for (const grant of this.snapshot.roots) {
      this.workspaces.set(grant.name, this.authorizationRevision ? new GrantedWorkspace(grant, this.store, this.snapshot) : primary);
    }
  }
  assertCurrent(): void { this.store.assertCurrent(this.snapshot); }
  catalog(): { name: string; isPrimary: boolean; readOnly: boolean }[] {
    this.assertCurrent();
    return this.snapshot.roots.map(r => ({ name: r.name, isPrimary: r.name === "main", readOnly: true }));
  }
  select(name = "main"): Workspace {
    this.assertCurrent();
    const workspace = this.workspaces.get(name);
    if (!workspace) throw new RootGrantError("UNKNOWN_ROOT", "Unknown root. Choose an authorized name from workspace_info.");
    return workspace;
  }
  git(name = "main"): Workspace {
    const workspace = this.select(name);
    if (this.authorizationRevision) {
      const top = runGit(workspace.root, ["rev-parse", "--show-toplevel"]);
      if (top.ok && fs.realpathSync.native(top.stdout.trim()) !== workspace.root) {
        throw new RootGrantError("GIT_ROOT_MISMATCH", "Git review requires the exact selected worktree root, not an enclosing repository.");
      }
    }
    return workspace;
  }
  info(name = "main"): GitInfo {
    try { return gitInfo(this.git(name).root); } catch (error) {
      // A files-only root can still be catalogued/read, without exposing a parent repo.
      if (error instanceof RootGrantError && error.code === "GIT_ROOT_MISMATCH") {
        return { isRepo: false, branch: null, commit: null, dirty: false };
      }
      throw error;
    }
  }
  /** Output provenance for managed roots; preserve legacy result shapes. */
  tag<T extends object>(name: string, value: T): T & { root?: string } {
    return this.authorizationRevision ? { ...value, root: name } : value;
  }
}
