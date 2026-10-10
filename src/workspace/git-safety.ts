import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

interface RepositoryContext { worktree: string; gitDir: string; prefix: string }

function smallFile(file: string): string {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 16 * 1024) throw new Error("Invalid Git metadata pointer");
  return fs.readFileSync(file, "utf8").trim();
}

function inside(root: string, candidate: string): boolean {
  const rel = path.relative(root, candidate);
  return rel === "" || (!path.isAbsolute(rel) && rel !== ".." && !rel.startsWith(`..${path.sep}`));
}

/** Discover from the filesystem, not core.worktree or inherited GIT_DIR. */
function repositoryContext(root: string): RepositoryContext | null {
  const canonicalRoot = fs.realpathSync.native(root);
  let current = canonicalRoot;
  const ceilings = (process.env.GIT_CEILING_DIRECTORIES ?? "").split(path.delimiter).filter(Boolean).map(p => path.resolve(p));
  for (;;) {
    if (current !== canonicalRoot && ceilings.includes(current)) return null;
    const marker = path.join(current, ".git");
    let stat: fs.Stats | undefined;
    try { stat = fs.lstatSync(marker); } catch { /* try parent */ }
    if (stat) {
      try {
        if (stat.isSymbolicLink()) return null;
        let gitDir: string;
        if (stat.isDirectory()) gitDir = fs.realpathSync.native(marker);
        else {
          const text = smallFile(marker);
          if (!text.startsWith("gitdir: ")) return null;
          gitDir = fs.realpathSync.native(path.resolve(current, text.slice(8)));
          if (!inside(current, gitDir)) {
            // Legitimate linked worktrees have a reciprocal gitdir pointer and
            // live under the common repository's worktrees directory. An arbitrary
            // .git symlink/file pointing at another repository is not a grant.
            if (fs.existsSync(path.join(gitDir, "commondir"))) {
              const backlink = fs.realpathSync.native(smallFile(path.join(gitDir, "gitdir")));
              const common = fs.realpathSync.native(path.resolve(gitDir, smallFile(path.join(gitDir, "commondir"))));
              if (backlink !== marker || !inside(path.join(common, "worktrees"), gitDir)) return null;
            } else {
              // Absorbed submodules have a reciprocal core.worktree entry in
              // their OWN config. Do not follow includes or inherited config.
              const config = path.join(gitDir, "config");
              smallFile(config);
              const back = spawnSync("git", ["config", "--no-includes", "--file", config, "--get", "core.worktree"], {
                cwd: current, env: gitEnvironment(), encoding: "utf8", timeout: 10_000,
                maxBuffer: 16 * 1024, windowsHide: true,
              });
              if (back.error || back.status !== 0 || !back.stdout.trim() ||
                  fs.realpathSync.native(path.resolve(gitDir, back.stdout.trim())) !== current) return null;
            }
          }
        }
        if (!fs.statSync(gitDir).isDirectory()) return null;
        // Never follow a second common-dir redirect from a normal .git directory.
        if (stat.isDirectory() && fs.existsSync(path.join(gitDir, "commondir"))) return null;
        const prefix = path.relative(current, canonicalRoot).split(path.sep).join("/");
        return { worktree: current, gitDir, prefix: prefix ? prefix + "/" : "" };
      } catch { return null; }
    }
    const parent = path.dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

export function workspaceGitPrefix(root: string): string | null {
  try { return repositoryContext(root)?.prefix ?? null; } catch { return null; }
}

// Git for Windows recognizes /dev/null; Node os.devNull is not a Git config path.
function gitEnvironment(): NodeJS.ProcessEnv {
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.toUpperCase().startsWith("GIT_")));
  return Object.assign(env, {
    GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null", GIT_CONFIG_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0", GIT_OPTIONAL_LOCKS: "0", GIT_NO_LAZY_FETCH: "1",
  });
}

/** Prevent read commands from running repository-defined filters/hooks/helpers. */
export function safeGitInvocation(root: string): { args: string[]; env: NodeJS.ProcessEnv } | null {
  let repo: RepositoryContext | null;
  try { repo = repositoryContext(root); } catch { return null; }
  if (!repo) return null;
  const env = gitEnvironment();
  const args = ["--no-pager", `--git-dir=${repo.gitDir}`, `--work-tree=${repo.worktree}`,
    "-c", "core.fsmonitor=", "-c", "core.untrackedCache=false", "-c", "core.hooksPath=/dev/null",
    "-c", "diff.relative=false", "-c", "status.relativePaths=false", "-c", "core.quotePath=false"];
  // --no-textconv does NOT disable clean/process filters used when comparing
  // worktree files. Enumerate names without executing them, then disable each.
  const filters = spawnSync("git", [...args, "config", "--null", "--get-regexp", "^filter\\..*\\.(clean|smudge|process|required)$"],
    { cwd: root, env, encoding: "utf8", timeout: 10_000, maxBuffer: 64 * 1024, windowsHide: true });
  if (filters.error || (filters.status !== 0 && filters.status !== 1)) return null;
  const entries = (filters.stdout ?? "").split("\0").filter(Boolean);
  if (entries.length > 256) return null;
  for (const entry of entries) {
    const key = entry.split("\n", 1)[0];
    if (!/^filter\..*\.(clean|smudge|process|required)$/.test(key)) return null;
    args.push("-c", `${key}=${key.endsWith(".required") ? "false" : ""}`);
  }
  return { args, env };
}
