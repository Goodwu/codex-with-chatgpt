# One project, multiple approved directories

A logical workspace keeps **one main directory, Bridge, connector, Project and
execution history**, but may expose up to 16 explicitly approved, non-overlapping
roots. Separate Git repositories and verified linked worktrees can be reviewed
through the same connector. Existing single-root setups need no migration.

## Quick start / 快速开始

These examples use an already built checkout. `c2c` means
`node "<checkout>/bin/c2c.js"` when the CLI is not globally linked.

```bash
# main is the existing project; dependency directories stay where they are.
c2c roots list -w ~/src/media-kit --json

# Preview only: shows canonical paths, exits 1, changes nothing.
c2c roots add mpv ~/src/mpv -w ~/src/media-kit --json

# Run only after explicitly approving that directory for ChatGPT read access.
c2c roots add mpv ~/src/mpv -w ~/src/media-kit --approve --json
c2c roots add ffmpeg ~/src/ffmpeg -w ~/src/media-kit --approve --json

# Start the same logical workspace and authorize its connector again.
c2c setup -w ~/src/media-kit --json
```

Add all intended roots before reauthorizing once. A changed grant stops the
verified running Bridge, revokes old authorization and returns
`rePairRequired: true`. Complete the existing connector's OAuth pairing again;
if the UI requires replacement, recreate only that exact connector name. Keep
the saved ChatGPT Project and conversations. A temporary tunnel may also get a
new URL. A stable hostname does **not** exempt the authorization change.

In Codex, a usable instruction is:

> 请把当前项目作为主目录，将 ~/src/mpv 和 ~/src/ffmpeg 加入同一个
> Codex with ChatGPT 项目。我明确同意 ChatGPT 只读访问这两个目录。
> 使用 mpv 和 ffmpeg 作为名称；保留现有 Project、对话和其他项目的连接。
> 先核对实际路径，授权完成后验证三个根目录的读取和 Git 状态。

Update the installed `skill/SKILL.md` from this checkout and fix its checkout
path as in the normal installation. The multi-root workflow is embedded in the
Skill; no additional Skill file is required. Use this feature branch's checkout,
not an older upstream build that does not understand the local root grants.

To remove a root (including an offline/deleted dependency directory):

```bash
c2c roots list -w ~/src/media-kit --json
c2c roots remove mpv -w ~/src/media-kit --json
c2c setup -w ~/src/media-kit --json
# Reauthorize the same connector; old tokens do not remain usable.
```

Always pass the **main** directory to setup, doctor, roots, session, record and
other project commands, even while editing a dependency. Registering a root
in another workspace does not grant access to it here. Codex's own additional
working-directory/sandbox permissions are separate: this feature does not
change them and does not make ChatGPT a writer.

## Read API

`workspace_info` returns the original project identity and a `roots` array with
`name`, `primary`, `projectType` and `git`. Absolute local root paths are not
included. Without `git.read`, Git metadata is `null` instead of bypassing scopes.

Six existing tools accept an optional `root` string; omission means `main`:

```text
read_file(root="mpv", path="player/main.c")
list_directory(root="ffmpeg", path="libavcodec")
search_workspace(root="mpv", query="video", limit=30)
read_image(root="main", path="screenshots/output.png")
git_status(root="mpv")
git_diff(root="ffmpeg", mode="unstaged")
```

Results identify their `root`; their paths remain relative to that root.
There is no wildcard root, automatic sibling discovery, aggregate diff mixing
repositories, or filesystem-path interpretation of a root name. To review a
cross-repository change, inspect each approved alias explicitly. Test records,
execution summaries and released command output still belong to the logical
workspace, so record commands under the main directory and label their working
directories in the command description. The tool inventory remains ten,
read-only. No MCP command can grant, remove, write or execute anything.

## Authorization design

* **Local, explicit grants.** Grants live in the private OS application state
  directory at `workspace-roots/<workspaceId>.json`, not in a checkout. Neither
  `.c2c.json`, README instructions, a symlink nor an MCP argument can grant a
  directory. `roots add` without `--approve` only previews. CLI access is part
  of the trusted local executor, not a capability available to ChatGPT.
* **Independent path boundaries.** Each alias has its own canonical Workspace
  and `.c2cignore`. Both lexical and resolved paths must stay in the selected
  root and pass default/custom deny rules. A symlink from root A to approved
  root B is still denied through A. Select B explicitly. Default deny rules
  cannot be negated by `.c2cignore`; `.git` and the C2C state subtree are denied.
* **Versioned authorization.** The main path-derived workspace ID remains stable
  for sessions/runtime. A separate digest of the root manifest and random
  revision is bound to access tokens, refresh tokens and authorization codes.
  Adding, removing or re-adding a root creates a new revision. Removing the last
  extra root retains a manifest: legacy authorization is never resurrected.
* **Fail closed.** Canonical path plus device/inode identity are pinned. Missing,
  replaced or retargeted roots, changed/corrupt/oversized/symlinked manifests
  prevent reads. The running Bridge checks its immutable grant snapshot at
  request entry and tool response completion, including in-flight async reads.
  Grant changes invalidate old refresh tokens as well as access tokens.
* **Bounded local updates.** Owner-only files, atomic replacement, an exclusive
  lock and an expected-version comparison prevent accidental concurrent
  overwrite. A CLI cannot update roots while a known Bridge remains running;
  uncertain runtime ownership fails rather than killing an unverified PID.
  Repeating an identical approved root is a no-op and does not revoke access.

New root aliases must be lowercase identifiers (1–32 characters, starting with a
letter; digits, `_` and `-` are allowed). `main` is reserved. Duplicate canonical
directories, ancestor/descendant overlaps, the filesystem root, the home
directory, sensitive directories and directories overlapping C2C state are
rejected. These conservative restrictions avoid ambiguous policy aliases.
Ordinary subdirectories of an approved root are already readable; they do not
need a second grant.

## Git review safety and compatibility

Each selected root is inspected independently. A root may be a repository or a
subtree of one; returned paths are root-relative. Status uses NUL-delimited
records. Diff inventories retain both sides of renames before applying the
selected boundary and deny rules, so a scoped patch cannot expose a sensitive
or out-of-root source through a rename. Patch pathspecs are top-level literals;
existing response pagination and byte caps remain.

Git calls do not inherit `GIT_*` overrides or global/system Git configuration.
The actual worktree and Git directory are supplied explicitly. External diff,
textconv, clean/smudge/process filters, fsmonitor, hooks, lazy fetching and
recursive submodule inspection are disabled. This can make a diff less pretty
than a user's custom local Git setup; the bridge must not run its scripts.

Normal repositories, verified linked worktrees and absorbed submodules with a
reciprocal `core.worktree` pointer are supported. Arbitrary `.git` symlinks or
external metadata redirects without a matching backlink are refused. A
submodule can be selected as its own main/approved root when it does not overlap
another grant; inspecting a parent does not silently recurse into its Git
history. Unverifiable Git layouts return `isRepo: false`; file tools remain
available inside their approved boundary.

References for the underlying Git behavior: [git-diff](https://git-scm.com/docs/git-diff),
[git-config](https://git-scm.com/docs/git-config),
[git-worktree](https://git-scm.com/docs/git-worktree),
and [git-submodule](https://git-scm.com/docs/git-submodule).

## Recovery and limits

For an offline extra root, list and remove it locally, then reauthorize. Restore
the same original directory to retain its identity, or remove/re-add a replaced
dependency with fresh approval. The primary root cannot be removed; moving the
main directory creates a different path-derived workspace. Do not hand-edit or
delete authorization manifests to work around a failure. An interrupted update
can leave a lock; confirm no update process owns it before local recovery.

The local CLI, the installed code, OS account/state directory and Git executable
remain trusted. Device/inode checks are conservative on filesystems whose
identities change after remount. This is not OS-level isolation against a
hostile same-user process racing arbitrary filesystem operations or restoring
old application state. Sensitive-pattern rules are not a general secret scanner:
secrets in an otherwise allowed source file still require an explicit deny rule.
Changes to `.c2cignore` take effect when that Workspace is recreated/restarted.

Automated tests cover legacy behavior, approval, scope isolation, paths,
symlinks, state tampering, revision changes, OAuth/HTTP revocation, in-flight
reads, root caps, CLI lifecycle refusal, independent Git, subtrees, worktrees,
submodules and non-execution of repository-defined Git helpers. Browser pairing
with a real ChatGPT account remains a separate end-to-end check; unit/HTTP tests
do not claim to complete that user-login flow.


## Review fixes: authorization state and recovery

The retained implementation is PR #2 (`feat/secure-multi-root-hardened`). PR #1
is closed; it supplies reviewed design properties, not a second implementation
to merge. Both arose from the same task. Commands continue to use `--approve`.

Activation now creates `workspace-roots/<workspaceId>.json.enabled` **before**
publishing the authorization JSON. The marker is retained after all extras are
removed. Marker/file contents are synced before publication; POSIX directory
entries are synced as well. A failed first publication leaves the marker and
blocks startup rather than silently returning to legacy permissions. An ordinary
single-root workspace with neither object does not create either on read/preview.

The application state directory and its `workspace-roots` child must be real,
private, user-owned directories. The marker and JSON must be single-linked regular
files. On POSIX, group/other access or a different owner is rejected on reads,
not merely corrected on creation. Reads use a bounded descriptor, no-follow flags
where supported, and identity/metadata checks after opening and reading. Windows
retains the upstream per-user application-directory ACL assumption; Node mode
bits do not verify ACLs. Directory fsync is not performed on Windows.

| Situation | Safe response |
| --- | --- |
| One or several extra directories are offline/replaced | `roots list`, then `roots remove <alias>` for each unwanted root. Removal preserves the other saved identities; it does not re-pin them. Restore or remove all unavailable roots before `setup` and re-pairing. |
| `ROOT_STATE_MISSING` | Stop. The marker exists but the grants do not. Restore verified local state; never remove the marker to make startup succeed. |
| `ROOT_MARKER_MISSING` | Stop. A JSON without its marker is not automatically adopted, including manifests made by pre-review development builds. Preserve it for local inspection; do not synthesize a marker or downgrade. |
| `UNSAFE_ROOT_STATE` | Stop and inspect ownership, permissions, links and integrity locally. Do not automatically chmod/chown or follow another state directory. |
| Interrupted first activation, no verified state to restore | Preserve the evidence, keep this workspace disconnected, and have the trusted local operator explicitly reconfigure and revoke its old authorization. This is not a browser reconnect error. |

There is no automatic import of either candidate's pre-review development state.
This does not migrate or overwrite PR #1's `root-grants` data. Do not point two
implementations at the same state directory or delete all state to defeat a
failure. Loss/rollback of the entire application state is outside the marker's
protection and the trusted-local-executor threat model.

`.codex` and its descendants are now denied by the same built-in policy used by
file, directory, search, image and Git tools. Custom ignore negations cannot
allow them. Explicit root approval, aliases or selecting a sensitive directory
as main cannot strip this protection. This is intentionally conservative: keep
code to be reviewed outside credential directories (including `.codex` subtrees).

A pure removal does not require surviving extra directories to be online, but it
must keep the primary identity and all retained grants unchanged. Additions still
require approval and live identity checks; concurrent edits still use the expected
version and an exclusive lock. A remaining offline root blocks runtime reads and
startup even when the CLI has successfully removed a different root.
