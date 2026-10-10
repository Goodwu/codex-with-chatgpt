# Security Model

## Trust boundaries

1. **Logical workspace** is the token audience. One bridge serves exactly one
   logical workspace, anchored by its main directory. Additional roots require
   explicit local approval outside repository content. Each selected root is
   still an independent path/deny-rule boundary; a token for project A cannot
   read project B. Tokens also bind the approved root-set revision, so existing
   authorization never silently expands when a directory is added.
2. **Workspace content is untrusted.** README, comments, diffs may contain
   prompt injection. Every MCP tool description carries an explicit warning and
   tools never grant capabilities based on file content.
3. **The model never sees long-lived credentials.** Computer Use only ever
   handles the one-time pairing code. Access/refresh tokens travel only inside
   the OAuth redirect/token endpoints between ChatGPT's client and the bridge.

## Threat model → mitigations

| Threat | Mitigation |
| --- | --- |
| MCP URL leaks | URL alone is useless: every `/mcp` request requires a valid bearer token (401 without, 403 wrong workspace) |
| Pairing code brute force | 8 chars from a 31-char CSPRNG alphabet (~40 bits), 5 attempts per session, per-IP rate limit (10/min), 5-minute TTL, one-time use, session destroyed on limit |
| OAuth CSRF | `state` round-tripped verbatim; authorization requests are server-side records keyed by random ids |
| Code interception | PKCE S256 mandatory (plain rejected); authorization codes are one-time, 5-minute TTL, bound to client + redirect URI |
| Token theft | Opaque high-entropy tokens; stored only as SHA-256 hashes; access tokens live 1 h; refresh tokens rotate on every use (replay of the old one fails); revocation endpoint + `c2c unpair` |
| Workspace traversal | `realpath` canonicalization of the deepest existing ancestor; containment check against the canonical root; canonical path-relative checks (without assuming macOS volumes are case-insensitive); rejects `..`, absolute escapes, backslash tricks, null bytes |
| Symlink escape | Canonicalization resolves symlinks before the containment check (file and directory symlinks both covered by tests) |
| Sensitive files | Deny-by-default patterns (.env*, keys, SSH, cloud creds, keychains…) enforced at resolve time — reads, listings, and search all pass through the same gate; `git diff` uses a rename-aware allowlist and literal pathspecs; `.env.example` allowed |
| Oversized file / diff DoS | read_file caps lines and bytes per response; git_diff paginates by byte offset with hard caps; search caps matches and file sizes |
| Tunnel exposure | Bridge binds 127.0.0.1 only (refuses 0.0.0.0); the only public surface is HTTPS via the tunnel, protected by OAuth; `/health` reveals only a path-derived workspace identifier (not an authentication secret) |
| Admin API abuse | Loopback-only + random admin token (0600 runtime file) + requests with proxy headers (`cf-connecting-ip`, `x-forwarded-for`) rejected; unauthenticated probes get 404 |
| Log credential leakage | Logger redacts token prefixes, bearer headers, token-like parameters, and pairing-code-shaped strings before writing |
| Execution output leak | Codex may nominate test/build/lint logs; a local sanitizer redacts tokens, pairing-code-shaped strings and home paths, truncates size, and refuses private-key blocks entirely. Restricted items are listed without a body. ChatGPT still cannot run commands. |
| Generated media handoff | ChatGPT's connector remains read-only. The local executor explicitly imports the original browser download into a new workspace-relative path; signatures, size, containment and SVG active-content checks are enforced, and existing files are never overwritten. |
| Checkpoint / resume dump | Session checkpoints store short protocol fields only (capped). Resume uses the existing chat or HANDOFF — no new protocol state, no log paste, no re-pairing. |

## Token & scope design

Scopes: `workspace.read`, `workspace.search`, `git.read`, `execution.read`,
`offline_access`. Tools enforce scopes individually (`INSUFFICIENT_SCOPE`).
Access tokens: 1 hour. Refresh tokens: 30 days, rotated. All tokens bound to
`workspace_id`, `client_id` and (after the first root change) the local root-set
authorization version. Removing all extra roots does not restore legacy tokens.

## Storage

State lives under the OS-convention app dir
(`~/Library/Application Support/codex-with-chatgpt` on macOS), directories 0700,
files 0600. Named-hostname preference and tunnel metadata live there too
(`tunnels/<workspaceId>.json`) — never in the project. Only SHA-256 hashes of
tokens are persisted — a stolen state file does not yield usable bearer tokens.

**V1 limitation**: client registrations and token hashes are file-based rather
than OS-keychain-based. Raw tokens are never written anywhere. Keychain
integration is a V2 item.

## What ChatGPT can never do (V1)

Write files, delete files, run shell commands, commit, install packages —
these tools do not exist on the server, so no prompt injection, scope bug, or
UI confusion can enable them.

## Multi-root extension

See [multi-root design and limits](multi-root.md) for the complete workflow.
The ten MCP tools remain read-only; only local `c2c roots` commands can change
root grants. Adding a root requires explicit `--approve`; removal also rotates
authorization. Root manifests use bounded, strict parsing, owner-only state,
atomic replacement, an exclusive lock and expected-version checks. Canonical
path/device/inode pins and request/response guards reject stale or replaced
roots. Old access tokens, refresh tokens and pending authorization flows fail
across changes, including remove/re-add cycles.

File, list, image, search and Git paths are checked within the **selected** root,
not merely within the union. Cross-approved-root symlinks stay blocked. Both
lexical and canonical sensitive paths are denied; default deny rules cannot be
negated, and project metadata reads go through the same gate. Root manifests
are never loaded from `.c2c.json`. Absolute root locations are local CLI data,
not added to `workspace_info` responses.

Git uses explicit worktree/metadata context, normalized subtree paths and
rename-aware filtering. Repository-defined external diff/textconv, filters,
fsmonitor and hooks are disabled, as are inherited Git configuration overrides
and recursive submodule inspection. No claim is made to sandbox a malicious
same-user OS process, compromised Git executable, or arbitrary filesystem races.
The trusted local executor and application state remain part of the trust base.


### Authorization storage review corrections

PR #2 incorporates PR #1's fail-closed storage properties without replacing the
retained Git/file boundaries. A durable activation marker precedes manifest
publication; missing JSON after activation, missing/bad markers, insecure POSIX
ownership/modes, hard-linked files and symlinked managed parents are rejected.
Descriptor identity and bounded reads are checked at open and completion. No
remote tool can repair or delete these objects. Files are fsynced before rename;
POSIX directories are synced, while Windows still relies on private account ACLs
and does not perform directory fsync. Ancestors above the application state root
remain part of the trusted OS/account environment; this is not an openat-style
sandbox against a hostile same-user process or rollback of the entire state.

Offline recovery can remove unchanged entries without resolving other extra
roots. It cannot replace/re-pin a retained root or bypass approval using a caller
flag. Runtime validation remains strict for every retained identity. `.codex`
and its subtree are part of the non-negatable built-in sensitive policy, including
when a directory itself is used as a root. See [recovery](multi-root.md#review-fixes-authorization-state-and-recovery)
for errors and pre-review development-state compatibility limits.
