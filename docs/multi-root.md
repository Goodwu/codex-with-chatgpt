# 一个项目、多个目录 / Multi-root workspaces

同一个 C2C 工作区可以连接最多 16 个明确授权、互不嵌套的目录（含主目录）。
一个 Bridge、一个 ChatGPT 连接、一个 ChatGPT Project 和原有会话保持不变；
每个目录有独立的路径检查、敏感文件策略、`.c2cignore` 和 Git 审查目标。
这是可选功能：不添加目录时，原有单目录命令和工具调用继续工作。

## 推荐用法

向已安装新版 Skill 的 Codex 说明：

> 保持当前 media-kit 为主工作区，把 ~/src/mpv 和 ~/src/ffmpeg 加入同一个
> Codex with ChatGPT 项目，允许 ChatGPT 只读访问这两个目录。分别用 mpv 和
> ffmpeg 作别名，保留原来的连接、Project 和对话，并验证两个目录都能读取。

Codex 应确认具体路径与用户授权，调用本机命令，再完成一次重启和重新授权。
仓库中的 README、AGENTS.md 或 `.c2c.json` 不能授予此权限。

## 命令行

`-w` 始终指向原来的主项目。别名不是路径，不受当前工作目录影响。

```sh
node ~/codex-with-chatgpt/bin/c2c.js roots add mpv ~/src/mpv -w ~/src/media-kit --allow-read
node ~/codex-with-chatgpt/bin/c2c.js roots add ffmpeg ~/src/ffmpeg -w ~/src/media-kit --allow-read
node ~/codex-with-chatgpt/bin/c2c.js roots list -w ~/src/media-kit
# 一批修改完成后只重启、重新授权一次。
node ~/codex-with-chatgpt/bin/c2c.js restart -w ~/src/media-kit
node ~/codex-with-chatgpt/bin/c2c.js doctor -w ~/src/media-kit --json
```

使用 Skill 的 multi-root repair 流程重新授权**这个项目原有的连接**。
临时 Cloudflare 地址可能随重启变化；固定地址也仍需要重新授权新目录集合。
保留原 Project 和会话，不操作其他工作区的连接。重复添加同名、同路径、
同目录身份的授权是无操作，不需要重启。`--json` 可获得结构化结果。

```sh
# 仅撤销访问权，不删除文件。
node ~/codex-with-chatgpt/bin/c2c.js roots remove mpv -w ~/src/media-kit
node ~/codex-with-chatgpt/bin/c2c.js restart -w ~/src/media-kit
```

撤销后同样重新授权缩小的集合。重命名或改指向需要 remove + 明确授权 add。
`main` 不可删除。多个额外目录失联时可逐一 remove，剩余集合在恢复有效前
不会被提供给 ChatGPT。不要通过删除状态文件或改成共同父目录绕过错误。

## ChatGPT 工具

```text
workspace_info()                           # 主项目身份 + 授权别名目录
workspace_info(root="mpv")                # mpv 的语言、框架和 Git 概况
read_file(root="mpv", path="player/main.c")
list_directory(root="ffmpeg", path="libavcodec")
search_workspace(root="ffmpeg", query="avcodec_send_packet")
git_status(root="main")
git_diff(root="mpv", mode="head")
read_image(root="main", path="screenshots/frame.png")
```

省略 `root` 等于 `main`；未知别名直接报错，绝不退回主目录。路径只相对于
选中的根目录。搜索、Git Diff 和分页逐个目录调用，不合并不同仓库的偏移量。
托管多目录模式的文件/图片/搜索/Git结果带 `root` 字段以标识来源；
`workspace_info` 的项目 ID 和名称仍属于主工作区。

文件型目录可以不是 Git 仓库。Git 工具只接受该目录正好是工作树根目录的
情况，不向上借用其他仓库；Git linked worktree 支持保留。读取 Git 历史和
索引依然依赖正常的本地 Git 元数据，不能把不可信 Git 配置当作操作系统沙箱。

`test_status`、`execution_summary`、`execution_output` 仍属于整个项目：
执行器显式提交的日志沿用原有脱敏和大小限制。变更文件可写成
`mpv:player/main.c` 等带别名的标签。移除目录不可能抹除已返回给 ChatGPT 的
内容或此前已经释放的执行日志。

## Authorization model

The authoritative allowlist lives under the private OS C2C state directory,
not a repository manifest. There is no remote root-mutation MCP tool, no new
public admin mutation route, no automatic `--add-dir` import and no change to
the Codex write sandbox. The trusted local executor must obtain user consent
for the exact directory before passing `--allow-read`.

Each request selects one root. Existing sensitive/custom rules still apply;
canonical traversal and symlink checks do not treat the root set as a union.
Cross-root symlinks, duplicate/nested roots, sensitive mounts and private-state
mounts are rejected. Root path and filesystem identity are pinned; unavailable
or replaced directories fail closed. Aliases are bounded and validated, and
host paths are only displayed by local CLI output, not the MCP catalog.

Every actual change generates a fresh random authorization revision. Tokens
and authorization codes carry that revision. A running bridge refuses data
after an edit, and rechecks after tool operations and OAuth body parsing.
Restarting does not upgrade old access/refresh tokens: re-pairing is required.
Client registrations, primary workspace identity, Project and session remain.
Even remove + re-add cannot revive an earlier authorization revision.

Manifests are size-limited and written atomically under an exclusive lock.
On POSIX, directories/files must be user-owned 0700/0600; symlinks and hard
links are rejected. A missing activated manifest is an error, not an empty
allowlist. Stale locks and damaged local state need inspection. Do not reset
authorization or widen paths as an automated repair. Windows uses the original
per-user app-directory ACL assumption; mode bits are not a Windows ACL check.

This extension preserves the upstream trusted-local-executor boundary. It is
not an OS sandbox against a hostile same-user process editing private state
or racing filesystem operations; it does not establish absence of every
TOCTOU race in upstream file/search/image handling. See [security model](security.md).

## 验证

```sh
corepack pnpm install --frozen-lockfile
corepack pnpm typecheck
corepack pnpm build
corepack pnpm test
```

新增测试覆盖显式授权、兼容性、逐目录读取/搜索/Git/图片、路径越界、敏感文件、
重复/嵌套目录、损坏状态、目录替换、旧令牌/刷新令牌失效、真实配对流程、
请求执行期间的撤销和外部 Git/ripgrep 配置。GitHub Actions 同时运行
Linux、macOS 和 Windows 验证；以当前提交的实际 CI 结果为准。
