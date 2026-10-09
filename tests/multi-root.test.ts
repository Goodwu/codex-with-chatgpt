import { afterEach, beforeEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { Workspace } from "../src/workspace/manager.js";
import { WorkspaceRoots, rootsFile, prepareRootAddition, prepareRootRemoval, commitRootChange } from "../src/workspace/roots.js";
import { AuthStore } from "../src/auth/store.js";
import { startBridge, type Bridge } from "../src/bridge/server.js";
import { cleanup, isolateStateDir, makeTmpDir, write, makeGitRepo, git, pkceVerifierAndChallenge } from "./helpers.js";

let main: string, dep: string, other: string, state: string, ws: Workspace;
let bridge: Bridge | undefined;
const clients: Client[] = [];
const allScopes = ["workspace.read", "workspace.search", "git.read", "execution.read", "offline_access"];
const body = (result: any) => JSON.parse(result.content[0].text);
const add = (name = "dep", directory = dep) => commitRootChange(prepareRootAddition(ws, name, directory), true);

beforeEach(() => {
  state = isolateStateDir(); main = makeTmpDir("roots-main"); dep = makeTmpDir("roots-dep"); other = makeTmpDir("roots-other");
  write(main, "same.txt", "MAIN marker\n"); write(dep, "same.txt", "DEP marker\n"); write(other, "same.txt", "OUTSIDE marker\n");
  ws = new Workspace(main);
});
afterEach(async () => {
  for (const client of clients.splice(0)) await client.close();
  if (bridge) { await bridge.close(); bridge = undefined; }
  for (const dir of [main, dep, other, state]) cleanup(dir);
  delete process.env.C2C_STATE_DIR;
});

async function connect(scopes = allScopes): Promise<Client> {
  bridge ??= await startBridge({ workspaceRoot: main, port: 0, persistRuntime: false });
  const tokens = bridge.authStore.issueTokens({ clientId: "test-client", scopes });
  const client = new Client({ name: "multi-root-test", version: "1" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${bridge.localBaseUrl()}/mcp`), {
    requestInit: { headers: { authorization: `Bearer ${tokens.accessToken}` } },
  }));
  clients.push(client); return client;
}

function symlink(target: string, link: string, directory = false): boolean {
  try { fs.symlinkSync(target, link, directory && process.platform === "win32" ? "junction" : directory ? "dir" : "file"); return true; }
  catch { return false; }
}

describe("local root authorization", () => {
  it("ignores root grants injected into .c2c.json", () => {
    write(main, ".c2c.json", JSON.stringify({ name: "demo", roots: [{ name: "stolen", path: other }] }));
    const roots = new WorkspaceRoots(new Workspace(main));
    expect(roots.approved.map(root => root.name)).toEqual(["main"]);
    expect(roots.authorizationVersion).toBeUndefined();
    expect(() => roots.select("stolen")).toThrow(/Unknown root/);
  });
  it("requires explicit approval and stores grants only in owner-only local state", () => {
    const change = prepareRootAddition(ws, "dep", dep);
    expect(() => commitRootChange(change)).toThrow(/--approve/);
    expect(fs.existsSync(rootsFile(ws.id))).toBe(false);
    commitRootChange(change, true);
    expect(fs.readdirSync(main)).toEqual(["same.txt"]);
    expect(new WorkspaceRoots(ws).approved.map(root => root.name)).toEqual(["main", "dep"]);
    if (process.platform !== "win32") expect(fs.statSync(rootsFile(ws.id)).mode & 0o777).toBe(0o600);
  });
  it("preserves workspace identity, and duplicate approvals are idempotent", () => {
    const id = ws.id; add();
    const version = new WorkspaceRoots(ws).authorizationVersion;
    const duplicate = prepareRootAddition(ws, "dep", dep);
    expect(duplicate.changed).toBe(false); commitRootChange(duplicate);
    expect(new WorkspaceRoots(ws).authorizationVersion).toBe(version);
    expect(new Workspace(main).id).toBe(id);
  });
  it.each(["main", "../dep", "/tmp", "Dep", "a/b", "a\\b", "", "x".repeat(33)])("rejects invalid/reserved alias %j", name => {
    expect(() => prepareRootAddition(ws, name, dep)).toThrow();
  });
  it("enforces the root count cap without mutating an existing grant", () => {
    const dirs: string[] = [];
    try {
      for (let i = 1; i <= 15; i++) {
        const dir = makeTmpDir(`root-cap-${i}`); dirs.push(dir); add(`dep${i}`, dir);
      }
      const before = new WorkspaceRoots(ws).authorizationVersion;
      expect(() => prepareRootAddition(ws, "extra", dep)).toThrow(/At most 16/);
      expect(new WorkspaceRoots(ws).authorizationVersion).toBe(before);
    } finally { for (const dir of dirs) cleanup(dir); }
  });
  it("rejects duplicate physical roots and ancestor/descendant overlap", () => {
    add(); fs.mkdirSync(path.join(dep, "child"));
    expect(() => prepareRootAddition(ws, "alias", dep)).toThrow(/unique/);
    expect(() => prepareRootAddition(ws, "nested", path.join(dep, "child"))).toThrow(/unique/);
    expect(() => prepareRootAddition(ws, "parent", path.dirname(dep))).toThrow();
    expect(() => prepareRootAddition(ws, "copy", main)).toThrow(/unique/);
  });
  it("rejects roots that expose C2C state, filesystem root, or credential directories", () => {
    fs.mkdirSync(path.join(other, ".ssh", "nested"), { recursive: true });
    for (const directory of [state, path.parse(main).root, path.join(other, ".ssh"), path.join(other, ".ssh", "nested")]) {
      expect(() => prepareRootAddition(ws, "bad", directory)).toThrow();
    }
  });
  it("uses canonical paths and catches symlink retargeting", () => {
    const link = path.join(other, "alias");
    if (!symlink(dep, link, true)) return;
    add("dep", link);
    expect(new WorkspaceRoots(ws).approved[1].path).toBe(dep);
    fs.unlinkSync(link); symlink(main, link, true);
    expect(new WorkspaceRoots(ws).select("dep").root).toBe(dep);
  });
  it("detects physical directory replacement", () => {
    add(); const roots = new WorkspaceRoots(ws); const moved = dep + "-old";
    fs.renameSync(dep, moved);
    try { fs.mkdirSync(dep); expect(() => roots.select("dep")).toThrow(/replaced/); }
    finally { cleanup(dep); fs.renameSync(moved, dep); }
  });
  it("removes missing roots, keeps main and never resurrects a legacy grant", () => {
    add(); const old = new WorkspaceRoots(ws).authorizationVersion; cleanup(dep);
    commitRootChange(prepareRootRemoval(ws, "dep"));
    const roots = new WorkspaceRoots(ws);
    expect(roots.approved.map(root => root.name)).toEqual(["main"]);
    expect(roots.authorizationVersion).toBeDefined(); expect(roots.authorizationVersion).not.toBe(old);
    expect(() => prepareRootRemoval(ws, "main")).toThrow(/cannot be removed/);
  });
  it("fails closed for corrupted, oversized, or symlinked authorization state", () => {
    add(); const roots = new WorkspaceRoots(ws); const file = rootsFile(ws.id); const good = fs.readFileSync(file);
    for (const bad of ["{", "null", "{}", " ".repeat(65537)]) {
      fs.writeFileSync(file, bad); expect(() => roots.assertCurrent()).toThrow(/Invalid local/);
    }
    fs.writeFileSync(file, good); fs.unlinkSync(file);
    const outside = write(other, "grants.json", good.toString());
    if (symlink(outside, file)) expect(() => new WorkspaceRoots(ws)).toThrow(/Invalid local/);
  });
  it("serializes concurrent modifications with a lease and an exclusive lock", () => {
    const first = prepareRootAddition(ws, "dep", dep); const stale = prepareRootAddition(ws, "other", other);
    commitRootChange(first, true);
    expect(() => commitRootChange(stale, true)).toThrow(/Another update/);
    const next = prepareRootAddition(ws, "other", other);
    fs.writeFileSync(rootsFile(ws.id) + ".lock", "busy");
    expect(() => commitRootChange(next, true)).toThrow(/Another root update/);
    expect(new WorkspaceRoots(ws).approved).toHaveLength(2);
  });
  it("invalidates access and refresh tokens, including after remove/re-add", () => {
    const legacy = new AuthStore(ws.id).issueTokens({ clientId: "client", scopes: allScopes });
    add(); const firstRoots = new WorkspaceRoots(ws);
    const first = new AuthStore(ws.id, { authorizationVersion: firstRoots.authorizationVersion });
    expect(first.verifyAccessToken(legacy.accessToken).ok).toBe(false);
    expect(first.refresh(legacy.refreshToken!, "client").ok).toBe(false);
    const issued = first.issueTokens({ clientId: "client", scopes: allScopes });
    commitRootChange(prepareRootRemoval(ws, "dep")); add();
    const next = new AuthStore(ws.id, { authorizationVersion: new WorkspaceRoots(ws).authorizationVersion });
    expect(next.verifyAccessToken(issued.accessToken).ok).toBe(false);
    expect(next.refresh(issued.refreshToken!, "client").ok).toBe(false);
    expect(() => firstRoots.select()).toThrow(/changed/);
  });
});

describe("multi-root MCP and OAuth", () => {
  it("selects by alias, returns provenance and retains all ten read-only tools", async () => {
    makeGitRepo(main); makeGitRepo(dep); add();
    const client = await connect(); const tools = (await client.listTools()).tools;
    expect(tools).toHaveLength(10); expect(tools.every(tool => tool.annotations?.readOnlyHint)).toBe(true);
    const mainResult = body(await client.callTool({ name: "read_file", arguments: { path: "same.txt" } }));
    const depResult = body(await client.callTool({ name: "read_file", arguments: { root: "dep", path: "same.txt" } }));
    expect(mainResult).toMatchObject({ root: "main", content: "MAIN marker" });
    expect(depResult).toMatchObject({ root: "dep", content: "DEP marker" });
    const info = body(await client.callTool({ name: "workspace_info", arguments: {} }));
    expect(info.workspaceId).toBe(ws.id); expect(info.roots.map((r: any) => r.name)).toEqual(["main", "dep"]);
    expect(info.roots.every((r: any) => r.git.isRepo)).toBe(true);
    expect(JSON.stringify(info)).not.toContain(dep); expect(JSON.stringify(info)).not.toContain(main);
    const unknown = await client.callTool({ name: "read_file", arguments: { root: "unknown", path: "same.txt" } });
    expect(unknown.isError).toBe(true); expect(body(unknown).error).toBe("UNKNOWN_ROOT");
  });
  it("blocks traversal and symlinks even into another approved root", async () => {
    add(); const linked = symlink(main, path.join(dep, "other-root"), true); const client = await connect();
    for (const p of [path.join(main, "same.txt"), "../" + path.basename(main) + "/same.txt", "..\\" + path.basename(main) + "\\same.txt", ...(linked ? ["other-root/same.txt"] : [])]) {
      const result = await client.callTool({ name: "read_file", arguments: { root: "dep", path: p } });
      expect(result.isError).toBe(true); expect(JSON.stringify(result)).not.toContain("MAIN marker");
    }
  });
  it("enforces each root's .c2cignore on read/list/search/git and cannot unignore built-in secrets", async () => {
    makeGitRepo(main); makeGitRepo(dep);
    write(dep, ".c2cignore", "private.txt\n!.env\n"); write(dep, "private.txt", "private needle\n");
    write(dep, "public.txt", "visible needle\n"); write(dep, ".env", "secret needle\n"); write(dep, ".env.example", "example needle\n");
    write(main, "private.txt", "main public needle\n"); git(dep, "add", "-f", ".env", ".env.example", "private.txt");
    add(); const client = await connect();
    for (const p of ["private.txt", ".env", ".git/config"]) {
      expect((await client.callTool({ name: "read_file", arguments: { root: "dep", path: p } })).isError).toBe(true);
    }
    expect(body(await client.callTool({ name: "read_file", arguments: { path: "private.txt" } })).content).toContain("main public");
    const listing = body(await client.callTool({ name: "list_directory", arguments: { root: "dep" } }));
    expect(listing.entries.some((e: any) => e.path === "private.txt" || e.path === ".env")).toBe(false);
    const search = body(await client.callTool({ name: "search_workspace", arguments: { root: "dep", query: "needle" } }));
    expect(search.matches.map((m: any) => m.path)).toContain("public.txt");
    expect(body(await client.callTool({ name: "read_file", arguments: { root: "dep", path: ".env.example" } })).content).toContain("example needle");
    expect(JSON.stringify(search)).not.toMatch(/secret needle|private needle/);
    const diff = body(await client.callTool({ name: "git_diff", arguments: { root: "dep", mode: "staged" } }));
    expect(diff.diff).toContain("example needle"); expect(diff.diff).not.toMatch(/secret needle|private needle/);
    const status = body(await client.callTool({ name: "git_status", arguments: { root: "dep" } }));
    expect(status.hidden.changes).toBeGreaterThan(0); expect(JSON.stringify(status.staged)).not.toContain("private.txt");
  });
  it("reads images from the selected root and does not bypass scopes", async () => {
    fs.writeFileSync(path.join(dep, "pixel.png"), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1]));
    add(); const client = await connect(["workspace.read"]);
    const image = await client.callTool({ name: "read_image", arguments: { root: "dep", path: "pixel.png" } });
    expect(image.structuredContent).toMatchObject({ root: "dep", mimeType: "image/png" });
    for (const name of ["git_status", "git_diff", "search_workspace"]) {
      const result = await client.callTool({ name, arguments: { root: "dep", query: "marker" } });
      expect(body(result).error).toBe("INSUFFICIENT_SCOPE");
    }
    const info = body(await client.callTool({ name: "workspace_info", arguments: {} }));
    expect(info.git).toBeNull(); expect(info.roots.every((r: any) => r.git === null)).toBe(true);
  });
  it("rejects stale HTTP/OAuth requests and old tokens after restarting", async () => {
    bridge = await startBridge({ workspaceRoot: main, port: 0, persistRuntime: false });
    const old = bridge.authStore.issueTokens({ clientId: "old", scopes: allScopes });
    add();
    expect((await fetch(`${bridge.localBaseUrl()}/mcp`, { method: "POST", headers: { authorization: `Bearer ${old.accessToken}`, "content-type": "application/json" }, body: "{}" })).status).toBe(503);
    expect((await fetch(`${bridge.localBaseUrl()}/oauth/token`, { method: "POST", body: new URLSearchParams({ grant_type: "refresh_token", client_id: "old", refresh_token: old.refreshToken! }) })).status).toBe(503);
    await bridge.close(); bridge = await startBridge({ workspaceRoot: main, port: 0, persistRuntime: false });
    expect((await fetch(`${bridge.localBaseUrl()}/mcp`, { method: "POST", headers: { authorization: `Bearer ${old.accessToken}` } })).status).toBe(401);
    expect((await fetch(`${bridge.localBaseUrl()}/oauth/token`, { method: "POST", body: new URLSearchParams({ grant_type: "refresh_token", client_id: "old", refresh_token: old.refreshToken! }) })).status).toBe(400);
  });
  it("withholds an in-flight read if root authorization changes before the response", async () => {
    const client = await connect();
    const original = bridge!.workspace.readFile.bind(bridge!.workspace);
    bridge!.workspace.readFile = async (...args) => {
      const result = await original(...args);
      add();
      return result;
    };
    const result = await client.callTool({ name: "read_file", arguments: { path: "same.txt" } });
    expect(result.isError).toBe(true);
    expect(body(result).error).toBe("ROOTS_CHANGED");
    expect(JSON.stringify(result)).not.toContain("MAIN marker");
  });
  it("shows the approved root aliases on the pairing consent page", async () => {
    add(); await connect(); const registered = bridge!.authStore.registerClient({ redirectUris: ["https://example.com/callback"] });
    const { challenge } = pkceVerifierAndChallenge();
    const query = new URLSearchParams({ client_id: registered.clientId, redirect_uri: "https://example.com/callback", response_type: "code", code_challenge: challenge, code_challenge_method: "S256" });
    const response = await fetch(`${bridge!.localBaseUrl()}/oauth/authorize?${query}`); const html = await response.text();
    expect(response.status).toBe(200); expect(html).toContain("<li>main</li>"); expect(html).toContain("<li>dep</li>"); expect(html).not.toContain(dep);
  });
});
