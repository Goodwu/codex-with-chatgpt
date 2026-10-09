import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { startBridge, type Bridge } from "../src/bridge/server.js";
import { createMcpServer } from "../src/mcp/server.js";
import { Workspace } from "../src/workspace/manager.js";
import { WorkspaceRoots, rootGrantStore } from "../src/workspace/roots.js";
import { nullLogger } from "../src/logger/index.js";
import { runGit } from "../src/workspace/git.js";
import { makeTmpDir, cleanup, write, makeGitRepo, git, pkceVerifierAndChallenge } from "./helpers.js";

let base: string, main: string, extra: string, state: string, bridge: Bridge;
let clients: Client[], previousState: string | undefined;
const scopes = ["workspace.read", "workspace.search", "git.read", "execution.read", "offline_access"];
const mkdir = (p: string): string => { fs.mkdirSync(p, { recursive: true, mode: 0o700 }); return fs.realpathSync.native(p); };
function json(result: { content?: unknown }): Record<string, any> {
  return JSON.parse((result.content as { type: string; text: string }[])[0].text);
}
async function connect(token?: string): Promise<Client> {
  const client = new Client({ name: "multi-root-test", version: "1" });
  const access = token ?? bridge.authStore.issueTokens({ clientId: "test", scopes }).accessToken;
  await client.connect(new StreamableHTTPClientTransport(new URL(`${bridge.localBaseUrl()}/mcp`), {
    requestInit: { headers: { authorization: `Bearer ${access}` } },
  }));
  clients.push(client); return client;
}
async function start(): Promise<void> {
  bridge = await startBridge({ workspaceRoot: main, port: 0, persistRuntime: false });
}
function mcp(token?: string, name = "workspace_info", args: object = {}): Promise<Response> {
  return fetch(`${bridge.localBaseUrl()}/mcp`, {
    method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
  });
}
beforeEach(() => {
  base = makeTmpDir("multi-root"); main = mkdir(path.join(base, "main")); extra = mkdir(path.join(base, "extra")); state = mkdir(path.join(base, "state"));
  previousState = process.env.C2C_STATE_DIR; process.env.C2C_STATE_DIR = state; clients = [];
  makeGitRepo(main); makeGitRepo(extra);
  write(main, "same.txt", "MAIN ONLY\n"); write(extra, "same.txt", "EXTRA ONLY\n");
  write(extra, ".c2cignore", "private.txt\n"); write(extra, "private.txt", "PRIVATE NEEDLE\n");
  write(extra, ".env", "PRIVATE NEEDLE\n"); write(extra, ".env.example", "PUBLIC NEEDLE\n");
  write(extra, "src/index.ts", "export const answer = 12345; // EXTRA DIFF\n");
});
afterEach(async () => {
  vi.restoreAllMocks(); vi.unstubAllEnvs();
  for (const client of clients) await client.close();
  if (bridge) await bridge.close();
  if (previousState === undefined) delete process.env.C2C_STATE_DIR; else process.env.C2C_STATE_DIR = previousState;
  cleanup(base);
});

describe("multi-root MCP and authorization", () => {
  it("keeps ten read-only tools, primary identity and unambiguous per-root results", async () => {
    rootGrantStore(new Workspace(main)).add("extra", extra, true); await start(); const client = await connect();
    const { tools } = await client.listTools(); expect(tools).toHaveLength(10);
    expect(tools.every(t => t.annotations?.readOnlyHint)).toBe(true);
    expect(tools.some(t => /add|remove|write|execute/.test(t.name))).toBe(false);
    const info = json(await client.callTool({ name: "workspace_info", arguments: { root: "extra" } }));
    expect(info.workspaceId).toBe(new Workspace(main).id);
    expect(info.roots).toEqual([{ name: "main", isPrimary: true, readOnly: true }, { name: "extra", isPrimary: false, readOnly: true }]);
    expect(JSON.stringify(info)).not.toContain(base);
    const omitted = json(await client.callTool({ name: "read_file", arguments: { path: "same.txt" } }));
    const selected = json(await client.callTool({ name: "read_file", arguments: { root: "extra", path: "same.txt" } }));
    expect(omitted).toMatchObject({ root: "main", content: "MAIN ONLY" });
    expect(selected).toMatchObject({ root: "extra", content: "EXTRA ONLY" });
    const listed = json(await client.callTool({ name: "list_directory", arguments: { root: "extra" } }));
    expect(listed.root).toBe("extra"); expect(JSON.stringify(listed)).not.toContain("private.txt");
    const diff = json(await client.callTool({ name: "git_diff", arguments: { root: "extra" } }));
    expect(diff).toMatchObject({ root: "extra", isRepo: true }); expect(diff.diff).toContain("EXTRA DIFF");
    const primaryDiff = json(await client.callTool({ name: "git_diff", arguments: {} })); expect(primaryDiff.diff).not.toContain("EXTRA DIFF");
    const status = json(await client.callTool({ name: "git_status", arguments: { root: "extra" } }));
    expect(status.root).toBe("extra"); expect(JSON.stringify(status.untracked)).not.toContain("private.txt");
  });
  it("denies sensitive files, unknown roots, traversal and cross-root links", async () => {
    fs.symlinkSync(extra, path.join(main, "link"), process.platform === "win32" ? "junction" : "dir");
    rootGrantStore(new Workspace(main)).add("extra", extra, true); await start(); const client = await connect();
    for (const [args, code] of [
      [{ root: "extra", path: ".env" }, "ACCESS_DENIED_SENSITIVE_FILE"],
      [{ root: "extra", path: "private.txt" }, "ACCESS_DENIED_SENSITIVE_FILE"],
      [{ root: "missing", path: "same.txt" }, "UNKNOWN_ROOT"],
      [{ root: "main", path: "../extra/same.txt" }, "INVALID_PATH"],
      [{ root: "main", path: "link/same.txt" }, "PATH_OUTSIDE_WORKSPACE"],
    ] as const) {
      const result = await client.callTool({ name: "read_file", arguments: args });
      expect(result.isError).toBe(true); expect(json(result).error).toBe(code);
    }
    const publicFile = json(await client.callTool({ name: "read_file", arguments: { root: "extra", path: ".env.example" } }));
    expect(publicFile.content).toBe("PUBLIC NEEDLE");
  });
  it.each(["0", "1"])("search honors selected-root policies (C2C_DISABLE_RG=%s)", async disable => {
    vi.stubEnv("C2C_DISABLE_RG", disable);
    const rgConfig = write(base, "rg-config", "--follow\n--hidden\n--no-ignore\n");
    vi.stubEnv("RIPGREP_CONFIG_PATH", rgConfig);
    fs.symlinkSync(extra, path.join(main, "leak"), process.platform === "win32" ? "junction" : "dir");
    rootGrantStore(new Workspace(main)).add("extra", extra, true); await start(); const client = await connect();
    const selected = json(await client.callTool({ name: "search_workspace", arguments: { root: "extra", query: "EXTRA ONLY" } }));
    expect(selected.root).toBe("extra"); expect(selected.matchCount).toBe(1);
    const primary = json(await client.callTool({ name: "search_workspace", arguments: { query: "EXTRA ONLY" } })); expect(primary.matchCount).toBe(0);
    const secrets = json(await client.callTool({ name: "search_workspace", arguments: { root: "extra", query: "PRIVATE NEEDLE" } })); expect(secrets.matchCount).toBe(0);
  });
  it("returns image provenance and preserves the original scope boundary", async () => {
    fs.writeFileSync(path.join(extra, "pixel.png"), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1]));
    rootGrantStore(new Workspace(main)).add("extra", extra, true); await start();
    const token = bridge.authStore.issueTokens({ clientId: "read-only", scopes: ["workspace.read"] });
    const client = await connect(token.accessToken);
    const image = await client.callTool({ name: "read_image", arguments: { root: "extra", path: "pixel.png" } });
    expect(image.structuredContent).toMatchObject({ root: "extra", path: "pixel.png", mimeType: "image/png" });
    const denied = await client.callTool({ name: "git_diff", arguments: { root: "extra" } });
    expect(json(denied).error).toBe("INSUFFICIENT_SCOPE");
  });
  it("revokes old access and refresh tokens across live edit and restart; admin remains local", async () => {
    await start(); const old = bridge.authStore.issueTokens({ clientId: "old", scopes });
    expect((await mcp(old.accessToken)).status).toBe(200);
    rootGrantStore(new Workspace(main)).add("extra", extra, true);
    expect((await mcp()).status).toBe(401);
    expect((await mcp(old.accessToken, "read_file", { root: "extra", path: "same.txt" })).status).toBe(503);
    const admin = await fetch(`${bridge.localBaseUrl()}/admin/info`, { headers: { authorization: `Bearer ${bridge.adminToken}` } });
    expect((await admin.json()).rootAuthorization.current).toBe(false);
    const proxy = await fetch(`${bridge.localBaseUrl()}/admin/info`, { headers: { authorization: `Bearer ${bridge.adminToken}`, "x-forwarded-for": "203.0.113.1" } }); expect(proxy.status).toBe(404);
    await bridge.close(); await start();
    expect((await mcp(old.accessToken)).status).toBe(401);
    const refreshed = await fetch(`${bridge.localBaseUrl()}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", client_id: "old", refresh_token: old.refreshToken! }) });
    expect(refreshed.status).toBe(400); expect((await refreshed.json()).error).toBe("invalid_grant");
    const client = await connect(); expect(json(await client.callTool({ name: "read_file", arguments: { root: "extra", path: "same.txt" } })).content).toBe("EXTRA ONLY");
    rootGrantStore(new Workspace(main)).remove("extra");
    await client.close(); clients = []; await bridge.close(); await start();
    const reduced = await connect(); expect(json(await reduced.callTool({ name: "read_file", arguments: { root: "extra", path: "same.txt" } })).error).toBe("UNKNOWN_ROOT");
  });
  it("completes real pairing + PKCE for the root set and shows aliases without host paths", async () => {
    rootGrantStore(new Workspace(main)).add("extra", extra, true); await start();
    const redirect = "http://127.0.0.1:19999/callback";
    const registration = await fetch(`${bridge.localBaseUrl()}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ client_name: "roots", redirect_uris: [redirect] }) });
    const clientId = (await registration.json()).client_id;
    const { verifier, challenge } = pkceVerifierAndChallenge();
    const authorize = new URL(`${bridge.localBaseUrl()}/oauth/authorize`);
    authorize.search = new URLSearchParams({ client_id: clientId, redirect_uri: redirect, response_type: "code", code_challenge: challenge, code_challenge_method: "S256", scope: scopes.join(" ") }).toString();
    const html = await (await fetch(authorize)).text(); expect(html).toContain("Authorized directories: main, extra"); expect(html).not.toContain(base);
    const requestId = html.match(/name="request_id" value="([a-f0-9]+)"/)?.[1]; expect(requestId).toBeTruthy();
    const codeResponse = await fetch(`${bridge.localBaseUrl()}/oauth/authorize`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ request_id: requestId!, pairing_code: bridge.pairing.create().code }) });
    expect(codeResponse.status).toBe(302); const code = new URL(codeResponse.headers.get("location")!).searchParams.get("code")!;
    const exchanged = await fetch(`${bridge.localBaseUrl()}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", client_id: clientId, redirect_uri: redirect, code_verifier: verifier, code }) });
    expect(exchanged.status).toBe(200); const token = (await exchanged.json()).access_token;
    const client = await connect(token); expect(json(await client.callTool({ name: "read_file", arguments: { root: "extra", path: "same.txt" } })).content).toBe("EXTRA ONLY");
  });
  it("rechecks authorization after a slow OAuth body is parsed", async () => {
    await start(); const body = JSON.stringify({ client_name: "late", redirect_uris: ["https://example.com/callback"] });
    const response = new Promise<number>(resolve => {
      const req = http.request(`${bridge.localBaseUrl()}/oauth/register`, { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) } }, res => { res.resume(); resolve(res.statusCode!); });
      req.write(body.slice(0, 10));
      // First chunk crosses the router; the second arrives after the local grant edit.
      setTimeout(() => { rootGrantStore(new Workspace(main)).add("extra", extra, true); req.end(body.slice(10)); }, 50);
    });
    expect(await response).toBe(503); expect(bridge.authStore.tokenCount()).toBe(0);
  });
  it("withholds in-flight file content if a grant changes before the result is returned", async () => {
    const store = rootGrantStore(new Workspace(main)); store.add("extra", extra, true);
    const workspace = new Workspace(main); const roots = new WorkspaceRoots(workspace);
    const selected = roots.select("extra"); const original = selected.readFile.bind(selected);
    let signal!: () => void, release!: () => void;
    const entered = new Promise<void>(r => { signal = r; }); const gate = new Promise<void>(r => { release = r; });
    vi.spyOn(selected, "readFile").mockImplementation(async (...args) => { const value = await original(...args); signal(); await gate; return value; });
    const server = createMcpServer({ workspace, roots, logger: nullLogger });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "inflight", version: "1" }); clients.push(client);
    await server.connect(serverTransport); await client.connect(clientTransport);
    const result = client.callTool({ name: "read_file", arguments: { root: "extra", path: "same.txt" } });
    await entered; store.remove("extra"); release();
    const data = await result; expect(data.isError).toBe(true); expect(json(data).error).toBe("ROOT_AUTHORIZATION_CHANGED"); expect(JSON.stringify(data)).not.toContain("EXTRA ONLY");
    await server.close();
  });
  it("does not let inherited Git routing or external textconv/diff helpers expand read capabilities", async () => {
    rootGrantStore(new Workspace(main)).add("extra", extra, true);
    vi.stubEnv("GIT_DIR", path.join(extra, ".git")); vi.stubEnv("GIT_WORK_TREE", extra);
    expect(fs.realpathSync.native(runGit(main, ["rev-parse", "--show-toplevel"]).stdout.trim())).toBe(main);
    const marker = path.join(base, "helper-ran");
    const script = write(base, "helper.cjs", `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'executed'); console.log('LEAK');`);
    const command = `"${process.execPath}" "${script}"`;
    git(extra, "config", "diff.external", command); git(extra, "config", "diff.custom.textconv", command);
    git(extra, "config", "core.fsmonitor", command);
    git(extra, "config", "filter.custom.clean", command); git(extra, "config", "filter.custom.process", command);
    git(extra, "config", "filter.custom.required", "true");
    write(extra, ".gitattributes", "*.ts diff=custom filter=custom\n");
    await start(); const client = await connect();
    const diff = json(await client.callTool({ name: "git_diff", arguments: { root: "extra" } }));
    expect(diff.diff).toContain("EXTRA DIFF"); expect(fs.existsSync(marker)).toBe(false);
  });
});
