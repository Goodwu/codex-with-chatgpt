import { beforeEach, afterEach, describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { Workspace } from "../src/workspace/manager.js";
import { rootsFile, WorkspaceRoots } from "../src/workspace/roots.js";
import { makeTmpDir, isolateStateDir, cleanup } from "./helpers.js";

let main: string, dep: string, state: string;
beforeEach(() => { state = isolateStateDir(); main = makeTmpDir("root-cli-main"); dep = makeTmpDir("root-cli-dep"); });
afterEach(() => { for (const dir of [main, dep, state]) cleanup(dir); delete process.env.C2C_STATE_DIR; });
function cli(...args: string[]) {
  const result = spawnSync(process.execPath, ["--import", "tsx/esm", "src/cli/index.ts", "roots", ...args, "-w", main, "--json"],
    { encoding: "utf8", env: { ...process.env }, timeout: 20_000 });
  return { status: result.status, data: JSON.parse(result.stdout) };
}

describe("c2c roots CLI", () => {
  it("lists a legacy workspace without writing a manifest", () => {
    const result = cli("list"); expect(result.status).toBe(0);
    expect(result.data.roots).toEqual([{ name: "main", path: main }]);
    expect(fs.existsSync(rootsFile(new Workspace(main).id))).toBe(false);
  });
  it("previews without side effects, explicitly adds, lists, and removes", () => {
    const denied = cli("add", "dep", dep); expect(denied.status).toBe(1);
    expect(denied.data.error).toBe("ROOT_APPROVAL_REQUIRED");
    expect(fs.existsSync(rootsFile(new Workspace(main).id))).toBe(false);
    const added = cli("add", "dep", dep, "--approve"); expect(added.status).toBe(0);
    expect(added.data.rePairRequired).toBe(true); expect(added.data.roots[1]).toEqual({ name: "dep", path: dep });
    const duplicate = cli("add", "dep", dep, "--approve"); expect(duplicate.data.changed).toBe(false);
    expect(duplicate.data.rePairRequired).toBe(false);
    expect(cli("list").data.roots).toHaveLength(2);
    const removed = cli("remove", "dep"); expect(removed.status).toBe(0); expect(removed.data.rePairRequired).toBe(true);
    expect(new WorkspaceRoots(new Workspace(main)).approved).toHaveLength(1);
  });
  it("lists and removes an offline directory", () => {
    expect(cli("add", "dep", dep, "--approve").status).toBe(0); cleanup(dep);
    expect(cli("list").data.roots).toHaveLength(2);
    expect(cli("remove", "dep").status).toBe(0);
  });
  it("reports success while revoking multiple offline roots one at a time", () => {
    const second = makeTmpDir("root-cli-second");
    try {
      expect(cli("add", "dep", dep, "--approve").status).toBe(0);
      expect(cli("add", "second", second, "--approve").status).toBe(0);
      cleanup(dep); cleanup(second);
      const first = cli("remove", "dep");
      expect(first.status).toBe(0); expect(first.data.rePairRequired).toBe(true);
      expect(first.data.roots.map((r: { name: string }) => r.name)).toEqual(["main", "second"]);
      expect(() => new WorkspaceRoots(new Workspace(main))).toThrow(/unavailable/);
      const last = cli("remove", "second");
      expect(last.status).toBe(0); expect(last.data.rePairRequired).toBe(true);
      expect(new WorkspaceRoots(new Workspace(main)).approved).toHaveLength(1);
    } finally { cleanup(second); }
  }, 30_000);
  it("does not start an uncertain bridge or mutate its root configuration", () => {
    const ws = new Workspace(main);
    fs.mkdirSync(path.join(state, "runtime"), { recursive: true });
    fs.writeFileSync(path.join(state, "runtime", ws.id + ".json"), JSON.stringify({
      workspaceId: ws.id, pid: process.pid, port: 1, adminToken: "unused", workspaceRoot: main,
    }));
    const result = cli("add", "dep", dep, "--approve");
    expect(result.status).toBe(1); expect(result.data.error).toBe("BRIDGE_STATE_UNKNOWN");
    expect(fs.existsSync(rootsFile(ws.id))).toBe(false);
  });
});
