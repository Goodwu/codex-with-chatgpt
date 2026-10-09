import type { Command } from "commander";
import path from "node:path";
import { Workspace } from "../workspace/manager.js";
import { WorkspaceRoots, listApprovedRoots, RootError, prepareRootAddition, prepareRootRemoval, commitRootChange, type RootChange } from "../workspace/roots.js";
import { findBridgeObservation } from "../bridge/runtime.js";
import { adminFetch } from "../process/daemon.js";
import { AuthStore } from "../auth/store.js";

type Options = { workspace?: string; json: boolean; approve?: boolean };
const workspaceFor = (opts: Options) => new Workspace(path.resolve(opts.workspace ?? process.cwd()));
const print = (data: object) => process.stdout.write(JSON.stringify(data) + "\n");

function failure(error: unknown, opts: Options): void {
  const message = error instanceof Error ? error.message : String(error);
  if (opts.json) print({ ok: false, error: error instanceof RootError ? error.code : "ROOT_UPDATE_FAILED", message });
  else process.stderr.write(message + "\n");
  process.exitCode = 1;
}

async function stopForChange(workspace: Workspace): Promise<void> {
  const observed = await findBridgeObservation(workspace.id);
  if (observed.state === "stopped") return;
  if (observed.state !== "healthy") throw new RootError("BRIDGE_STATE_UNKNOWN", "Cannot confirm the bridge state. No root changes were made.");
  // Use the authenticated local admin endpoint, never kill an unverified/stale PID.
  await adminFetch(observed.runtime, "POST", "/admin/revoke-all", 5000);
  await adminFetch(observed.runtime, "POST", "/admin/shutdown", 5000);
  const deadline = Date.now() + 8000;
  do {
    await new Promise(resolve => setTimeout(resolve, 150));
    if ((await findBridgeObservation(workspace.id)).state === "stopped") return;
  } while (Date.now() < deadline);
  throw new RootError("BRIDGE_STOP_FAILED", "The bridge did not stop; root authorization was not changed.");
}

async function apply(change: RootChange, opts: Options): Promise<void> {
  if (change.changed && change.expandsAccess && !opts.approve) {
    const data = { ok: false, error: "ROOT_APPROVAL_REQUIRED", changed: false,
      roots: change.config.roots.map(root => ({ name: root.name, path: root.path })),
      message: "Review these canonical directories. Repeat with --approve only after the user explicitly approves read access." };
    if (opts.json) print(data);
    else process.stdout.write(data.message + "\n" + data.roots.map(root => `${root.name}\t${root.path}`).join("\n") + "\n");
    process.exitCode = 1;
    return;
  }
  if (change.changed) {
    await stopForChange(change.workspace);
    commitRootChange(change, opts.approve === true);
    new AuthStore(change.workspace.id).revokeAll();
  }
  const data = { ok: true, changed: change.changed, workspaceId: change.workspace.id,
    roots: new WorkspaceRoots(change.workspace).approved.map(root => ({ name: root.name, path: root.path })),
    rePairRequired: change.changed,
    nextStep: change.changed ? "Run c2c setup for this main workspace and authorize its existing connector again. Keep the Project and saved conversations." : null };
  if (opts.json) print(data);
  else process.stdout.write(data.roots.map(root => `${root.name}\t${root.path}`).join("\n") + "\n" + (data.nextStep ? data.nextStep + "\n" : ""));
}

export function registerRootsCommand(program: Command): void {
  const roots = program.command("roots").description("Manage explicitly approved read-only roots for one workspace");
  roots.command("list", { isDefault: true }).description("List locally approved directories")
    .option("-w, --workspace <path>", "main workspace directory").option("--json", "machine-readable output", false)
    .action((opts: Options) => {
      try {
        const workspace = workspaceFor(opts);
        const data = { ok: true, workspaceId: workspace.id, roots: listApprovedRoots(workspace).map(root => ({ name: root.name, path: root.path })) };
        if (opts.json) print(data);
        else process.stdout.write(data.roots.map(root => `${root.name}\t${root.path}`).join("\n") + "\n");
      } catch (error) { failure(error, opts); }
    });
  roots.command("add <name> <directory>").description("Approve another directory (preview without --approve)")
    .option("-w, --workspace <path>", "main workspace directory").option("--json", "machine-readable output", false)
    .option("--approve", "explicitly approve read access to the shown canonical directory", false)
    .action(async (name: string, directory: string, opts: Options) => {
      try { await apply(prepareRootAddition(workspaceFor(opts), name, directory), opts); }
      catch (error) { failure(error, opts); }
    });
  roots.command("remove <name>").description("Remove a directory and invalidate existing authorization")
    .option("-w, --workspace <path>", "main workspace directory").option("--json", "machine-readable output", false)
    .action(async (name: string, opts: Options) => {
      try { await apply(prepareRootRemoval(workspaceFor(opts), name), opts); }
      catch (error) { failure(error, opts); }
    });
}
