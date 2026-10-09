import type { Command } from "commander";
import path from "node:path";
import { Workspace } from "../workspace/manager.js";
import { rootGrantStore } from "../workspace/roots.js";

interface Options { workspace?: string; json?: boolean; allowRead?: boolean }
export function registerRootCommands(program: Command): void {
  const roots = program.command("roots").description("Manage explicitly authorized read-only directories for this project");
  const options = (cmd: Command): Command => cmd.option("-w, --workspace <path>", "Primary workspace directory")
    .option("--json", "Print machine-readable output");
  const store = (opts: Options) => rootGrantStore(new Workspace(path.resolve(opts.workspace ?? process.cwd())));
  const emit = (data: object, opts: Options, text: string): void => {
    process.stdout.write((opts.json ? JSON.stringify(data, null, 2) : text) + "\n");
  };
  options(roots.command("list").description("List directory grants; absolute paths are shown locally only"))
    .action((opts: Options) => {
      const grants = store(opts); const snapshot = grants.snapshot();
      const entries = snapshot.roots.map(r => ({ name: r.name, path: r.path, readOnly: true }));
      emit({ workspaceId: grants.workspaceId, roots: entries, managed: Boolean(snapshot.revision) }, opts,
        entries.map(r => `${r.name}\t${r.path}\t(read-only)`).join("\n"));
    });
  const report = (result: { changed: boolean; revision?: string }, opts: Options): void => {
    const message = result.changed
      ? "Directory authorization changed. Restart this workspace's bridge and re-pair its connector. Keep the same Project and conversation."
      : "No change; existing authorization is unchanged.";
    emit({ ...result, restartRequired: result.changed, reauthorizationRequired: result.changed, message }, opts, message);
  };
  options(roots.command("add <name> <directory>").description("Authorize a directory after obtaining consent for its exact path"))
    .option("--allow-read", "Explicitly grant this connector read access to this directory")
    .action((name: string, directory: string, opts: Options) => report(store(opts).add(name, path.resolve(directory), opts.allowRead === true), opts));
  options(roots.command("remove <name>").description("Revoke an extra directory; never deletes project files"))
    .action((name: string, opts: Options) => report(store(opts).remove(name), opts));
}
