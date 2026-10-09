import { getStateDir } from "../config/paths.js";
import ignore, { type Ignore } from "ignore";
import fs from "node:fs";
import path from "node:path";

/**
 * Files that must never be readable through MCP, regardless of user config.
 * Matched with gitignore semantics against workspace-relative paths.
 */
export const SENSITIVE_PATTERNS: string[] = [
  ".git",
  ".git/",
  ".env",
  ".env.*",
  "!.env.example",
  "*.pem",
  "*.key",
  "*.p12",
  "*.pfx",
  "*.jks",
  "*.keystore",
  "id_rsa",
  "id_rsa.*",
  "id_ed25519",
  "id_ed25519.*",
  "id_ecdsa",
  "id_ecdsa.*",
  "id_dsa",
  "id_dsa.*",
  ".ssh/",
  ".aws/",
  ".gnupg/",
  ".npmrc",
  ".netrc",
  "_netrc",
  ".git-credentials",
  "*.keychain",
  "*.keychain-db",
  ".cloudflared/",
  "credentials.json",
  "service-account*.json",
  "secrets.json",
  "cookies.sqlite",
  "Cookies",
  ".c2c-secrets*",
];

/** High-noise directories excluded from listing/search by default. */
export const NOISE_PATTERNS: string[] = [
  ".git/",
  "node_modules/",
  "dist/",
  "build/",
  "out/",
  ".next/",
  ".nuxt/",
  ".svelte-kit/",
  "coverage/",
  ".cache/",
  ".turbo/",
  ".venv/",
  "venv/",
  "__pycache__/",
  ".pytest_cache/",
  ".mypy_cache/",
  "target/",
  ".gradle/",
  ".idea/",
  ".tooling/",
  ".pnpm-store/",
  ".DS_Store",
  "*.lock",
  "pnpm-lock.yaml",
  "package-lock.json",
  "yarn.lock",
];

export class IgnoreRules {
  private sensitive: Ignore;
  private noise: Ignore;
  private custom: Ignore;
  private readonly stateRelative: string | null;

  constructor(workspaceRoot: string) {
    const state = fs.existsSync(getStateDir()) ? fs.realpathSync.native(getStateDir()) : path.resolve(getStateDir());
    const relative = path.relative(workspaceRoot, state);
    this.stateRelative = !path.isAbsolute(relative) && relative !== ".." && !relative.startsWith(`..${path.sep}`)
      ? relative.split(path.sep).join("/") : null;
    this.sensitive = ignore().add(SENSITIVE_PATTERNS);
    this.noise = ignore().add(NOISE_PATTERNS);
    this.custom = ignore();
    const c2cignore = path.join(workspaceRoot, ".c2cignore");
    try {
      const info = fs.lstatSync(c2cignore);
      const real = fs.realpathSync.native(c2cignore);
      const rel = path.relative(workspaceRoot, real);
      if (!info.isFile() || info.isSymbolicLink() || path.isAbsolute(rel) || rel === ".." ||
          rel.startsWith(`..${path.sep}`) || info.size > 64 * 1024) {
        throw new Error("Invalid .c2cignore: policy must be a regular, bounded file inside its root.");
      }
      this.custom.add(fs.readFileSync(real, "utf8"));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }

  /** True when the path must be denied with ACCESS_DENIED_SENSITIVE_FILE. */
  isSensitive(relPath: string): boolean {
    if (!relPath || relPath === ".") return false;
    if (this.stateRelative !== null && (this.stateRelative === "" || relPath === this.stateRelative || relPath.startsWith(this.stateRelative + "/"))) return true;
    return this.sensitive.ignores(relPath) || this.custom.ignores(relPath);
  }

  /** True when the path should be hidden from listing/search (not an error). */
  isNoise(relPath: string): boolean {
    if (!relPath || relPath === ".") return false;
    return this.noise.ignores(relPath);
  }

  isHidden(relPath: string): boolean {
    return this.isSensitive(relPath) || this.isNoise(relPath);
  }
}
