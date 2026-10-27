// Runs an adapter as a child process speaking JSON lines (see ADAPTERS.md).

import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";

export type Manifest = {
  name: string;
  description: string;
  kind: "wallet" | "library" | "reference" | "example";
  command: string[];
  build?: string;
  dir: string;
};

export type Hello = { name: string; version: string; ops: string[]; profiles: string[] };

export type Response = Record<string, unknown> & { error?: { code: string; message?: string } };

export const ADAPTERS_DIR = resolve(import.meta.dirname, "../adapters");

export function loadManifests(dir = ADAPTERS_DIR): Manifest[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true })
    .filter((d) => d.isDirectory() && existsSync(join(dir, d.name, "adapter.json")))
    .map((d) => ({ ...JSON.parse(readFileSync(join(dir, d.name, "adapter.json"), "utf8")), dir: join(dir, d.name) }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

export class AdapterClient {
  readonly manifest: Manifest;
  private child: ChildProcess;
  private nextId = 1;
  private pending = new Map<number, (r: Response) => void>();
  private stderr = "";
  private exited: string | null = null;

  constructor(manifest: Manifest) {
    this.manifest = manifest;
    const [cmd, ...args] = manifest.command;
    this.child = spawn(cmd, args, { cwd: manifest.dir, stdio: ["pipe", "pipe", "pipe"] });
    this.child.stderr!.setEncoding("utf8").on("data", (d: string) => {
      this.stderr = (this.stderr + d).slice(-4000);
    });
    const failAll = (why: string) => {
      this.exited = why;
      for (const resolveFn of this.pending.values()) resolveFn({ error: { code: "adapter_exited", message: why } });
      this.pending.clear();
    };
    this.child.on("error", (e) => failAll(`could not start: ${e.message}`));
    this.child.on("exit", (code) => failAll(`exited with code ${code}. ${this.stderr.trim()}`.trim()));
    createInterface({ input: this.child.stdout! }).on("line", (line) => {
      let msg: Response;
      try {
        msg = JSON.parse(line);
      } catch {
        return; // not protocol output
      }
      const id = Number(msg.id);
      const resolveFn = this.pending.get(id);
      if (resolveFn) {
        this.pending.delete(id);
        resolveFn(msg);
      }
    });
  }

  request(op: string, params: Record<string, unknown> = {}, timeoutMs = 15_000): Promise<Response> {
    if (this.exited) return Promise.resolve({ error: { code: "adapter_exited", message: this.exited } });
    const id = this.nextId++;
    return new Promise((resolveFn) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        resolveFn({ error: { code: "timeout", message: `no response to ${op} within ${timeoutMs} ms` } });
      }, timeoutMs);
      this.pending.set(id, (r) => {
        clearTimeout(timer);
        resolveFn(r);
      });
      this.child.stdin!.write(JSON.stringify({ id, op, ...params }) + "\n");
    });
  }

  close() {
    this.child.stdin!.end();
    this.child.kill();
  }
}
