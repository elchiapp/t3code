// @effect-diagnostics nodeBuiltinImport:off -- Tests use private temporary installation fixtures.
import { expect, it, vi } from "vite-plus/test";
import * as NodeFSP from "node:fs/promises";
import * as NodePath from "node:path";
import * as NodeOS from "node:os";
import * as NodeCrypto from "node:crypto";
import {
  createManagedVerifierRuntime,
  createVerifierSupervisor,
  readManagedRuntime,
} from "./verifierRuntime.ts";

it("shares cold startup across requests and restarts only its own exited process", async () => {
  let release!: (value: boolean) => void;
  const firstProbe = new Promise<boolean>((resolve) => {
    release = resolve;
  });
  const children: Array<{ live: boolean; stop: ReturnType<typeof vi.fn> }> = [];
  const probe = vi.fn().mockResolvedValue(false).mockReturnValueOnce(firstProbe);
  const start = vi.fn(async () => {
    const child = { live: true, stop: vi.fn() };
    children.push(child);
    return { alive: () => child.live, stop: child.stop };
  });
  const supervisor = createVerifierSupervisor({ probe, start, ready: async () => {} });
  const first = supervisor.ensure();
  const second = supervisor.ensure();
  expect(first).toBe(second);
  release(false);
  await Promise.all([first, second]);
  expect(start).toHaveBeenCalledTimes(1);
  children[0]!.live = false;
  await supervisor.ensure();
  expect(start).toHaveBeenCalledTimes(2);
  supervisor.stop();
  expect(children[0]!.stop).not.toHaveBeenCalled();
  expect(children[1]!.stop).toHaveBeenCalledOnce();
});

it("leaves a healthy existing verifier outside its ownership", async () => {
  const start = vi.fn();
  const supervisor = createVerifierSupervisor({
    probe: async () => true,
    start,
    ready: async () => {},
  });
  await supervisor.ensure();
  supervisor.stop();
  expect(start).not.toHaveBeenCalled();
});

it("stops a failed owned startup and allows the next check to repair it", async () => {
  const stop = vi.fn();
  const start = vi.fn(async () => ({ alive: () => true, stop }));
  const ready = vi
    .fn()
    .mockRejectedValueOnce(new Error("startup failed"))
    .mockResolvedValue(undefined);
  const supervisor = createVerifierSupervisor({ probe: async () => false, start, ready });
  await expect(supervisor.ensure()).rejects.toThrow("startup failed");
  expect(stop).toHaveBeenCalledOnce();
  await supervisor.ensure();
  expect(start).toHaveBeenCalledTimes(2);
  supervisor.stop();
});

it("does not leave a process behind when quitting overlaps startup", async () => {
  const stop = vi.fn();
  let started!: (value: { alive: () => boolean; stop: () => void }) => void;
  const pendingChild = new Promise<{ alive: () => boolean; stop: () => void }>((resolve) => {
    started = resolve;
  });
  let beginning!: () => void;
  const beginningPromise = new Promise<void>((resolve) => {
    beginning = resolve;
  });
  const supervisor = createVerifierSupervisor({
    probe: async () => false,
    start: () => {
      beginning();
      return pendingChild;
    },
    ready: async () => {},
  });
  const result = supervisor.ensure();
  await beginningPromise;
  supervisor.stop();
  started({ alive: () => true, stop });
  await expect(result).rejects.toThrow("closing");
  expect(stop).toHaveBeenCalledOnce();
});

async function fixture(platform = "darwin") {
  const support = await NodeFSP.mkdtemp(NodePath.join(NodeOS.tmpdir(), "t3-owned-verifier-"));
  const app = NodePath.join(support, "T3 Attested.app");
  const runtime = NodePath.join(support, "VerificationRuntime", "test-1");
  await NodeFSP.mkdir(runtime, { recursive: true, mode: 0o700 });
  const executable = platform === "win32" ? "node.exe" : "node";
  const files = [];
  for (const path of [executable, "start.mjs"]) {
    const content = Buffer.from("test-only " + path);
    await NodeFSP.writeFile(NodePath.join(runtime, path), content, { mode: 0o700 });
    files.push({ path, sha256: NodeCrypto.createHash("sha256").update(content).digest("hex") });
  }
  const receipt = { installed: true, app, runtime, release: "test-1" };
  await NodeFSP.writeFile(
    NodePath.join(support, "installer-receipt.json"),
    JSON.stringify(receipt),
    { mode: 0o600 },
  );
  await NodeFSP.writeFile(
    NodePath.join(runtime, "manifest.json"),
    JSON.stringify({ version: 1, release: "test-1", files }),
    { mode: 0o600 },
  );
  return {
    support,
    app,
    runtime,
    receipt,
    [Symbol.asyncDispose]: () => NodeFSP.rm(support, { recursive: true, force: true }),
  };
}

it.each(["darwin", "linux", "win32"])("uses a verified local profile on %s", async (platform) => {
  await using f = await fixture(platform);
  const profile = await readManagedRuntime(f.support, f.app, platform);
  expect(profile.root).toBe(f.runtime);
  expect(NodePath.basename(profile.executable)).toBe(platform === "win32" ? "node.exe" : "node");
});

it("refuses changed code and an arbitrary runtime path before executing anything", async () => {
  await using f = await fixture();
  await NodeFSP.writeFile(NodePath.join(f.runtime, "start.mjs"), "changed");
  await expect(readManagedRuntime(f.support, f.app, "darwin")).rejects.toThrow("code changed");
  await NodeFSP.writeFile(
    NodePath.join(f.support, "installer-receipt.json"),
    JSON.stringify({ ...f.receipt, runtime: "/other/code" }),
  );
  await expect(readManagedRuntime(f.support, f.app, "darwin")).rejects.toThrow("does not match");
});

it("refuses linked runtime code", async () => {
  await using f = await fixture();
  await NodeFSP.rename(
    NodePath.join(f.runtime, "start.mjs"),
    NodePath.join(f.runtime, "original.mjs"),
  );
  await NodeFSP.symlink(
    NodePath.join(f.runtime, "original.mjs"),
    NodePath.join(f.runtime, "start.mjs"),
  );
  await expect(readManagedRuntime(f.support, f.app, "darwin")).rejects.toThrow("not trusted");
});

it("does not start a late eager request after the app has already quit", async () => {
  const retireLegacy = vi.fn();
  const runtime = createManagedVerifierRuntime({
    support: "/unused",
    app: "/unused",
    platform: "darwin",
    retireLegacy,
  });
  runtime.stop();
  await expect(runtime.ensure("http://127.0.0.1:43210", "https://vm.example:8447")).rejects.toThrow(
    "closing",
  );
  expect(retireLegacy).not.toHaveBeenCalled();
});
