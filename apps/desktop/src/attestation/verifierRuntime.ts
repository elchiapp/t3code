// @effect-diagnostics nodeBuiltinImport:off -- This native boundary owns only the bundled verifier process.
/* oxlint-disable t3code/no-global-process-runtime -- This OS adapter verifies file ownership and builds a whitelisted child environment. */
import * as NodeFSP from "node:fs/promises";
import * as NodePath from "node:path";
import * as NodeHttp from "node:http";
import * as NodeCrypto from "node:crypto";
import * as NodeChildProcess from "node:child_process";
import * as NodeTimersPromises from "node:timers/promises";

export interface OwnedVerifier {
  alive: () => boolean;
  stop: () => void;
}

export function createVerifierSupervisor(services: {
  probe: () => Promise<boolean>;
  start: () => Promise<OwnedVerifier>;
  ready: (process: OwnedVerifier) => Promise<void>;
}) {
  let pending: Promise<void> | undefined;
  let owned: OwnedVerifier | undefined;
  let closed = false;
  return {
    ensure(): Promise<void> {
      if (closed) return Promise.reject(new Error("T3 is closing."));
      if (pending) return pending;
      pending = (async () => {
        if (await services.probe()) return;
        if (closed) throw new Error("T3 is closing.");
        if (!owned?.alive()) {
          const started = await services.start();
          if (closed) {
            started.stop();
            throw new Error("T3 is closing.");
          }
          owned = started;
        }
        try {
          await services.ready(owned);
        } catch (error) {
          owned.stop();
          owned = undefined;
          throw error;
        }
      })().finally(() => {
        pending = undefined;
      });
      return pending;
    },
    stop() {
      closed = true;
      owned?.stop();
      owned = undefined;
    },
  };
}

async function regular(path: string, maxBytes?: number, bundled = false) {
  const stat = await NodeFSP.lstat(path);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    (maxBytes !== undefined && stat.size > maxBytes) ||
    (process.platform !== "win32" &&
      ((stat.uid !== process.getuid!() && !(bundled && stat.uid === 0)) || stat.mode & 0o022))
  )
    throw new Error("The verification file is not trusted.");
  return stat;
}

export async function readDevicePolicy(local: string, bundled?: string): Promise<unknown> {
  try {
    const stat = await regular(local, 32_768);
    if (process.platform !== "win32" && stat.mode & 0o077)
      throw new Error("Untrusted device policy");
    return JSON.parse(await NodeFSP.readFile(local, "utf8"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  if (!bundled) return null;
  try {
    await regular(bundled, 32_768, true);
    return JSON.parse(await NodeFSP.readFile(bundled, "utf8"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

export async function readBundledRuntime(resources: string, platform: string) {
  const root = NodePath.join(resources, "attestation-verifier");
  const stat = await NodeFSP.lstat(root);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    (platform !== "win32" &&
      ((stat.uid !== process.getuid!() && stat.uid !== 0) || stat.mode & 0o022))
  )
    throw new Error("The bundled verification directory is not trusted.");
  await regular(NodePath.join(root, "manifest.json"), 65_536, true);
  const manifest = JSON.parse(await NodeFSP.readFile(NodePath.join(root, "manifest.json"), "utf8"));
  if (
    manifest.version !== 1 ||
    typeof manifest.release !== "string" ||
    !/^[-a-zA-Z0-9.]+$/.test(manifest.release) ||
    !Array.isArray(manifest.files) ||
    manifest.files.length === 0 ||
    manifest.files.length > 100
  )
    throw new Error("The verification runtime manifest is invalid.");
  const names = new Set<string>();
  for (const item of manifest.files) {
    if (
      typeof item.path !== "string" ||
      !/^[-a-zA-Z0-9_./]+$/.test(item.path) ||
      item.path.split("/").some((part: string) => !part || part === "." || part === "..") ||
      names.has(item.path) ||
      !/^[a-f0-9]{64}$/.test(item.sha256)
    )
      throw new Error("The verification runtime manifest is invalid.");
    names.add(item.path);
    const file = NodePath.join(root, item.path);
    // Reject linked ancestors as well as linked files.
    let parent = NodePath.dirname(file);
    while (parent !== root) {
      if ((await NodeFSP.lstat(parent)).isSymbolicLink())
        throw new Error("Linked verification code is not accepted.");
      parent = NodePath.dirname(parent);
    }
    await regular(file, undefined, true);
    if (
      NodeCrypto.createHash("sha256")
        .update(await NodeFSP.readFile(file))
        .digest("hex") !== item.sha256
    )
      throw new Error("Verification code changed. Replace T3 Attested with a trusted copy.");
  }
  const executable = platform === "win32" ? "node.exe" : "node";
  if (!names.has(executable) || !names.has("start.mjs"))
    throw new Error("The verifier executable is missing.");
  return {
    root,
    executable: NodePath.join(root, executable),
    release: manifest.release as string,
  };
}

function probe(origin: string, expectedModel: string): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const request = NodeHttp.get(origin + "/status", { agent: false }, (response) => {
      let size = 0;
      const chunks: Buffer[] = [];
      response.on("data", (data: Buffer) => {
        size += data.length;
        if (size > 131_072) request.destroy(new Error("Local verification response is too large."));
        else chunks.push(data);
      });
      response.on("end", () => {
        try {
          if (
            response.statusCode !== 200 ||
            JSON.parse(Buffer.concat(chunks).toString()).modelOrigin !== expectedModel
          )
            throw new Error("Another service is using the verification port.");
          resolve(true);
        } catch (error) {
          reject(error);
        }
      });
      response.on("error", reject);
    });
    request.setTimeout(1000, () =>
      request.destroy(Object.assign(new Error("Local verifier timed out."), { code: "ETIMEDOUT" })),
    );
    request.on("error", (error: NodeJS.ErrnoException) => {
      if (["ECONNREFUSED", "ECONNRESET", "ETIMEDOUT"].includes(error.code ?? "")) resolve(false);
      else reject(error);
    });
  });
}

export function createManagedVerifierRuntime(options: {
  support: string;
  resources: string;
  platform: string;
  retireLegacy: () => Promise<void>;
}) {
  let supervisor: ReturnType<typeof createVerifierSupervisor> | undefined;
  let identity: string | undefined;
  let closed = false;
  let legacyRetired = false;
  const log = NodePath.join(options.support, "VerificationState", "service.log");
  return {
    ensure(origin: string, modelOrigin: string) {
      if (closed) return Promise.reject(new Error("T3 is closing."));
      const url = new URL(origin);
      if (
        url.protocol !== "http:" ||
        url.hostname !== "127.0.0.1" ||
        url.username ||
        url.password ||
        url.pathname !== "/" ||
        url.search ||
        url.hash ||
        !url.port ||
        Number(url.port) < 1024
      )
        return Promise.reject(new Error("The verifier must use a private local address."));
      const key = JSON.stringify([url.origin, modelOrigin]);
      if (identity && identity !== key)
        return Promise.reject(new Error("Verification configuration changed. Restart T3."));
      identity = key;
      supervisor ??= createVerifierSupervisor({
        probe: async () => {
          if (!legacyRetired) {
            await options.retireLegacy();
            legacyRetired = true;
          }
          return probe(url.origin, modelOrigin);
        },
        start: async () => {
          const runtime = await readBundledRuntime(options.resources, options.platform);
          const state = NodePath.dirname(log);
          await NodeFSP.mkdir(state, { recursive: true, mode: 0o700 });
          const stat = await NodeFSP.lstat(state);
          if (
            !stat.isDirectory() ||
            stat.isSymbolicLink() ||
            (options.platform !== "win32" && (stat.uid !== process.getuid!() || stat.mode & 0o022))
          )
            throw new Error("The verification state directory is not trusted.");
          try {
            await regular(log);
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
          }
          const output = await NodeFSP.open(log, "a", 0o600);
          const env: NodeJS.ProcessEnv = {};
          for (const name of [
            "PATH",
            "HOME",
            "USER",
            "LOGNAME",
            "TMPDIR",
            "LANG",
            "LC_ALL",
            "SystemRoot",
            "WINDIR",
            "ComSpec",
            "PATHEXT",
            "APPDATA",
            "LOCALAPPDATA",
            "USERPROFILE",
            "XDG_CONFIG_HOME",
          ])
            if (process.env[name] !== undefined) env[name] = process.env[name];
          env.T3_ATTESTATION_STATE_DIR = state;
          env.T3_ATTESTATION_PORT = url.port;
          let error: Error | undefined;
          const child = NodeChildProcess.spawn(
            runtime.executable,
            [NodePath.join(runtime.root, "start.mjs")],
            {
              cwd: runtime.root,
              env,
              windowsHide: true,
              stdio: ["ignore", output.fd, output.fd, "ipc"],
            },
          );
          try {
            await new Promise<void>((resolve, reject) => {
              child.on("error", (cause) => {
                error = cause;
                reject(cause);
              });
              child.once("spawn", resolve);
            });
          } finally {
            await output.close();
          }
          return {
            alive: () => !error && child.exitCode === null && child.signalCode === null,
            stop: () => {
              if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
            },
          };
        },
        ready: async (child) => {
          for (let attempt = 0; attempt < 30; attempt++) {
            if (!child.alive()) break;
            if (await probe(url.origin, modelOrigin)) return;
            await NodeTimersPromises.setTimeout(100);
          }
          throw new Error("The local verifier could not start. Diagnostic log: " + log);
        },
      });
      return supervisor.ensure();
    },
    stop() {
      closed = true;
      supervisor?.stop();
    },
  };
}
