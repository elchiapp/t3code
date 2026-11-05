import * as NodeFSP from "node:fs/promises";
import * as NodePath from "node:path";
import * as NodeCrypto from "node:crypto";
import * as NodeChildProcess from "node:child_process";
import * as NodeUtil from "node:util";
import * as NodeURL from "node:url";
import * as NodeOS from "node:os";
const execute = NodeUtil.promisify(NodeChildProcess.execFile);
const digest = (bytes) => NodeCrypto.createHash("sha256").update(bytes).digest("hex");
export const LABEL = "io.elchiapp.t3attested.verifier";
const LEGACY = "io.elchiapp.t3-attestation-air";

export async function ownedDirectory(directory) {
  await NodeFSP.mkdir(directory, { recursive: true, mode: 0o700 });
  const stat = await NodeFSP.lstat(directory);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    (process.getuid && stat.uid !== process.getuid())
  )
    throw Error("Installation directory is not owned by this account.");
}
export async function safeTarget(home, relative) {
  if (!NodePath.isAbsolute(home) || NodePath.resolve(home) === "/")
    throw Error("A normal absolute user home is required.");
  const root = NodePath.resolve(home),
    target = NodePath.resolve(root, relative);
  const homeStat = await NodeFSP.lstat(root);
  if (!homeStat.isDirectory() || homeStat.isSymbolicLink())
    throw Error("A linked user home is not accepted.");
  if (!target.startsWith(root + NodePath.sep))
    throw Error("Installation path escapes the user home.");
  let current = root;
  for (const part of NodePath.relative(root, target).split(NodePath.sep)) {
    current = NodePath.join(current, part);
    try {
      if ((await NodeFSP.lstat(current)).isSymbolicLink())
        throw Error("A linked installation path is not accepted.");
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
  return target;
}
export async function verifyRuntime(root, manifest) {
  if (
    !manifest ||
    manifest.version !== 1 ||
    !Array.isArray(manifest.files) ||
    manifest.files.length > 100
  )
    throw Error("Invalid runtime manifest.");
  for (const file of manifest.files) {
    if (
      !file ||
      !/^[-a-zA-Z0-9_./]+$/.test(file.path) ||
      file.path.startsWith("/") ||
      file.path.split("/").some((p) => !p || p === ".." || p === ".") ||
      !/^[a-f0-9]{64}$/.test(file.sha256)
    )
      throw Error("Invalid runtime file identity.");
    const full = NodePath.join(root, file.path);
    const stat = await NodeFSP.lstat(full);
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      digest(await NodeFSP.readFile(full)) !== file.sha256
    )
      throw Error("Runtime file does not match its source manifest: " + file.path);
  }
}
async function exists(p) {
  try {
    await NodeFSP.lstat(p);
    return true;
  } catch (e) {
    if (e.code === "ENOENT") return false;
    throw e;
  }
}
async function atomicFile(target, bytes) {
  const temporary = target + ".tmp-" + NodeCrypto.randomUUID();
  try {
    await NodeFSP.writeFile(temporary, bytes, { mode: 0o600, flag: "wx" });
    await NodeFSP.rename(temporary, target);
  } finally {
    await NodeFSP.unlink(temporary).catch((e) => {
      if (e.code !== "ENOENT") throw e;
    });
  }
}
export async function installPackage({ payload, home, services }) {
  const metadata = JSON.parse(
    await NodeFSP.readFile(NodePath.join(payload, "package.json"), "utf8"),
  );
  if (
    metadata.schema !== 1 ||
    metadata.architecture !== "arm64" ||
    !/^[-a-zA-Z0-9.]+$/.test(metadata.release)
  )
    throw Error("Unsupported installer metadata.");
  if (services.architecture !== "arm64") throw Error("This installer is for Apple silicon Macs.");
  const manifest = JSON.parse(
    await NodeFSP.readFile(NodePath.join(payload, "runtime", "manifest.json"), "utf8"),
  );
  await verifyRuntime(NodePath.join(payload, "runtime"), manifest);
  const appSource = NodePath.join(payload, "T3 Attested.app");
  if (
    digest(await NodeFSP.readFile(NodePath.join(appSource, "Contents/Resources/app.asar"))) !==
    metadata.appAsarSha256
  )
    throw Error("The app does not match its build manifest.");
  await services.verifyApp(appSource);
  const applications = await safeTarget(home, "Applications");
  const support = await safeTarget(home, "Library/Application Support/T3 Attested");
  const base = await safeTarget(home, ".t3-attested");
  const agents = await safeTarget(home, "Library/LaunchAgents");
  for (const dir of [applications, support, base, agents]) await ownedDirectory(dir);
  const policyPath = NodePath.join(base, "attestation-client.json");
  const policy = JSON.parse(
    await NodeFSP.readFile(NodePath.join(payload, "client-policy.json"), "utf8"),
  );
  const server = new URL(policy.verifierOrigin);
  if (
    server.origin !== "http://127.0.0.1:3420" ||
    !/^[a-f0-9]{64}$/.test(policy.tlsSpkiSha256 ?? "")
  )
    throw Error("Invalid device verification policy.");
  if (await exists(policyPath)) {
    const stat = await NodeFSP.lstat(policyPath);
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      stat.mode & 0o077 ||
      (process.getuid && stat.uid !== process.getuid())
    )
      throw Error("Existing client policy is not protected.");
    const previous = JSON.parse(await NodeFSP.readFile(policyPath, "utf8"));
    if (JSON.stringify(previous) !== JSON.stringify(policy))
      throw Error(
        "Existing verification configuration differs. It was preserved; use the existing installation instead.",
      );
  }
  const destination = NodePath.join(applications, "T3 Attested.app");
  if (await exists(destination)) {
    await services.verifyApp(destination);
    if (await exists(NodePath.join(destination, "Contents/Resources/t3-attested-launch.json")))
      throw Error(
        "This Mac has a custom T3 data home. Its installation was preserved; use its managed updater instead.",
      );
  }
  await services.preflight({ agents, modelOrigin: policy.modelOrigin });
  const id = NodeCrypto.randomUUID();
  const stage = NodePath.join(support, ".install-" + id);
  await ownedDirectory(stage);
  const versions = NodePath.join(support, "VerificationRuntime");
  await ownedDirectory(versions);
  const runtime = NodePath.join(versions, metadata.release);
  const state = NodePath.join(support, "VerificationState");
  await ownedDirectory(state);
  const backups = NodePath.join(support, "InstallerBackups");
  await ownedDirectory(backups);
  const backupApp = NodePath.join(backups, "T3-Attested-" + id + ".app");
  const job = NodePath.join(agents, LABEL + ".plist");
  const oldJob = (await exists(job)) ? await NodeFSP.readFile(job) : null;
  const hadPolicy = await exists(policyPath);
  let appMoved = false,
    newApp = false,
    newRuntime = false,
    jobChanged = false,
    retired;
  try {
    await NodeFSP.cp(appSource, NodePath.join(stage, "T3 Attested.app"), {
      recursive: true,
      verbatimSymlinks: true,
    });
    await NodeFSP.cp(NodePath.join(payload, "runtime"), NodePath.join(stage, "runtime"), {
      recursive: true,
      verbatimSymlinks: true,
    });
    await services.verifyApp(NodePath.join(stage, "T3 Attested.app"));
    await verifyRuntime(NodePath.join(stage, "runtime"), manifest);
    if (await exists(runtime)) await verifyRuntime(runtime, manifest);
    else {
      await NodeFSP.rename(NodePath.join(stage, "runtime"), runtime);
      newRuntime = true;
    }
    retired = await services.retireLegacy({ agents, backups });
    if (await exists(destination)) {
      await NodeFSP.rename(destination, backupApp);
      appMoved = true;
    }
    await NodeFSP.rename(NodePath.join(stage, "T3 Attested.app"), destination);
    newApp = true;
    if (!hadPolicy) await atomicFile(policyPath, JSON.stringify(policy) + "\n");
    // The app owns verification now. Retire only the old installer-owned Login Item.
    await services.stop({ label: LABEL });
    if (oldJob) {
      await atomicFile(NodePath.join(backups, "verifier-" + id + ".plist"), oldJob);
      await NodeFSP.unlink(job);
      jobChanged = true;
    }
    await services.startRuntime({ runtime, state });
    await services.ready({ release: metadata.release });
    const receipt = {
      installed: true,
      release: metadata.release,
      app: destination,
      runtime,
      source: metadata.source,
      oldApp: appMoved ? backupApp : null,
      policyPreserved: hadPolicy,
      accountsImported: false,
      deviceDecisionsImported: false,
      trustApproved: false,
    };
    await atomicFile(
      NodePath.join(support, "installer-receipt.json"),
      JSON.stringify(receipt, null, 2) + "\n",
    );
    await services.finishRuntime();
    return receipt;
  } catch (error) {
    await services.stop({ label: LABEL }).catch(() => {});
    if (newApp && (await exists(destination)))
      await NodeFSP.rename(destination, NodePath.join(backups, "Rejected-" + id + ".app"));
    if (appMoved) await NodeFSP.rename(backupApp, destination);
    if (!hadPolicy)
      await NodeFSP.unlink(policyPath).catch((e) => {
        if (e.code !== "ENOENT") throw e;
      });
    if (jobChanged) {
      if (oldJob) await atomicFile(job, oldJob);
      else
        await NodeFSP.unlink(job).catch((e) => {
          if (e.code !== "ENOENT") throw e;
        });
    }
    if (oldJob) await services.activate({ job, label: LABEL }).catch(() => {});
    if (retired) await services.restoreLegacy(retired).catch(() => {});
    if (newRuntime) await NodeFSP.rename(runtime, NodePath.join(backups, "Rejected-runtime-" + id));
    throw error;
  } finally {
    await NodeFSP.rm(stage, { recursive: true, force: true });
  }
}

export function nativeServices() {
  const uid = process.getuid();
  const target = `gui/${uid}`;
  const run = async (args) => execute("/bin/launchctl", args, { timeout: 10000, maxBuffer: 32768 });
  const loaded = async (label) => {
    try {
      await run(["print", target + "/" + label]);
      return true;
    } catch {
      return false;
    }
  };
  let bootstrapProcess;
  const finishRuntime = async () => {
    const child = bootstrapProcess;
    bootstrapProcess = undefined;
    if (!child || child.exitCode !== null || child.signalCode !== null) return;
    await new Promise((resolve) => {
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        resolve();
      }, 2000);
      child.once("exit", () => {
        clearTimeout(timer);
        resolve();
      });
      child.kill("SIGTERM");
    });
  };
  const stop = async ({ label }) => {
    await finishRuntime();
    if (await loaded(label)) await run(["bootout", target + "/" + label]);
  };
  const activate = async ({ job, label }) => {
    if (await loaded(label)) await stop({ label });
    for (let attempt = 0; attempt < 20; attempt++) {
      try {
        await run(["bootstrap", target, job]);
        return;
      } catch (error) {
        if (attempt === 19) throw error;
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
    }
  };
  return {
    // oxlint-disable-next-line t3code/no-global-process-runtime -- This standalone OS adapter runs before T3 and has no Effect runtime.
    architecture: process.arch,
    startRuntime: async ({ runtime, state }) => {
      const output = await NodeFSP.open(NodePath.join(state, "service.log"), "a", 0o600);
      try {
        const env = {
          PATH: "/usr/bin:/bin",
          HOME: NodeOS.homedir(),
          T3_ATTESTATION_STATE_DIR: state,
        };
        bootstrapProcess = NodeChildProcess.spawn(
          NodePath.join(runtime, "node"),
          [NodePath.join(runtime, "start.mjs")],
          {
            cwd: runtime,
            env,
            stdio: ["ignore", output.fd, output.fd, "ipc"],
          },
        );
        await new Promise((resolve, reject) => {
          bootstrapProcess.once("spawn", resolve);
          bootstrapProcess.on("error", reject);
        });
      } finally {
        await output.close();
      }
    },
    finishRuntime,
    verifyApp: async (app) => {
      await execute("/usr/bin/codesign", ["--verify", "--deep", "--strict", app], {
        timeout: 20000,
      });
      const { stdout } = await execute("/usr/bin/plutil", [
        "-extract",
        "CFBundleIdentifier",
        "raw",
        "-o",
        "-",
        NodePath.join(app, "Contents/Info.plist"),
      ]);
      if (stdout.trim() !== "io.elchiapp.t3attested.desktop")
        throw Error("A different application uses the installation NodePath.");
    },
    preflight: async ({ agents, modelOrigin }) => {
      const output = await execute("/usr/sbin/lsof", ["-nP", "-iTCP:3420", "-sTCP:LISTEN"])
        .then((x) => x.stdout)
        .catch((e) => {
          if (e.code === 1) return "";
          throw e;
        });
      if (!output.trim()) return;
      if (!(await loaded(LABEL)) && !(await exists(NodePath.join(agents, LEGACY + ".plist"))))
        throw Error("Port3420 belongs to another service. No installation was changed.");
      const active = await execute("/usr/sbin/lsof", ["-nP", "-iTCP:3420", "-sTCP:ESTABLISHED"])
        .then((x) => x.stdout)
        .catch((e) => {
          if (e.code === 1) return "";
          throw e;
        });
      if (active.trim()) throw Error("Verification connections are active. Close T3 and retry.");
      const response = await fetch("http://127.0.0.1:3420/status", {
        signal: AbortSignal.timeout(5000),
      });
      if (!response.ok || (await response.json()).modelOrigin !== modelOrigin)
        throw Error("An unrelated verifier is using port3420.");
    },
    retireLegacy: async ({ agents, backups }) => {
      const file = NodePath.join(agents, LEGACY + ".plist");
      if (!(await exists(file))) return null;
      const { stdout } = await execute("/usr/bin/plutil", [
        "-extract",
        "Label",
        "raw",
        "-o",
        "-",
        file,
      ]);
      if (stdout.trim() !== LEGACY) throw Error("Legacy service identity differs.");
      await stop({ label: LEGACY });
      const backup = NodePath.join(backups, LEGACY + "-" + NodeCrypto.randomUUID() + ".plist");
      await NodeFSP.rename(file, backup);
      return { file, backup };
    },
    restoreLegacy: async ({ file, backup }) => {
      await NodeFSP.rename(backup, file);
      await activate({ job: file, label: LEGACY });
    },
    ready: async ({ release }) => {
      for (let attempt = 0; attempt < 40; attempt++) {
        if (
          bootstrapProcess &&
          (bootstrapProcess.exitCode !== null || bootstrapProcess.signalCode !== null)
        )
          throw Error("The verification self-check exited. See VerificationState/service.log.");
        try {
          const response = await fetch("http://127.0.0.1:3420/status", {
            headers: { Connection: "close" },
            signal: AbortSignal.timeout(1000),
          });
          if (response.ok && (await response.json()).runtimeRelease === release) return;
        } catch {}
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
      throw Error(
        "The new verification service did not start. The previous installation will be restored.",
      );
    },
    activate,
    stop,
  };
}
if (process.argv[1] && import.meta.url === NodeURL.pathToFileURL(process.argv[1]).href) {
  const [payload, home] = process.argv.slice(2);
  try {
    // oxlint-disable-next-line t3code/no-global-process-runtime -- The installer must reject other operating systems before starting T3.
    if (process.platform !== "darwin") throw Error("This installer is for macOS.");
    const result = await installPackage({ payload, home, services: nativeServices() });
    console.log(JSON.stringify(result));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
