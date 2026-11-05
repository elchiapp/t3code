import * as NodeFSP from "node:fs/promises";
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import * as NodeCrypto from "node:crypto";
import * as NodeChildProcess from "node:child_process";
import * as NodeUtil from "node:util";
import * as NodeURL from "node:url";
import { buildVerificationRuntime } from "./build-runtime.mjs";
const run = NodeUtil.promisify(NodeChildProcess.execFile);
const own = NodePath.dirname(NodeURL.fileURLToPath(import.meta.url));
const repo = NodePath.resolve(own, "../../..");
const hash = (bytes) => NodeCrypto.createHash("sha256").update(bytes).digest("hex");
const [appSource, sdk, guardSource, clientPolicyFile, nodeSource, outputArgument, identity] =
  process.argv.slice(2);
const output = NodePath.resolve(outputArgument ?? "");
if (!identity)
  throw Error("Usage: build.mjs APP SDK GUARD CLIENT_POLICY NODE OUTPUT SIGNING_IDENTITY");
const release = "0.1.6-turing.15-air1";
if (NodeFS.existsSync(output)) throw Error("Choose a fresh build directory.");
await NodeFSP.mkdir(output, { recursive: true });
const source = (await run("git", ["-C", repo, "rev-parse", "HEAD"])).stdout.trim();
if ((await run("git", ["-C", repo, "status", "--porcelain"])).stdout.trim())
  throw Error("Commit the installer recipe before building.");
const lock = JSON.parse(
  await NodeFSP.readFile(
    NodePath.join(repo, "integrations/confidential-vm/source-lock.json"),
    "utf8",
  ),
);
if (
  (await run("git", ["-C", sdk, "rev-parse", "HEAD"])).stdout.trim() !== lock.sdk_revision ||
  (await run("git", ["-C", sdk, "status", "--porcelain"])).stdout.trim()
)
  throw Error("SDK source must be the clean pinned revision.");
const app = NodePath.join(output, "Install T3 Attested.app");
const resources = NodePath.join(app, "Contents/Resources");
const payload = NodePath.join(resources, "payload");
const runtime = NodePath.join(payload, "runtime");
await NodeFSP.mkdir(runtime, { recursive: true });
await NodeFSP.mkdir(NodePath.join(app, "Contents/MacOS"), { recursive: true });
const client = JSON.parse(await NodeFSP.readFile(clientPolicyFile, "utf8"));
const model = new URL(client.modelOrigin);
if (
  model.protocol !== "https:" ||
  !client.allowedEnvironmentOrigins.includes("https://" + model.hostname + ":8446") ||
  !/^[a-f0-9]{64}$/.test(client.tlsSpkiSha256 ?? "")
)
  throw Error("Invalid public client configuration.");
client.allowedEnvironmentOrigins = ["http://127.0.0.1:3773", "https://" + model.hostname + ":8446"];
client.verifierOrigin = "http://127.0.0.1:3420";
await NodeFSP.writeFile(
  NodePath.join(payload, "client-policy.json"),
  JSON.stringify(client) + "\n",
  { mode: 0o600 },
);
await NodeFSP.cp(appSource, NodePath.join(payload, "T3 Attested.app"), {
  recursive: true,
  verbatimSymlinks: true,
});
await NodeFSP.unlink(
  NodePath.join(payload, "T3 Attested.app/Contents/Resources/t3-attested-launch.json"),
);
await run(
  "/usr/bin/codesign",
  [
    "--force",
    "--deep",
    "--sign",
    identity,
    "--preserve-metadata=entitlements",
    NodePath.join(payload, "T3 Attested.app"),
  ],
  { timeout: 120000 },
);
await run("/usr/bin/codesign", [
  "--verify",
  "--deep",
  "--strict",
  NodePath.join(payload, "T3 Attested.app"),
]);
await buildVerificationRuntime({
  sdk,
  guardSource,
  nodeSource,
  output,
  runtime,
  release,
  sdkRevision: lock.sdk_revision,
});
await NodeFSP.copyFile(NodePath.join(own, "install.mjs"), NodePath.join(resources, "install.mjs"));
const appAsarSha256 = hash(
  await NodeFSP.readFile(NodePath.join(payload, "T3 Attested.app/Contents/Resources/app.asar")),
);
await NodeFSP.writeFile(
  NodePath.join(payload, "package.json"),
  JSON.stringify({ schema: 1, release, source, architecture: "arm64", appAsarSha256 }, null, 2) +
    "\n",
);
const info = {
  CFBundleIdentifier: "io.elchiapp.t3attested.installer",
  CFBundleName: "Install T3 Attested",
  CFBundleDisplayName: "Install T3 Attested",
  CFBundleExecutable: "Installer",
  CFBundlePackageType: "APPL",
  CFBundleShortVersionString: "0.1.6",
  CFBundleVersion: "9",
  LSMinimumSystemVersion: "13.0",
  NSHighResolutionCapable: true,
};
await NodeFSP.writeFile(NodePath.join(output, "installer-info.json"), JSON.stringify(info));
await run("/usr/bin/plutil", [
  "-convert",
  "xml1",
  "-o",
  NodePath.join(app, "Contents/Info.plist"),
  NodePath.join(output, "installer-info.json"),
]);
await run(
  "/usr/bin/xcrun",
  [
    "swiftc",
    NodePath.join(own, "Installer.swift"),
    "-O",
    "-framework",
    "AppKit",
    "-target",
    "arm64-apple-macos13.0",
    "-module-cache-path",
    NodePath.join(output, "ModuleCache"),
    "-o",
    NodePath.join(app, "Contents/MacOS/Installer"),
  ],
  { timeout: 120000 },
);
await run("/usr/bin/codesign", ["--force", "--sign", identity, app], { timeout: 120000 });
await run("/usr/bin/codesign", ["--verify", "--deep", "--strict", app]);
await NodeFSP.writeFile(
  NodePath.join(output, "build-receipt.json"),
  JSON.stringify(
    {
      release,
      source,
      runtimeSource: source,
      sdkRevision: lock.sdk_revision,
      installer: app,
      appAsarSha256,
      accountsIncluded: false,
      deviceDecisionsIncluded: false,
      privateKeysIncluded: false,
      notarized: false,
    },
    null,
    2,
  ) + "\n",
);
console.log("Signed portable installer built: " + app);
