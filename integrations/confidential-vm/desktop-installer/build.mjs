import * as NodeFSP from "node:fs/promises";
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import * as NodeCrypto from "node:crypto";
import * as NodeChildProcess from "node:child_process";
import * as NodeUtil from "node:util";
import * as NodeURL from "node:url";
import * as NodeModule from "node:module";
const run = NodeUtil.promisify(NodeChildProcess.execFile);
const own = NodePath.dirname(NodeURL.fileURLToPath(import.meta.url));
const repo = NodePath.resolve(own, "../../..");
const hash = (bytes) => NodeCrypto.createHash("sha256").update(bytes).digest("hex");
const [appSource, sdk, guardSource, clientPolicyFile, nodeSource, outputArgument, identity] =
  process.argv.slice(2);
const output = NodePath.resolve(outputArgument ?? "");
if (!identity)
  throw Error("Usage: build.mjs APP SDK GUARD CLIENT_POLICY NODE OUTPUT SIGNING_IDENTITY");
const release = "0.1.6-turing.13-air1";
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
const files = [
  "collect-evidence.mjs",
  "crypto-verifier.mjs",
  "endpoint-binding.mjs",
  "gate-state.mjs",
  "gate-server.mjs",
  "main.mjs",
  "release-approvals.mjs",
  "device-approval-store.mjs",
  "version-review-service.mjs",
  "proof-collector.mjs",
];
for (const name of files)
  await NodeFSP.copyFile(NodePath.join(guardSource, name), NodePath.join(runtime, name));
await NodeFSP.cp(NodePath.join(guardSource, "verifier"), NodePath.join(runtime, "verifier"), {
  recursive: true,
});
for (const name of await NodeFSP.readdir(NodePath.join(runtime, "verifier")))
  if (/test|fixture/.test(name)) await NodeFSP.unlink(NodePath.join(runtime, "verifier", name));
// Runtime source contains public roots only; owner decisions are deliberately not copied.
await NodeFSP.copyFile(nodeSource, NodePath.join(runtime, "node"));
await NodeFSP.chmod(NodePath.join(runtime, "node"), 0o755);
await run("/usr/bin/codesign", ["--verify", "--strict", NodePath.join(runtime, "node")]);
const sdkRequire = NodeModule.createRequire(NodePath.join(sdk, "package.json"));
const { rolldown } = await import(
  NodeURL.pathToFileURL(NodePath.join(sdk, "node_modules/rolldown/dist/index.mjs"))
);
const entry = NodePath.join(output, "sdk-entry.mjs");
await NodeFSP.writeFile(
  entry,
  `export {Verifier,assembleAttestationBundle} from ${JSON.stringify(NodePath.join(sdk, "packages/verifier/dist/index.js"))};\nexport {verifySigstoreBundle} from ${JSON.stringify(NodePath.join(sdk, "packages/verifier/dist/sigstore.js"))};\nexport {CertificateChain} from ${JSON.stringify(NodePath.join(sdk, "packages/verifier/dist/sev/cert-chain.js"))};\nexport {X509Certificate} from ${JSON.stringify(sdkRequire.resolve("@freedomofpress/sigstore-browser"))};\n`,
);
const bundle = await rolldown({
  input: entry,
  platform: "node",
  onwarn(w) {
    if (w.code === "UNRESOLVED_IMPORT") throw Error(w.message);
  },
});
await bundle.write({
  file: NodePath.join(runtime, "sdk-bundle.mjs"),
  format: "esm",
  minify: true,
  codeSplitting: false,
});
await bundle.close();
let verifier = await NodeFSP.readFile(NodePath.join(runtime, "crypto-verifier.mjs"), "utf8");
const start = verifier.indexOf("const sdk='");
const end = verifier.indexOf("const verifyVcekBindings=", start);
if (start < 0 || end < 0) throw Error("Verifier import boundary changed.");
verifier =
  verifier.slice(0, start) +
  `if(hash(readFileSync(new URL('sdk-bundle.mjs',root)))!==inputs.sdkBundleSha256)throw Error('Bundled SDK hash differs');\nconst {Verifier,assembleAttestationBundle,verifySigstoreBundle,CertificateChain,X509Certificate}=await import('./sdk-bundle.mjs');\n` +
  verifier.slice(end);
await NodeFSP.writeFile(NodePath.join(runtime, "crypto-verifier.mjs"), verifier);
let main = await NodeFSP.readFile(NodePath.join(runtime, "main.mjs"), "utf8");
main = main.replace(
  "import {writeFileSync} from 'node:fs';",
  "import {writeFileSync} from 'node:fs';\nimport {join} from 'node:path';\nconst port=Number(process.env.T3_ATTESTATION_PORT??3420);if(!Number.isInteger(port)||port<1024||port>65535)throw Error('Invalid private verifier port');\n",
);
main = main
  .replace("createGateServer({gate,", "createGateServer({port,gate,")
  .replace("server.listen(3420,'127.0.0.1'", "server.listen(port,'127.0.0.1'")
  .replace(
    "new URL('./gate-process.json',import.meta.url)",
    "join(process.env.T3_ATTESTATION_STATE_DIR,'gate-process.json')",
  );
await NodeFSP.writeFile(NodePath.join(runtime, "main.mjs"), main);
let gate = await NodeFSP.readFile(NodePath.join(runtime, "gate-server.mjs"), "utf8");
gate = gate.replace(
  "...gate.status(),modelOrigin,modelRequestsReceived",
  "...gate.status(),runtimeRelease:process.env.T3_ATTESTATION_RUNTIME_RELEASE,modelOrigin,modelRequestsReceived",
);
await NodeFSP.writeFile(NodePath.join(runtime, "gate-server.mjs"), gate);
const inputsFile = NodePath.join(runtime, "verifier/inputs.json");
const inputs = JSON.parse(await NodeFSP.readFile(inputsFile, "utf8"));
inputs.sdkBundleSha256 = hash(await NodeFSP.readFile(NodePath.join(runtime, "sdk-bundle.mjs")));
await NodeFSP.writeFile(inputsFile, JSON.stringify(inputs) + "\n");
await NodeFSP.copyFile(
  NodePath.join(repo, "integrations/confidential-vm/mobile/THIRD-PARTY-NOTICES.txt"),
  NodePath.join(runtime, "THIRD-PARTY-NOTICES.txt"),
);
const inventory = [];
async function walk(dir, prefix = "") {
  for (const name of (await NodeFSP.readdir(dir)).sort()) {
    const relative = prefix + name,
      full = NodePath.join(dir, name);
    const stat = await NodeFSP.lstat(full);
    if (stat.isSymbolicLink()) throw Error("Runtime links are not allowed.");
    if (stat.isDirectory()) await walk(full, relative + "/");
    else inventory.push({ path: relative, sha256: hash(await NodeFSP.readFile(full)) });
  }
}
await walk(runtime);
const startup = await NodeFSP.readFile(NodePath.join(own, "start.mjs"), "utf8");
await NodeFSP.writeFile(NodePath.join(runtime, "start.mjs"), startup);
inventory.push({ path: "start.mjs", sha256: hash(Buffer.from(startup)) });
await NodeFSP.writeFile(
  NodePath.join(runtime, "manifest.json"),
  JSON.stringify(
    { version: 1, release, sdkRevision: lock.sdk_revision, files: inventory },
    null,
    2,
  ) + "\n",
);
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
