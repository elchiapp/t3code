import * as NodeFSP from "node:fs/promises";
import * as NodePath from "node:path";
import * as NodeURL from "node:url";
import * as NodeChildProcess from "node:child_process";
import * as NodeUtil from "node:util";
import * as NodeCrypto from "node:crypto";
import { buildVerificationRuntime } from "./build-runtime.mjs";

const run = NodeUtil.promisify(NodeChildProcess.execFile);
const repo = NodePath.resolve(NodePath.dirname(NodeURL.fileURLToPath(import.meta.url)), "../../..");
const [appSource, sdk, guardSource, clientPolicyFile, nodeSource, outputArgument, identity] =
  process.argv.slice(2);
if (!identity)
  throw Error("Usage: build-app.mjs APP SDK GUARD PUBLIC_POLICY NODE OUTPUT SIGNING_IDENTITY");
const output = NodePath.resolve(outputArgument);
const source = (await run("git", ["-C", repo, "rev-parse", "HEAD"])).stdout.trim();
if ((await run("git", ["-C", repo, "status", "--porcelain"])).stdout.trim())
  throw Error("Commit the bundle recipe before building.");
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
await NodeFSP.mkdir(output, { recursive: false });
const app = NodePath.join(output, "T3 Attested.app");
await NodeFSP.cp(appSource, app, { recursive: true, verbatimSymlinks: true });
const resources = NodePath.join(app, "Contents", "Resources");
await NodeFSP.rm(NodePath.join(resources, "t3-attested-launch.json"), { force: true });
const client = JSON.parse(await NodeFSP.readFile(clientPolicyFile, "utf8"));
const model = new globalThis.URL(client.modelOrigin);
if (
  model.protocol !== "https:" ||
  !client.allowedEnvironmentOrigins.includes("https://" + model.hostname + ":8446") ||
  !/^[a-f0-9]{64}$/.test(client.tlsSpkiSha256 ?? "")
)
  throw Error("Invalid public client configuration.");
client.verifierOrigin = "http://127.0.0.1:3420";
await NodeFSP.writeFile(
  NodePath.join(resources, "attestation-client.json"),
  JSON.stringify(client) + "\n",
  {
    mode: 0o644,
  },
);
const runtime = NodePath.join(resources, "attestation-verifier");
await NodeFSP.mkdir(runtime, { mode: 0o755 });
const version = JSON.parse(
  await NodeFSP.readFile(NodePath.join(repo, "apps/desktop/package.json"), "utf8"),
).version;
await buildVerificationRuntime({
  sdk,
  guardSource,
  nodeSource,
  output,
  runtime,
  release: version + "-bundled",
  sdkRevision: lock.sdk_revision,
});
// Seal the app without re-signing the official Node executable or changing its JIT entitlements.
await run(
  "/usr/bin/codesign",
  ["--force", "--sign", identity, "--preserve-metadata=entitlements", app],
  { timeout: 120000 },
);
await run("/usr/bin/codesign", ["--verify", "--deep", "--strict", app]);
const hash = (bytes) => NodeCrypto.createHash("sha256").update(bytes).digest("hex");
if (
  hash(await NodeFSP.readFile(NodePath.join(runtime, "node"))) !==
  hash(await NodeFSP.readFile(nodeSource))
)
  throw Error("Official Node bytes changed.");
await NodeFSP.writeFile(
  NodePath.join(output, "build-receipt.json"),
  JSON.stringify(
    {
      source,
      release: version,
      app,
      sdkRevision: lock.sdk_revision,
      appAsarSha256: hash(await NodeFSP.readFile(NodePath.join(resources, "app.asar"))),
      publicPolicySha256: hash(
        await NodeFSP.readFile(NodePath.join(resources, "attestation-client.json")),
      ),
      bundledVerifier: true,
      installerRequired: false,
      accountsIncluded: false,
      deviceDecisionsIncluded: false,
      privateKeysIncluded: false,
      notarized: false,
    },
    null,
    2,
  ) + "\n",
);
console.log("Signed self-contained app built: " + app);
