import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import * as NodeCrypto from "node:crypto";
import * as NodeURL from "node:url";
const root = NodePath.dirname(NodeURL.fileURLToPath(import.meta.url));
const manifest = JSON.parse(NodeFS.readFileSync(NodePath.join(root, "manifest.json")));
if (manifest.version !== 1 || !Array.isArray(manifest.files) || manifest.files.length > 100)
  throw Error("Invalid verification runtime manifest");
for (const file of manifest.files) {
  if (
    typeof file.path !== "string" ||
    file.path.split("/").some((value) => value === ".." || !value) ||
    NodePath.isAbsolute(file.path) ||
    !/^[a-f0-9]{64}$/.test(file.sha256) ||
    NodeCrypto.createHash("sha256")
      .update(NodeFS.readFileSync(NodePath.join(root, file.path)))
      .digest("hex") !== file.sha256
  )
    throw Error("Verification runtime hash differs");
}
const keep = new Set([
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "TMPDIR",
  "LANG",
  "LC_ALL",
  "T3_ATTESTATION_STATE_DIR",
  "T3_ATTESTATION_PORT",
]);
for (const name of Object.keys(process.env)) if (!keep.has(name)) delete process.env[name];
process.env.DO_NOT_TRACK = "1";
process.env.T3_ATTESTATION_RUNTIME_RELEASE = manifest.release;
if (!process.env.T3_ATTESTATION_STATE_DIR) throw Error("Private state directory missing");
await import("./main.mjs");
