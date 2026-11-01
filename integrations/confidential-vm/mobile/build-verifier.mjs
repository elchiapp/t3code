import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import * as NodeURL from "node:url";
import * as NodeCrypto from "node:crypto";
import * as NodeChildProcess from "node:child_process";
import * as NodeModule from "node:module";

const root = NodePath.resolve(NodePath.dirname(NodeURL.fileURLToPath(import.meta.url)), "../../..");
const [configPath, sdkPath] = process.argv.slice(2);
if (!configPath || !sdkPath)
  throw Error(
    "Usage: node integrations/confidential-vm/mobile/build-verifier.mjs CONFIG_JSON PINNED_SDK_SOURCE",
  );
const sdk = NodePath.resolve(sdkPath);
const lock = JSON.parse(
  NodeFS.readFileSync(NodePath.join(root, "integrations/confidential-vm/source-lock.json")),
);
const hash = (bytes) => NodeCrypto.createHash("sha256").update(bytes).digest("hex");
if (
  NodeChildProcess.execFileSync("git", ["-C", sdk, "rev-parse", "HEAD"], {
    encoding: "utf8",
  }).trim() !== lock.sdk_revision ||
  NodeChildProcess.execFileSync("git", ["-C", sdk, "status", "--porcelain"], {
    encoding: "utf8",
  }).trim()
)
  throw Error("Verifier SDK source is not the clean pinned revision");
for (const name of ["verifier-core.mjs", "vcek-bindings.mjs", "inference-release-policy.mjs"]) {
  const relative = "templates/attestation/verifier/" + name + ".template";
  if (
    hash(NodeFS.readFileSync(NodePath.join(root, "integrations/confidential-vm", relative))) !==
    lock.files[relative].template_sha256
  )
    throw Error("Owned verifier source differs: " + name);
}
const configuration = JSON.parse(NodeFS.readFileSync(NodePath.resolve(configPath)));
const model = new URL(configuration.modelOrigin);
if (
  model.protocol !== "https:" ||
  model.username ||
  model.password ||
  model.origin !== configuration.modelOrigin
)
  throw Error("Inference proxy requires an exact HTTPS origin");
if (!/^[a-f0-9]{64}$/.test(configuration.tlsSpkiSha256))
  throw Error("A pinned VM SPKI is required");
if (!Array.isArray(configuration.environmentOrigins) || !configuration.environmentOrigins.length)
  throw Error("Environment origins are missing");
for (const value of configuration.environmentOrigins) {
  const url = new URL(value);
  if (
    url.origin !== value ||
    url.protocol !== "https:" ||
    url.hostname !== model.hostname ||
    url.username ||
    url.password
  )
    throw Error("Environment origin differs from the pinned VM");
}
const proof = new URL(configuration.proofOrigin);
if (
  proof.origin !== configuration.proofOrigin ||
  !["http:", "https:"].includes(proof.protocol) ||
  proof.username ||
  proof.password
)
  throw Error("Invalid public-proof origin");
if (proof.protocol === "http:") {
  const parts = proof.hostname.split(".").map(Number);
  if (
    parts.length !== 4 ||
    parts[0] !== 100 ||
    parts[1] < 64 ||
    parts[1] > 127 ||
    parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)
  )
    throw Error("HTTP proof collection is restricted to a Tailscale address");
}
if (!/^[a-f0-9]{96}$/.test(configuration.proofPolicy?.hardware?.snp?.measurementHex ?? ""))
  throw Error("An approved VM launch measurement is required");
configuration.hostname = model.hostname;
configuration.tlsSpkiBase64 = Buffer.from(configuration.tlsSpkiSha256, "hex").toString("base64");
configuration.ownerApprovals ??= [];
const output = NodePath.join(root, "apps/mobile/.attestation-build");
NodeFS.mkdirSync(output, { recursive: true });
const policyFile = NodePath.join(output, "policy.json");
NodeFS.writeFileSync(policyFile, JSON.stringify(configuration));
const sdkRequire = NodeModule.createRequire(NodePath.join(sdk, "package.json"));
const { rolldown } = await import(
  NodeURL.pathToFileURL(NodePath.join(sdk, "node_modules/rolldown/dist/index.mjs"))
);
const build = await rolldown({
  input: NodePath.join(root, "integrations/confidential-vm/mobile/worker.mjs"),
  platform: "browser",
  plugins: [
    {
      name: "owned-mobile-verifier",
      resolveId(id) {
        if (id === "zlib") return "\0no-zlib";
      },
      load(id) {
        if (id === "\0no-zlib")
          return "export function gunzipSync(){throw Error('DecompressionStream is required')}";
        if (id.endsWith(".mjs.template"))
          return { code: NodeFS.readFileSync(id, "utf8"), moduleType: "js" };
      },
    },
  ],
  resolve: {
    alias: {
      "@tinfoilsh/verifier": NodePath.join(sdk, "packages/verifier/dist/index.js"),
      "@t3-pinned-vcek": NodePath.join(sdk, "packages/verifier/dist/sev/cert-chain.js"),
      "@t3-pinned-x509": sdkRequire.resolve("@freedomofpress/sigstore-browser"),
      "@t3-mobile-policy": policyFile,
    },
  },
  onwarn(warning) {
    if (warning.code === "UNRESOLVED_IMPORT") throw Error(warning.message);
  },
});
const generated = await build.generate({ format: "iife", minify: true });
await build.close();
const packages = new Map();
for (const chunk of generated.output) {
  if (chunk.type !== "chunk") continue;
  for (const filename of Object.keys(chunk.modules ?? {})) {
    if (!NodePath.isAbsolute(filename) || !filename.startsWith(sdk + NodePath.sep)) continue;
    let directory = NodePath.dirname(filename);
    while (directory.startsWith(sdk)) {
      const manifest = NodePath.join(directory, "package.json");
      if (NodeFS.existsSync(manifest)) {
        const metadata = JSON.parse(NodeFS.readFileSync(manifest));
        if (metadata.name)
          packages.set(`${metadata.name}@${metadata.version ?? "workspace"}`, {
            directory,
            metadata,
          });
        break;
      }
      const parent = NodePath.dirname(directory);
      if (parent === directory) break;
      directory = parent;
    }
  }
}
if (!packages.size) throw Error("The verifier dependency notice inventory is empty");
const notices = [];
for (const [name, { directory, metadata }] of [...packages.entries()].sort()) {
  let current = directory;
  let license;
  while (current.startsWith(sdk)) {
    const candidate = NodeFS.readdirSync(current).find((value) =>
      /^licen[cs]e(?:\.[a-z]+)?$/i.test(value),
    );
    if (candidate) {
      license = NodeFS.readFileSync(NodePath.join(current, candidate), "utf8");
      break;
    }
    const parent = NodePath.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  if (!license) throw Error("Missing dependency license: " + name);
  notices.push(`${name}\nLicense: ${metadata.license ?? "See license text"}\n\n${license}`);
}
NodeFS.writeFileSync(
  NodePath.join(root, "integrations/confidential-vm/mobile/THIRD-PARTY-NOTICES.txt"),
  notices.join("\n\n========================================\n\n"),
);
const code = generated.output
  .find((item) => item.type === "chunk")
  .code.replaceAll("</script", "<\\/script");
const html = `<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'nonce-t3-owned-verifier'; connect-src https://inference.tinfoil.sh https://github-proxy.tinfoil.sh https://kds-proxy.tinfoil.sh; frame-src 'none'; object-src 'none'; base-uri 'none'"><script nonce="t3-owned-verifier">${code}</script>`;
NodeFS.writeFileSync(NodePath.join(output, "verifier.html"), html);
configuration.verifierSha256 = hash(Buffer.from(html));
NodeFS.writeFileSync(policyFile, JSON.stringify(configuration));
NodeFS.writeFileSync(
  NodePath.join(output, "inputs.json"),
  JSON.stringify(
    {
      sdkRevision: lock.sdk_revision,
      verifierSha256: configuration.verifierSha256,
      sourceLockSha256: hash(
        NodeFS.readFileSync(NodePath.join(root, "integrations/confidential-vm/source-lock.json")),
      ),
    },
    null,
    2,
  ),
);
console.log("Owned mobile verifier prepared; public policy and generated assets stay outside Git.");
