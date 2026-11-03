import * as NodeTest from "node:test";
import * as NodeAssert from "node:assert/strict";
import * as NodeFSP from "node:fs/promises";
import * as NodePath from "node:path";
import * as NodeOS from "node:os";
import * as NodeCrypto from "node:crypto";
import { installPackage, safeTarget } from "./install.mjs";
const hash = (bytes) => NodeCrypto.createHash("sha256").update(bytes).digest("hex");
async function fixture() {
  const root = await NodeFSP.mkdtemp(NodePath.join(NodeOS.tmpdir(), "t3-air-install-"));
  const home = NodePath.join(root, "home");
  const payload = NodePath.join(root, "payload");
  await NodeFSP.mkdir(home);
  await NodeFSP.mkdir(NodePath.join(payload, "runtime"), { recursive: true });
  await NodeFSP.mkdir(NodePath.join(payload, "T3 Attested.app/Contents/Resources"), {
    recursive: true,
  });
  const code = Buffer.from("synthetic app code");
  await NodeFSP.writeFile(
    NodePath.join(payload, "T3 Attested.app/Contents/Resources/app.asar"),
    code,
  );
  const runtimeCode = "synthetic verification code";
  await NodeFSP.writeFile(NodePath.join(payload, "runtime/main.mjs"), runtimeCode);
  await NodeFSP.writeFile(
    NodePath.join(payload, "runtime/manifest.json"),
    JSON.stringify({ version: 1, files: [{ path: "main.mjs", sha256: hash(runtimeCode) }] }),
  );
  await NodeFSP.writeFile(
    NodePath.join(payload, "package.json"),
    JSON.stringify({
      schema: 1,
      architecture: "arm64",
      release: "test-1",
      source: "fixture-only",
      appAsarSha256: hash(code),
    }),
  );
  const policy = {
    verifierOrigin: "http://127.0.0.1:3420",
    modelOrigin: "https://vm.example:8447",
    tlsSpkiSha256: "c".repeat(64),
    allowedEnvironmentOrigins: ["http://127.0.0.1:3773", "https://vm.example:8446"],
  };
  await NodeFSP.writeFile(NodePath.join(payload, "client-policy.json"), JSON.stringify(policy));
  const services = {
    architecture: "arm64",
    verifyApp: async () => {},
    preflight: async () => {},
    retireLegacy: async () => null,
    restoreLegacy: async () => {},
    activate: async () => {},
    ready: async () => {},
    stop: async () => {},
  };
  return {
    home,
    payload,
    root,
    policy,
    services,
    cleanup: () => NodeFSP.rm(root, { recursive: true, force: true }),
  };
}
NodeTest.test(
  "fresh install is portable and does not import credentials, history or trust decisions",
  async () => {
    const f = await fixture();
    try {
      const privateFile = NodePath.join(
        f.home,
        "Library/Application Support/T3 Attested/attestation-versions.json",
      );
      await NodeFSP.mkdir(NodePath.dirname(privateFile), { recursive: true });
      await NodeFSP.writeFile(privateFile, "owner decision sentinel");
      const r = await installPackage(f);
      NodeAssert.equal(r.installed, true);
      NodeAssert.equal(r.accountsImported, false);
      NodeAssert.equal(r.deviceDecisionsImported, false);
      NodeAssert.equal(await NodeFSP.readFile(privateFile, "utf8"), "owner decision sentinel");
      const policy = NodePath.join(f.home, ".t3-attested/attestation-client.json");
      NodeAssert.equal((await NodeFSP.stat(policy)).mode & 0o077, 0);
      NodeAssert.deepEqual(JSON.parse(await NodeFSP.readFile(policy, "utf8")), f.policy);
      const plist = await NodeFSP.readFile(
        NodePath.join(f.home, "Library/LaunchAgents/io.elchiapp.t3attested.verifier.plist"),
        "utf8",
      );
      NodeAssert.ok(plist.includes(f.home));
      NodeAssert.ok(!plist.includes("/Users/marco"));
      NodeAssert.ok(!plist.includes("SSH_AUTH_SOCK"));
    } finally {
      await f.cleanup();
    }
  },
);
NodeTest.test(
  "tampered runtime or app stops before changing an existing installation",
  async () => {
    for (const corrupt of ["runtime/main.mjs", "T3 Attested.app/Contents/Resources/app.asar"]) {
      const f = await fixture();
      try {
        await NodeFSP.writeFile(NodePath.join(f.payload, corrupt), "tampered");
        await NodeAssert.rejects(installPackage(f), /does not match/);
        await NodeAssert.rejects(
          NodeFSP.stat(NodePath.join(f.home, "Applications/T3 Attested.app")),
          (e) => e.code === "ENOENT",
        );
      } finally {
        await f.cleanup();
      }
    }
  },
);
NodeTest.test(
  "different existing policies and linked paths are preserved rather than overwritten",
  async () => {
    const f = await fixture();
    try {
      const base = NodePath.join(f.home, ".t3-attested");
      await NodeFSP.mkdir(base);
      const policy = NodePath.join(base, "attestation-client.json");
      await NodeFSP.writeFile(
        policy,
        JSON.stringify({ ...f.policy, modelOrigin: "https://other.example" }),
        { mode: 0o600 },
      );
      await NodeAssert.rejects(installPackage(f), /configuration differs/);
      NodeAssert.ok((await NodeFSP.readFile(policy, "utf8")).includes("other.example"));
      const outside = NodePath.join(f.root, "outside");
      await NodeFSP.mkdir(outside);
      await NodeFSP.symlink(outside, NodePath.join(f.home, "linked"));
      await NodeAssert.rejects(safeTarget(f.home, "linked/code"), /linked installation/);
      await NodeAssert.rejects(safeTarget(f.home, "../outside"), /escapes/);
    } finally {
      await f.cleanup();
    }
  },
);
NodeTest.test(
  "failed verifier startup rolls back app code and leaves old data and decisions intact",
  async () => {
    const f = await fixture();
    try {
      const app = NodePath.join(f.home, "Applications/T3 Attested.app");
      await NodeFSP.mkdir(app, { recursive: true });
      await NodeFSP.writeFile(NodePath.join(app, "old-code"), "old");
      const data = NodePath.join(f.home, ".t3-attested/userdata");
      await NodeFSP.mkdir(data, { recursive: true });
      await NodeFSP.writeFile(NodePath.join(data, "history.sentinel"), "history stays");
      const policy = NodePath.join(f.home, ".t3-attested/attestation-client.json");
      await NodeFSP.writeFile(policy, JSON.stringify(f.policy), { mode: 0o600 });
      f.services.ready = async () => {
        throw Error("startup failed");
      };
      await NodeAssert.rejects(installPackage(f), /startup failed/);
      NodeAssert.equal(await NodeFSP.readFile(NodePath.join(app, "old-code"), "utf8"), "old");
      NodeAssert.equal(
        await NodeFSP.readFile(NodePath.join(data, "history.sentinel"), "utf8"),
        "history stays",
      );
      NodeAssert.deepEqual(JSON.parse(await NodeFSP.readFile(policy, "utf8")), f.policy);
    } finally {
      await f.cleanup();
    }
  },
);
NodeTest.test(
  "custom data-home installs and unsupported CPUs cannot be replaced accidentally",
  async () => {
    const f = await fixture();
    try {
      f.services.architecture = "x64";
      await NodeAssert.rejects(installPackage(f), /Apple silicon/);
      f.services.architecture = "arm64";
      const resources = NodePath.join(f.home, "Applications/T3 Attested.app/Contents/Resources");
      await NodeFSP.mkdir(resources, { recursive: true });
      await NodeFSP.writeFile(
        NodePath.join(resources, "t3-attested-launch.json"),
        "custom-home-sentinel",
      );
      await NodeAssert.rejects(installPackage(f), /custom T3 data home/);
      NodeAssert.equal(
        await NodeFSP.readFile(NodePath.join(resources, "t3-attested-launch.json"), "utf8"),
        "custom-home-sentinel",
      );
    } finally {
      await f.cleanup();
    }
  },
);
