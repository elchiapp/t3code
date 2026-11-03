// @effect-diagnostics nodeBuiltinImport:off -- This build-only adapter compiles and copies native OS-auth helpers before packaging.
import * as NodeChildProcess from "node:child_process";
import * as NodeUtil from "node:util";
import * as NodeFSP from "node:fs/promises";
import * as NodePath from "node:path";

const execute = NodeUtil.promisify(NodeChildProcess.execFile);
export async function stageAttestationAuth(input: {
  readonly repoRoot: string;
  readonly stageResourcesDir: string;
  readonly platform: "mac" | "win" | "linux";
  readonly arch: "arm64" | "x64" | "universal";
}) {
  const source = NodePath.join(input.repoRoot, "native", "attestation-auth");
  const output = NodePath.join(input.stageResourcesDir, "attestation-auth");
  const scratch = NodePath.join(
    input.repoRoot,
    ".t3",
    "attestation-auth",
    input.platform,
    input.arch,
  );
  await NodeFSP.mkdir(output, { recursive: true });
  await NodeFSP.mkdir(scratch, { recursive: true });
  if (input.platform === "linux") {
    await NodeFSP.copyFile(
      NodePath.join(source, "io.elchiapp.t3attested.approve-version.policy"),
      NodePath.join(output, "io.elchiapp.t3attested.approve-version.policy"),
    );
    return;
  }
  if (input.platform === "win") {
    await execute(
      "cmake",
      ["-S", source, "-B", scratch, "-A", input.arch === "arm64" ? "ARM64" : "x64"],
      { cwd: input.repoRoot },
    );
    await execute("cmake", ["--build", scratch, "--config", "Release"], { cwd: input.repoRoot });
    await NodeFSP.copyFile(
      NodePath.join(scratch, "Release", "t3-attestation-auth.exe"),
      NodePath.join(output, "t3-attestation-auth.exe"),
    );
    return;
  }
  const architectures = input.arch === "universal" ? ["arm64", "x64"] : [input.arch];
  const binaries: string[] = [];
  for (const architecture of architectures) {
    const binary = NodePath.join(scratch, `t3-attestation-auth-${architecture}`);
    await execute(
      "xcrun",
      [
        "swiftc",
        NodePath.join(source, "macos.swift"),
        "-O",
        "-framework",
        "LocalAuthentication",
        "-target",
        `${architecture === "arm64" ? "arm64" : "x86_64"}-apple-macos12.0`,
        "-module-cache-path",
        NodePath.join(scratch, "ModuleCache"),
        "-Xlinker",
        "-sectcreate",
        "-Xlinker",
        "__TEXT",
        "-Xlinker",
        "__info_plist",
        "-Xlinker",
        NodePath.join(source, "macos-info.plist"),
        "-o",
        binary,
      ],
      { cwd: input.repoRoot },
    );
    binaries.push(binary);
  }
  const destination = NodePath.join(output, "t3-attestation-auth");
  if (binaries.length === 1) await NodeFSP.copyFile(binaries[0]!, destination);
  else
    await execute("lipo", ["-create", ...binaries, "-output", destination], {
      cwd: input.repoRoot,
    });
}
