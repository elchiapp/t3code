// @effect-diagnostics nodeBuiltinImport:off -- Native approval uses only bundled OS-auth helpers and the system Polkit agent.
import * as NodeChildProcess from "node:child_process";
import * as NodeFSP from "node:fs/promises";

export interface DeviceAuthenticationContext {
  readonly platform: NodeJS.Platform;
  readonly helperPath: string;
  readonly windowHandle: Uint8Array;
  readonly signal?: AbortSignal;
}

function command(
  executable: string,
  args: ReadonlyArray<string>,
  signal?: AbortSignal,
): Promise<number> {
  return new Promise((resolve, reject) => {
    NodeChildProcess.execFile(
      executable,
      [...args],
      { windowsHide: true, timeout: 180_000, signal },
      (error) => {
        if (!error) return resolve(0);
        if (typeof error.code === "number") return resolve(error.code);
        if (error.name === "AbortError") return resolve(2);
        reject(new Error("System authentication is unavailable on this installation."));
      },
    );
  });
}

export async function authenticateDevice(
  reason: string,
  context: DeviceAuthenticationContext,
): Promise<boolean> {
  if (!reason || reason.length > 512) throw new Error("Invalid authentication request.");
  let code: number;
  if (context.platform === "darwin") {
    code = await command(context.helperPath, [reason], context.signal);
  } else if (context.platform === "win32") {
    const view = new DataView(
      context.windowHandle.buffer,
      context.windowHandle.byteOffset,
      context.windowHandle.byteLength,
    );
    const handle =
      context.windowHandle.byteLength === 8
        ? view.getBigUint64(0, true)
        : context.windowHandle.byteLength === 4
          ? BigInt(view.getUint32(0, true))
          : 0n;
    if (!handle) throw new Error("The T3 approval window is unavailable.");
    code = await command(context.helperPath, [handle.toString(16), reason], context.signal);
  } else if (context.platform === "linux") {
    const stat = await NodeFSP.readFile(`/proc/${process.pid}/stat`, "utf8");
    const started = stat
      .slice(stat.lastIndexOf(")") + 2)
      .trim()
      .split(/\s+/)[19];
    if (!started || !/^\d+$/.test(started) || process.getuid === undefined)
      throw new Error("The local authentication process cannot be identified.");
    code = await command(
      "/usr/bin/pkcheck",
      [
        "--action-id",
        "io.elchiapp.t3attested.approve-version",
        "--process",
        `${process.pid},${started},${process.getuid()}`,
        "--allow-user-interaction",
      ],
      context.signal,
    );
    if (code === 127)
      throw new Error("T3 system authentication needs its Polkit approval policy installed.");
  } else throw new Error("System authentication is not supported on this platform.");
  if (code === 0) return true;
  if (code === 1 || code === 2) return false;
  throw new Error("Device authentication is unavailable or not configured. No approval was saved.");
}

export async function configureLinuxApprovalPolicy(policyPath: string): Promise<boolean> {
  const destination = "/usr/share/polkit-1/actions/io.elchiapp.t3attested.approve-version.policy";
  const source = await NodeFSP.readFile(policyPath, "utf8");
  if (
    !source.includes('action id="io.elchiapp.t3attested.approve-version"') ||
    !source.includes("<allow_active>auth_self</allow_active>")
  )
    throw new Error("The bundled authentication policy is invalid.");
  const current = await NodeFSP.readFile(destination, "utf8").catch(() => null);
  if (current === source) return true;
  const code = await command("/usr/bin/pkexec", [
    "/usr/bin/install",
    "-m",
    "0644",
    policyPath,
    destination,
  ]);
  if (code !== 0) return false;
  return (await NodeFSP.readFile(destination, "utf8")) === source;
}
