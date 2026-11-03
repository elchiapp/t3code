// @effect-diagnostics nodeBuiltinImport:off -- Approval metadata uses an owner-only atomic file shared with the device-local inference guard.
import * as NodeFSP from "node:fs/promises";
import * as NodePath from "node:path";
import { DeviceVersionDecisionRecord } from "@t3tools/contracts";
import * as Schema from "effect/Schema";

const decode = Schema.decodeUnknownSync(
  Schema.Struct({
    version: Schema.Literal(1),
    decisions: Schema.Array(DeviceVersionDecisionRecord),
  }),
);

export function createDesktopVersionStore(
  path: string,
  newId: () => Promise<string>,
  owner: { platform: NodeJS.Platform; uid: number },
) {
  const read = async () => {
    let stat;
    try {
      stat = await NodeFSP.lstat(path);
    } catch (cause) {
      if ((cause as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw cause;
    }
    if (
      !stat.isFile() ||
      stat.size > 65536 ||
      (owner.platform !== "win32" && (stat.uid !== owner.uid || stat.mode & 0o077))
    )
      throw new Error("The device approval file is not protected.");
    const result = decode(JSON.parse(await NodeFSP.readFile(path, "utf8")));
    if (result.decisions.length > 32) throw new Error("Too many device decisions.");
    return result.decisions;
  };
  return {
    read,
    async write(decisions: ReadonlyArray<DeviceVersionDecisionRecord>) {
      decode({ version: 1, decisions });
      await read();
      const directory = NodePath.dirname(path);
      await NodeFSP.mkdir(directory, { recursive: true, mode: 0o700 });
      const parent = await NodeFSP.lstat(directory);
      if (!parent.isDirectory() || (owner.platform !== "win32" && parent.uid !== owner.uid))
        throw new Error("The device approval directory is not trusted.");
      const temporary = NodePath.join(directory, `.version-decision-${await newId()}.tmp`);
      try {
        await NodeFSP.writeFile(temporary, JSON.stringify({ version: 1, decisions }) + "\n", {
          flag: "wx",
          mode: 0o600,
        });
        await NodeFSP.rename(temporary, path);
      } finally {
        await NodeFSP.unlink(temporary).catch((cause: NodeJS.ErrnoException) => {
          if (cause.code !== "ENOENT") throw cause;
        });
      }
    },
  };
}
