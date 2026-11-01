import { ORCHESTRATION_V2_WS_METHODS, WS_METHODS } from "@t3tools/contracts";

const stopCommands = new Set([
  "thread.stop",
  "run.interrupt",
  "subagent.stop",
  "queued-run.cancel",
  "thread.user-input.dismiss",
]);
const metadataCommands = new Set([
  "thread.archive",
  "thread.unarchive",
  "thread.settle",
  "thread.auto-settle",
  "thread.unsettle",
  "thread.snooze",
  "thread.unsnooze",
  "thread.auto-settle.set",
  "thread.pin",
  "thread.unpin",
  "thread.pin.reorder",
  "thread.active.reorder",
  "thread.visit",
  "thread.mark-unread",
  "thread.runtime-mode.set",
  "thread.interaction-mode.set",
  "thread.model-selection.set",
  "thread.guest-share.close",
  "thread.guest-message.dismiss",
  "queued-run.reorder",
]);

export function requiresClientAttestation(method: string, input: unknown): boolean {
  if (method === WS_METHODS.attachmentsCreateUploadUrl) return true;
  if (method !== ORCHESTRATION_V2_WS_METHODS.dispatchCommand) return false;
  if (
    typeof input !== "object" ||
    input === null ||
    !("type" in input) ||
    typeof input.type !== "string"
  )
    return true;
  return !stopCommands.has(input.type) && !metadataCommands.has(input.type);
}
