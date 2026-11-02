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

const clientThreadScope = Symbol("client-attestation-thread");

/** Client authorization context only; symbols are never part of the JSON RPC payload. */
export function withClientAttestationThread<T extends object>(input: T, threadId: string): T {
  return { ...input, [clientThreadScope]: threadId };
}

export function clientAttestationThreadId(input: unknown): string | null {
  if (typeof input !== "object" || input === null) return null;
  const scoped = input as {
    threadId?: unknown;
    targetThreadId?: unknown;
    [clientThreadScope]?: unknown;
  };
  const threadId = scoped.threadId ?? scoped.targetThreadId ?? scoped[clientThreadScope];
  return typeof threadId === "string" && threadId !== "" ? threadId : null;
}

export function clientAttestationProviderId(input: unknown): string | undefined {
  if (typeof input !== "object" || input === null || !("modelSelection" in input)) return undefined;
  const selection = input.modelSelection;
  return typeof selection === "object" &&
    selection !== null &&
    "instanceId" in selection &&
    typeof selection.instanceId === "string"
    ? selection.instanceId
    : undefined;
}
