import type { EnvironmentId } from "@t3tools/contracts";
import * as Option from "effect/Option";
import { clientAttestation, normalizeAttestationOrigin } from "@t3tools/client-runtime/attestation";
import { appAtomRegistry } from "../../state/atom-registry";
import { environmentSession } from "../../state/session";

export function mobileAttestationThread(
  draftKey: string,
  queued: ReadonlyArray<{ readonly messageId: string; readonly threadId: string }> = [],
): string | null {
  if (draftKey.startsWith("new-task:")) return draftKey;
  if (draftKey.startsWith("pending-task:"))
    return (
      queued.find((message) => `pending-task:${message.messageId}` === draftKey)?.threadId ?? null
    );
  const separator = draftKey.lastIndexOf(":");
  return separator > 0 ? draftKey.slice(separator + 1) : null;
}

/** A draft becoming a thread is the same conversation, not consent for an unrelated thread. */
export function inheritDraftAttestationOverride(
  environmentId: EnvironmentId,
  draftKey: string,
  threadId: string,
): void {
  const connection = appAtomRegistry.get(
    environmentSession.preparedConnectionValueAtom(environmentId),
  );
  if (Option.isNone(connection)) return;
  const origin = normalizeAttestationOrigin(connection.value.httpBaseUrl);
  clientAttestation.moveOverride(origin, draftKey, threadId);
}
